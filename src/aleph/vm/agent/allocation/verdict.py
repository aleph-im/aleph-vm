"""Turning a request body into a plan, and a plan into an immediate answer.

Everything here is pure and await-free by design: the handler must not yield to
the event loop between reading the supervisor's view and swapping the desired
state, or a concurrent push could invalidate the verdict it just returned.
"""

import logging
from datetime import datetime
from hashlib import sha256
from typing import Protocol

from aleph_message.models import ExecutableContent, ItemHash

from aleph.vm.agent.allocation.plan import (
    LIVE_STATUSES,
    AllocationPlan,
    PlannedVm,
    PlanVerdict,
    by_hash,
)
from aleph.vm.agent.allocation.teardown import is_removable_by_allocation
from aleph.vm.agent.allocation.verify import VerificationOutcome, verify_entry
from aleph.vm.agent.capacity import (
    AdmissionVerdict,
    ResourceRequirements,
    requirements_from_message,
)
from aleph.vm.agent.vm_registry import AgentVmRecord
from aleph.vm.resources import GpuDevice
from aleph.vm.supervisor_interface.types import ConfidentialMode, VmInfo, VmStatus

logger = logging.getLogger(__name__)


class _Registry(Protocol):
    """The slice of AgentVmRegistry this module needs."""

    def get(self, vm_hash: ItemHash) -> AgentVmRecord | None: ...


class _Capacity(Protocol):
    """The slice of CapacityManager this module needs."""

    def simulate(
        self,
        candidates: list[tuple[ItemHash, ResourceRequirements]],
        *,
        releasing: frozenset[ItemHash] = ...,
        available_gpus: list[GpuDevice] | None = ...,
    ) -> list[AdmissionVerdict]: ...


def compute_plan_id(planned: list[str], rejected: list[str]) -> str:
    """A stable identity for a plan, for correlation in logs and responses.

    Order-independent within each half, so the scheduler re-pushing the same
    set in a different order is visibly the same plan.

    The two halves are digested apart and then together: one merged sorted list
    gives the same identity to a push that planned A and refused B as to one
    that planned B and refused A. Every key is digested on its own before the
    join, for the same reason one level down: a rejected key is whatever junk
    the push carried in place of a hash, so joining the keys directly lets a
    single key holding the separator pass for the two either side of it.
    """

    def digest(hashes: list[str]) -> str:
        return sha256("\n".join(sorted(sha256(key.encode()).hexdigest() for key in hashes)).encode()).hexdigest()

    return "sha256:" + sha256(f"{digest(planned)}:{digest(rejected)}".encode()).hexdigest()


def build_plan(body: dict, *, now: datetime) -> tuple[AllocationPlan, dict[str, dict]]:
    """Verify every entry and assemble the plan.

    Rejected entries are returned separately: they are answered in the response
    and never enter the plan, so nothing downstream can act on them.

    Separately is not silently: an entry whose hash we could read is named in
    the plan's ``refused`` set, because the convergence loop tears down every
    VM the push did not name and a message we would not verify is no reason
    to delete the VM it names. An entry whose hash we could not read is left
    out of that set, since it names no VM here and so has nothing to protect.

    A bad entry is data to reject, but a body we cannot read raises. An empty
    plan is a real instruction, the one that stops everything this node runs,
    so a shape we cannot make sense of must never be read as one: ``vms: 5``
    and ``vms: null`` used to raise a bare TypeError here, and ``vms: "abc"``
    was quietly walked character by character into a plan of nothing at all.
    The list has to be there and be a list; the handler answers 400.
    """
    vms = body.get("vms") if isinstance(body, dict) else None
    if not isinstance(vms, list):
        msg = "plan body has no 'vms' list"
        raise ValueError(msg)
    entries: dict[ItemHash, PlannedVm] = {}
    rejected: dict[str, dict] = {}
    refused: set[ItemHash] = set()
    for entry in vms:
        # This is the validation boundary for a body the scheduler controls, so
        # a bad entry is data to reject, never an exception: one unusable hash
        # must not take down the whole push.
        raw_hash = entry.get("item_hash") if isinstance(entry, dict) else None
        try:
            vm_hash = ItemHash(str(raw_hash))
        except Exception:
            logger.warning("Refusing plan entry with an unusable item_hash: %r", raw_hash)
            rejected[str(raw_hash)] = {"code": "invalid_message", "message": "unusable item_hash"}
            continue
        if vm_hash in rejected:
            # The same hash pushed twice, refused once. A later entry must not
            # talk the plan into carrying a hash the answer says was refused.
            logger.warning("Ignoring a repeat entry for %s: already refused by this push", vm_hash)
            continue
        outcome, verified, reason = verify_entry(entry)
        if outcome is VerificationOutcome.REJECTED:
            rejected[vm_hash] = {"code": "invalid_message", "message": reason}
            refused.add(vm_hash)
            # The other order of the same duplicate: an earlier entry may
            # already have put this hash in the plan.
            entries.pop(vm_hash, None)
            continue
        entries[vm_hash] = PlannedVm(vm_hash=vm_hash, verified=verified)
    plan_id = compute_plan_id([str(h) for h in entries], [str(h) for h in rejected])
    plan = AllocationPlan(plan_id=plan_id, received_at=now, entries=entries, refused=frozenset(refused))
    return plan, rejected


def _retention_reason(record: AgentVmRecord, info: VmInfo) -> str:
    """Why an allocation push is not allowed to stop this VM."""
    if not record.persistent:
        return "non_persistent"
    if record.uses_payment_stream:
        return "payment_stream"
    if record.uses_payment_credit:
        return "payment_credit"
    if info.gpus:
        return "gpu"
    if info.confidential_mode is not ConfidentialMode.NONE:
        return "confidential"
    # Unreachable while the branches above mirror is_removable_by_allocation,
    # which is the point: a reason it grows that this does not answers here
    # rather than passing a VM off as removable.
    return "operator_policy"


def _required_node_hash(content: ExecutableContent) -> str | None:
    """The CRN this message pins itself to, if it pins one."""
    requirements = getattr(content, "requirements", None)
    node = getattr(requirements, "node", None) if requirements else None
    required = getattr(node, "node_hash", None) if node else None
    return str(required) if required else None


def compute_verdict(
    plan: AllocationPlan,
    *,
    infos: list[VmInfo],
    registry: _Registry,
    capacity: _Capacity,
    node_hash: str | None = None,
    available_gpus: list[GpuDevice] | None = None,
) -> PlanVerdict:
    """The immediate answer: what we take, what we drop, what we refuse.

    ``available_gpus`` is the host's unattached cards. Reading them is an
    async call on the supervisor and this stays await-free, for the reason at
    the top of the module, so the handler reads them first and hands them in.
    Without them simulate refuses every candidate that asks for a card, which
    is the right answer to give when the cards were not looked at.
    """
    verdict = PlanVerdict()
    known = by_hash(infos)
    unchanged: set[ItemHash] = set()

    for vm_hash, info in known.items():
        if vm_hash in plan.entries:
            if info.status in LIVE_STATUSES or info.awaiting_confidential_init:
                unchanged.add(vm_hash)
                verdict.unchanged.append(vm_hash)
            # A planned VM the supervisor holds dead is about to be created
            # again, and its stale record still counts as committed, but that
            # is simulate's business: it leaves every candidate's own record
            # out of the sums the way check_capacity's exclude_vm_hash does.
            # Listing it as released here would credit that memory to the
            # other candidates too, and for one still waiting on its message
            # or refused for another node it would credit memory nobody is
            # freeing at all.
            continue
        record = registry.get(vm_hash)
        # A VM the supervisor runs that we hold no record for is left alone
        # and reported as neither dropped nor kept. We know nothing about what
        # it is owed, and an allocation push is not the place to find out.
        if record is None or info.status is not VmStatus.RUNNING:
            continue
        if is_removable_by_allocation(record, info):
            verdict.removing.append(vm_hash)
        else:
            verdict.retained[vm_hash] = _retention_reason(record, info)

    candidates = []
    for vm_hash, planned in plan.entries.items():
        if vm_hash in unchanged:
            continue
        if planned.verified is None:
            verdict.pending.append(vm_hash)
            continue
        content = planned.verified.message.content
        required_node = _required_node_hash(content)
        if required_node and node_hash is None:
            # Not knowing our own hash yet is not the same answer as "you asked
            # for a different CRN": the legacy path returns 503 here so the
            # scheduler retries rather than treating it as settled.
            logger.info("Cannot place %s: this node has not discovered its own hash", vm_hash)
            verdict.rejected[vm_hash] = {
                "code": "node_hash_unknown",
                "message": "this node has not discovered its own hash yet",
            }
            continue
        if required_node and required_node != str(node_hash):
            logger.info("Refusing %s: allocated to another node", vm_hash)
            verdict.rejected[vm_hash] = {
                "code": "node_mismatch",
                "message": "this instance is allocated to a different node",
            }
            continue
        candidates.append((vm_hash, requirements_from_message(content)))

    admissions = capacity.simulate(candidates, releasing=frozenset(verdict.removing), available_gpus=available_gpus)
    for admission in admissions:
        if admission.accepted:
            verdict.accepted.append(admission.vm_hash)
        else:
            verdict.rejected[admission.vm_hash] = {"code": admission.code, "message": admission.detail}

    return verdict


def narrow_plan(plan: AllocationPlan, verdict: PlanVerdict) -> AllocationPlan:
    """The plan the reconciler is handed: the push, less what the answer refused.

    A refused entry must never reach the loop. Left in, it would be retried
    forever at backoff rate, and started the moment room appeared, on a node
    the scheduler was told had refused it and has since placed it elsewhere
    from. Pending entries stay: nothing judged them, and the fetch that will
    is the loop's own. The identity stays too, since it names the push, and a
    re-push of the same set is the same plan whatever the host had room for
    the first time.

    Dropped is not forgotten: the refused hashes are carried alongside, so
    the loop can tell a VM this push refused from one it never mentioned. It
    tears down the second kind, and a refusal is no reason to destroy a VM.
    The ones build_plan already refused, over a message it would not verify,
    are carried through for the same reason.
    """
    entries = {vm_hash: planned for vm_hash, planned in plan.entries.items() if vm_hash not in verdict.rejected}
    return AllocationPlan(
        plan_id=plan.plan_id,
        received_at=plan.received_at,
        entries=entries,
        refused=plan.refused | (frozenset(plan.entries) - frozenset(entries)),
    )
