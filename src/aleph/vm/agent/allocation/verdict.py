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

from aleph.vm.agent.allocation.plan import AllocationPlan, PlannedVm, PlanVerdict
from aleph.vm.agent.allocation.teardown import is_removable_by_allocation
from aleph.vm.agent.allocation.verify import VerificationOutcome, verify_entry
from aleph.vm.agent.capacity import (
    AdmissionVerdict,
    ResourceRequirements,
    requirements_from_message,
)
from aleph.vm.agent.vm_registry import AgentVmRecord
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
    ) -> list[AdmissionVerdict]: ...


# A VM the supervisor is already working on does not need re-creating.
LIVE_STATUSES = (VmStatus.RUNNING, VmStatus.BOOTING, VmStatus.DEFINED)


def compute_plan_id(planned: list[str], rejected: list[str]) -> str:
    """A stable identity for a plan, for correlation in logs and responses.

    Order-independent within each half, so the scheduler re-pushing the same
    set in a different order is visibly the same plan.

    The two halves are digested apart and then together: one merged sorted list
    gives the same identity to a push that planned A and refused B as to one
    that planned B and refused A. Digesting rather than joining with a
    separator keeps that true for a rejected key, which is whatever junk the
    push carried in place of a hash and may hold the separator itself.
    """

    def digest(hashes: list[str]) -> str:
        return sha256("\n".join(sorted(hashes)).encode()).hexdigest()

    return "sha256:" + sha256(f"{digest(planned)}:{digest(rejected)}".encode()).hexdigest()


def build_plan(body: dict, *, now: datetime) -> tuple[AllocationPlan, dict[str, dict]]:
    """Verify every entry and assemble the plan.

    Rejected entries are returned separately: they are answered in the response
    and never enter the plan, so nothing downstream can act on them.

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
            # The other order of the same duplicate: an earlier entry may
            # already have put this hash in the plan.
            entries.pop(vm_hash, None)
            continue
        entries[vm_hash] = PlannedVm(vm_hash=vm_hash, verified=verified)
    plan_id = compute_plan_id([str(h) for h in entries], [str(h) for h in rejected])
    return AllocationPlan(plan_id=plan_id, received_at=now, entries=entries), rejected


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
) -> PlanVerdict:
    """The immediate answer: what we take, what we drop, what we refuse."""
    verdict = PlanVerdict()
    by_hash = {ItemHash(info.vm_id): info for info in infos}
    unchanged: set[ItemHash] = set()

    for vm_hash, info in by_hash.items():
        record = registry.get(vm_hash)
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

    for admission in capacity.simulate(candidates, releasing=frozenset(verdict.removing)):
        if admission.accepted:
            verdict.accepted.append(admission.vm_hash)
        else:
            verdict.rejected[admission.vm_hash] = {"code": admission.code, "message": admission.detail}

    return verdict
