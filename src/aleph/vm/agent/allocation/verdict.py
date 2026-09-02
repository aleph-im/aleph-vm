"""Turning a request body into a plan, and a plan into an immediate answer.

Everything here is pure and await-free by design: the handler must not yield to
the event loop between reading the supervisor's view and swapping the desired
state, or a concurrent push could invalidate the verdict it just returned.
"""

import logging
from datetime import datetime
from hashlib import sha256
from typing import Protocol

from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ItemHash,
    VerifiableProgramContent,
)

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
        candidates: list[tuple[ItemHash, ResourceRequirements, bool]],
        *,
        releasing: frozenset[ItemHash] = ...,
    ) -> list[AdmissionVerdict]: ...


# A VM the supervisor is already working on does not need re-creating.
LIVE_STATUSES = (VmStatus.RUNNING, VmStatus.BOOTING, VmStatus.DEFINED)


def compute_plan_id(hashes: list[str]) -> str:
    """A stable identity for a plan, for correlation in logs and responses.

    Order-independent, so the scheduler re-pushing the same set in a different
    order is visibly the same plan.
    """
    return "sha256:" + sha256("\n".join(sorted(hashes)).encode()).hexdigest()


def build_plan(body: dict, *, now: datetime) -> tuple[AllocationPlan, dict[str, dict]]:
    """Verify every entry and assemble the plan.

    Rejected entries are returned separately: they are answered in the response
    and never enter the plan, so nothing downstream can act on them.
    """
    entries: dict[ItemHash, PlannedVm] = {}
    rejected: dict[str, dict] = {}
    for entry in body.get("vms", []):
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
        outcome, verified, reason = verify_entry(entry)
        if outcome is VerificationOutcome.REJECTED:
            rejected[vm_hash] = {"code": "invalid_message", "message": reason}
            continue
        entries[vm_hash] = PlannedVm(vm_hash=vm_hash, verified=verified)
    plan_id = compute_plan_id([str(h) for h in entries] + [str(h) for h in rejected])
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
    # Planned VMs the supervisor holds in a dead state are about to be created
    # again. Their registry records still count as committed, so admission has
    # to discount them or a recreate is judged against its own resources; the
    # enforced path does the same thing with check_capacity's exclude_vm_hash.
    recreating: set[ItemHash] = set()

    for vm_hash, info in by_hash.items():
        record = registry.get(vm_hash)
        if vm_hash in plan.entries:
            if info.status in LIVE_STATUSES or info.awaiting_confidential_init:
                unchanged.add(vm_hash)
                verdict.unchanged.append(vm_hash)
            elif record is not None:
                recreating.add(vm_hash)
            continue
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
        # A v-program belongs in the instance memory bucket but is not an
        # InstanceContent, the same distinction _admit makes in run.py.
        is_instance = isinstance(content, (InstanceContent, VerifiableProgramContent))
        candidates.append((vm_hash, requirements_from_message(content), is_instance))

    for admission in capacity.simulate(candidates, releasing=frozenset(verdict.removing) | recreating):
        if admission.accepted:
            verdict.accepted.append(admission.vm_hash)
        else:
            verdict.rejected[admission.vm_hash] = {"code": admission.code, "message": admission.detail}

    return verdict
