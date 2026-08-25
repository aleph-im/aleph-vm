"""Turning a request body into a plan, and a plan into an immediate answer.

Everything here is pure and await-free by design: the handler must not yield to
the event loop between reading the supervisor's view and swapping the desired
state, or a concurrent push could invalidate the verdict it just returned.
"""

import logging
from datetime import datetime
from hashlib import sha256

from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ItemHash,
    VerifiableProgramContent,
)

from aleph.vm.agent.allocation.plan import AllocationPlan, PlannedVm, PlanVerdict
from aleph.vm.agent.allocation.teardown import is_removable_by_allocation
from aleph.vm.agent.allocation.verify import VerificationOutcome, verify_entry
from aleph.vm.agent.capacity import requirements_from_message
from aleph.vm.supervisor_interface.types import ConfidentialMode, VmInfo, VmStatus

logger = logging.getLogger(__name__)

# A VM the supervisor is already working on does not need re-creating.
LIVE_STATUSES = (VmStatus.RUNNING, VmStatus.BOOTING, VmStatus.DEFINED)


def compute_plan_id(hashes: list[str]) -> str:
    """A stable identity for a plan, for correlation in logs and responses.

    Order-independent, so the scheduler re-pushing the same set in a different
    order is visibly the same plan.
    """
    return "sha256:" + sha256("\n".join(sorted(hashes)).encode()).hexdigest()


def build_plan(body: dict, *, now: datetime) -> tuple[AllocationPlan, dict[ItemHash, dict]]:
    """Verify every entry and assemble the plan.

    Rejected entries are returned separately: they are answered in the response
    and never enter the plan, so nothing downstream can act on them.
    """
    entries: dict[ItemHash, PlannedVm] = {}
    rejected: dict[ItemHash, dict] = {}
    for entry in body.get("vms", []):
        vm_hash = ItemHash(entry["item_hash"])
        outcome, verified, reason = verify_entry(entry)
        if outcome is VerificationOutcome.REJECTED:
            rejected[vm_hash] = {"code": "invalid_message", "message": reason}
            continue
        entries[vm_hash] = PlannedVm(vm_hash=vm_hash, verified=verified)
    plan_id = compute_plan_id([str(h) for h in entries] + [str(h) for h in rejected])
    return AllocationPlan(plan_id=plan_id, received_at=now, entries=entries), rejected


def _retention_reason(record, info: VmInfo) -> str:
    """Why an allocation push is not allowed to stop this VM."""
    if record.uses_payment_stream:
        return "payment_stream"
    if record.uses_payment_credit:
        return "payment_credit"
    if info.gpus:
        return "gpu"
    if info.confidential_mode is not ConfidentialMode.NONE:
        return "confidential"
    return "operator_policy"


def _targets_another_node(content: ExecutableContent, node_hash: str | None) -> bool:
    """Whether the message pins itself to a CRN that is not us."""
    requirements = getattr(content, "requirements", None)
    node = getattr(requirements, "node", None) if requirements else None
    required = getattr(node, "node_hash", None) if node else None
    if not required:
        return False
    return node_hash is None or str(required) != str(node_hash)


def compute_verdict(
    plan: AllocationPlan,
    *,
    infos: list[VmInfo],
    registry,
    capacity,
    node_hash: str | None = None,
) -> PlanVerdict:
    """The immediate answer: what we take, what we drop, what we refuse."""
    verdict = PlanVerdict()
    by_hash = {ItemHash(info.vm_id): info for info in infos}

    for vm_hash, info in by_hash.items():
        record = registry.get(vm_hash)
        if vm_hash in plan.entries:
            if info.status in LIVE_STATUSES or info.awaiting_confidential_init:
                verdict.unchanged.append(vm_hash)
            continue
        if record is None or info.status is not VmStatus.RUNNING:
            continue
        if is_removable_by_allocation(record, info):
            verdict.removing.append(vm_hash)
        else:
            verdict.retained[vm_hash] = _retention_reason(record, info)

    candidates = []
    for vm_hash, planned in plan.entries.items():
        if vm_hash in verdict.unchanged:
            continue
        if planned.verified is None:
            verdict.pending.append(vm_hash)
            continue
        content = planned.verified.message.content
        if _targets_another_node(content, node_hash):
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

    for admission in capacity.simulate(candidates, releasing=frozenset(verdict.removing)):
        if admission.accepted:
            verdict.accepted.append(admission.vm_hash)
        else:
            verdict.rejected[admission.vm_hash] = {"code": admission.code, "message": admission.detail}

    return verdict
