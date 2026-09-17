"""Stopping a VM because the scheduler's plan no longer lists it.

The scheduler is the single source of truth for what runs on this node,
whatever the payment tier, GPU or confidential mode: the CCN removes an
instance message its balance no longer covers, the scheduler validates PAYG
streams, and anything failing either leaves the plan. The node matches the
allocation rather than forming its own opinion. The one VM it keeps is one it
never started persistent, which no allocation ever listed.

Stopping means retiring as GONE: the scheduler said this VM should not exist,
so the record and side state go, and the disks follow VOLUME_RETENTION. The
named seam exists because the legacy endpoint and the v2 reconciler share this
exact behaviour.
"""

from aleph_message.models import ItemHash

from aleph.vm.agent.vm.retire import RetireReason, retire_vm
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.supervisor_interface.abc import Supervisor


def retention_reason(record: AgentVmRecord) -> str | None:
    """Why an allocation push may not stop this VM, None when it may.

    The one rule, and the answer the push is given for a VM it asked to have
    stopped and did not get: the verdict reports this rather than keeping a
    list of its own that could drift from the loop's.
    """
    if not record.persistent:
        return "non_persistent"
    return None


def is_removable_by_allocation(record: AgentVmRecord) -> bool:
    """Whether an allocation push may stop this VM when the plan drops it."""
    return retention_reason(record) is None


async def teardown_vm(vm_hash: ItemHash, *, supervisor: Supervisor, registry: AgentVmRegistry) -> None:
    """Retire the VM as GONE, the allocation plane's one way to stop a VM.

    Everything this used to do by hand (supervisor delete, registry forget,
    DB rows, staging directories) is what GONE does, plus device teardown and
    the retention policy for the disks; a VM the supervisor has already
    forgotten is still cleaned, since the rest of that state is ours.
    """
    await retire_vm(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
