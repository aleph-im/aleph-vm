"""Stopping a VM because the scheduler's plan no longer lists it.

Removability is not uniform. A VM the user pays for directly (a payment stream
or credits), one holding GPUs, or a confidential one is retained: the scheduler
is not the authority on those. A v-program inverts that, because the scheduler
IS its single source of truth, and it is credit-paid and confidential by
construction.

Stopping means retiring as GONE: the scheduler said this VM should not exist,
so the record and side state go, and the disks follow VOLUME_RETENTION. The
named seam exists because the legacy endpoint and the v2 reconciler share this
exact behaviour.
"""

from aleph_message.models import ItemHash

from aleph.vm.agent.vm.retire import RetireReason, retire_vm
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.types import ConfidentialMode, VmInfo


def is_removable_by_allocation(record: AgentVmRecord, info: VmInfo) -> bool:
    """Whether an allocation push may stop this VM when the plan drops it."""
    if not record.persistent:
        return False
    if record.is_vprogram:
        return True
    return (
        not record.uses_payment_stream
        and not record.uses_payment_credit
        and not info.gpus
        and info.confidential_mode is ConfidentialMode.NONE
    )


async def teardown_vm(vm_hash: ItemHash, *, supervisor: Supervisor, registry: AgentVmRegistry) -> None:
    """Retire the VM as GONE, the allocation plane's one way to stop a VM.

    Everything this used to do by hand (supervisor delete, registry forget,
    DB rows, staging directories) is what GONE does, plus device teardown and
    the retention policy for the disks; a VM the supervisor has already
    forgotten is still cleaned, since the rest of that state is ours.
    """
    await retire_vm(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
