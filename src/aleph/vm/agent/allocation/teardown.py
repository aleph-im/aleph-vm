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


def retention_reason(record: AgentVmRecord, info: VmInfo) -> str | None:
    """Why an allocation push may not stop this VM, None when it may.

    The one rule, and the answer the push is given for a VM it asked to have
    stopped and did not get. The two used to be written out separately, here
    and in the verdict, and a reason the list grew that the other did not
    would have had a retained VM reported under a reason for retaining a
    different one.
    """
    if not record.persistent:
        return "non_persistent"
    if record.is_vprogram:
        # The scheduler is a v-program's single source of truth, so none of
        # the reasons below hold against it, credit-paid and confidential
        # though it is by construction.
        return None
    if record.uses_payment_stream:
        return "payment_stream"
    if record.uses_payment_credit:
        return "payment_credit"
    if info.gpus:
        return "gpu"
    if info.confidential_mode is not ConfidentialMode.NONE:
        return "confidential"
    return None


def is_removable_by_allocation(record: AgentVmRecord, info: VmInfo) -> bool:
    """Whether an allocation push may stop this VM when the plan drops it."""
    return retention_reason(record, info) is None


async def teardown_vm(vm_hash: ItemHash, *, supervisor: Supervisor, registry: AgentVmRegistry) -> None:
    """Retire the VM as GONE, the allocation plane's one way to stop a VM.

    Everything this used to do by hand (supervisor delete, registry forget,
    DB rows, staging directories) is what GONE does, plus device teardown and
    the retention policy for the disks; a VM the supervisor has already
    forgotten is still cleaned, since the rest of that state is ours.
    """
    await retire_vm(vm_hash, RetireReason.GONE, supervisor=supervisor, registry=registry)
