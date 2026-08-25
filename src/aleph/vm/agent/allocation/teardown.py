"""Stopping a VM because the scheduler's plan no longer lists it.

Removability is not uniform. A VM the user pays for directly (a payment stream
or credits), one holding GPUs, or a confidential one is retained: the scheduler
is not the authority on those. A v-program inverts that, because the scheduler
IS its single source of truth, and it is credit-paid and confidential by
construction.

Tearing down is a composite: the supervisor owns the VM, the agent owns the
registry record, the DB rows and the staging directories, so all of them have
to go.
"""

import logging

from aleph_message.models import ItemHash

from aleph.vm.agent.metrics import delete_records_for_vm
from aleph.vm.agent.snp_instance_launch import remove_snp_instance_staging
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.agent.vprogram_launch import remove_vprogram_staging
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import ConfidentialMode, VmId, VmInfo

logger = logging.getLogger(__name__)


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
    """Delete the VM and every piece of agent-side state that belongs to it.

    Idempotent: a VM the supervisor has already forgotten still has its agent
    state cleaned, since that state is ours and would otherwise leak.
    """
    try:
        await supervisor.delete_vm(VmId(str(vm_hash)))
    except VmNotFoundError:
        logger.info("Supervisor no longer knows %s; cleaning agent state anyway", vm_hash)
    registry.forget(vm_hash)
    await delete_records_for_vm(str(vm_hash))
    remove_vprogram_staging(vm_hash)
    remove_snp_instance_staging(vm_hash)
