import logging
from typing import Dict, Optional

from aleph_message.models import ProgramContent, ProgramMessage
from .conf import settings
from .models import VmHash, VmExecution

logger = logging.getLogger(__name__)


class VmPool:
    """Pool of VMs already started and used to decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.

    The counter is used by the VMs to set their tap interface name and the corresponding
    IPv4 subnet.
    """

    counter: int  # Used to provide distinct ids to network interfaces
    executions: Dict[VmHash, VmExecution]
    message_cache: Dict[str, ProgramMessage] = {}

    def __init__(self):
        self.counter = settings.START_ID_INDEX
        self.executions = {}

    async def create_a_vm(
        self, vm_hash: VmHash, program: ProgramContent, original: ProgramContent
    ) -> VmExecution:
        """Create a new Aleph Firecracker VM from an Aleph function message."""
        execution = VmExecution(vm_hash=vm_hash, program=program, original=original)
        self.executions[vm_hash] = execution
        await execution.prepare()
        self.counter += 1
        await execution.create(address=self.counter)
        return execution

    async def get_running_vm(self, vm_hash: VmHash) -> Optional[VmExecution]:
        """Return a running VM or None. Disables the VM expiration task."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running:
            execution.cancel_expiration()
            return execution
        else:
            return None

    def forget_vm(self, vm_hash: VmHash) -> None:
        self.executions.pop(vm_hash)
