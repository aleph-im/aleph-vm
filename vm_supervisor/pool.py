import asyncio
import logging
from typing import Dict, Optional, Iterable

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
        vm_id = self.get_unique_vm_id()
        await execution.create(vm_id=vm_id)
        return execution

    def get_unique_vm_id(self) -> int:
        """Get a unique identifier for the VM.

        This identifier is used to name the network interface and in the IPv4 range
        dedicated to the VM.
        """
        self.counter += 1
        if self.counter < 255**2:
            # In common cases, use the counter itself as the vm_id. This makes it
            # easier to debug.
            return self.counter
        else:
            # The value of the counter is too high and some functions such as the
            # IPv4 range dedicated to the VM do not support such high values.
            #
            # We therefore recycle vm_id values from executions that are not running
            # anymore.
            currently_used_vm_ids = set(execution.vm.vm_id
                                        for execution in self.executions.values()
                                        if execution.is_running)
            for i in range(settings.START_ID_INDEX, 255**2):
                if i not in currently_used_vm_ids:
                    return i

    async def get_running_vm(self, vm_hash: VmHash) -> Optional[VmExecution]:
        """Return a running VM or None. Disables the VM expiration task."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running:
            execution.cancel_expiration()
            return execution
        else:
            return None

    def forget_vm(self, vm_hash: VmHash) -> None:
        """Remove a VM from the executions pool.

        Used after self.create_a_vm(...) raised an error in order to
        completely forget about the execution and enforce a new execution
        when attempted again.
        """
        try:
            del self.executions[vm_hash]
        except KeyError:
            pass

    async def stop(self):
        """Stop all VMs in the pool."""

        # Stop executions in parallel:
        await asyncio.gather(
            *(execution.stop() for vm_hash, execution in self.executions.items())
        )

    def get_long_running_executions(self) -> Iterable[VmExecution]:
        for vm_hash, execution in self.executions.items():
            if execution.marked_as_long_running and execution.is_running:
                yield execution
