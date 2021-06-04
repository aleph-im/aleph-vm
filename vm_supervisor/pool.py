import asyncio
import logging
from typing import Dict, Optional

from aleph_message.models import ProgramContent
from vm_supervisor.conf import settings
from vm_supervisor.vm.firecracker_microvm import (
    AlephFirecrackerVM,
    AlephFirecrackerResources,
)

logger = logging.getLogger(__name__)


class StartedVM:
    vm: AlephFirecrackerVM
    timeout_task: Optional[asyncio.Task]

    def __init__(self, vm: AlephFirecrackerVM):
        self.vm = vm
        self.timeout_task = None


class VmPool:
    """Pool of VMs already started and used to decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.

    The counter is used by the VMs to set their tap interface name and the corresponding
    IPv4 subnet.
    """

    counter: int  # Used to provide distinct ids to network interfaces
    started_vms_cache: Dict[ProgramContent, StartedVM]

    def __init__(self):
        self.counter = settings.START_ID_INDEX
        self.started_vms_cache = {}

    async def create_a_vm(self, message_content: ProgramContent, vm_hash: str) -> AlephFirecrackerVM:
        """Create a new Aleph Firecracker VM from an Aleph function message."""
        vm_resources = AlephFirecrackerResources(message_content)
        await vm_resources.download_all()
        self.counter += 1
        vm = AlephFirecrackerVM(
            vm_id=self.counter,
            vm_hash=vm_hash,
            resources=vm_resources,
            enable_networking=message_content.environment.internet,
            hardware_resources=message_content.resources,
        )
        try:
            await vm.setup()
            await vm.start()
            await vm.configure()
            await vm.start_guest_api()
            return vm
        except Exception:
            await vm.teardown()
            raise


    async def get_a_vm(self, message: ProgramContent, vm_hash: str, ) -> AlephFirecrackerVM:
        """Provision a VM in the pool, then return the first VM from the pool."""
        try:
            started_vm = self.started_vms_cache.pop(message)
            started_vm.timeout_task.cancel()
            return started_vm.vm
        except KeyError:
            return await self.create_a_vm(message_content=message, vm_hash=vm_hash)

    def keep_in_cache(
        self, vm: AlephFirecrackerVM, message: ProgramContent, timeout: float = 1.0
    ) -> None:
        """Keep a VM running for `timeout` seconds in case another query comes by."""

        if message in self.started_vms_cache:
            logger.warning("VM already in keep_in_cache, not caching")
            return

        started_vm = StartedVM(vm=vm)
        self.started_vms_cache[message] = started_vm

        loop = asyncio.get_event_loop()
        started_vm.timeout_task = loop.create_task(self.expire(vm, message, timeout))

    async def expire(
        self, vm: AlephFirecrackerVM, message: ProgramContent, timeout: float
    ):
        """Coroutine that will stop the VM after 'timeout' seconds."""
        await asyncio.sleep(timeout)
        assert self.started_vms_cache[message].vm is vm
        del self.started_vms_cache[message]
        await vm.teardown()
