import asyncio

from firecracker.microvm import MicroVM
from vm_supervisor.conf import settings
from vm_supervisor.vm.firecracker_microvm import start_new_vm


class VmPool:
    """Pool of VMs pre-allocated in order to decrease response time.
    The counter is used by the VMs to set their tap interface name and the corresponding
    IPv4 subnet.
    """

    queue: asyncio.Queue
    counter: int  # Used for network interfaces

    def __init__(self):
        self.queue = asyncio.Queue()
        self.counter = settings.VM_ID_START_INDEX

    async def provision(self, kernel_image_path, rootfs_path):
        self.counter += 1
        vm = await start_new_vm(
            vm_id=self.counter,
            kernel_image_path=kernel_image_path,
            rootfs_path=rootfs_path,
        )
        await self.queue.put(vm)
        return vm

    async def get_a_vm(self, kernel_image_path, rootfs_path) -> MicroVM:
        loop = asyncio.get_event_loop()
        loop.create_task(self.provision(kernel_image_path, rootfs_path))
        # Return the first VM from the pool
        return await self.queue.get()
