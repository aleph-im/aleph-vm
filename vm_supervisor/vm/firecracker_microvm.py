import asyncio
import logging
from os.path import isfile

from vm_supervisor.conf import settings
from firecracker.microvm import MicroVM, setfacl

logger = logging.getLogger(__name__)


async def start_new_vm(vm_id: int,
                       kernel_image_path: str,
                       rootfs_path: str) -> MicroVM:
    logger.info('Created VM= %s', vm_id)

    assert isfile(kernel_image_path)
    assert isfile(rootfs_path)

    await setfacl()
    vm = MicroVM(vm_id,
                 firecracker_bin_path=settings.FIRECRACKER_PATH,
                 use_jailer=settings.USE_JAILER,
                 jailer_bin_path=settings.JAILER_PATH)
    vm.cleanup_jailer()
    await vm.start()
    await vm.socket_is_ready()
    await vm.set_boot_source(kernel_image_path, enable_console=settings.PRINT_SYSTEM_LOGS)
    await vm.set_rootfs(rootfs_path)
    await vm.set_vsock()
    await vm.set_network()

    if settings.PRINT_SYSTEM_LOGS:
        asyncio.get_running_loop().create_task(vm.print_logs())

    await asyncio.gather(
        vm.start_instance(),
        vm.wait_for_init(),
    )
    return vm
