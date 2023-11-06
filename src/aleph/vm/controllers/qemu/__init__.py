import logging
from pathlib import Path
from typing import Optional

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import AlephFirecrackerResources
from aleph.vm.network.interfaces import TapInterface
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources

logger = logging.getLogger(__name__)

class AlephQemuResources(AlephFirecrackerResources):
    # async def download_runtime(self):
    #     self.rootfs_path = await create_devmapper(self.message_content.rootfs, self.namespace)
    #     assert self.rootfs_path.is_block_device(), f"Runtime not found on {self.rootfs_path}"

    async def download_all(self):
        volume = self.message_content.rootfs
        # self.namespace
        # image_path = get_rootfs_base_path(volume.parent.ref)
        if settings.USE_FAKE_INSTANCE_BASE and settings.FAKE_INSTANCE_BASE:
            logger.debug("Using fake instance base")

            self.rootfs_path = Path(settings.FAKE_INSTANCE_BASE)
        # self.message_content.rootfs
        return
        # await asyncio.gather(
        #     self.download_kernel(),
        #     self.download_runtime(),
        #     self.download_volumes(),
        # )

from abc import ABC
class AlephControllerInterface(ABC):
    tap_interface: Optional[TapInterface] = None
    resources: AlephFirecrackerResources
    vm_id: int
    vm_hash: ItemHash
    enable_console: bool
    enable_networking: bool
    hardware_resources: MachineResources

    def get_vm_ip(self) -> Optional[str]:
        if self.tap_interface:
            return self.tap_interface.guest_ip.with_prefixlen
        return None

    def get_vm_route(self) -> Optional[str]:
        if self.tap_interface:
            return str(self.tap_interface.host_ip).split("/", 1)[0]
        return None

    def get_vm_ipv6(self) -> Optional[str]:
        if self.tap_interface:
            return self.tap_interface.guest_ipv6.with_prefixlen
        return None


    def get_vm_ipv6_gateway(self) -> Optional[str]:
        if self.tap_interface:
            return str(self.tap_interface.host_ipv6.ip)
        return None
