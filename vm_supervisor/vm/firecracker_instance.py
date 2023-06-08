import asyncio
import logging
from multiprocessing import set_start_method
from pathlib import Path
from typing import Dict, List, Optional

try:
    import psutil as psutil
except ImportError:
    psutil = None
from aleph_message.models.execution.environment import MachineResources

from firecracker.config import (
    BootSource,
    Drive,
    FirecrackerConfig,
    MachineConfig,
    NetworkInterface,
    Vsock,
)
from firecracker.microvm import MicroVM, setfacl

from .firecracker_microvm import AlephFirecrackerVM, AlephFirecrackerResources, Interface, Volume, HostVolume, \
    VMConfiguration
from ..conf import settings
from ..models import InstanceContent
from ..network.firewall import teardown_nftables_for_vm
from ..network.interfaces import TapInterface
from ..storage import create_devmapper

logger = logging.getLogger(__name__)
set_start_method("spawn")


class AlephInstanceResources(AlephFirecrackerResources):

    message_content: InstanceContent

    kernel_image_path: Path
    rootfs_path: Path
    volumes: List[HostVolume]
    volume_paths: Dict[str, Path]
    namespace: str

    def __init__(self, message_content: InstanceContent, namespace: str):
        super().__init__(message_content, namespace)

    async def download_runtime(self):
        self.rootfs_path = await create_devmapper(self.message_content.rootfs, self.namespace)
        assert self.rootfs_path.is_block_device(), f"Runtime not found on {self.rootfs_path}"

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_runtime(),
            self.download_volumes(),
        )


class AlephFirecrackerInstance(AlephFirecrackerVM):
    vm_id: int
    vm_hash: str
    resources: AlephInstanceResources
    enable_console: bool
    enable_networking: bool
    is_instance: bool
    hardware_resources: MachineResources
    fvm: Optional[MicroVM] = None
    tap_interface: Optional[TapInterface] = None

    def __init__(
        self,
        vm_id: int,
        vm_hash: str,
        resources: AlephInstanceResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: Optional[TapInterface] = None,
    ):
        super().__init__(vm_id, vm_hash, resources, enable_networking, enable_console, hardware_resources, tap_interface)
        self.is_instance = True

    async def setup(self, config: FirecrackerConfig):
        logger.debug("instance setup started")
        await setfacl()

        config = config or FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(
                    self.fvm.enable_kernel(self.resources.kernel_image_path)
                ),
                boot_args=BootSource.args(enable_console=self.enable_console, writable=self.is_instance),
            ),
            drives=[
                Drive(
                    drive_id="rootfs",
                    path_on_host=self.fvm.enable_rootfs(self.resources.rootfs_path),
                    is_root_device=True,
                    is_read_only=False,
                ),
            ]
            + [
                self.fvm.enable_drive(volume.path_on_host, read_only=volume.read_only)
                for volume in self.resources.volumes
            ],
            machine_config=MachineConfig(
                vcpu_count=self.hardware_resources.vcpus,
                mem_size_mib=self.hardware_resources.memory,
            ),
            vsock=Vsock(),
            network_interfaces=[
                NetworkInterface(
                    iface_id="eth0", host_dev_name=self.tap_interface.device_name
                )
            ]
            if self.enable_networking
            else [],
        )

        await super().setup(config)

    async def configure(self, volumes: Optional[List[Volume]], interface: Optional[Interface]):
        """Configure the VM by sending configuration info to it's init"""
        interface = interface or Interface.executable
        await super().configure(volumes, interface)

        # TODO: Implement Machine handler to check if is mounted or not

    async def teardown(self):
        if self.fvm:
            await self.fvm.teardown()
            teardown_nftables_for_vm(self.vm_id)
            await self.tap_interface.delete()
