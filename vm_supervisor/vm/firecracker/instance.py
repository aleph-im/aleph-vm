import asyncio
import logging
import subprocess
from pathlib import Path
from typing import Optional

from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources

from firecracker.config import (
    BootSource,
    Drive,
    FirecrackerConfig,
    MachineConfig,
    NetworkInterface,
    Vsock,
)
from firecracker.microvm import setfacl
from vm_supervisor.network.interfaces import TapInterface
from vm_supervisor.storage import create_devmapper
from vm_supervisor.utils import ping, HostNotFoundError

from .executable import (
    AlephFirecrackerExecutable,
    AlephFirecrackerResources,
    BaseConfiguration,
)

logger = logging.getLogger(__name__)


class AlephInstanceResources(AlephFirecrackerResources):
    async def download_runtime(self):
        self.rootfs_path = await create_devmapper(
            self.message_content.rootfs, self.namespace
        )
        assert (
            self.rootfs_path.is_block_device()
        ), f"Runtime not found on {self.rootfs_path}"

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_runtime(),
            self.download_volumes(),
        )


class AlephFirecrackerInstance(AlephFirecrackerExecutable):
    vm_configuration: BaseConfiguration
    resources: AlephInstanceResources
    is_instance = True

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephInstanceResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: Optional[TapInterface] = None,
    ):
        super().__init__(
            vm_id,
            vm_hash,
            resources,
            enable_networking,
            enable_console,
            hardware_resources,
            tap_interface,
        )

    async def setup(self):
        logger.debug("instance setup started")
        await setfacl()

        self._firecracker_config = FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(
                    self.fvm.enable_kernel(self.resources.kernel_image_path)
                ),
                boot_args=BootSource.args(
                    enable_console=self.enable_console, writable=True
                ),
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

    async def wait_for_init(self) -> None:
        """Wait for the init process of the instance to be ready."""
        if not self.vm_configuration:
            raise ValueError("The VM has not been configured yet")

        if not self.vm_configuration.ip:
            raise ValueError("VM IP address not set")

        attempts = 5
        timeout_seconds = 1.0

        for attempt in range(attempts):
            try:
                await ping(self.vm_configuration.ip, packets=1, timeout=timeout_seconds)
                return
            except HostNotFoundError:
                if attempt < (attempts - 1):
                    continue
                else:
                    raise

    async def configure(self):
        """Configure the VM by sending configuration info to it's init"""
        # TODO: Implement Cloud-init interface
        pass
