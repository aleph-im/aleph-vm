import asyncio
import base64
import json
import logging
from pathlib import Path
from tempfile import NamedTemporaryFile

import yaml
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources

from aleph.vm.conf import settings
from aleph.vm.hypervisors.firecracker.config import (
    BootSource,
    Drive,
    FirecrackerConfig,
    MachineConfig,
    NetworkInterface,
    Vsock,
)
from aleph.vm.hypervisors.firecracker.microvm import setfacl
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.storage import create_devmapper, create_volume_file
from aleph.vm.utils import NotEnoughDiskSpaceError, check_disk_space, run_in_subprocess

from .executable import (
    AlephFirecrackerExecutable,
    AlephFirecrackerResources,
    BaseConfiguration,
)
from .snapshots import CompressedDiskVolumeSnapshot, DiskVolume, DiskVolumeSnapshot

logger = logging.getLogger(__name__)


class AlephInstanceResources(AlephFirecrackerResources):
    async def download_runtime(self):
        self.rootfs_path = await create_devmapper(self.message_content.rootfs, self.namespace)
        assert self.rootfs_path.is_block_device(), f"Runtime not found on {self.rootfs_path}"

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_runtime(),
            self.download_volumes(),
        )


class AlephFirecrackerInstance(AlephFirecrackerExecutable):
    vm_configuration: BaseConfiguration
    resources: AlephInstanceResources
    latest_snapshot: DiskVolumeSnapshot | None
    is_instance = True
    support_snapshot = False

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephInstanceResources,
        enable_networking: bool = False,
        enable_console: bool | None = None,
        hardware_resources: MachineResources | None = None,
        tap_interface: TapInterface | None = None,
        prepare_jailer: bool = True,
    ):
        self.latest_snapshot = None
        persistent = True
        super().__init__(
            vm_id,
            vm_hash,
            resources,
            enable_networking,
            enable_console,
            hardware_resources or MachineResources(),
            tap_interface,
            persistent,
            prepare_jailer,
        )

    async def setup(self):
        logger.debug("instance setup started")
        await setfacl()

        cloud_init_drive = await self._create_cloud_init_drive()

        self._firecracker_config = FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(self.fvm.enable_kernel(self.resources.kernel_image_path)),
                boot_args=BootSource.args(enable_console=self.enable_console, writable=True),
            ),
            drives=[
                Drive(
                    drive_id="rootfs",
                    path_on_host=self.fvm.enable_rootfs(self.resources.rootfs_path),
                    is_root_device=True,
                    is_read_only=False,
                ),
                cloud_init_drive,
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
            network_interfaces=(
                [NetworkInterface(iface_id="eth0", host_dev_name=self.tap_interface.device_name)]
                if self.enable_networking and self.tap_interface
                else []
            ),
        )

    async def create_snapshot(self) -> CompressedDiskVolumeSnapshot:
        """Create a VM snapshot"""
        volume_path = await create_volume_file(self.resources.message_content.rootfs, self.resources.namespace)
        volume = DiskVolume(path=volume_path)

        if not check_disk_space(volume.size):
            raise NotEnoughDiskSpaceError

        snapshot = await volume.take_snapshot()
        compressed_snapshot = await snapshot.compress(settings.SNAPSHOT_COMPRESSION_ALGORITHM)

        if self.latest_snapshot:
            self.latest_snapshot.delete()

        self.latest_snapshot = snapshot
        return compressed_snapshot

    def _get_hostname(self) -> str:
        item_hash_binary: bytes = base64.b16decode(self.vm_hash.encode().upper())
        return base64.b32encode(item_hash_binary).decode().strip("=").lower()

    def _encode_user_data(self) -> bytes:
        """Creates user data configuration file for cloud-init tool"""

        ssh_authorized_keys: list[str] | None
        if settings.USE_DEVELOPER_SSH_KEYS:
            ssh_authorized_keys = settings.DEVELOPER_SSH_KEYS or []
        else:
            ssh_authorized_keys = self.resources.message_content.authorized_keys or []

        config: dict[str, str | bool | list[str]] = {
            "hostname": self._get_hostname(),
            "disable_root": False,
            "ssh_pwauth": False,
            "ssh_authorized_keys": ssh_authorized_keys,
            # Avoid the resize error because we already do it on the VM disk creation stage
            "resize_rootfs": False,
        }

        cloud_config_header = "#cloud-config\n"
        config_output = yaml.safe_dump(config, default_flow_style=False, sort_keys=False)

        return (cloud_config_header + config_output).encode()

    def _create_network_file(self) -> bytes:
        """Creates network configuration file for cloud-init tool"""

        assert self.enable_networking and self.tap_interface, f"Network not enabled for VM {self.vm_id}"

        ip = self.get_ip()
        route = self.get_ip_route()
        ipv6 = self.get_ipv6()
        ipv6_gateway = self.get_ipv6_gateway()

        nameservers_ip = []
        if ip:
            nameservers_ip = settings.DNS_NAMESERVERS_IPV4
        if ipv6:
            nameservers_ip += settings.DNS_NAMESERVERS_IPV6
        network = {
            "ethernets": {
                "eth0": {
                    "dhcp4": False,
                    "dhcp6": False,
                    "addresses": [ip, ipv6],
                    "gateway4": route,
                    "gateway6": ipv6_gateway,
                    "nameservers": {
                        "addresses": nameservers_ip,
                    },
                },
            },
            "version": 2,
        }

        return yaml.safe_dump(network, default_flow_style=False, sort_keys=False).encode()

    def _create_metadata_file(self) -> bytes:
        """Creates metadata configuration file for cloud-init tool"""

        metadata = {
            "instance-id": f"iid-instance-{self.vm_id}",
            "local-hostname": self._get_hostname(),
        }

        return json.dumps(metadata).encode()

    async def _create_cloud_init_drive(self) -> Drive:
        """Creates the cloud-init volume to configure and setup the VM"""

        disk_image_path = settings.EXECUTION_ROOT / f"cloud-init-{self.vm_hash}.img"

        with NamedTemporaryFile() as user_data_config_file:
            user_data = self._encode_user_data()
            user_data_config_file.write(user_data)
            user_data_config_file.flush()
            with NamedTemporaryFile() as network_config_file:
                network_config = self._create_network_file()
                network_config_file.write(network_config)
                network_config_file.flush()
                with NamedTemporaryFile() as metadata_config_file:
                    metadata_config = self._create_metadata_file()
                    metadata_config_file.write(metadata_config)
                    metadata_config_file.flush()

                    await run_in_subprocess(
                        [
                            "cloud-localds",
                            f"--network-config={network_config_file.name}",
                            str(disk_image_path),
                            user_data_config_file.name,
                            metadata_config_file.name,
                        ]
                    )

        return self.fvm.enable_drive(disk_image_path, read_only=True)
