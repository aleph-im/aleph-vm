import asyncio
import logging
import shutil
from asyncio.subprocess import Process
from collections.abc import Callable
from pathlib import Path

from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import AMDSEVPolicy, MachineResources

from aleph.vm.conf import settings
from aleph.vm.controllers.configuration import (
    Configuration,
    HypervisorType,
    QemuConfidentialVMConfiguration,
    QemuGPU,
    QemuVMHostVolume,
    save_controller_configuration,
)
from aleph.vm.controllers.qemu import AlephQemuInstance
from aleph.vm.controllers.qemu.instance import (
    AlephQemuResources,
    ConfigurationType,
    logger,
)
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.storage import get_existing_file

logger = logging.getLogger(__name__)


class AlephQemuConfidentialResources(AlephQemuResources):
    firmware_path: Path

    async def download_firmware(self):
        firmware = self.message_content.environment.trusted_execution.firmware
        self.firmware_path = await get_existing_file(firmware)

    async def download_all(self):
        await asyncio.gather(
            self.download_runtime(),
            self.download_firmware(),
            self.download_volumes(),
        )


class AlephQemuConfidentialInstance(AlephQemuInstance):
    vm_id: int
    vm_hash: ItemHash
    resources: AlephQemuConfidentialResources
    enable_console: bool
    enable_networking: bool
    hardware_resources: MachineResources
    tap_interface: TapInterface | None = None
    vm_configuration: ConfigurationType | None
    is_instance: bool
    qemu_process: Process | None
    support_snapshot = False
    persistent = True
    _queue_cancellers: dict[asyncio.Queue, Callable] = {}
    controller_configuration: Configuration
    confidential_policy: int

    def __repr__(self):
        return f"<AlephQemuInstance {self.vm_id}>"

    def __str__(self):
        return f"vm-{self.vm_id}"

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephQemuConfidentialResources,
        enable_networking: bool = False,
        confidential_policy: int = AMDSEVPolicy.NO_DBG,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: TapInterface | None = None,
    ):
        super().__init__(vm_id, vm_hash, resources, enable_networking, hardware_resources, tap_interface)
        self.confidential_policy = confidential_policy

    async def setup(self):
        pass

    async def configure(self, incoming_migration_port: int | None = None):
        """Configure the VM by saving controller service configuration.

        Note: incoming_migration_port is ignored for confidential VMs as they don't support live migration.
        """
        logger.debug(f"Making Qemu configuration: {self}")
        monitor_socket_path = settings.EXECUTION_ROOT / (str(self.vm_id) + "-monitor.socket")

        cloud_init_drive = await self._create_cloud_init_drive()

        image_path = str(self.resources.rootfs_path)
        firmware_path = str(self.resources.firmware_path)
        vcpu_count = self.hardware_resources.vcpus
        mem_size_mib = self.hardware_resources.memory
        mem_size_mb = str(int(mem_size_mib / 1024 / 1024 * 1000 * 1000))

        vm_session_path = settings.CONFIDENTIAL_SESSION_DIRECTORY / self.vm_hash
        session_file_path = vm_session_path / "vm_session.b64"
        godh_file_path = vm_session_path / "vm_godh.b64"

        qemu_bin_path = shutil.which("qemu-system-x86_64")
        interface_name = None
        if self.tap_interface:
            interface_name = self.tap_interface.device_name
        cloud_init_drive_path = str(cloud_init_drive.path_on_host) if cloud_init_drive else None
        vm_configuration = QemuConfidentialVMConfiguration(
            qemu_bin_path=qemu_bin_path,
            cloud_init_drive_path=cloud_init_drive_path,
            image_path=image_path,
            monitor_socket_path=monitor_socket_path,
            qmp_socket_path=self.qmp_socket_path,
            vcpu_count=vcpu_count,
            mem_size_mb=mem_size_mb,
            interface_name=interface_name,
            ovmf_path=firmware_path,
            sev_session_file=session_file_path,
            sev_dh_cert_file=godh_file_path,
            sev_policy=self.confidential_policy,
            host_volumes=[
                QemuVMHostVolume(
                    mount=volume.mount,
                    path_on_host=volume.path_on_host,
                    read_only=volume.read_only,
                )
                for volume in self.resources.volumes
            ],
            gpus=[QemuGPU(pci_host=gpu.pci_host) for gpu in self.resources.gpus],
        )

        configuration = Configuration(
            vm_id=self.vm_id,
            vm_hash=self.vm_hash,
            settings=settings,
            vm_configuration=vm_configuration,
            hypervisor=HypervisorType.qemu,
        )
        logger.debug(configuration)

        save_controller_configuration(self.vm_hash, configuration)

    async def wait_for_init(self) -> None:
        """Wait for the init process of the instance to be ready."""
        # FIXME: Cannot ping since network is not set up yet.
        return
