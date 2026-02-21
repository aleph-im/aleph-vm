import asyncio
import json
import logging
import shutil
from asyncio.subprocess import Process
from pathlib import Path
from typing import Generic, TypeVar

import psutil
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources
from aleph_message.models.execution.instance import RootfsVolume
from aleph_message.models.execution.volume import PersistentVolume, VolumePersistence

from aleph.vm.conf import settings
from aleph.vm.controllers.configuration import (
    Configuration,
    HypervisorType,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
    save_controller_configuration,
)
from aleph.vm.controllers.firecracker.executable import (
    AlephFirecrackerResources,
    VmSetupError,
)
from aleph.vm.controllers.interface import AlephVmControllerInterface
from aleph.vm.controllers.qemu.cloudinit import CloudInitMixin
from aleph.vm.network.firewall import teardown_nftables_for_vm
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.resources import HostGPU
from aleph.vm.storage import get_rootfs_base_path
from aleph.vm.utils import run_in_subprocess

logger = logging.getLogger(__name__)


class AlephQemuResources(AlephFirecrackerResources):
    gpus: list[HostGPU] = []

    async def download_runtime(self) -> None:
        volume = self.message_content.rootfs
        parent_image_path = await get_rootfs_base_path(volume.parent.ref)
        self.rootfs_path = await self.make_writable_volume(parent_image_path, volume)

    async def download_all(self):
        await asyncio.gather(
            self.download_runtime(),
            self.download_volumes(),
        )

    async def make_writable_volume(self, parent_image_path, volume: PersistentVolume | RootfsVolume):
        """Create a new qcow2 image file based on the passed one, that we give to the VM to write onto"""
        qemu_img_path: str | None = shutil.which("qemu-img")
        if not qemu_img_path:
            msg = "qemu-img not found in PATH"
            raise VmSetupError(msg)

        volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"

        # detect the image format
        out_json = await run_in_subprocess([qemu_img_path, "info", str(parent_image_path), "--output=json"])
        out = json.loads(out_json)
        parent_format = out.get("format", None)
        if parent_format is None:
            msg = f"Failed to detect format for {volume}: {out_json}"
            raise VmSetupError(msg)
        if parent_format not in ("qcow2", "raw"):
            msg = f"Format {parent_format} for {volume} unhandled by QEMU hypervisor"
            raise VmSetupError(msg)

        dest_path = settings.PERSISTENT_VOLUMES_DIR / self.namespace / f"{volume_name}.qcow2"
        # Do not override if user asked for host persistence.
        if dest_path.exists() and volume.persistence == VolumePersistence.host:
            return dest_path

        dest_path.parent.mkdir(parents=True, exist_ok=True)
        size_in_bytes = int(volume.size_mib * 1024 * 1024)

        await run_in_subprocess(
            [
                qemu_img_path,
                "create",
                "-f",  # Format
                "qcow2",
                "-F",
                parent_format,
                "-b",
                str(parent_image_path),
                str(dest_path),
                str(size_in_bytes),
            ]
        )
        return dest_path


ConfigurationType = TypeVar("ConfigurationType")


class AlephQemuInstance(Generic[ConfigurationType], CloudInitMixin, AlephVmControllerInterface):
    vm_id: int
    vm_hash: ItemHash
    resources: AlephQemuResources
    enable_networking: bool
    hardware_resources: MachineResources
    tap_interface: TapInterface | None = None
    vm_configuration: ConfigurationType | None
    is_instance: bool
    qemu_process: Process | None
    support_snapshot = False
    persistent = True
    controller_configuration: Configuration

    def __repr__(self):
        return f"<AlephQemuInstance {self.vm_id}>"

    def __str__(self):
        return f"vm-{self.vm_id}"

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephQemuResources,
        enable_networking: bool = False,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: TapInterface | None = None,
    ):
        self.vm_id = vm_id
        self.vm_hash = vm_hash
        self.resources = resources
        self.enable_networking = enable_networking and settings.ALLOW_VM_NETWORKING
        self.hardware_resources = hardware_resources
        self.tap_interface = tap_interface
        self.qemu_process = None

    # TODO : wait for andress soltion for pid handling
    def to_dict(self):
        """Dict representation of the virtual machine. Used to record resource usage and for JSON serialization."""
        if self.qemu_process and psutil:
            # The Qemu process is still running and process information can be obtained from `psutil`.
            try:
                p = psutil.Process(self.qemu_process.pid)
                pid_info = {
                    "status": p.status(),
                    "create_time": p.create_time(),
                    "cpu_times": p.cpu_times(),
                    "cpu_percent": p.cpu_percent(),
                    "memory_info": p.memory_info(),
                    "io_counters": p.io_counters(),
                    "open_files": p.open_files(),
                    "connections": p.connections(),
                    "num_threads": p.num_threads(),
                    "num_ctx_switches": p.num_ctx_switches(),
                }
            except psutil.NoSuchProcess:
                logger.warning("Cannot read process metrics (process %s not found)", self.qemu_process)
                pid_info = None
        else:
            pid_info = None

        return {
            "process": pid_info,
            **self.__dict__,
        }

    async def setup(self):
        pass

    async def configure(self):
        """Configure the VM by saving controller service configuration"""

        logger.debug(f"Making  Qemu configuration: {self} ")
        monitor_socket_path = settings.EXECUTION_ROOT / (str(self.vm_hash) + "-monitor.socket")

        cloud_init_drive = await self._create_cloud_init_drive()

        image_path = str(self.resources.rootfs_path)
        vcpu_count = self.hardware_resources.vcpus
        mem_size_mib = self.hardware_resources.memory
        mem_size_mb = str(int(mem_size_mib / 1024 / 1024 * 1000 * 1000))

        qemu_bin_path = shutil.which("qemu-system-x86_64")
        interface_name = None
        if self.tap_interface:
            interface_name = self.tap_interface.device_name
        cloud_init_drive_path = str(cloud_init_drive.path_on_host) if cloud_init_drive else None
        vm_configuration = QemuVMConfiguration(
            qemu_bin_path=qemu_bin_path,
            cloud_init_drive_path=cloud_init_drive_path,
            image_path=image_path,
            monitor_socket_path=monitor_socket_path,
            qmp_socket_path=self.qmp_socket_path,
            qga_socket_path=self.qga_socket_path,
            vcpu_count=vcpu_count,
            mem_size_mb=mem_size_mb,
            interface_name=interface_name,
            host_volumes=[
                QemuVMHostVolume(
                    mount=volume.mount,
                    path_on_host=volume.path_on_host,
                    read_only=volume.read_only,
                )
                for volume in self.resources.volumes
            ],
            gpus=[QemuGPU(pci_host=gpu.pci_host, supports_x_vga=gpu.supports_x_vga) for gpu in self.resources.gpus],
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

    def save_controller_configuration(self):
        """Save VM configuration to be used by the controller service"""
        path = Path(f"{settings.EXECUTION_ROOT}/{self.vm_hash}-controller.json")
        path.open("w").write(self.controller_configuration.json(by_alias=True, exclude_none=True, indent=4))
        path.chmod(0o644)
        return path

    @property
    def qmp_socket_path(self) -> Path:
        return settings.EXECUTION_ROOT / f"{self.vm_hash}-qmp.socket"

    @property
    def qga_socket_path(self) -> Path:
        return settings.EXECUTION_ROOT / f"{self.vm_hash}-qga.socket"

    async def start(self):
        # Start via systemd not here
        raise NotImplementedError()

    async def start_guest_api(self):
        pass

    async def stop_guest_api(self):
        pass

    async def teardown(self):
        if self.enable_networking:
            teardown_nftables_for_vm(self.vm_id)
            if self.tap_interface:
                await self.tap_interface.delete()
        await self.stop_guest_api()
