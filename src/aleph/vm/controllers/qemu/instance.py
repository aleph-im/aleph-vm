import asyncio
import logging
import shutil
from asyncio.subprocess import Process
from pathlib import Path
from typing import Generic, Optional

import psutil

from aleph.vm.controllers.interface import AlephControllerInterface
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources
from aleph_message.models.execution.instance import RootfsVolume
from aleph_message.models.execution.volume import PersistentVolume

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import (
    AlephFirecrackerResources,
    ConfigurationType,
)
from aleph.vm.controllers.qemu.cloudinit import CloudInitMixin
from aleph.vm.network.firewall import teardown_nftables_for_vm
from aleph.vm.network.hostnetwork import make_ipv6_allocator
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.network.ipaddresses import IPv4NetworkWithInterfaces
from aleph.vm.orchestrator.vm.vm_type import VmType
from aleph.vm.utils import run_in_subprocess

logger = logging.getLogger(__name__)


class AlephQemuResources(AlephFirecrackerResources):
    async def download_all(self):
        volume = self.message_content.rootfs
        # image_path = get_rootfs_base_path(volume.parent.ref)
        if settings.USE_FAKE_INSTANCE_BASE and settings.FAKE_INSTANCE_BASE:
            logger.debug("Using fake instance base")

            base_image_path = Path(settings.FAKE_INSTANCE_BASE)

            self.rootfs_path = await self.make_writable_volume(base_image_path, volume)

        return

    async def make_writable_volume(self, qcow2_file_path, volume: PersistentVolume | RootfsVolume):
        qemu_img_path = shutil.which("qemu-img")
        volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"

        dest_path = settings.PERSISTENT_VOLUMES_DIR / self.namespace / f"{volume_name}.qcow2"
        dest_path.parent.mkdir(parents=True, exist_ok=True)
        await run_in_subprocess(
            [
                qemu_img_path,
                "create",
                "-f",
                "qcow2",
                "-F",
                "qcow2",
                "-b",
                str(qcow2_file_path),
                str(dest_path),
            ]
        )
        return dest_path


class AlephQemuInstance(Generic[ConfigurationType], CloudInitMixin, AlephControllerInterface):
    vm_id: int
    vm_hash: ItemHash
    resources: AlephQemuResources
    enable_console: bool
    enable_networking: bool
    hardware_resources: MachineResources
    tap_interface: Optional[TapInterface] = None
    vm_configuration: Optional[ConfigurationType]
    is_instance: bool
    qemu_process: Optional[Process]
    support_snapshot = False

    def __str__(self):
        return f"<AlephQemuInstance {self.vm_id}>"

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephQemuResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: Optional[TapInterface] = None,
    ):
        self.vm_id = vm_id
        self.vm_hash = vm_hash
        self.resources = resources
        if enable_console is None:
            enable_console = settings.PRINT_SYSTEM_LOGS
        self.enable_console = enable_console
        self.enable_networking = enable_networking and settings.ALLOW_VM_NETWORKING
        self.hardware_resources = hardware_resources
        self.tap_interface = tap_interface

    def to_dict(self):
        """Dict representation of the virtual machine. Used to record resource usage and for JSON serialization."""
        if self.qemu_process and psutil:
            # The firecracker process is still running and process information can be obtained from `psutil`.
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

    async def start(self):
        logger.debug(f"Starting Qemu: {self} ")
        # Based on the command
        #  qemu-system-x86_64 -enable-kvm -m 2048 -net nic,model=virtio
        # -net tap,ifname=tap0,script=no,downscript=no -drive file=alpine.qcow2,media=disk,if=virtio -nographic

        qemu_path = shutil.which("qemu-system-x86_64")
        image_path = self.resources.rootfs_path
        vcpu_count = self.hardware_resources.vcpus
        mem_size_mib = self.hardware_resources.memory
        mem_size_mb = int(mem_size_mib / 1024 / 1024 * 1000 * 1000)
        # hardware_resources.published ports -> not implemented at the moment
        # hardware_resources.seconds -> only for microvm

        args = [
            qemu_path,
            "-enable-kvm",
            "-m",
            str(mem_size_mb),
            "-smp",
            str(vcpu_count),
            # Disable floppy
            "-fda",
            "",
            # "-snapshot",  # Do not save anything to disk
            "-drive",
            f"file={image_path},media=disk,if=virtio",
            # Comment for debug
            "-display",
            "none",
            "--no-reboot",  # Rebooting from inside the VM shuts down the machine
        ]
        # FIXME local HACK
        if not self.enable_networking:
            self.enable_networking = True
            self.tap_interface = TapInterface(
                device_name="tap0",
                ip_network=IPv4NetworkWithInterfaces("172.16.0.0/30"),
                ipv6_network=make_ipv6_allocator(
                    allocation_policy=settings.IPV6_ALLOCATION_POLICY,
                    address_pool=settings.IPV6_ADDRESS_POOL,
                    subnet_prefix=settings.IPV6_SUBNET_PREFIX,
                ).allocate_vm_ipv6_subnet(self.vm_id, self.vm_hash, VmType.instance),
                ndp_proxy=None,
            )
        if self.tap_interface:
            interface_name = self.tap_interface.device_name
            # script=no, downscript=no tell qemu not to try to set up the network itself
            args += ["-net", "nic,model=virtio", "-net", f"tap,ifname={interface_name},script=no,downscript=no"]

        cloud_init_drive = await self._create_cloud_init_drive()
        if cloud_init_drive:
            args += ["-cdrom", f"{cloud_init_drive.path_on_host}"]

        try:
            print(*args)
            self.qemu_process = proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
            )
            self.enable_networking = False  # HACK

            logger.debug(f"setup done {self}, {proc}")

            async def handle_termination(proc: Process):
                await proc.wait()
                logger.info(f"{self} Process terminated with {proc.returncode} : {str(args)}")

            loop = asyncio.get_running_loop()
            loop.create_task(handle_termination(proc))
        except Exception:
            # Stop the VM and clear network interfaces in case any error prevented the start of the virtual machine.
            logger.error("VM startup failed, cleaning up network")
            if self.enable_networking:
                teardown_nftables_for_vm(self.vm_id)
            if self.tap_interface:
                await self.tap_interface.delete()
            raise

        if self.enable_console:
            pass
            # self.fvm.start_printing_logs()

        await self.wait_for_init()
        logger.debug(f"started qemu vm {self}")

    async def wait_for_init(self) -> None:
        """Wait for the init process of the virtual machine to be ready.
        May be empty."""

        return

    async def configure(self):
        "Nothing to configure, we do the configuration via cloud init"
        pass

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
