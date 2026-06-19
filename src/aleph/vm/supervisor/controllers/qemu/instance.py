import logging
from asyncio.subprocess import Process
from pathlib import Path
from typing import TYPE_CHECKING, Generic, TypeVar

import psutil
from aleph_message.models import InstanceContent, ItemHash

from aleph.vm.conf import settings
from aleph.vm.network.firewall import teardown_nftables_for_vm
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.resources import HostGPU
from aleph.vm.supervisor.controllers.interface import AlephVmControllerInterface
from aleph.vm.supervisor.controllers.resources import (
    HostVolume,
    VmResources,
    disk_usage_delta,
)
from aleph.vm.supervisor_interface.types import HardwareResources

if TYPE_CHECKING:
    from aleph.vm.supervisor_interface.types import CreateVmSpec

logger = logging.getLogger(__name__)


class AlephQemuResources(VmResources):
    """Resources required to start a QEMU VM.

    A QEMU execution may be driven by an Aleph message or built message-free
    from a :class:`CreateVmSpec` (see :meth:`from_spec`), so ``message_content``
    is optional. It deliberately does *not* inherit from
    ``AlephFirecrackerResources``: the two hypervisors share host-resource
    mechanics (see ``VmResources``) but not the message contract.
    """

    # QEMU only ever runs instances, so the content is strongly typed. It is
    # optional because the holder may be built message-free from a CreateVmSpec.
    message_content: InstanceContent | None
    gpus: list[HostGPU] = []

    def __init__(self, message_content: InstanceContent | None, namespace: str):
        super().__init__(namespace)
        self.message_content = message_content

    def get_disk_usage_delta(self) -> int:
        # Intentionally 0 for the spec path: message_content is None and the
        # spec-built volumes carry no size_mib, so nothing is counted. Spec VMs
        # do not reserve disk through the pool; the agent sizes them upfront.
        return disk_usage_delta(self.message_content, self.rootfs_path, self.volumes)

    @classmethod
    def from_spec(cls, spec: "CreateVmSpec", namespace: str) -> "AlephQemuResources":
        """Build a message-free resources holder from a CreateVmSpec.

        No download is performed: every path comes from the spec, which the
        agent already resolved on disk. The holder satisfies the attribute
        surface the QEMU controller and pool read (rootfs_path, volumes,
        gpus, kernel_image_path), with message_content left None.
        """
        # Local import keeps the supervisor.* dependency out of module load order.
        from aleph.vm.supervisor_interface.types import DiskRole

        resources = cls(None, namespace)
        resources.kernel_image_path = Path(settings.LINUX_PATH)

        resources.rootfs_path = spec.require_rootfs().path

        # Guest mount points do not cross the supervisor boundary; the
        # HostVolume.mount field only matters on the message (legacy) path.
        resources.volumes = [
            HostVolume(mount="", path_on_host=d.path, read_only=d.readonly, size_mib=None)
            for d in spec.disks
            if d.role is DiskRole.EXTRA
        ]
        resources.gpus = [HostGPU(pci_host=g.pci_host, supports_x_vga=g.supports_x_vga) for g in spec.gpus]
        return resources


ConfigurationType = TypeVar("ConfigurationType")


class AlephQemuInstance(Generic[ConfigurationType], AlephVmControllerInterface):
    vm_id: int
    vm_hash: ItemHash
    resources: AlephQemuResources
    enable_networking: bool
    hardware_resources: HardwareResources
    tap_interface: TapInterface | None = None
    vm_configuration: ConfigurationType | None
    is_instance: bool
    qemu_process: Process | None
    support_snapshot = False
    persistent = True

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
        hardware_resources: HardwareResources = HardwareResources(),
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

    def get_ip(self) -> str | None:
        """Get the guest IP address."""
        if self.tap_interface:
            return str(self.tap_interface.guest_ip)
        return None
