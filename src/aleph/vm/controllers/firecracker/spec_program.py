"""Message-free Firecracker program controller, driven by a CreateVmSpec.

The supervisor side of the program (microvm) split: boots a Firecracker VM
from resolved on-disk paths only — no Aleph message, no download, no guest
configuration. The Aleph-runtime protocols (config push, code execution,
guest API) are the agent's business, spoken over the vsock control socket
this VM exposes (reported via VmInfo.control_socket_path).

Drive order is part of the contract with the agent: root device (the
RUNTIME-role disk), then the CODE-role disk if present, then EXTRA disks in
spec order. The agent derives guest device names (vdb, vdc, …) from that
order when it builds its configuration push.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources

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
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import CreateVmSpec, DiskRole, DiskSpec

from .executable import AlephFirecrackerExecutable

logger = logging.getLogger(__name__)


@dataclass
class SpecProgramResources:
    """Resolved paths for a spec-driven program boot. No download happens
    here: the agent prepared every file and the spec carries the paths."""

    kernel_image_path: Path
    rootfs_path: Path  # the RUNTIME-role disk: a program's root filesystem
    code_disk: DiskSpec | None
    extra_disks: list[DiskSpec] = field(default_factory=list)

    @classmethod
    def from_spec(cls, spec: CreateVmSpec) -> SpecProgramResources:
        kernel_path = spec.kernel_path
        if not str(kernel_path) or str(kernel_path) == ".":
            raise InvalidBackendError("A program spec requires a kernel_path")

        runtime_disks = [disk for disk in spec.disks if disk.role is DiskRole.RUNTIME]
        if len(runtime_disks) != 1:
            raise InvalidBackendError(f"A program spec requires exactly one RUNTIME disk, got {len(runtime_disks)}")

        code_disks = [disk for disk in spec.disks if disk.role is DiskRole.CODE]
        if len(code_disks) > 1:
            raise InvalidBackendError(f"A program spec carries at most one CODE disk, got {len(code_disks)}")

        return cls(
            kernel_image_path=kernel_path,
            rootfs_path=runtime_disks[0].path,
            code_disk=code_disks[0] if code_disks else None,
            extra_disks=[disk for disk in spec.disks if disk.role is DiskRole.EXTRA],
        )

    def to_dict(self):
        return self.__dict__


class SpecFirecrackerProgram(AlephFirecrackerExecutable[None]):
    """Spec-driven program microvm: VMM boot + init handshake only."""

    resources: SpecProgramResources  # type: ignore[assignment]
    is_instance = False
    support_snapshot = False

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        spec: CreateVmSpec,
        resources: SpecProgramResources,
        tap_interface: TapInterface | None = None,
        prepare_jailer: bool = True,
    ):
        super().__init__(
            vm_id=vm_id,
            vm_hash=vm_hash,
            resources=resources,  # type: ignore[arg-type]
            enable_networking=spec.network.internet_access,
            hardware_resources=MachineResources(vcpus=spec.vcpus, memory=spec.memory_mib),
            tap_interface=tap_interface,
            persistent=spec.persistent,
            prepare_jailer=prepare_jailer,
        )
        self.spec = spec

    async def setup(self) -> None:
        logger.debug("Setup started for spec program VM=%s", self.vm_id)
        await setfacl()

        extra_disks = ([self.resources.code_disk] if self.resources.code_disk else []) + self.resources.extra_disks
        self._firecracker_config = FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(self.fvm.enable_kernel(self.resources.kernel_image_path)),
                boot_args=BootSource.args(enable_console=self.enable_console, writable=False),
            ),
            drives=[
                Drive(
                    drive_id="rootfs",
                    path_on_host=self.fvm.enable_rootfs(self.resources.rootfs_path),
                    is_root_device=True,
                    is_read_only=True,
                ),
            ]
            + [self.fvm.enable_drive(disk.path, read_only=disk.readonly) for disk in extra_disks],
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

    async def wait_for_init(self) -> None:
        """The init-ready handshake is part of boot for program-mode VMs."""
        await self.fvm.wait_for_init()

    async def start_guest_api(self):
        """Agent-owned across the boundary: the agent binds `<vsock>_53` itself."""

    async def stop_guest_api(self):
        """Agent-owned across the boundary; nothing to stop here."""
