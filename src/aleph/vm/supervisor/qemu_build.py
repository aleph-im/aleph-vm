"""Build a controller Configuration from a message-agnostic CreateVmSpec.

This module is the QEMU-specific configuration builder introduced in Phase 0.C
of the supervisor refactor. It mirrors AlephQemuInstance.configure() but is
sourced entirely from CreateVmSpec -- no aleph_message types appear here.

Runtime behaviour is intentionally identical to the original; this is a
decouple, not a rewrite.
"""

from __future__ import annotations

import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from aleph.vm.conf import settings
from aleph.vm.controllers.configuration import (
    Configuration,
    HypervisorType,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
from aleph.vm.controllers.qemu.cloudinit import (
    create_cloud_init_drive_image,
    get_hostname_from_hash,
)
from aleph.vm.sizes import MiB
from aleph.vm.supervisor.errors import InvalidBackendError
from aleph.vm.supervisor.types import Backend, CreateVmSpec, DiskRole

if TYPE_CHECKING:
    from aleph.vm.network.interfaces import TapInterface


async def build_cloud_init_drive(
    vm_hash: str,
    vm_id: int,
    tap_interface: TapInterface | None,
    ssh_authorized_keys: list[str],
    is_confidential: bool,
    has_gpu: bool,
) -> Path:
    """Create the cloud-init ISO image for a VM identified by *vm_hash*.

    Network parameters are derived from *tap_interface* using the same
    expressions as AlephVmControllerInterface.get_ip / get_ipv6 etc.
    """
    disk_image_path = settings.EXECUTION_ROOT / f"cloud-init-{vm_hash}.img"
    hostname = get_hostname_from_hash(vm_hash)  # type: ignore[arg-type]

    if tap_interface is not None:
        ip: str = tap_interface.guest_ip.with_prefixlen
        route: str = str(tap_interface.host_ip).split("/", 1)[0]
        ipv6: str = tap_interface.guest_ipv6.with_prefixlen
        ipv6_gateway: str = str(tap_interface.host_ipv6.ip)
    else:
        ip = ""
        route = ""
        ipv6 = ""
        ipv6_gateway = ""

    nameservers = settings.DNS_NAMESERVERS

    keys = list(ssh_authorized_keys)
    if settings.USE_DEVELOPER_SSH_KEYS:
        keys += settings.DEVELOPER_SSH_KEYS

    await create_cloud_init_drive_image(
        disk_image_path,
        hostname,
        vm_id,
        ip,
        ipv6,
        ipv6_gateway,
        nameservers,
        route,
        keys,
        has_gpu=has_gpu,
        is_confidential=is_confidential,
    )

    return disk_image_path


async def build_qemu_configuration(
    spec: CreateVmSpec,
    vm_id: int,
    tap_interface: TapInterface | None,
) -> Configuration:
    """Build a controller Configuration from a CreateVmSpec.

    Mirrors AlephQemuInstance.configure() exactly. The memory formula is
    reproduced verbatim -- do not "fix" it; this is a deliberate decouple.
    """
    # Locate the rootfs disk.
    rootfs_disks = [d for d in spec.disks if d.role is DiskRole.ROOTFS]
    if not rootfs_disks:
        raise InvalidBackendError("CreateVmSpec has no ROOTFS disk")
    image_path = str(rootfs_disks[0].path)

    # Extra / data volumes become host volumes.
    # The real mount point is carried from the DiskSpec.
    host_volumes = [
        QemuVMHostVolume(
            mount=disk.mount,
            path_on_host=disk.path,
            read_only=disk.readonly,
        )
        for disk in spec.disks
        if disk.role in {DiskRole.EXTRA, DiskRole.DATA}
    ]

    vcpu_count = spec.vcpus

    # QEMU's -m flag takes a value in MiB; spec.memory_mib is already MiB.
    # Pass it through via a typed size to avoid unit-mixing under-allocation.
    mem_size_mb = MiB(spec.memory_mib)

    gpus = [QemuGPU(pci_host=g.pci_host, supports_x_vga=g.supports_x_vga) for g in spec.gpus]

    interface_name: str | None = tap_interface.device_name if tap_interface else None

    # Socket paths -- same derivation as AlephQemuInstance properties.
    monitor_socket_path = settings.EXECUTION_ROOT / (spec.vm_id + "-monitor.socket")
    qmp_socket_path = settings.EXECUTION_ROOT / f"{spec.vm_id}-qmp.socket"
    qga_socket_path = settings.EXECUTION_ROOT / f"{spec.vm_id}-qga.socket"

    qemu_bin_path: str | None = shutil.which("qemu-system-x86_64")

    cloud_init_path = await build_cloud_init_drive(
        vm_hash=spec.vm_id,
        vm_id=vm_id,
        tap_interface=tap_interface,
        ssh_authorized_keys=spec.ssh_authorized_keys,
        is_confidential=(spec.backend is Backend.QEMU_SEV),
        has_gpu=bool(spec.gpus),
    )
    cloud_init_drive_path = str(cloud_init_path)

    vm_configuration = QemuVMConfiguration(
        qemu_bin_path=qemu_bin_path,
        cloud_init_drive_path=cloud_init_drive_path,
        image_path=image_path,
        monitor_socket_path=monitor_socket_path,
        qmp_socket_path=qmp_socket_path,
        qga_socket_path=qga_socket_path,
        vcpu_count=vcpu_count,
        mem_size_mb=mem_size_mb,
        interface_name=interface_name,
        host_volumes=host_volumes,
        gpus=gpus,
    )

    return Configuration(
        vm_id=vm_id,
        vm_hash=spec.vm_id,
        settings=settings,
        vm_configuration=vm_configuration,
        hypervisor=HypervisorType.qemu,
    )
