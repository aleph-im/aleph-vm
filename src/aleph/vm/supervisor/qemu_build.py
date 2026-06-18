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
from aleph.vm.contract.configuration import (
    Configuration,
    HypervisorType,
    QemuConfidentialVMConfiguration,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)
from aleph.vm.controllers.qemu.cloudinit import create_cloud_init_drive_image
from aleph.vm.sizes import MiB
from aleph.vm.contract.errors import InvalidBackendError
from aleph.vm.contract.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    NetworkConfig,
    PciAddress,
    VmId,
)

if TYPE_CHECKING:
    from aleph.vm.network.interfaces import TapInterface


async def build_cloud_init_drive(
    vm_hash: str,
    vm_id: int,
    tap_interface: TapInterface | None,
    ssh_authorized_keys: list[str],
    hostname: str,
    is_confidential: bool,
    has_gpu: bool,
    install_guest_agent: bool = True,
) -> Path:
    """Create the cloud-init ISO image for a VM identified by *vm_hash*.

    Network parameters are derived from *tap_interface* using the same
    expressions as AlephVmControllerInterface.get_ip / get_ipv6 etc.
    The hostname is the client's (see CreateVmSpec.hostname); an empty one
    falls back to a mechanical truncation of the VM id.
    """
    disk_image_path = settings.EXECUTION_ROOT / f"cloud-init-{vm_hash}.img"
    # Hostnames are capped at 63 characters per label; the 64-hex-char vm_id
    # is truncated to fit.
    hostname = hostname or vm_hash[:63]

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
        install_guest_agent=install_guest_agent,
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
    image_path = str(spec.require_rootfs().path)

    # Extra / data volumes become host volumes. The guest mount point is the
    # client's business and no longer crosses the boundary; QemuVM never
    # consumed the controller-config `mount` field, so it is written empty.
    host_volumes = [
        QemuVMHostVolume(
            mount="",
            path_on_host=disk.path,
            read_only=disk.readonly,
        )
        for disk in spec.disks
        if disk.role is DiskRole.EXTRA
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
        hostname=spec.hostname,
        is_confidential=(spec.tee is not None),
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


async def build_qemu_confidential_configuration(
    spec: CreateVmSpec,
    vm_id: int,
    tap_interface: TapInterface | None,
) -> Configuration:
    """Build a confidential controller Configuration from a CreateVmSpec.

    Mirrors AlephQemuConfidentialInstance.configure() exactly (SAFETY-CRITICAL:
    a confidential VM must never boot under a weaker configuration than the
    message path produces). The only inputs are the spec's resolved on-disk
    paths and its TeeConfig.

    Requires spec.tee with a resolved firmware_path; raises InvalidBackendError
    otherwise. The caller (pool.create_vm_from_spec) must let that propagate and
    NEVER fall back to a plain QemuVMConfiguration: failing to build the
    confidential config is a hard stop, not a downgrade to an unprotected boot.
    """
    tee = spec.tee
    if tee is None:
        raise InvalidBackendError("build_qemu_confidential_configuration requires spec.tee")
    if tee.firmware_path is None:
        # No firmware = no confidential launch. Refuse rather than risk a boot
        # without the measured OVMF the owner attests against.
        raise InvalidBackendError("Confidential spec has no resolved firmware_path; refusing to build configuration")

    # The session certificates the owner uploads later land here; the paths must
    # match initialize_confidential, which writes vm_session.b64 / vm_godh.b64
    # under settings.CONFIDENTIAL_SESSION_DIRECTORY/<vm_hash>.
    vm_session_path = settings.CONFIDENTIAL_SESSION_DIRECTORY / spec.vm_id
    session_file_path = vm_session_path / "vm_session.b64"
    godh_file_path = vm_session_path / "vm_godh.b64"

    # SEV policy crosses the boundary as a string; the engine converts to the
    # AMDSEVPolicy int. int(.., 0) accepts hex ("0x1") and decimal forms.
    sev_policy = int(tee.policy, 0)

    image_path = str(spec.require_rootfs().path)

    host_volumes = [
        QemuVMHostVolume(
            mount="",
            path_on_host=disk.path,
            read_only=disk.readonly,
        )
        for disk in spec.disks
        if disk.role is DiskRole.EXTRA
    ]

    # The message confidential path builds QemuGPU(pci_host=...) only (default
    # supports_x_vga=True); reproduce that exactly.
    gpus = [QemuGPU(pci_host=g.pci_host) for g in spec.gpus]

    vcpu_count = spec.vcpus
    mem_size_mb = MiB(spec.memory_mib)

    interface_name: str | None = tap_interface.device_name if tap_interface else None

    monitor_socket_path = settings.EXECUTION_ROOT / (spec.vm_id + "-monitor.socket")
    qmp_socket_path = settings.EXECUTION_ROOT / f"{spec.vm_id}-qmp.socket"
    qga_socket_path = settings.EXECUTION_ROOT / f"{spec.vm_id}-qga.socket"

    qemu_bin_path: str | None = shutil.which("qemu-system-x86_64")

    # Confidential VMs install no guest agent (the message path passes
    # install_guest_agent=False in configure()).
    cloud_init_path = await build_cloud_init_drive(
        vm_hash=spec.vm_id,
        vm_id=vm_id,
        tap_interface=tap_interface,
        ssh_authorized_keys=spec.ssh_authorized_keys,
        hostname=spec.hostname,
        is_confidential=True,
        has_gpu=bool(spec.gpus),
        install_guest_agent=False,
    )
    cloud_init_drive_path = str(cloud_init_path)

    vm_configuration = QemuConfidentialVMConfiguration(
        qemu_bin_path=qemu_bin_path,
        cloud_init_drive_path=cloud_init_drive_path,
        image_path=image_path,
        monitor_socket_path=monitor_socket_path,
        qmp_socket_path=qmp_socket_path,
        qga_socket_path=qga_socket_path,
        vcpu_count=vcpu_count,
        mem_size_mb=mem_size_mb,
        interface_name=interface_name,
        ovmf_path=Path(tee.firmware_path),
        sev_session_file=session_file_path,
        sev_dh_cert_file=godh_file_path,
        sev_policy=sev_policy,
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


def spec_from_controller_configuration(config: Configuration) -> CreateVmSpec:
    """Reconstruct a CreateVmSpec from an on-disk controller Configuration.

    The inverse of build_qemu_configuration, used by reboot-recovery to
    reattach a running VM message-free. Only non-confidential QEMU configs
    are supported (QemuConfidentialVMConfiguration is a separate type).
    """
    vm_cfg = config.vm_configuration
    if not isinstance(vm_cfg, QemuVMConfiguration):
        msg = f"Reattach supports QemuVMConfiguration only, got {type(vm_cfg).__name__}"
        raise InvalidBackendError(msg)

    disks: list[DiskSpec] = [
        DiskSpec(
            path=Path(vm_cfg.image_path),
            readonly=False,
            format=DiskFormat.QCOW2,
            role=DiskRole.ROOTFS,
        )
    ] + [
        DiskSpec(
            path=v.path_on_host,
            readonly=v.read_only,
            format=DiskFormat.RAW,
            role=DiskRole.EXTRA,
        )
        for v in vm_cfg.host_volumes
    ]

    gpus = [GpuSpec(pci_host=PciAddress(g.pci_host), supports_x_vga=g.supports_x_vga) for g in vm_cfg.gpus]

    return CreateVmSpec(
        vm_id=VmId(str(config.vm_hash)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=disks,
        vcpus=vm_cfg.vcpu_count,
        memory_mib=vm_cfg.mem_size_mb.count,
        tee=None,
        network=NetworkConfig(
            internet_access=bool(vm_cfg.interface_name),
            requested_ipv6="",
            ipv6_prefix_len=0,
        ),
        gpus=gpus,
        numa_node=None,
        persistent=True,
    )
