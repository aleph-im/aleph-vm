"""Agnostic DTOs and enums for the Supervisor boundary.

Frozen dataclasses mirroring proto/supervisor.proto messages. No Aleph or
protobuf types appear here: this is the vocabulary the agent and any future
remote supervisor share. Proto/dataclass mapping lives only in the gRPC
implementation (Phase 0.D).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import NewType

VmId = NewType("VmId", str)
BackupId = NewType("BackupId", str)
MigrationId = NewType("MigrationId", str)
PciAddress = NewType("PciAddress", str)
HostPort = NewType("HostPort", int)
GuestPort = NewType("GuestPort", int)
DirectoryPath = NewType("DirectoryPath", Path)


class Backend(Enum):
    """The VMM. Orthogonal to confidential computing: a confidential VM is
    QEMU plus a TeeConfig (whose presence selects the confidential launch
    path)."""

    FIRECRACKER = "firecracker"
    QEMU = "qemu"


class VmStatus(Enum):
    DEFINED = "defined"
    BOOTING = "booting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class ConfidentialMode(Enum):
    NONE = "none"
    SEV = "sev"
    SEV_ES = "sev_es"
    SEV_SNP = "sev_snp"


class DiskFormat(Enum):
    RAW = "raw"
    QCOW2 = "qcow2"
    SQUASHFS = "squashfs"


class DiskRole(Enum):
    """Mechanism-only: which disk is the root device. Everything else is
    attached in spec order; guest device names derive from that order."""

    ROOTFS = "rootfs"
    EXTRA = "extra"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"


class LogSource(Enum):
    SERIAL = "serial"
    STDOUT = "stdout"
    STDERR = "stderr"
    SYSTEMD = "systemd"


class BackupStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


class MigrationPhase(Enum):
    PREPARING = "preparing"
    EXPORTING = "exporting"
    IMPORTING = "importing"
    COMPLETE = "complete"
    FAILED = "failed"


class ErrorCode(Enum):
    """Mirror of proto ErrorCode. Carried by SupervisorError."""

    VM_NOT_FOUND = "vm_not_found"
    VM_ALREADY_EXISTS = "vm_already_exists"
    INSUFFICIENT_RESOURCES = "insufficient_resources"
    RESOURCE_DOWNLOAD_FAILED = "resource_download_failed"
    FILE_TOO_LARGE = "file_too_large"
    VM_SETUP_FAILED = "vm_setup_failed"
    MICROVM_INIT_FAILED = "microvm_init_failed"
    INVALID_BACKEND = "invalid_backend"
    TEE_UNAVAILABLE = "tee_unavailable"
    PORT_UNAVAILABLE = "port_unavailable"
    HOST_NOT_FOUND = "host_not_found"
    BACKUP_NOT_FOUND = "backup_not_found"
    MIGRATION_IN_PROGRESS = "migration_in_progress"
    INTERNAL = "internal"


class TeeBackend(Enum):
    NONE = ""
    SEV = "sev"  # AMD SEV / SEV-ES; the mode is refined by TeeConfig.policy
    SEV_SNP = "sev-snp"
    TDX = "tdx"
    NVIDIA_CC = "nvidia-cc"


class HealthStatus(Enum):
    OK = "ok"
    DEGRADED = "degraded"


@dataclass(frozen=True)
class DiskSpec:
    """A disk by host path. Where the guest mounts it is the client's
    business (keyed by disk order); no mount point crosses the boundary."""

    path: Path
    readonly: bool
    format: DiskFormat
    role: DiskRole


@dataclass(frozen=True)
class TeeConfig:
    backend: TeeBackend
    policy: str
    session_dir: DirectoryPath


@dataclass(frozen=True)
class NetworkConfig:
    internet_access: bool
    requested_ipv6: str
    ipv6_prefix_len: int


@dataclass(frozen=True)
class GpuSpec:
    pci_host: PciAddress
    supports_x_vga: bool


@dataclass(frozen=True)
class GuestChannelSpec:
    """Host⇄guest control channel request (Firecracker vsock today). The
    supervisor exposes the channel and waits for the guest's ready signal on
    `ready_port` as part of boot; the payloads spoken over it are the
    client's business."""

    ready_port: int


@dataclass(frozen=True)
class CreateVmSpec:
    vm_id: VmId
    backend: Backend
    kernel_path: Path
    initrd_path: Path
    disks: list[DiskSpec]
    vcpus: int
    memory_mib: int
    tee: TeeConfig | None
    network: NetworkConfig
    gpus: list[GpuSpec]
    numa_node: int | None
    persistent: bool
    ssh_authorized_keys: list[str] = field(default_factory=list)
    # Guest hostname for provisioning (cloud-init); naming is the client's
    # business. Empty = mechanical fallback derived from vm_id.
    hostname: str = ""
    # Optional host⇄guest control channel; None = no channel. See
    # GuestChannelSpec and VmInfo.guest_channel_path.
    guest_channel: GuestChannelSpec | None = None

    @property
    def rootfs(self) -> DiskSpec | None:
        """The single rootfs disk, or None for a rootfs-less spec.

        Raises if more than one ROOTFS disk is present, which is a malformed
        spec.
        """
        # Local import: aleph.vm.supervisor.errors imports ErrorCode from this
        # module, so a top-level import would be circular.
        from aleph.vm.supervisor.errors import InvalidBackendError

        rootfs_disks = [disk for disk in self.disks if disk.role is DiskRole.ROOTFS]
        if len(rootfs_disks) > 1:
            raise InvalidBackendError(f"CreateVmSpec has {len(rootfs_disks)} ROOTFS disks, expected at most one")
        return rootfs_disks[0] if rootfs_disks else None

    def require_rootfs(self) -> DiskSpec:
        """The single rootfs disk; raises if absent (or if more than one present)."""
        from aleph.vm.supervisor.errors import InvalidBackendError

        rootfs = self.rootfs
        if rootfs is None:
            raise InvalidBackendError("CreateVmSpec has no ROOTFS disk")
        return rootfs


@dataclass(frozen=True)
class IpAssignment:
    """One address family's assignment for a VM; all fields empty until the
    tap device exists."""

    address: str = ""  # the guest's address, bare IP
    network_cidr: str = ""  # the tap network, e.g. "172.16.3.0/24"
    gateway: str = ""  # host-side tap address (bare IP); the guest's default route


@dataclass(frozen=True)
class VmInfo:
    vm_id: VmId
    status: VmStatus
    ipv4: IpAssignment
    ipv6: IpAssignment
    uptime_secs: int
    backend: Backend
    numa_node: int | None
    status_message: str
    # Lifecycle timestamps, unix nanoseconds UTC; 0 = stage not reached.
    defined_at_ns: int = 0
    preparing_at_ns: int = 0
    prepared_at_ns: int = 0
    starting_at_ns: int = 0
    started_at_ns: int = 0
    stopping_at_ns: int = 0
    stopped_at_ns: int = 0
    # Precise confidential-computing mode (the agent reduces to a bool for Aleph
    # APIs). NONE for non-confidential VMs.
    confidential_mode: ConfidentialMode = ConfidentialMode.NONE
    # Exact PCI devices attached to this VM; mirrors HostInfo.gpus.
    gpus: list[GpuDevice] = field(default_factory=list)
    # Host UDS endpoint of the guest control channel; empty when the VM was
    # created without one. The client dials it for guest-level protocols and
    # binds `<path>_<port>` listeners for guest-initiated connections.
    guest_channel_path: str = ""
    # Raw bytes the guest sent with its ready signal, passed through opaquely;
    # empty until the signal arrived (or for VMs without a channel).
    guest_ready_payload: bytes = b""


@dataclass(frozen=True)
class PortForwardSpec:
    vm_id: VmId
    host_port: HostPort
    vm_port: GuestPort
    protocol: Protocol


@dataclass(frozen=True)
class PortForwardInfo:
    vm_id: VmId
    host_port: HostPort
    vm_port: GuestPort
    protocol: Protocol


@dataclass(frozen=True)
class LogChunk:
    timestamp_ns: int
    line: str
    source: LogSource


@dataclass(frozen=True)
class BackupInfo:
    vm_id: VmId
    backup_id: BackupId
    status: BackupStatus
    size_bytes: int
    created_at_unix_secs: int
    error_message: str


@dataclass(frozen=True)
class BackupChunk:
    data: bytes
    offset: int


@dataclass(frozen=True)
class MigrationInfo:
    vm_id: VmId
    migration_id: MigrationId
    phase: MigrationPhase
    bytes_transferred: int
    bytes_total: int
    error_message: str


@dataclass(frozen=True)
class Measurement:
    vm_id: VmId
    measurement_bytes: bytes
    tee_backend: TeeBackend


@dataclass(frozen=True)
class NumaNodeInfo:
    index: int
    cpu_count: int
    memory_mib: int


@dataclass(frozen=True)
class GpuDevice:
    pci_host: PciAddress
    device_id: str
    model: str
    supports_x_vga: bool


@dataclass(frozen=True)
class HealthInfo:
    status: HealthStatus
    vm_count: int


@dataclass(frozen=True)
class HostInfo:
    cpu_count: int = 0
    memory_mib: int = 0
    cpu_architecture: str = ""
    cpu_vendor: str = ""
    cpu_model: str = ""
    kernel_version: str = ""
    hostname: str = ""
    sev_supported: bool = False
    sev_es_supported: bool = False
    sev_snp_supported: bool = False
    tdx_supported: bool = False
    host_ipv4: str = ""  # primary external IPv4; empty when host networking is disabled
    numa_nodes: list[NumaNodeInfo] = field(default_factory=list)
    gpus: list[GpuDevice] = field(default_factory=list)
