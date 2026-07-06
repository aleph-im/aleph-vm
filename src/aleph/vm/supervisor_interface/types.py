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
    # Host path to the resolved OVMF firmware blob (the message path's
    # trusted_execution.firmware ref, downloaded to disk by the agent before
    # create). The engine feeds it to QemuConfidentialVMConfiguration.ovmf_path.
    firmware_path: Path | None = None


@dataclass(frozen=True)
class NetworkConfig:
    internet_access: bool
    requested_ipv6: str
    ipv6_prefix_len: int


@dataclass(frozen=True)
class GpuSpec:
    """A GPU on a CreateVmSpec: a RESOLVED assignment.

    ``pci_host`` is the concrete host address, always set. Which card serves
    which workload is the client's decision (the agent resolves its requested
    device kinds against the host inventory before create); the supervisor
    only validates that the card exists and is not already attached.
    """

    pci_host: PciAddress
    supports_x_vga: bool


@dataclass(frozen=True)
class GuestChannelSpec:
    """Host⇄guest control channel request (Firecracker vsock today). The
    supervisor exposes the channel and waits for the guest's ready signal on
    `ready_port` as part of boot; the payloads spoken over it are the
    client's business."""

    ready_port: int
    # How long to wait for the ready signal before failing the boot; the
    # client knows its guest image. 0 = supervisor default.
    ready_timeout_secs: int = 0


@dataclass
class RuntimeConfiguration:
    """Version handshake the Aleph runtime sends in its guest-channel ready
    payload. Part of the guest-init protocol both sides interpret: the
    supervisor parses it from the ready signal, the agent uses it to shape
    the configuration push."""

    version: str

    def supports_ipv6(self) -> bool:
        return self.version != "1.0.0"


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
        # Local import: aleph.vm.supervisor_interface.errors imports ErrorCode from this
        # module, so a top-level import would be circular.
        from aleph.vm.supervisor_interface.errors import InvalidBackendError

        rootfs_disks = [disk for disk in self.disks if disk.role is DiskRole.ROOTFS]
        if len(rootfs_disks) > 1:
            raise InvalidBackendError(f"CreateVmSpec has {len(rootfs_disks)} ROOTFS disks, expected at most one")
        return rootfs_disks[0] if rootfs_disks else None

    def require_rootfs(self) -> DiskSpec:
        """The single rootfs disk; raises if absent (or if more than one present)."""
        from aleph.vm.supervisor_interface.errors import InvalidBackendError

        rootfs = self.rootfs
        if rootfs is None:
            raise InvalidBackendError("CreateVmSpec has no ROOTFS disk")
        return rootfs


@dataclass(frozen=True)
class HardwareResources:
    """Message-free hardware sizing handed to controllers.

    Mirrors the fields the controllers read from aleph_message's
    MachineResources (vcpus, memory in MiB) so the daemon never imports a
    message type. The `seconds` run-timeout field is intentionally absent: it
    is agent-side policy (the agent passes the timeout over the gRPC run call).
    Field names match MachineResources so controller field access is unchanged.
    """

    vcpus: int = 1
    memory: int = 128  # MiB


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
    # True while a confidential VM is started but waiting for its owner to upload
    # the session certificates: not running, but not dead either. The agent lists
    # such VMs so the scheduler does not re-allocate them forever.
    awaiting_confidential_init: bool = False
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
class VmEvent:
    """A lifecycle transition, streamed by watch_events."""

    vm_id: VmId
    old_status: VmStatus
    new_status: VmStatus
    timestamp_ns: int


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
    # Archive metadata, populated for completed archives on disk. The agent
    # turns these into the HTTP response body (checksum, volumes, source_sizes)
    # and the download sidecar headers (X-Backup-Checksum, X-Source-Size). They
    # default to empty so in-flight RUNNING/FAILED jobs construct cleanly.
    checksum: str = ""
    volumes: list[str] = field(default_factory=list)
    source_sizes: dict[str, int] = field(default_factory=dict)


@dataclass(frozen=True)
class BackupChunk:
    data: bytes
    offset: int


@dataclass(frozen=True)
class SevInfo:
    """AMD SEV platform/launch state, mirroring the QEMU query-sev result the
    confidential client needs to verify a launch measurement. The field set
    matches the seven values today's measurement endpoint returns."""

    enabled: bool
    api_major: int
    api_minor: int
    build_id: int
    policy: int
    state: str
    handle: int


@dataclass(frozen=True)
class Measurement:
    vm_id: VmId
    measurement_bytes: bytes
    tee_backend: TeeBackend
    # SEV launch attestation, preserved for the confidential measurement
    # response. sev_info is the query-sev platform state and launch_measure is
    # the base64 launch measurement; both default to empty for callers that only
    # carry measurement_bytes/tee_backend.
    sev_info: SevInfo | None = None
    launch_measure: str = ""


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
    cpu_frequency_mhz: int = 0
    memory_type: str = ""
    memory_clock_mhz: int = 0
    # Reservation-aware figures the agent's /about endpoints surface. The
    # embedded engine fills them from the pool. ``gpu_inventory`` /
    # ``available_gpus`` carry the rich agent GpuDevice (vendor, device_name,
    # device_class) as plain dicts so the public usage endpoint does not
    # regress to the narrow boundary GpuDevice; they ride the proto as JSON
    # strings. Raw hardware only: the network annotation (model name,
    # aggregate-whitelist compatibility) is the agent's job.
    available_disk_bytes: int = 0
    gpu_inventory: list[dict] = field(default_factory=list)
    available_gpus: list[dict] = field(default_factory=list)
