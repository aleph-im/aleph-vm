"""Agnostic DTOs and enums for the Supervisor boundary.

Frozen dataclasses mirroring proto/supervisor.proto messages. No Aleph or
protobuf types appear here: this is the vocabulary the agent and any future
remote supervisor share. Proto/dataclass mapping lives only in the gRPC
implementation (Phase 0.D).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Backend(Enum):
    FIRECRACKER = "firecracker"
    QEMU = "qemu"
    QEMU_SEV = "qemu_sev"


class VmStatus(Enum):
    DEFINED = "defined"
    BOOTING = "booting"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class DiskFormat(Enum):
    RAW = "raw"
    QCOW2 = "qcow2"
    SQUASHFS = "squashfs"


class DiskRole(Enum):
    ROOTFS = "rootfs"
    CODE = "code"
    RUNTIME = "runtime"
    DATA = "data"
    EXTRA = "extra"


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"


class LogSource(Enum):
    SERIAL = "serial"
    STDOUT = "stdout"
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


@dataclass(frozen=True)
class DiskSpec:
    path: str
    readonly: bool
    format: DiskFormat
    role: DiskRole


@dataclass(frozen=True)
class TeeConfig:
    backend: str
    policy: str
    session_dir: str


@dataclass(frozen=True)
class NetworkConfig:
    internet_access: bool
    requested_ipv6: str
    ipv6_prefix_len: int


@dataclass(frozen=True)
class GpuSpec:
    pci_host: str
    supports_x_vga: bool


@dataclass(frozen=True)
class CreateVmSpec:
    vm_id: str
    backend: Backend
    kernel_path: str
    initrd_path: str
    disks: list[DiskSpec]
    vcpus: int
    memory_mib: int
    tee: TeeConfig | None
    network: NetworkConfig
    gpus: list[GpuSpec]
    numa_node: int | None
    persistent: bool


@dataclass(frozen=True)
class VmInfo:
    vm_id: str
    status: VmStatus
    ipv4: str
    ipv6: str
    uptime_secs: int
    backend: Backend
    numa_node: int | None
    status_message: str


@dataclass(frozen=True)
class PortForwardSpec:
    vm_id: str
    host_port: int
    vm_port: int
    protocol: Protocol


@dataclass(frozen=True)
class PortForwardInfo:
    vm_id: str
    host_port: int
    vm_port: int
    protocol: Protocol


@dataclass(frozen=True)
class LogChunk:
    timestamp_ns: int
    line: str
    source: LogSource


@dataclass(frozen=True)
class BackupInfo:
    vm_id: str
    backup_id: str
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
    vm_id: str
    migration_id: str
    phase: MigrationPhase
    bytes_transferred: int
    bytes_total: int
    error_message: str


@dataclass(frozen=True)
class Measurement:
    vm_id: str
    measurement_bytes: bytes
    tee_backend: str


@dataclass(frozen=True)
class NumaNodeInfo:
    index: int
    cpu_count: int
    memory_mib: int


@dataclass(frozen=True)
class GpuDevice:
    pci_host: str
    device_id: str
    model: str
    supports_x_vga: bool


@dataclass(frozen=True)
class HealthInfo:
    status: str
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
    numa_nodes: list[NumaNodeInfo] = field(default_factory=list)
    gpus: list[GpuDevice] = field(default_factory=list)
