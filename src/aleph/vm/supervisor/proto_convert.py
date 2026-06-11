"""DTO ⇄ protobuf conversion for the Supervisor gRPC transport.

Pure mapping between the frozen dataclasses in `types.py` and the generated
messages in `_pb.supervisor_pb2`. No I/O, no Aleph imports. Shared by the
gRPC server (DTO results → wire) and the client (wire → DTO results).

Path convention: empty wire strings mean "no path". `Path("")` normalises to
`Path(".")` in Python, so both spellings serialise to "" and "" parses back
to `Path("")`.
"""

from __future__ import annotations

from pathlib import Path

from aleph.vm.supervisor._pb import supervisor_pb2 as pb
from aleph.vm.supervisor.types import (
    Backend,
    BackupChunk,
    BackupId,
    BackupInfo,
    BackupStatus,
    ConfidentialMode,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    ErrorCode,
    GpuDevice,
    GpuSpec,
    GuestPort,
    HealthInfo,
    HealthStatus,
    HostInfo,
    HostPort,
    LogChunk,
    LogSource,
    Measurement,
    MigrationId,
    MigrationInfo,
    MigrationPhase,
    NetworkConfig,
    NumaNodeInfo,
    PciAddress,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    TeeBackend,
    TeeConfig,
    VmId,
    VmInfo,
    VmStatus,
)

# ── Enum tables ──────────────────────────────────────────────────────────────

BACKEND_TO_PB = {
    Backend.FIRECRACKER: pb.BACKEND_FIRECRACKER,
    Backend.QEMU: pb.BACKEND_QEMU,
    Backend.QEMU_SEV: pb.BACKEND_QEMU_SEV,
}
BACKEND_FROM_PB = {v: k for k, v in BACKEND_TO_PB.items()}

VM_STATUS_TO_PB = {
    VmStatus.DEFINED: pb.VM_STATUS_DEFINED,
    VmStatus.BOOTING: pb.VM_STATUS_BOOTING,
    VmStatus.RUNNING: pb.VM_STATUS_RUNNING,
    VmStatus.STOPPING: pb.VM_STATUS_STOPPING,
    VmStatus.STOPPED: pb.VM_STATUS_STOPPED,
    VmStatus.FAILED: pb.VM_STATUS_FAILED,
}
VM_STATUS_FROM_PB = {v: k for k, v in VM_STATUS_TO_PB.items()}

CONFIDENTIAL_MODE_TO_PB = {
    ConfidentialMode.NONE: pb.CONFIDENTIAL_MODE_NONE,
    ConfidentialMode.SEV: pb.CONFIDENTIAL_MODE_SEV,
    ConfidentialMode.SEV_ES: pb.CONFIDENTIAL_MODE_SEV_ES,
    ConfidentialMode.SEV_SNP: pb.CONFIDENTIAL_MODE_SEV_SNP,
}
CONFIDENTIAL_MODE_FROM_PB = {v: k for k, v in CONFIDENTIAL_MODE_TO_PB.items()}

DISK_FORMAT_TO_PB = {
    DiskFormat.RAW: pb.DiskConfig.FORMAT_RAW,
    DiskFormat.QCOW2: pb.DiskConfig.FORMAT_QCOW2,
    DiskFormat.SQUASHFS: pb.DiskConfig.FORMAT_SQUASHFS,
}
DISK_FORMAT_FROM_PB = {v: k for k, v in DISK_FORMAT_TO_PB.items()}

DISK_ROLE_TO_PB = {
    DiskRole.ROOTFS: pb.DiskConfig.DISK_ROLE_ROOTFS,
    DiskRole.CODE: pb.DiskConfig.DISK_ROLE_CODE,
    DiskRole.RUNTIME: pb.DiskConfig.DISK_ROLE_RUNTIME,
    DiskRole.DATA: pb.DiskConfig.DISK_ROLE_DATA,
    DiskRole.EXTRA: pb.DiskConfig.DISK_ROLE_EXTRA,
}
DISK_ROLE_FROM_PB = {v: k for k, v in DISK_ROLE_TO_PB.items()}

LOG_SOURCE_TO_PB = {
    LogSource.SERIAL: pb.LogChunk.LOG_SOURCE_SERIAL,
    LogSource.STDOUT: pb.LogChunk.LOG_SOURCE_STDOUT,
    LogSource.STDERR: pb.LogChunk.LOG_SOURCE_STDERR,
    LogSource.SYSTEMD: pb.LogChunk.LOG_SOURCE_SYSTEMD,
}
LOG_SOURCE_FROM_PB = {v: k for k, v in LOG_SOURCE_TO_PB.items()}

BACKUP_STATUS_TO_PB = {
    BackupStatus.PENDING: pb.BACKUP_STATUS_PENDING,
    BackupStatus.RUNNING: pb.BACKUP_STATUS_RUNNING,
    BackupStatus.COMPLETE: pb.BACKUP_STATUS_COMPLETE,
    BackupStatus.FAILED: pb.BACKUP_STATUS_FAILED,
}
BACKUP_STATUS_FROM_PB = {v: k for k, v in BACKUP_STATUS_TO_PB.items()}

MIGRATION_PHASE_TO_PB = {
    MigrationPhase.PREPARING: pb.MIGRATION_PHASE_PREPARING,
    MigrationPhase.EXPORTING: pb.MIGRATION_PHASE_EXPORTING,
    MigrationPhase.IMPORTING: pb.MIGRATION_PHASE_IMPORTING,
    MigrationPhase.COMPLETE: pb.MIGRATION_PHASE_COMPLETE,
    MigrationPhase.FAILED: pb.MIGRATION_PHASE_FAILED,
}
MIGRATION_PHASE_FROM_PB = {v: k for k, v in MIGRATION_PHASE_TO_PB.items()}

ERROR_CODE_TO_PB = {
    ErrorCode.VM_NOT_FOUND: pb.ERROR_CODE_VM_NOT_FOUND,
    ErrorCode.VM_ALREADY_EXISTS: pb.ERROR_CODE_VM_ALREADY_EXISTS,
    ErrorCode.INSUFFICIENT_RESOURCES: pb.ERROR_CODE_INSUFFICIENT_RESOURCES,
    ErrorCode.RESOURCE_DOWNLOAD_FAILED: pb.ERROR_CODE_RESOURCE_DOWNLOAD_FAILED,
    ErrorCode.FILE_TOO_LARGE: pb.ERROR_CODE_FILE_TOO_LARGE,
    ErrorCode.VM_SETUP_FAILED: pb.ERROR_CODE_VM_SETUP_FAILED,
    ErrorCode.MICROVM_INIT_FAILED: pb.ERROR_CODE_MICROVM_INIT_FAILED,
    ErrorCode.INVALID_BACKEND: pb.ERROR_CODE_INVALID_BACKEND,
    ErrorCode.TEE_UNAVAILABLE: pb.ERROR_CODE_TEE_UNAVAILABLE,
    ErrorCode.PORT_UNAVAILABLE: pb.ERROR_CODE_PORT_UNAVAILABLE,
    ErrorCode.HOST_NOT_FOUND: pb.ERROR_CODE_HOST_NOT_FOUND,
    ErrorCode.BACKUP_NOT_FOUND: pb.ERROR_CODE_BACKUP_NOT_FOUND,
    ErrorCode.MIGRATION_IN_PROGRESS: pb.ERROR_CODE_MIGRATION_IN_PROGRESS,
    ErrorCode.INTERNAL: pb.ERROR_CODE_INTERNAL,
}
ERROR_CODE_FROM_PB = {v: k for k, v in ERROR_CODE_TO_PB.items()}

# ── Path helpers ─────────────────────────────────────────────────────────────


def path_to_wire(path: Path) -> str:
    """Serialise a path; the empty path (Path("") == Path(".")) becomes ""."""
    text = str(path)
    return "" if text == "." else text


def path_from_wire(text: str) -> Path:
    return Path(text)


# ── Lifecycle messages ───────────────────────────────────────────────────────


def disk_spec_to_pb(disk: DiskSpec) -> pb.DiskConfig:
    return pb.DiskConfig(
        path=path_to_wire(disk.path),
        readonly=disk.readonly,
        format=DISK_FORMAT_TO_PB[disk.format],
        role=DISK_ROLE_TO_PB[disk.role],
        mount=disk.mount,
    )


def disk_spec_from_pb(msg: pb.DiskConfig) -> DiskSpec:
    return DiskSpec(
        path=path_from_wire(msg.path),
        readonly=msg.readonly,
        format=DISK_FORMAT_FROM_PB[msg.format],
        role=DISK_ROLE_FROM_PB[msg.role],
        mount=msg.mount,
    )


def create_vm_spec_to_pb(spec: CreateVmSpec) -> pb.CreateVmRequest:
    request = pb.CreateVmRequest(
        vm_id=str(spec.vm_id),
        backend=BACKEND_TO_PB[spec.backend],
        kernel_path=path_to_wire(spec.kernel_path),
        initrd_path=path_to_wire(spec.initrd_path),
        disks=[disk_spec_to_pb(disk) for disk in spec.disks],
        vcpus=spec.vcpus,
        memory_mib=spec.memory_mib,
        network=pb.NetworkConfig(
            internet_access=spec.network.internet_access,
            requested_ipv6=spec.network.requested_ipv6,
            ipv6_prefix_len=spec.network.ipv6_prefix_len,
        ),
        gpus=[pb.GpuConfig(pci_host=str(gpu.pci_host), supports_x_vga=gpu.supports_x_vga) for gpu in spec.gpus],
        persistent=spec.persistent,
        ssh_authorized_keys=list(spec.ssh_authorized_keys),
    )
    if spec.tee is not None:
        request.tee.CopyFrom(
            pb.TeeConfig(
                backend=spec.tee.backend.value,
                policy=spec.tee.policy,
                session_dir=path_to_wire(Path(spec.tee.session_dir)),
            )
        )
    if spec.numa_node is not None:
        request.numa_node = spec.numa_node
    return request


def create_vm_spec_from_pb(msg: pb.CreateVmRequest) -> CreateVmSpec:
    tee: TeeConfig | None = None
    if msg.HasField("tee"):
        tee = TeeConfig(
            backend=TeeBackend(msg.tee.backend),
            policy=msg.tee.policy,
            session_dir=DirectoryPath(path_from_wire(msg.tee.session_dir)),
        )
    return CreateVmSpec(
        vm_id=VmId(msg.vm_id),
        backend=BACKEND_FROM_PB[msg.backend],
        kernel_path=path_from_wire(msg.kernel_path),
        initrd_path=path_from_wire(msg.initrd_path),
        disks=[disk_spec_from_pb(disk) for disk in msg.disks],
        vcpus=msg.vcpus,
        memory_mib=msg.memory_mib,
        tee=tee,
        network=NetworkConfig(
            internet_access=msg.network.internet_access,
            requested_ipv6=msg.network.requested_ipv6,
            ipv6_prefix_len=msg.network.ipv6_prefix_len,
        ),
        gpus=[GpuSpec(pci_host=PciAddress(gpu.pci_host), supports_x_vga=gpu.supports_x_vga) for gpu in msg.gpus],
        numa_node=msg.numa_node if msg.HasField("numa_node") else None,
        persistent=msg.persistent,
        ssh_authorized_keys=list(msg.ssh_authorized_keys),
    )


def gpu_device_to_pb(gpu: GpuDevice) -> pb.GpuDevice:
    return pb.GpuDevice(
        pci_host=str(gpu.pci_host),
        device_id=gpu.device_id,
        model=gpu.model,
        supports_x_vga=gpu.supports_x_vga,
    )


def gpu_device_from_pb(msg: pb.GpuDevice) -> GpuDevice:
    return GpuDevice(
        pci_host=PciAddress(msg.pci_host),
        device_id=msg.device_id,
        model=msg.model,
        supports_x_vga=msg.supports_x_vga,
    )


def vm_info_to_pb(info: VmInfo) -> pb.VmInfo:
    msg = pb.VmInfo(
        vm_id=str(info.vm_id),
        status=VM_STATUS_TO_PB[info.status],
        ipv4=info.ipv4,
        ipv6=info.ipv6,
        uptime_secs=info.uptime_secs,
        backend=BACKEND_TO_PB[info.backend],
        status_message=info.status_message,
        ipv4_network=info.ipv4_network,
        ipv6_network=info.ipv6_network,
        defined_at_ns=info.defined_at_ns,
        preparing_at_ns=info.preparing_at_ns,
        prepared_at_ns=info.prepared_at_ns,
        starting_at_ns=info.starting_at_ns,
        started_at_ns=info.started_at_ns,
        stopping_at_ns=info.stopping_at_ns,
        stopped_at_ns=info.stopped_at_ns,
        is_instance=info.is_instance,
        confidential_mode=CONFIDENTIAL_MODE_TO_PB[info.confidential_mode],
        gpus=[gpu_device_to_pb(gpu) for gpu in info.gpus],
    )
    if info.numa_node is not None:
        msg.numa_node = info.numa_node
    return msg


def vm_info_from_pb(msg: pb.VmInfo) -> VmInfo:
    return VmInfo(
        vm_id=VmId(msg.vm_id),
        status=VM_STATUS_FROM_PB[msg.status],
        ipv4=msg.ipv4,
        ipv6=msg.ipv6,
        uptime_secs=msg.uptime_secs,
        backend=BACKEND_FROM_PB[msg.backend],
        numa_node=msg.numa_node if msg.HasField("numa_node") else None,
        status_message=msg.status_message,
        ipv4_network=msg.ipv4_network,
        ipv6_network=msg.ipv6_network,
        defined_at_ns=msg.defined_at_ns,
        preparing_at_ns=msg.preparing_at_ns,
        prepared_at_ns=msg.prepared_at_ns,
        starting_at_ns=msg.starting_at_ns,
        started_at_ns=msg.started_at_ns,
        stopping_at_ns=msg.stopping_at_ns,
        stopped_at_ns=msg.stopped_at_ns,
        is_instance=msg.is_instance,
        confidential_mode=CONFIDENTIAL_MODE_FROM_PB[msg.confidential_mode],
        gpus=[gpu_device_from_pb(gpu) for gpu in msg.gpus],
    )


# ── Host messages ────────────────────────────────────────────────────────────


def health_info_to_pb(info: HealthInfo) -> pb.HealthResponse:
    return pb.HealthResponse(status=info.status.value, vm_count=info.vm_count)


def health_info_from_pb(msg: pb.HealthResponse) -> HealthInfo:
    return HealthInfo(status=HealthStatus(msg.status), vm_count=msg.vm_count)


def host_info_to_pb(info: HostInfo) -> pb.HostInfo:
    return pb.HostInfo(
        cpu_count=info.cpu_count,
        cpu_architecture=info.cpu_architecture,
        cpu_vendor=info.cpu_vendor,
        cpu_model=info.cpu_model,
        memory_mib=info.memory_mib,
        numa_nodes=[
            pb.NumaNode(index=node.index, cpu_count=node.cpu_count, memory_mib=node.memory_mib)
            for node in info.numa_nodes
        ],
        gpus=[gpu_device_to_pb(gpu) for gpu in info.gpus],
        sev_supported=info.sev_supported,
        sev_es_supported=info.sev_es_supported,
        sev_snp_supported=info.sev_snp_supported,
        tdx_supported=info.tdx_supported,
        hostname=info.hostname,
        kernel_version=info.kernel_version,
        host_ipv4=info.host_ipv4,
    )


def host_info_from_pb(msg: pb.HostInfo) -> HostInfo:
    return HostInfo(
        cpu_count=msg.cpu_count,
        cpu_architecture=msg.cpu_architecture,
        cpu_vendor=msg.cpu_vendor,
        cpu_model=msg.cpu_model,
        memory_mib=msg.memory_mib,
        numa_nodes=[
            NumaNodeInfo(index=node.index, cpu_count=node.cpu_count, memory_mib=node.memory_mib)
            for node in msg.numa_nodes
        ],
        gpus=[gpu_device_from_pb(gpu) for gpu in msg.gpus],
        sev_supported=msg.sev_supported,
        sev_es_supported=msg.sev_es_supported,
        sev_snp_supported=msg.sev_snp_supported,
        tdx_supported=msg.tdx_supported,
        hostname=msg.hostname,
        kernel_version=msg.kernel_version,
        host_ipv4=msg.host_ipv4,
    )


# ── Port forwarding ──────────────────────────────────────────────────────────


def port_forward_info_to_pb(info: PortForwardInfo) -> pb.PortForwardInfo:
    return pb.PortForwardInfo(
        vm_id=str(info.vm_id),
        host_port=int(info.host_port),
        vm_port=int(info.vm_port),
        protocol=info.protocol.value,
    )


def port_forward_info_from_pb(msg: pb.PortForwardInfo) -> PortForwardInfo:
    return PortForwardInfo(
        vm_id=VmId(msg.vm_id),
        host_port=HostPort(msg.host_port),
        vm_port=GuestPort(msg.vm_port),
        protocol=Protocol(msg.protocol),
    )


def port_forward_spec_to_pb(spec: PortForwardSpec) -> pb.AddPortForwardRequest:
    return pb.AddPortForwardRequest(
        vm_id=str(spec.vm_id),
        host_port=int(spec.host_port),
        vm_port=int(spec.vm_port),
        protocol=spec.protocol.value,
    )


def port_forward_spec_from_pb(msg: pb.AddPortForwardRequest) -> PortForwardSpec:
    return PortForwardSpec(
        vm_id=VmId(msg.vm_id),
        host_port=HostPort(msg.host_port),
        vm_port=GuestPort(msg.vm_port),
        protocol=Protocol(msg.protocol),
    )


# ── Logs ─────────────────────────────────────────────────────────────────────


def log_chunk_to_pb(chunk: LogChunk) -> pb.LogChunk:
    return pb.LogChunk(
        timestamp_ns=chunk.timestamp_ns,
        line=chunk.line,
        source=LOG_SOURCE_TO_PB[chunk.source],
    )


def log_chunk_from_pb(msg: pb.LogChunk) -> LogChunk:
    return LogChunk(
        timestamp_ns=msg.timestamp_ns,
        line=msg.line,
        source=LOG_SOURCE_FROM_PB[msg.source],
    )


# ── Backups ──────────────────────────────────────────────────────────────────


def backup_info_to_pb(info: BackupInfo) -> pb.BackupInfo:
    return pb.BackupInfo(
        vm_id=str(info.vm_id),
        backup_id=str(info.backup_id),
        status=BACKUP_STATUS_TO_PB[info.status],
        size_bytes=info.size_bytes,
        created_at_unix_secs=info.created_at_unix_secs,
        error_message=info.error_message,
    )


def backup_info_from_pb(msg: pb.BackupInfo) -> BackupInfo:
    return BackupInfo(
        vm_id=VmId(msg.vm_id),
        backup_id=BackupId(msg.backup_id),
        status=BACKUP_STATUS_FROM_PB[msg.status],
        size_bytes=msg.size_bytes,
        created_at_unix_secs=msg.created_at_unix_secs,
        error_message=msg.error_message,
    )


def backup_chunk_to_pb(chunk: BackupChunk) -> pb.BackupChunk:
    return pb.BackupChunk(data=chunk.data, offset=chunk.offset)


def backup_chunk_from_pb(msg: pb.BackupChunk) -> BackupChunk:
    return BackupChunk(data=msg.data, offset=msg.offset)


# ── Migration ────────────────────────────────────────────────────────────────


def migration_info_to_pb(info: MigrationInfo) -> pb.MigrationInfo:
    return pb.MigrationInfo(
        vm_id=str(info.vm_id),
        migration_id=str(info.migration_id),
        phase=MIGRATION_PHASE_TO_PB[info.phase],
        bytes_transferred=info.bytes_transferred,
        bytes_total=info.bytes_total,
        error_message=info.error_message,
    )


def migration_info_from_pb(msg: pb.MigrationInfo) -> MigrationInfo:
    return MigrationInfo(
        vm_id=VmId(msg.vm_id),
        migration_id=MigrationId(msg.migration_id),
        phase=MIGRATION_PHASE_FROM_PB[msg.phase],
        bytes_transferred=msg.bytes_transferred,
        bytes_total=msg.bytes_total,
        error_message=msg.error_message,
    )


# ── Confidential ─────────────────────────────────────────────────────────────


def measurement_to_pb(measurement: Measurement) -> pb.Measurement:
    return pb.Measurement(
        vm_id=str(measurement.vm_id),
        measurement_bytes=measurement.measurement_bytes,
        tee_backend=measurement.tee_backend.value,
    )


def measurement_from_pb(msg: pb.Measurement) -> Measurement:
    return Measurement(
        vm_id=VmId(msg.vm_id),
        measurement_bytes=msg.measurement_bytes,
        tee_backend=TeeBackend(msg.tee_backend),
    )
