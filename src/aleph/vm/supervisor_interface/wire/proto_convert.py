"""DTO ⇄ protobuf conversion for the Supervisor gRPC transport.

Pure mapping between the frozen dataclasses in `types.py` and the generated
messages in `_pb.supervisor_pb2`. No I/O, no Aleph imports. Shared by the
gRPC server (DTO results → wire) and the client (wire → DTO results).

Path convention: empty wire strings mean "no path". `Path("")` normalises to
`Path(".")` in Python, so both spellings serialise to "" and "" parses back
to `Path("")`.
"""

from __future__ import annotations

import json
from pathlib import Path

from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    ErrorCode,
    GpuDevice,
    GpuSpec,
    GuestChannelSpec,
    GuestPort,
    HealthInfo,
    HealthStatus,
    HostInfo,
    HostPort,
    IpAssignment,
    LogChunk,
    LogSource,
    Measurement,
    NetworkConfig,
    NumaNodeInfo,
    PciAddress,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    SevInfo,
    TeeBackend,
    TeeConfig,
    VmEvent,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2 as pb

# ── Enum tables ──────────────────────────────────────────────────────────────

BACKEND_TO_PB = {
    Backend.FIRECRACKER: pb.BACKEND_FIRECRACKER,
    Backend.QEMU: pb.BACKEND_QEMU,
}
BACKEND_FROM_PB = {v: k for k, v in BACKEND_TO_PB.items()}

TEE_BACKEND_TO_PB = {
    TeeBackend.NONE: pb.TEE_BACKEND_UNSPECIFIED,
    TeeBackend.SEV: pb.TEE_BACKEND_SEV,
    TeeBackend.SEV_SNP: pb.TEE_BACKEND_SEV_SNP,
    TeeBackend.TDX: pb.TEE_BACKEND_TDX,
    TeeBackend.NVIDIA_CC: pb.TEE_BACKEND_NVIDIA_CC,
}
TEE_BACKEND_FROM_PB = {v: k for k, v in TEE_BACKEND_TO_PB.items()}

HEALTH_STATUS_TO_PB = {
    HealthStatus.OK: pb.HEALTH_STATUS_OK,
    HealthStatus.DEGRADED: pb.HEALTH_STATUS_DEGRADED,
}
HEALTH_STATUS_FROM_PB = {v: k for k, v in HEALTH_STATUS_TO_PB.items()}

PROTOCOL_TO_PB = {
    Protocol.TCP: pb.PROTOCOL_TCP,
    Protocol.UDP: pb.PROTOCOL_UDP,
}
PROTOCOL_FROM_PB = {v: k for k, v in PROTOCOL_TO_PB.items()}

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
    )


def disk_spec_from_pb(msg: pb.DiskConfig) -> DiskSpec:
    return DiskSpec(
        path=path_from_wire(msg.path),
        readonly=msg.readonly,
        format=DISK_FORMAT_FROM_PB[msg.format],
        role=DISK_ROLE_FROM_PB[msg.role],
    )


def create_vm_spec_to_pb(spec: CreateVmSpec) -> pb.VmSpec:
    request = pb.VmSpec(
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
        gpus=[
            pb.GpuConfig(
                pci_host=str(gpu.pci_host),
                supports_x_vga=gpu.supports_x_vga,
            )
            for gpu in spec.gpus
        ],
        persistent=spec.persistent,
        ssh_authorized_keys=list(spec.ssh_authorized_keys),
        hostname=spec.hostname,
    )
    if spec.guest_channel is not None:
        request.guest_channel.CopyFrom(
            pb.GuestChannel(
                ready_port=spec.guest_channel.ready_port,
                ready_timeout_secs=spec.guest_channel.ready_timeout_secs,
            )
        )
    if spec.tee is not None:
        request.tee.CopyFrom(
            pb.TeeConfig(
                backend=TEE_BACKEND_TO_PB[spec.tee.backend],
                policy=spec.tee.policy,
                session_dir=path_to_wire(Path(spec.tee.session_dir)),
                firmware_path=path_to_wire(spec.tee.firmware_path) if spec.tee.firmware_path is not None else "",
                kernel_cmdline=spec.tee.kernel_cmdline,
                cpu_model=spec.tee.cpu_model,
            )
        )
    if spec.numa_node is not None:
        request.numa_node = spec.numa_node
    return request


def create_vm_spec_from_pb(msg: pb.VmSpec) -> CreateVmSpec:
    tee: TeeConfig | None = None
    if msg.HasField("tee"):
        tee = TeeConfig(
            backend=TEE_BACKEND_FROM_PB[msg.tee.backend],
            policy=msg.tee.policy,
            session_dir=DirectoryPath(path_from_wire(msg.tee.session_dir)),
            firmware_path=path_from_wire(msg.tee.firmware_path) if msg.tee.firmware_path else None,
            kernel_cmdline=msg.tee.kernel_cmdline,
            cpu_model=msg.tee.cpu_model,
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
        gpus=[
            GpuSpec(
                pci_host=PciAddress(gpu.pci_host),
                supports_x_vga=gpu.supports_x_vga,
            )
            for gpu in msg.gpus
        ],
        numa_node=msg.numa_node if msg.HasField("numa_node") else None,
        persistent=msg.persistent,
        ssh_authorized_keys=list(msg.ssh_authorized_keys),
        hostname=msg.hostname,
        guest_channel=(
            GuestChannelSpec(
                ready_port=msg.guest_channel.ready_port,
                ready_timeout_secs=msg.guest_channel.ready_timeout_secs,
            )
            if msg.HasField("guest_channel")
            else None
        ),
    )


def gpu_device_to_pb(gpu: GpuDevice) -> pb.GpuDevice:
    return pb.GpuDevice(
        pci_host=str(gpu.pci_host),
        device_id=gpu.device_id,
        model=gpu.model,
        supports_x_vga=gpu.supports_x_vga,
        cc_mode=gpu.cc_mode or "",
    )


def gpu_device_from_pb(msg: pb.GpuDevice) -> GpuDevice:
    return GpuDevice(
        pci_host=PciAddress(msg.pci_host),
        device_id=msg.device_id,
        model=msg.model,
        supports_x_vga=msg.supports_x_vga,
        cc_mode=msg.cc_mode or None,
    )


def ip_assignment_to_pb(ip: IpAssignment) -> pb.IpAssignment:
    return pb.IpAssignment(address=ip.address, network_cidr=ip.network_cidr, gateway=ip.gateway)


def ip_assignment_from_pb(msg: pb.IpAssignment) -> IpAssignment:
    return IpAssignment(address=msg.address, network_cidr=msg.network_cidr, gateway=msg.gateway)


def vm_info_to_pb(info: VmInfo) -> pb.VmInfo:
    msg = pb.VmInfo(
        vm_id=str(info.vm_id),
        status=VM_STATUS_TO_PB[info.status],
        ipv4=ip_assignment_to_pb(info.ipv4),
        ipv6=ip_assignment_to_pb(info.ipv6),
        uptime_secs=info.uptime_secs,
        backend=BACKEND_TO_PB[info.backend],
        status_message=info.status_message,
        defined_at_ns=info.defined_at_ns,
        preparing_at_ns=info.preparing_at_ns,
        prepared_at_ns=info.prepared_at_ns,
        starting_at_ns=info.starting_at_ns,
        started_at_ns=info.started_at_ns,
        stopping_at_ns=info.stopping_at_ns,
        stopped_at_ns=info.stopped_at_ns,
        confidential_mode=CONFIDENTIAL_MODE_TO_PB[info.confidential_mode],
        awaiting_confidential_init=info.awaiting_confidential_init,
        gpus=[gpu_device_to_pb(gpu) for gpu in info.gpus],
        guest_channel_path=info.guest_channel_path,
        guest_ready_payload=info.guest_ready_payload,
    )
    if info.numa_node is not None:
        msg.numa_node = info.numa_node
    return msg


def vm_info_from_pb(msg: pb.VmInfo) -> VmInfo:
    return VmInfo(
        vm_id=VmId(msg.vm_id),
        status=VM_STATUS_FROM_PB[msg.status],
        ipv4=ip_assignment_from_pb(msg.ipv4),
        ipv6=ip_assignment_from_pb(msg.ipv6),
        uptime_secs=msg.uptime_secs,
        backend=BACKEND_FROM_PB[msg.backend],
        numa_node=msg.numa_node if msg.HasField("numa_node") else None,
        status_message=msg.status_message,
        defined_at_ns=msg.defined_at_ns,
        preparing_at_ns=msg.preparing_at_ns,
        prepared_at_ns=msg.prepared_at_ns,
        starting_at_ns=msg.starting_at_ns,
        started_at_ns=msg.started_at_ns,
        stopping_at_ns=msg.stopping_at_ns,
        stopped_at_ns=msg.stopped_at_ns,
        confidential_mode=CONFIDENTIAL_MODE_FROM_PB[msg.confidential_mode],
        awaiting_confidential_init=msg.awaiting_confidential_init,
        gpus=[gpu_device_from_pb(gpu) for gpu in msg.gpus],
        guest_channel_path=msg.guest_channel_path,
        guest_ready_payload=msg.guest_ready_payload,
    )


# ── Host messages ────────────────────────────────────────────────────────────


def health_info_to_pb(info: HealthInfo) -> pb.HealthResponse:
    return pb.HealthResponse(status=HEALTH_STATUS_TO_PB[info.status], vm_count=info.vm_count)


def health_info_from_pb(msg: pb.HealthResponse) -> HealthInfo:
    return HealthInfo(status=HEALTH_STATUS_FROM_PB[msg.status], vm_count=msg.vm_count)


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
        cpu_frequency_mhz=info.cpu_frequency_mhz,
        memory_type=info.memory_type,
        memory_clock_mhz=info.memory_clock_mhz,
        available_disk_bytes=info.available_disk_bytes,
        gpu_inventory_json=json.dumps(info.gpu_inventory),
        available_gpus_json=json.dumps(info.available_gpus),
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
        cpu_frequency_mhz=msg.cpu_frequency_mhz,
        memory_type=msg.memory_type,
        memory_clock_mhz=msg.memory_clock_mhz,
        available_disk_bytes=msg.available_disk_bytes,
        gpu_inventory=json.loads(msg.gpu_inventory_json) if msg.gpu_inventory_json else [],
        available_gpus=json.loads(msg.available_gpus_json) if msg.available_gpus_json else [],
    )


# ── Port forwarding ──────────────────────────────────────────────────────────


def port_forward_info_to_pb(info: PortForwardInfo) -> pb.PortForwardInfo:
    return pb.PortForwardInfo(
        vm_id=str(info.vm_id),
        host_port=int(info.host_port),
        vm_port=int(info.vm_port),
        protocol=PROTOCOL_TO_PB[info.protocol],
    )


def port_forward_info_from_pb(msg: pb.PortForwardInfo) -> PortForwardInfo:
    return PortForwardInfo(
        vm_id=VmId(msg.vm_id),
        host_port=HostPort(msg.host_port),
        vm_port=GuestPort(msg.vm_port),
        protocol=PROTOCOL_FROM_PB[msg.protocol],
    )


def port_forward_spec_to_pb(spec: PortForwardSpec) -> pb.AddPortForwardRequest:
    return pb.AddPortForwardRequest(
        vm_id=str(spec.vm_id),
        host_port=int(spec.host_port),
        vm_port=int(spec.vm_port),
        protocol=PROTOCOL_TO_PB[spec.protocol],
    )


def port_forward_spec_from_pb(msg: pb.AddPortForwardRequest) -> PortForwardSpec:
    return PortForwardSpec(
        vm_id=VmId(msg.vm_id),
        host_port=HostPort(msg.host_port),
        vm_port=GuestPort(msg.vm_port),
        protocol=PROTOCOL_FROM_PB[msg.protocol],
    )


# ── Events ───────────────────────────────────────────────────────────────────


def vm_event_to_pb(event: VmEvent) -> pb.VmEvent:
    return pb.VmEvent(
        vm_id=str(event.vm_id),
        old_status=VM_STATUS_TO_PB[event.old_status],
        new_status=VM_STATUS_TO_PB[event.new_status],
        timestamp_ns=event.timestamp_ns,
    )


def vm_event_from_pb(msg: pb.VmEvent) -> VmEvent:
    return VmEvent(
        vm_id=VmId(msg.vm_id),
        old_status=VM_STATUS_FROM_PB[msg.old_status],
        new_status=VM_STATUS_FROM_PB[msg.new_status],
        timestamp_ns=msg.timestamp_ns,
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


# ── Confidential ─────────────────────────────────────────────────────────────


def sev_info_to_pb(info: SevInfo) -> pb.SevInfo:
    return pb.SevInfo(
        enabled=info.enabled,
        api_major=info.api_major,
        api_minor=info.api_minor,
        build_id=info.build_id,
        policy=info.policy,
        state=info.state,
        handle=info.handle,
    )


def sev_info_from_pb(msg: pb.SevInfo) -> SevInfo:
    return SevInfo(
        enabled=msg.enabled,
        api_major=msg.api_major,
        api_minor=msg.api_minor,
        build_id=msg.build_id,
        policy=msg.policy,
        state=msg.state,
        handle=msg.handle,
    )


def measurement_to_pb(measurement: Measurement) -> pb.Measurement:
    msg = pb.Measurement(
        vm_id=str(measurement.vm_id),
        measurement_bytes=measurement.measurement_bytes,
        tee_backend=TEE_BACKEND_TO_PB[measurement.tee_backend],
        launch_measure=measurement.launch_measure,
    )
    if measurement.sev_info is not None:
        msg.sev_info.CopyFrom(sev_info_to_pb(measurement.sev_info))
    return msg


def measurement_from_pb(msg: pb.Measurement) -> Measurement:
    return Measurement(
        vm_id=VmId(msg.vm_id),
        measurement_bytes=msg.measurement_bytes,
        tee_backend=TEE_BACKEND_FROM_PB[msg.tee_backend],
        sev_info=sev_info_from_pb(msg.sev_info) if msg.HasField("sev_info") else None,
        launch_measure=msg.launch_measure,
    )
