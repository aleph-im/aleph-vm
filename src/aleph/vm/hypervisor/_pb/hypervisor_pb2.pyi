from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Backend(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    BACKEND_UNSPECIFIED: _ClassVar[Backend]
    BACKEND_FIRECRACKER: _ClassVar[Backend]
    BACKEND_QEMU: _ClassVar[Backend]
    BACKEND_QEMU_SEV: _ClassVar[Backend]

class VmStatus(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    VM_STATUS_UNSPECIFIED: _ClassVar[VmStatus]
    VM_STATUS_DEFINED: _ClassVar[VmStatus]
    VM_STATUS_BOOTING: _ClassVar[VmStatus]
    VM_STATUS_RUNNING: _ClassVar[VmStatus]
    VM_STATUS_STOPPING: _ClassVar[VmStatus]
    VM_STATUS_STOPPED: _ClassVar[VmStatus]
    VM_STATUS_FAILED: _ClassVar[VmStatus]
BACKEND_UNSPECIFIED: Backend
BACKEND_FIRECRACKER: Backend
BACKEND_QEMU: Backend
BACKEND_QEMU_SEV: Backend
VM_STATUS_UNSPECIFIED: VmStatus
VM_STATUS_DEFINED: VmStatus
VM_STATUS_BOOTING: VmStatus
VM_STATUS_RUNNING: VmStatus
VM_STATUS_STOPPING: VmStatus
VM_STATUS_STOPPED: VmStatus
VM_STATUS_FAILED: VmStatus

class HealthRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HealthResponse(_message.Message):
    __slots__ = ("status", "vm_count")
    STATUS_FIELD_NUMBER: _ClassVar[int]
    VM_COUNT_FIELD_NUMBER: _ClassVar[int]
    status: str
    vm_count: int
    def __init__(self, status: _Optional[str] = ..., vm_count: _Optional[int] = ...) -> None: ...

class GetHostInfoRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class HostInfo(_message.Message):
    __slots__ = ("cpu_count", "memory_mib", "numa_nodes", "gpus", "sev_snp_supported", "tdx_supported", "hostname", "kernel_version")
    CPU_COUNT_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    NUMA_NODES_FIELD_NUMBER: _ClassVar[int]
    GPUS_FIELD_NUMBER: _ClassVar[int]
    SEV_SNP_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    TDX_SUPPORTED_FIELD_NUMBER: _ClassVar[int]
    HOSTNAME_FIELD_NUMBER: _ClassVar[int]
    KERNEL_VERSION_FIELD_NUMBER: _ClassVar[int]
    cpu_count: int
    memory_mib: int
    numa_nodes: _containers.RepeatedCompositeFieldContainer[NumaNode]
    gpus: _containers.RepeatedCompositeFieldContainer[GpuDevice]
    sev_snp_supported: bool
    tdx_supported: bool
    hostname: str
    kernel_version: str
    def __init__(self, cpu_count: _Optional[int] = ..., memory_mib: _Optional[int] = ..., numa_nodes: _Optional[_Iterable[_Union[NumaNode, _Mapping]]] = ..., gpus: _Optional[_Iterable[_Union[GpuDevice, _Mapping]]] = ..., sev_snp_supported: bool = ..., tdx_supported: bool = ..., hostname: _Optional[str] = ..., kernel_version: _Optional[str] = ...) -> None: ...

class NumaNode(_message.Message):
    __slots__ = ("index", "cpu_count", "memory_mib")
    INDEX_FIELD_NUMBER: _ClassVar[int]
    CPU_COUNT_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    index: int
    cpu_count: int
    memory_mib: int
    def __init__(self, index: _Optional[int] = ..., cpu_count: _Optional[int] = ..., memory_mib: _Optional[int] = ...) -> None: ...

class GpuDevice(_message.Message):
    __slots__ = ("pci_host", "device_id", "model", "supports_x_vga")
    PCI_HOST_FIELD_NUMBER: _ClassVar[int]
    DEVICE_ID_FIELD_NUMBER: _ClassVar[int]
    MODEL_FIELD_NUMBER: _ClassVar[int]
    SUPPORTS_X_VGA_FIELD_NUMBER: _ClassVar[int]
    pci_host: str
    device_id: str
    model: str
    supports_x_vga: bool
    def __init__(self, pci_host: _Optional[str] = ..., device_id: _Optional[str] = ..., model: _Optional[str] = ..., supports_x_vga: bool = ...) -> None: ...

class CreateVmRequest(_message.Message):
    __slots__ = ("vm_id", "backend", "kernel_path", "initrd_path", "disks", "vcpus", "memory_mib", "tee", "network", "gpus", "numa_node", "persistent")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    BACKEND_FIELD_NUMBER: _ClassVar[int]
    KERNEL_PATH_FIELD_NUMBER: _ClassVar[int]
    INITRD_PATH_FIELD_NUMBER: _ClassVar[int]
    DISKS_FIELD_NUMBER: _ClassVar[int]
    VCPUS_FIELD_NUMBER: _ClassVar[int]
    MEMORY_MIB_FIELD_NUMBER: _ClassVar[int]
    TEE_FIELD_NUMBER: _ClassVar[int]
    NETWORK_FIELD_NUMBER: _ClassVar[int]
    GPUS_FIELD_NUMBER: _ClassVar[int]
    NUMA_NODE_FIELD_NUMBER: _ClassVar[int]
    PERSISTENT_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    backend: Backend
    kernel_path: str
    initrd_path: str
    disks: _containers.RepeatedCompositeFieldContainer[DiskConfig]
    vcpus: int
    memory_mib: int
    tee: TeeConfig
    network: NetworkConfig
    gpus: _containers.RepeatedCompositeFieldContainer[GpuConfig]
    numa_node: int
    persistent: bool
    def __init__(self, vm_id: _Optional[str] = ..., backend: _Optional[_Union[Backend, str]] = ..., kernel_path: _Optional[str] = ..., initrd_path: _Optional[str] = ..., disks: _Optional[_Iterable[_Union[DiskConfig, _Mapping]]] = ..., vcpus: _Optional[int] = ..., memory_mib: _Optional[int] = ..., tee: _Optional[_Union[TeeConfig, _Mapping]] = ..., network: _Optional[_Union[NetworkConfig, _Mapping]] = ..., gpus: _Optional[_Iterable[_Union[GpuConfig, _Mapping]]] = ..., numa_node: _Optional[int] = ..., persistent: bool = ...) -> None: ...

class DiskConfig(_message.Message):
    __slots__ = ("path", "readonly", "format", "role")
    class Format(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        FORMAT_UNSPECIFIED: _ClassVar[DiskConfig.Format]
        FORMAT_RAW: _ClassVar[DiskConfig.Format]
        FORMAT_QCOW2: _ClassVar[DiskConfig.Format]
        FORMAT_SQUASHFS: _ClassVar[DiskConfig.Format]
    FORMAT_UNSPECIFIED: DiskConfig.Format
    FORMAT_RAW: DiskConfig.Format
    FORMAT_QCOW2: DiskConfig.Format
    FORMAT_SQUASHFS: DiskConfig.Format
    class DiskRole(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        DISK_ROLE_UNSPECIFIED: _ClassVar[DiskConfig.DiskRole]
        DISK_ROLE_ROOTFS: _ClassVar[DiskConfig.DiskRole]
        DISK_ROLE_CODE: _ClassVar[DiskConfig.DiskRole]
        DISK_ROLE_RUNTIME: _ClassVar[DiskConfig.DiskRole]
        DISK_ROLE_DATA: _ClassVar[DiskConfig.DiskRole]
        DISK_ROLE_EXTRA: _ClassVar[DiskConfig.DiskRole]
    DISK_ROLE_UNSPECIFIED: DiskConfig.DiskRole
    DISK_ROLE_ROOTFS: DiskConfig.DiskRole
    DISK_ROLE_CODE: DiskConfig.DiskRole
    DISK_ROLE_RUNTIME: DiskConfig.DiskRole
    DISK_ROLE_DATA: DiskConfig.DiskRole
    DISK_ROLE_EXTRA: DiskConfig.DiskRole
    PATH_FIELD_NUMBER: _ClassVar[int]
    READONLY_FIELD_NUMBER: _ClassVar[int]
    FORMAT_FIELD_NUMBER: _ClassVar[int]
    ROLE_FIELD_NUMBER: _ClassVar[int]
    path: str
    readonly: bool
    format: DiskConfig.Format
    role: DiskConfig.DiskRole
    def __init__(self, path: _Optional[str] = ..., readonly: bool = ..., format: _Optional[_Union[DiskConfig.Format, str]] = ..., role: _Optional[_Union[DiskConfig.DiskRole, str]] = ...) -> None: ...

class TeeConfig(_message.Message):
    __slots__ = ("backend", "policy", "session_dir")
    BACKEND_FIELD_NUMBER: _ClassVar[int]
    POLICY_FIELD_NUMBER: _ClassVar[int]
    SESSION_DIR_FIELD_NUMBER: _ClassVar[int]
    backend: str
    policy: str
    session_dir: str
    def __init__(self, backend: _Optional[str] = ..., policy: _Optional[str] = ..., session_dir: _Optional[str] = ...) -> None: ...

class NetworkConfig(_message.Message):
    __slots__ = ("internet_access", "requested_ipv6", "ipv6_prefix_len")
    INTERNET_ACCESS_FIELD_NUMBER: _ClassVar[int]
    REQUESTED_IPV6_FIELD_NUMBER: _ClassVar[int]
    IPV6_PREFIX_LEN_FIELD_NUMBER: _ClassVar[int]
    internet_access: bool
    requested_ipv6: str
    ipv6_prefix_len: int
    def __init__(self, internet_access: bool = ..., requested_ipv6: _Optional[str] = ..., ipv6_prefix_len: _Optional[int] = ...) -> None: ...

class GpuConfig(_message.Message):
    __slots__ = ("pci_host", "supports_x_vga")
    PCI_HOST_FIELD_NUMBER: _ClassVar[int]
    SUPPORTS_X_VGA_FIELD_NUMBER: _ClassVar[int]
    pci_host: str
    supports_x_vga: bool
    def __init__(self, pci_host: _Optional[str] = ..., supports_x_vga: bool = ...) -> None: ...

class VmInfo(_message.Message):
    __slots__ = ("vm_id", "status", "ipv4", "ipv6", "uptime_secs", "backend", "numa_node", "status_message")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    STATUS_FIELD_NUMBER: _ClassVar[int]
    IPV4_FIELD_NUMBER: _ClassVar[int]
    IPV6_FIELD_NUMBER: _ClassVar[int]
    UPTIME_SECS_FIELD_NUMBER: _ClassVar[int]
    BACKEND_FIELD_NUMBER: _ClassVar[int]
    NUMA_NODE_FIELD_NUMBER: _ClassVar[int]
    STATUS_MESSAGE_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    status: VmStatus
    ipv4: str
    ipv6: str
    uptime_secs: int
    backend: Backend
    numa_node: int
    status_message: str
    def __init__(self, vm_id: _Optional[str] = ..., status: _Optional[_Union[VmStatus, str]] = ..., ipv4: _Optional[str] = ..., ipv6: _Optional[str] = ..., uptime_secs: _Optional[int] = ..., backend: _Optional[_Union[Backend, str]] = ..., numa_node: _Optional[int] = ..., status_message: _Optional[str] = ...) -> None: ...

class GetVmRequest(_message.Message):
    __slots__ = ("vm_id",)
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    def __init__(self, vm_id: _Optional[str] = ...) -> None: ...

class ListVmsRequest(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListVmsResponse(_message.Message):
    __slots__ = ("vms",)
    VMS_FIELD_NUMBER: _ClassVar[int]
    vms: _containers.RepeatedCompositeFieldContainer[VmInfo]
    def __init__(self, vms: _Optional[_Iterable[_Union[VmInfo, _Mapping]]] = ...) -> None: ...

class DeleteVmRequest(_message.Message):
    __slots__ = ("vm_id",)
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    def __init__(self, vm_id: _Optional[str] = ...) -> None: ...

class DeleteVmResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class RebootVmRequest(_message.Message):
    __slots__ = ("vm_id", "hard")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    HARD_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    hard: bool
    def __init__(self, vm_id: _Optional[str] = ..., hard: bool = ...) -> None: ...

class ReinstallVmRequest(_message.Message):
    __slots__ = ("vm_id",)
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    def __init__(self, vm_id: _Optional[str] = ...) -> None: ...

class AddPortForwardRequest(_message.Message):
    __slots__ = ("vm_id", "host_port", "vm_port", "protocol")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_PORT_FIELD_NUMBER: _ClassVar[int]
    VM_PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    host_port: int
    vm_port: int
    protocol: str
    def __init__(self, vm_id: _Optional[str] = ..., host_port: _Optional[int] = ..., vm_port: _Optional[int] = ..., protocol: _Optional[str] = ...) -> None: ...

class PortForwardInfo(_message.Message):
    __slots__ = ("vm_id", "host_port", "vm_port", "protocol")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_PORT_FIELD_NUMBER: _ClassVar[int]
    VM_PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    host_port: int
    vm_port: int
    protocol: str
    def __init__(self, vm_id: _Optional[str] = ..., host_port: _Optional[int] = ..., vm_port: _Optional[int] = ..., protocol: _Optional[str] = ...) -> None: ...

class RemovePortForwardRequest(_message.Message):
    __slots__ = ("vm_id", "host_port", "protocol")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    HOST_PORT_FIELD_NUMBER: _ClassVar[int]
    PROTOCOL_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    host_port: int
    protocol: str
    def __init__(self, vm_id: _Optional[str] = ..., host_port: _Optional[int] = ..., protocol: _Optional[str] = ...) -> None: ...

class RemovePortForwardResponse(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class ListPortForwardsRequest(_message.Message):
    __slots__ = ("vm_id",)
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    def __init__(self, vm_id: _Optional[str] = ...) -> None: ...

class ListPortForwardsResponse(_message.Message):
    __slots__ = ("forwards",)
    FORWARDS_FIELD_NUMBER: _ClassVar[int]
    forwards: _containers.RepeatedCompositeFieldContainer[PortForwardInfo]
    def __init__(self, forwards: _Optional[_Iterable[_Union[PortForwardInfo, _Mapping]]] = ...) -> None: ...

class GetLogsRequest(_message.Message):
    __slots__ = ("vm_id", "max_lines", "from_tail")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    MAX_LINES_FIELD_NUMBER: _ClassVar[int]
    FROM_TAIL_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    max_lines: int
    from_tail: bool
    def __init__(self, vm_id: _Optional[str] = ..., max_lines: _Optional[int] = ..., from_tail: bool = ...) -> None: ...

class GetLogsResponse(_message.Message):
    __slots__ = ("lines",)
    LINES_FIELD_NUMBER: _ClassVar[int]
    lines: _containers.RepeatedCompositeFieldContainer[LogChunk]
    def __init__(self, lines: _Optional[_Iterable[_Union[LogChunk, _Mapping]]] = ...) -> None: ...

class StreamLogsRequest(_message.Message):
    __slots__ = ("vm_id", "include_history")
    VM_ID_FIELD_NUMBER: _ClassVar[int]
    INCLUDE_HISTORY_FIELD_NUMBER: _ClassVar[int]
    vm_id: str
    include_history: bool
    def __init__(self, vm_id: _Optional[str] = ..., include_history: bool = ...) -> None: ...

class LogChunk(_message.Message):
    __slots__ = ("timestamp_ns", "line", "source")
    class LogSource(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
        __slots__ = ()
        LOG_SOURCE_UNSPECIFIED: _ClassVar[LogChunk.LogSource]
        LOG_SOURCE_SERIAL: _ClassVar[LogChunk.LogSource]
        LOG_SOURCE_STDOUT: _ClassVar[LogChunk.LogSource]
        LOG_SOURCE_SYSTEMD: _ClassVar[LogChunk.LogSource]
    LOG_SOURCE_UNSPECIFIED: LogChunk.LogSource
    LOG_SOURCE_SERIAL: LogChunk.LogSource
    LOG_SOURCE_STDOUT: LogChunk.LogSource
    LOG_SOURCE_SYSTEMD: LogChunk.LogSource
    TIMESTAMP_NS_FIELD_NUMBER: _ClassVar[int]
    LINE_FIELD_NUMBER: _ClassVar[int]
    SOURCE_FIELD_NUMBER: _ClassVar[int]
    timestamp_ns: int
    line: str
    source: LogChunk.LogSource
    def __init__(self, timestamp_ns: _Optional[int] = ..., line: _Optional[str] = ..., source: _Optional[_Union[LogChunk.LogSource, str]] = ...) -> None: ...
