"""Round-trip tests for the DTO ⇄ protobuf conversion layer."""

from pathlib import Path

from aleph.vm.supervisor import proto_convert as conv
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

FULL_SPEC = CreateVmSpec(
    vm_id=VmId("cafe" * 16),
    backend=Backend.QEMU_SEV,
    kernel_path=Path("/opt/kernel/vmlinux.bin"),
    initrd_path=Path("/opt/kernel/initrd.img"),
    disks=[
        DiskSpec(path=Path("/var/cache/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS),
        DiskSpec(
            path=Path("/var/cache/data.raw"), readonly=True, format=DiskFormat.RAW, role=DiskRole.DATA, mount="/data"
        ),
    ],
    vcpus=4,
    memory_mib=4096,
    tee=TeeConfig(backend=TeeBackend.SEV_SNP, policy="0x07", session_dir=DirectoryPath(Path("/var/lib/sessions"))),
    network=NetworkConfig(internet_access=True, requested_ipv6="fd00::42", ipv6_prefix_len=124),
    gpus=[GpuSpec(pci_host=PciAddress("0000:01:00.0"), supports_x_vga=True)],
    numa_node=1,
    persistent=True,
    ssh_authorized_keys=["ssh-ed25519 AAAA test@host"],
)

MINIMAL_SPEC = CreateVmSpec(
    vm_id=VmId("beef" * 16),
    backend=Backend.FIRECRACKER,
    kernel_path=Path(""),
    initrd_path=Path(""),
    disks=[],
    vcpus=1,
    memory_mib=128,
    tee=None,
    network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
    gpus=[],
    numa_node=None,
    persistent=False,
    program_mode=True,
)

FULL_VM_INFO = VmInfo(
    vm_id=VmId("cafe" * 16),
    status=VmStatus.RUNNING,
    ipv4="172.16.4.2",
    ipv6="fd00::42",
    uptime_secs=1234,
    backend=Backend.QEMU,
    numa_node=0,
    status_message="all good",
    ipv4_network="172.16.4.0/24",
    ipv6_network="fd00::/64",
    defined_at_ns=1,
    preparing_at_ns=2,
    prepared_at_ns=3,
    starting_at_ns=4,
    started_at_ns=5,
    stopping_at_ns=0,
    stopped_at_ns=0,
    is_instance=True,
    confidential_mode=ConfidentialMode.SEV_ES,
    gpus=[GpuDevice(pci_host=PciAddress("0000:01:00.0"), device_id="10de:2204", model="RTX 3090", supports_x_vga=True)],
    control_socket_path="/var/lib/aleph/vm/jailer/firecracker/3/root/tmp/v.sock",
    runtime_version="2.0.0",
    ipv4_gateway="172.16.4.1",
    ipv6_gateway="fd00::1",
)


def test_create_vm_spec_round_trip_full():
    assert conv.create_vm_spec_from_pb(conv.create_vm_spec_to_pb(FULL_SPEC)) == FULL_SPEC


def test_create_vm_spec_round_trip_minimal():
    restored = conv.create_vm_spec_from_pb(conv.create_vm_spec_to_pb(MINIMAL_SPEC))
    # Path("") normalises to Path("."); both serialise to "" on the wire.
    assert restored.kernel_path == Path("")
    assert restored.initrd_path == Path("")
    assert restored.tee is None
    assert restored.numa_node is None
    assert restored == MINIMAL_SPEC


def test_vm_info_round_trip_full():
    assert conv.vm_info_from_pb(conv.vm_info_to_pb(FULL_VM_INFO)) == FULL_VM_INFO


def test_vm_info_round_trip_unset_numa():
    info = VmInfo(
        vm_id=VmId("beef" * 16),
        status=VmStatus.DEFINED,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.FIRECRACKER,
        numa_node=None,
        status_message="",
    )
    restored = conv.vm_info_from_pb(conv.vm_info_to_pb(info))
    assert restored.numa_node is None
    assert restored == info


def test_host_info_round_trip():
    info = HostInfo(
        cpu_count=64,
        memory_mib=512_000,
        cpu_architecture="x86_64",
        cpu_vendor="AuthenticAMD",
        cpu_model="AMD EPYC 9354P",
        kernel_version="6.9.0",
        hostname="crn-test",
        sev_supported=True,
        sev_es_supported=True,
        sev_snp_supported=False,
        tdx_supported=False,
        host_ipv4="203.0.113.7",
        numa_nodes=[NumaNodeInfo(index=0, cpu_count=32, memory_mib=256_000)],
        gpus=[
            GpuDevice(pci_host=PciAddress("0000:41:00.0"), device_id="10de:1234", model="H100", supports_x_vga=False)
        ],
    )
    assert conv.host_info_from_pb(conv.host_info_to_pb(info)) == info


def test_health_info_round_trip():
    info = HealthInfo(status=HealthStatus.OK, vm_count=3)
    assert conv.health_info_from_pb(conv.health_info_to_pb(info)) == info


def test_port_forward_round_trip():
    info = PortForwardInfo(
        vm_id=VmId("dead" * 16), host_port=HostPort(24000), vm_port=GuestPort(22), protocol=Protocol.TCP
    )
    assert conv.port_forward_info_from_pb(conv.port_forward_info_to_pb(info)) == info
    spec = PortForwardSpec(
        vm_id=VmId("dead" * 16), host_port=HostPort(0), vm_port=GuestPort(8080), protocol=Protocol.UDP
    )
    assert conv.port_forward_spec_from_pb(conv.port_forward_spec_to_pb(spec)) == spec


def test_log_chunk_round_trip():
    chunk = LogChunk(timestamp_ns=1_700_000_000_123_456_000, line="hello", source=LogSource.STDERR)
    assert conv.log_chunk_from_pb(conv.log_chunk_to_pb(chunk)) == chunk


def test_backup_round_trip():
    info = BackupInfo(
        vm_id=VmId("dead" * 16),
        backup_id=BackupId("backup-1"),
        status=BackupStatus.COMPLETE,
        size_bytes=42,
        created_at_unix_secs=1_700_000_000,
        error_message="",
    )
    assert conv.backup_info_from_pb(conv.backup_info_to_pb(info)) == info
    chunk = BackupChunk(data=b"\x00\x01", offset=1024)
    assert conv.backup_chunk_from_pb(conv.backup_chunk_to_pb(chunk)) == chunk


def test_migration_info_round_trip():
    info = MigrationInfo(
        vm_id=VmId("dead" * 16),
        migration_id=MigrationId("mig-1"),
        phase=MigrationPhase.EXPORTING,
        bytes_transferred=10,
        bytes_total=100,
        error_message="",
    )
    assert conv.migration_info_from_pb(conv.migration_info_to_pb(info)) == info


def test_measurement_round_trip():
    measurement = Measurement(vm_id=VmId("dead" * 16), measurement_bytes=b"\xaa\xbb", tee_backend=TeeBackend.SEV_SNP)
    assert conv.measurement_from_pb(conv.measurement_to_pb(measurement)) == measurement


def test_error_code_table_is_total():
    """Every ErrorCode value maps to a distinct proto value and back."""
    assert set(conv.ERROR_CODE_TO_PB) == set(ErrorCode)
    assert len(set(conv.ERROR_CODE_TO_PB.values())) == len(ErrorCode)
    for code, pb_value in conv.ERROR_CODE_TO_PB.items():
        assert conv.ERROR_CODE_FROM_PB[pb_value] is code


def test_enum_tables_are_total():
    assert set(conv.BACKEND_TO_PB) == set(Backend)
    assert set(conv.VM_STATUS_TO_PB) == set(VmStatus)
    assert set(conv.CONFIDENTIAL_MODE_TO_PB) == set(ConfidentialMode)
    assert set(conv.DISK_FORMAT_TO_PB) == set(DiskFormat)
    assert set(conv.DISK_ROLE_TO_PB) == set(DiskRole)
    assert set(conv.LOG_SOURCE_TO_PB) == set(LogSource)
    assert set(conv.BACKUP_STATUS_TO_PB) == set(BackupStatus)
    assert set(conv.MIGRATION_PHASE_TO_PB) == set(MigrationPhase)
