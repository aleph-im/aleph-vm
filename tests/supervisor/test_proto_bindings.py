"""Smoke tests for the generated supervisor.proto Python bindings.

These verify that the proto compiles, the generated modules import, and
the service/messages/enums are present with the expected names and
fields. Behavioural tests live with the Supervisor implementations
(plans 0.C and 0.D).
"""

from aleph.vm.supervisor._pb import supervisor_pb2


def test_generated_modules_importable():
    from aleph.vm.supervisor._pb import (  # noqa: F401
        supervisor_pb2,
        supervisor_pb2_grpc,
    )


def test_service_descriptor_present():
    from aleph.vm.supervisor._pb import supervisor_pb2_grpc

    assert hasattr(supervisor_pb2_grpc, "SupervisorStub")
    assert hasattr(supervisor_pb2_grpc, "SupervisorServicer")
    assert hasattr(supervisor_pb2_grpc, "add_SupervisorServicer_to_server")


def test_health_rpc_defined():
    from aleph.vm.supervisor._pb import supervisor_pb2

    # Request and response types exist
    assert hasattr(supervisor_pb2, "HealthRequest")
    assert hasattr(supervisor_pb2, "HealthResponse")
    # Response fields
    fields = {f.name for f in supervisor_pb2.HealthResponse.DESCRIPTOR.fields}
    assert {"status", "vm_count"} <= fields
    # Service has the RPC
    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert "Health" in methods


def test_get_host_info_rpc_defined():
    from aleph.vm.supervisor._pb import supervisor_pb2

    assert hasattr(supervisor_pb2, "GetHostInfoRequest")
    assert hasattr(supervisor_pb2, "HostInfo")
    fields = {f.name for f in supervisor_pb2.HostInfo.DESCRIPTOR.fields}
    assert {
        "cpu_count",
        "memory_mib",
        "numa_nodes",
        "gpus",
        "sev_snp_supported",
        "tdx_supported",
        "hostname",
        "kernel_version",
        # extended for /about/capability coverage
        "cpu_architecture",
        "cpu_vendor",
        "cpu_model",
        "cpu_frequency_mhz",
        "memory_type",
        "memory_clock_mhz",
        "sev_supported",
        "sev_es_supported",
    } <= fields
    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert "GetHostInfo" in methods


def test_lifecycle_rpcs_defined():
    from aleph.vm.supervisor._pb import supervisor_pb2

    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"CreateVm", "GetVm", "ListVms", "DeleteVm", "RebootVm", "ReinstallVm"} <= methods


def test_backend_enum_complete():
    from aleph.vm.supervisor._pb import supervisor_pb2

    values = {v.name for v in supervisor_pb2.Backend.DESCRIPTOR.values}
    assert values == {"BACKEND_UNSPECIFIED", "BACKEND_FIRECRACKER", "BACKEND_QEMU", "BACKEND_QEMU_SEV"}


def test_create_vm_request_shape():
    from aleph.vm.supervisor._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.CreateVmRequest.DESCRIPTOR.fields}
    expected = {
        "vm_id",
        "backend",
        "kernel_path",
        "initrd_path",
        "disks",
        "vcpus",
        "memory_mib",
        "tee",
        "network",
        "gpus",
        "numa_node",
        "persistent",
    }
    missing = expected - fields
    assert not missing, f"missing fields: {missing}"


def test_disk_config_has_role_and_format_enums():
    from aleph.vm.supervisor._pb import supervisor_pb2

    disk_fields = {f.name for f in supervisor_pb2.DiskConfig.DESCRIPTOR.fields}
    assert {"path", "readonly", "format", "role"} <= disk_fields
    formats = {v.name for v in supervisor_pb2.DiskConfig.Format.DESCRIPTOR.values}
    assert {"FORMAT_UNSPECIFIED", "FORMAT_RAW", "FORMAT_QCOW2", "FORMAT_SQUASHFS"} <= formats
    roles = {v.name for v in supervisor_pb2.DiskConfig.DiskRole.DESCRIPTOR.values}
    # Mechanism-only: root device or not. Workload roles (code/runtime/data)
    # are client vocabulary, mapped onto devices via disk order.
    assert roles == {
        "DISK_ROLE_UNSPECIFIED",
        "DISK_ROLE_ROOTFS",
        "DISK_ROLE_EXTRA",
    }


def test_vm_info_has_status_enum_and_core_fields():
    from aleph.vm.supervisor._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.VmInfo.DESCRIPTOR.fields}
    assert {"vm_id", "status", "ipv4", "ipv6", "uptime_secs", "backend", "numa_node"} <= fields
    statuses = {v.name for v in supervisor_pb2.VmStatus.DESCRIPTOR.values}
    assert {
        "VM_STATUS_UNSPECIFIED",
        "VM_STATUS_DEFINED",
        "VM_STATUS_BOOTING",
        "VM_STATUS_RUNNING",
        "VM_STATUS_STOPPING",
        "VM_STATUS_STOPPED",
        "VM_STATUS_FAILED",
    } <= statuses


def test_port_forwarding_rpcs_defined():
    from aleph.vm.supervisor._pb import supervisor_pb2

    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"AddPortForward", "RemovePortForward", "ListPortForwards"} <= methods


def test_port_forward_info_shape():
    from aleph.vm.supervisor._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.PortForwardInfo.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields
    fields = {f.name for f in supervisor_pb2.AddPortForwardRequest.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields


def test_log_rpcs_defined_with_streaming():
    from aleph.vm.supervisor._pb import supervisor_pb2

    methods = {m.name: m for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert "GetLogs" in methods
    assert "StreamLogs" in methods
    assert methods["StreamLogs"].server_streaming is True
    assert methods["GetLogs"].server_streaming is False

    fields = {f.name for f in supervisor_pb2.LogChunk.DESCRIPTOR.fields}
    assert {"timestamp_ns", "line", "source"} <= fields


def test_backup_rpcs_defined():
    from aleph.vm.supervisor._pb import supervisor_pb2

    methods = {m.name: m for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"StartBackup", "GetBackupStatus", "ListBackups", "DownloadBackup", "DeleteBackup", "RestoreBackup"} <= set(
        methods
    )
    assert methods["DownloadBackup"].server_streaming is True


def test_backup_info_shape():
    from aleph.vm.supervisor._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.BackupInfo.DESCRIPTOR.fields}
    assert {"vm_id", "backup_id", "status", "size_bytes", "created_at_unix_secs"} <= fields
    statuses = {v.name for v in supervisor_pb2.BackupStatus.DESCRIPTOR.values}
    assert {
        "BACKUP_STATUS_UNSPECIFIED",
        "BACKUP_STATUS_PENDING",
        "BACKUP_STATUS_RUNNING",
        "BACKUP_STATUS_COMPLETE",
        "BACKUP_STATUS_FAILED",
    } <= statuses


def test_migration_rpcs_defined():
    from aleph.vm.supervisor._pb import supervisor_pb2

    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"ExportVm", "ImportVm", "GetMigrationStatus"} <= methods


def test_migration_info_shape():
    from aleph.vm.supervisor._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.MigrationInfo.DESCRIPTOR.fields}
    assert {"vm_id", "migration_id", "phase", "bytes_transferred", "bytes_total"} <= fields
    phases = {v.name for v in supervisor_pb2.MigrationPhase.DESCRIPTOR.values}
    assert {
        "MIGRATION_PHASE_UNSPECIFIED",
        "MIGRATION_PHASE_PREPARING",
        "MIGRATION_PHASE_EXPORTING",
        "MIGRATION_PHASE_IMPORTING",
        "MIGRATION_PHASE_COMPLETE",
        "MIGRATION_PHASE_FAILED",
    } <= phases


def test_confidential_rpcs_defined():
    from aleph.vm.supervisor._pb import supervisor_pb2

    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"InitializeConfidential", "GetMeasurement", "InjectSecret"} <= methods


def test_confidential_message_shapes():
    from aleph.vm.supervisor._pb import supervisor_pb2

    init = {f.name for f in supervisor_pb2.InitializeConfidentialRequest.DESCRIPTOR.fields}
    assert {"vm_id", "session_bytes", "godh_bytes"} <= init

    meas = {f.name for f in supervisor_pb2.Measurement.DESCRIPTOR.fields}
    assert {"vm_id", "measurement_bytes", "tee_backend"} <= meas

    inj = {f.name for f in supervisor_pb2.InjectSecretRequest.DESCRIPTOR.fields}
    assert {"vm_id", "secret_header_bytes", "secret_bytes"} <= inj


def test_error_code_enum_covers_design_doc_cases():
    from aleph.vm.supervisor._pb import supervisor_pb2

    values = {v.name for v in supervisor_pb2.ErrorCode.DESCRIPTOR.values}
    required = {
        "ERROR_CODE_UNSPECIFIED",
        "ERROR_CODE_VM_NOT_FOUND",
        "ERROR_CODE_VM_ALREADY_EXISTS",
        "ERROR_CODE_INSUFFICIENT_RESOURCES",
        "ERROR_CODE_RESOURCE_DOWNLOAD_FAILED",
        "ERROR_CODE_VM_SETUP_FAILED",
        "ERROR_CODE_MICROVM_INIT_FAILED",
        "ERROR_CODE_FILE_TOO_LARGE",
        "ERROR_CODE_INVALID_BACKEND",
        "ERROR_CODE_TEE_UNAVAILABLE",
        "ERROR_CODE_PORT_UNAVAILABLE",
        "ERROR_CODE_BACKUP_NOT_FOUND",
        "ERROR_CODE_MIGRATION_IN_PROGRESS",
        "ERROR_CODE_HOST_NOT_FOUND",
        "ERROR_CODE_INTERNAL",
    }
    missing = required - values
    assert not missing, f"missing error codes: {missing}"


def test_error_detail_message_shape():
    from aleph.vm.supervisor._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.ErrorDetail.DESCRIPTOR.fields}
    assert {"code", "message", "vm_id"} <= fields


def test_delete_vm_request_has_wipe_field():
    from aleph.vm.supervisor._pb import supervisor_pb2

    req = supervisor_pb2.DeleteVmRequest(vm_id="x", wipe=True)
    assert req.wipe is True
    assert supervisor_pb2.DeleteVmRequest(vm_id="x").wipe is False


def test_reinstall_vm_request_has_wipe_volumes_field():
    from aleph.vm.supervisor._pb import supervisor_pb2

    req = supervisor_pb2.ReinstallVmRequest(vm_id="x", wipe_volumes=True)
    assert req.wipe_volumes is True
    assert supervisor_pb2.ReinstallVmRequest(vm_id="x").wipe_volumes is False


def test_log_source_has_stderr():
    from aleph.vm.supervisor._pb import supervisor_pb2

    assert supervisor_pb2.LogChunk.LOG_SOURCE_STDERR == 4

    from aleph.vm.supervisor.types import LogSource

    assert LogSource.STDERR.value == "stderr"


def test_full_service_surface_pinned():
    """Whole-surface assertion. Update this list intentionally when the
    contract changes (and bump the proto package version when breaking)."""
    from aleph.vm.supervisor._pb import supervisor_pb2

    expected = {
        # Host
        "Health",
        "GetHostInfo",
        # Lifecycle
        "CreateVm",
        "GetVm",
        "ListVms",
        "DeleteVm",
        "RebootVm",
        "ReinstallVm",
        # Port forwarding
        "AddPortForward",
        "RemovePortForward",
        "ListPortForwards",
        # Logs
        "GetLogs",
        "StreamLogs",
        # Backups
        "StartBackup",
        "GetBackupStatus",
        "ListBackups",
        "DownloadBackup",
        "DeleteBackup",
        "RestoreBackup",
        # Migration
        "ExportVm",
        "ImportVm",
        "GetMigrationStatus",
        # Confidential
        "InitializeConfidential",
        "GetMeasurement",
        "InjectSecret",
    }
    actual = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert actual == expected, f"unexpected drift: missing {expected - actual}, " f"extra {actual - expected}"


def test_vm_info_network_and_lifecycle_fields_default():
    info = supervisor_pb2.VmInfo()
    assert info.ipv4_network == ""
    assert info.ipv6_network == ""
    for field in (
        "defined_at_ns",
        "preparing_at_ns",
        "prepared_at_ns",
        "starting_at_ns",
        "started_at_ns",
        "stopping_at_ns",
        "stopped_at_ns",
    ):
        assert getattr(info, field) == 0
    # The instance/program distinction is client vocabulary; the wire does
    # not carry it (field 18 is reserved).
    assert not hasattr(info, "is_instance")


def test_host_info_host_ipv4_defaults_empty():
    host = supervisor_pb2.HostInfo()
    assert host.host_ipv4 == ""


def test_vm_info_dataclass_new_fields_default():
    from aleph.vm.supervisor.types import Backend, VmId, VmInfo, VmStatus

    info = VmInfo(
        vm_id=VmId("x"),
        status=VmStatus.RUNNING,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )
    assert info.ipv4_network == ""
    assert info.defined_at_ns == 0
    assert info.stopped_at_ns == 0
    assert not hasattr(info, "is_instance")
    assert info.guest_channel_path == ""
    assert info.guest_ready_payload == b""


def test_host_info_dataclass_host_ipv4_defaults_empty():
    from aleph.vm.supervisor.types import HostInfo

    assert HostInfo().host_ipv4 == ""
