"""Smoke tests for the generated hypervisor.proto Python bindings.

These verify that the proto compiles, the generated modules import, and
the service/messages/enums are present with the expected names and
fields. Behavioural tests live with the Hypervisor implementations
(plans 0.C and 0.D).
"""


def test_generated_modules_importable():
    from aleph.vm.hypervisor._pb import hypervisor_pb2, hypervisor_pb2_grpc  # noqa: F401


def test_service_descriptor_present():
    from aleph.vm.hypervisor._pb import hypervisor_pb2_grpc
    assert hasattr(hypervisor_pb2_grpc, "HypervisorStub")
    assert hasattr(hypervisor_pb2_grpc, "HypervisorServicer")
    assert hasattr(hypervisor_pb2_grpc, "add_HypervisorServicer_to_server")


def test_health_rpc_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    # Request and response types exist
    assert hasattr(hypervisor_pb2, "HealthRequest")
    assert hasattr(hypervisor_pb2, "HealthResponse")
    # Response fields
    fields = {f.name for f in hypervisor_pb2.HealthResponse.DESCRIPTOR.fields}
    assert {"status", "vm_count"} <= fields
    # Service has the RPC
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert "Health" in methods


def test_get_host_info_rpc_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    assert hasattr(hypervisor_pb2, "GetHostInfoRequest")
    assert hasattr(hypervisor_pb2, "HostInfo")
    fields = {f.name for f in hypervisor_pb2.HostInfo.DESCRIPTOR.fields}
    assert {"cpu_count", "memory_mib", "numa_nodes", "gpus",
            "sev_snp_supported", "tdx_supported",
            "hostname", "kernel_version"} <= fields
    # Service has the RPC
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert "GetHostInfo" in methods


def test_lifecycle_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"CreateVm", "GetVm", "ListVms", "DeleteVm",
            "RebootVm", "ReinstallVm"} <= methods


def test_backend_enum_complete():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    values = {v.name for v in hypervisor_pb2.Backend.DESCRIPTOR.values}
    assert values == {"BACKEND_UNSPECIFIED", "BACKEND_FIRECRACKER",
                      "BACKEND_QEMU", "BACKEND_QEMU_SEV"}


def test_create_vm_request_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.CreateVmRequest.DESCRIPTOR.fields}
    expected = {"vm_id", "backend", "kernel_path", "initrd_path", "disks",
                "vcpus", "memory_mib", "tee", "network", "gpus",
                "numa_node", "persistent"}
    missing = expected - fields
    assert not missing, f"missing fields: {missing}"


def test_disk_config_has_role_and_format_enums():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    disk_fields = {f.name for f in hypervisor_pb2.DiskConfig.DESCRIPTOR.fields}
    assert {"path", "readonly", "format", "role"} <= disk_fields
    formats = {v.name for v in hypervisor_pb2.DiskConfig.Format.DESCRIPTOR.values}
    assert {"FORMAT_UNSPECIFIED", "FORMAT_RAW", "FORMAT_QCOW2",
            "FORMAT_SQUASHFS"} <= formats
    roles = {v.name for v in hypervisor_pb2.DiskConfig.DiskRole.DESCRIPTOR.values}
    assert {"DISK_ROLE_UNSPECIFIED", "DISK_ROLE_ROOTFS", "DISK_ROLE_CODE",
            "DISK_ROLE_RUNTIME", "DISK_ROLE_DATA", "DISK_ROLE_EXTRA"} <= roles


def test_vm_info_has_status_enum_and_core_fields():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.VmInfo.DESCRIPTOR.fields}
    assert {"vm_id", "status", "ipv4", "ipv6", "uptime_secs",
            "backend", "numa_node"} <= fields
    statuses = {v.name for v in hypervisor_pb2.VmStatus.DESCRIPTOR.values}
    assert {"VM_STATUS_UNSPECIFIED", "VM_STATUS_DEFINED", "VM_STATUS_BOOTING",
            "VM_STATUS_RUNNING", "VM_STATUS_STOPPING", "VM_STATUS_STOPPED",
            "VM_STATUS_FAILED"} <= statuses


def test_port_forwarding_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"AddPortForward", "RemovePortForward",
            "ListPortForwards"} <= methods


def test_port_forward_info_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.PortForwardInfo.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields
    fields = {f.name for f in hypervisor_pb2.AddPortForwardRequest.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields


def test_log_rpcs_defined_with_streaming():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name: m for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert "GetLogs" in methods
    assert "StreamLogs" in methods
    assert methods["StreamLogs"].server_streaming is True
    assert methods["GetLogs"].server_streaming is False

    fields = {f.name for f in hypervisor_pb2.LogChunk.DESCRIPTOR.fields}
    assert {"timestamp_ns", "line", "source"} <= fields


def test_backup_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name: m for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"StartBackup", "GetBackupStatus", "ListBackups",
            "DownloadBackup", "DeleteBackup", "RestoreBackup"} <= set(methods)
    assert methods["DownloadBackup"].server_streaming is True


def test_backup_info_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.BackupInfo.DESCRIPTOR.fields}
    assert {"vm_id", "backup_id", "status", "size_bytes",
            "created_at_unix_secs"} <= fields
    statuses = {v.name for v in hypervisor_pb2.BackupStatus.DESCRIPTOR.values}
    assert {"BACKUP_STATUS_UNSPECIFIED", "BACKUP_STATUS_PENDING",
            "BACKUP_STATUS_RUNNING", "BACKUP_STATUS_COMPLETE",
            "BACKUP_STATUS_FAILED"} <= statuses


def test_migration_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"ExportVm", "ImportVm", "GetMigrationStatus"} <= methods


def test_migration_info_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.MigrationInfo.DESCRIPTOR.fields}
    assert {"vm_id", "migration_id", "phase", "bytes_transferred",
            "bytes_total"} <= fields
    phases = {v.name for v in hypervisor_pb2.MigrationPhase.DESCRIPTOR.values}
    assert {"MIGRATION_PHASE_UNSPECIFIED", "MIGRATION_PHASE_PREPARING",
            "MIGRATION_PHASE_EXPORTING", "MIGRATION_PHASE_IMPORTING",
            "MIGRATION_PHASE_COMPLETE",
            "MIGRATION_PHASE_FAILED"} <= phases


def test_confidential_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"InitializeConfidential", "GetMeasurement",
            "InjectSecret"} <= methods


def test_confidential_message_shapes():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    init = {f.name for f in
            hypervisor_pb2.InitializeConfidentialRequest.DESCRIPTOR.fields}
    assert {"vm_id", "session_bytes", "godh_bytes"} <= init

    meas = {f.name for f in hypervisor_pb2.Measurement.DESCRIPTOR.fields}
    assert {"vm_id", "measurement_bytes", "tee_backend"} <= meas

    inj = {f.name for f in hypervisor_pb2.InjectSecretRequest.DESCRIPTOR.fields}
    assert {"vm_id", "secret_header_bytes", "secret_bytes"} <= inj
