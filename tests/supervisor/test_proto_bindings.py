"""Smoke tests for the generated supervisor.proto Python bindings.

These verify that the proto compiles, the generated modules import, and
the service/messages/enums are present with the expected names and
fields. Behavioural tests live with the Supervisor implementations
(plans 0.C and 0.D).
"""

import pytest

from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2


def test_generated_modules_importable():
    from aleph.vm.supervisor_interface.wire._pb import (  # noqa: F401
        supervisor_pb2,
        supervisor_pb2_grpc,
    )


def test_service_descriptor_present():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2_grpc

    assert hasattr(supervisor_pb2_grpc, "SupervisorStub")
    assert hasattr(supervisor_pb2_grpc, "SupervisorServicer")
    assert hasattr(supervisor_pb2_grpc, "add_SupervisorServicer_to_server")


def test_health_rpc_defined():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

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
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

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
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"CreateVm", "GetVm", "GetVmSpec", "ListVms", "DeleteVm", "RebootVm"} <= methods
    # Storage is the agent's: there is no RPC left that asks the supervisor to
    # delete a VM's disks.
    assert "ReinstallVm" not in methods


def test_backend_enum_complete():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    # The VMM only: confidential computing is selected by TeeConfig presence,
    # not a backend variant (BACKEND_QEMU_SEV is reserved).
    values = {v.name for v in supervisor_pb2.Backend.DESCRIPTOR.values}
    assert values == {"BACKEND_UNSPECIFIED", "BACKEND_FIRECRACKER", "BACKEND_QEMU"}


def test_tee_backend_enum_complete():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    values = {v.name for v in supervisor_pb2.TeeBackend.DESCRIPTOR.values}
    assert values == {
        "TEE_BACKEND_UNSPECIFIED",
        "TEE_BACKEND_SEV",
        "TEE_BACKEND_SEV_SNP",
        "TEE_BACKEND_TDX",
        "TEE_BACKEND_NVIDIA_CC",
    }
    # Enum-typed on the wire, not stringly-typed.
    tee_field = supervisor_pb2.TeeConfig.DESCRIPTOR.fields_by_name["backend"]
    assert tee_field.enum_type is supervisor_pb2.TeeBackend.DESCRIPTOR
    meas_field = supervisor_pb2.Measurement.DESCRIPTOR.fields_by_name["tee_backend"]
    assert meas_field.enum_type is supervisor_pb2.TeeBackend.DESCRIPTOR


def test_health_status_enum_typed():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    values = {v.name for v in supervisor_pb2.HealthStatus.DESCRIPTOR.values}
    assert values == {"HEALTH_STATUS_UNSPECIFIED", "HEALTH_STATUS_OK", "HEALTH_STATUS_DEGRADED"}
    field = supervisor_pb2.HealthResponse.DESCRIPTOR.fields_by_name["status"]
    assert field.enum_type is supervisor_pb2.HealthStatus.DESCRIPTOR


def test_protocol_enum_typed():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    values = {v.name for v in supervisor_pb2.Protocol.DESCRIPTOR.values}
    assert values == {"PROTOCOL_UNSPECIFIED", "PROTOCOL_TCP", "PROTOCOL_UDP"}
    for message in (
        supervisor_pb2.AddPortForwardRequest,
        supervisor_pb2.PortForwardInfo,
        supervisor_pb2.RemovePortForwardRequest,
    ):
        field = message.DESCRIPTOR.fields_by_name["protocol"]
        assert field.enum_type is supervisor_pb2.Protocol.DESCRIPTOR


def test_create_vm_request_shape():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.VmSpec.DESCRIPTOR.fields}
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
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    disk_fields = {f.name for f in supervisor_pb2.DiskConfig.DESCRIPTOR.fields}
    assert {"path", "readonly", "format", "role"} <= disk_fields
    # Guest mount points are client vocabulary; the wire does not carry them.
    assert "mount" not in disk_fields
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
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

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
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"AddPortForward", "RemovePortForward", "ListPortForwards"} <= methods


def test_port_forward_info_shape():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.PortForwardInfo.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields
    fields = {f.name for f in supervisor_pb2.AddPortForwardRequest.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields


def test_log_rpcs_defined_with_streaming():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    methods = {m.name: m for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert "GetLogs" in methods
    assert "StreamLogs" in methods
    assert methods["StreamLogs"].server_streaming is True
    assert methods["GetLogs"].server_streaming is False

    fields = {f.name for f in supervisor_pb2.LogChunk.DESCRIPTOR.fields}
    assert {"timestamp_ns", "line", "source"} <= fields


def test_guest_quiescence_rpcs_defined():
    """The supervisor's only part in a backup: freeze and thaw the guest.
    The archive surface itself (StartBackup and friends) is the agent's."""
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    methods = {m.name: m for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"FreezeGuest", "ThawGuest"} <= set(methods)
    assert not any(name.endswith("Backup") or name.startswith("Backup") for name in methods)
    assert "RestoreFromImage" not in methods
    assert {f.name for f in supervisor_pb2.FreezeGuestRequest.DESCRIPTOR.fields} == {"vm_id"}
    assert {f.name for f in supervisor_pb2.FreezeGuestResponse.DESCRIPTOR.fields} == {"frozen"}
    assert {f.name for f in supervisor_pb2.ThawGuestRequest.DESCRIPTOR.fields} == {"vm_id"}


def test_confidential_rpcs_defined():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    methods = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert {"InitializeConfidential", "GetMeasurement", "InjectSecret"} <= methods


def test_confidential_message_shapes():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    init = {f.name for f in supervisor_pb2.InitializeConfidentialRequest.DESCRIPTOR.fields}
    assert {"vm_id", "session_bytes", "godh_bytes"} <= init

    meas = {f.name for f in supervisor_pb2.Measurement.DESCRIPTOR.fields}
    assert {"vm_id", "measurement_bytes", "tee_backend"} <= meas

    inj = {f.name for f in supervisor_pb2.InjectSecretRequest.DESCRIPTOR.fields}
    assert {"vm_id", "secret_header_bytes", "secret_bytes"} <= inj


def test_error_code_enum_covers_design_doc_cases():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

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
        "ERROR_CODE_HOST_NOT_FOUND",
        "ERROR_CODE_INTERNAL",
    }
    missing = required - values
    assert not missing, f"missing error codes: {missing}"


def test_error_detail_message_shape():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.ErrorDetail.DESCRIPTOR.fields}
    assert {"code", "message", "vm_id"} <= fields


def test_delete_vm_request_has_no_wipe_field():
    """`wipe` is gone: DeleteVm never deletes storage, so no client may ask
    it to."""
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    fields = {f.name for f in supervisor_pb2.DeleteVmRequest.DESCRIPTOR.fields}
    assert "wipe" not in fields
    with pytest.raises(ValueError):
        supervisor_pb2.DeleteVmRequest(vm_id="x", wipe=True)


def test_delete_vm_request_has_keep_port_mappings_field():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    req = supervisor_pb2.DeleteVmRequest(vm_id="x", keep_port_mappings=True)
    assert req.keep_port_mappings is True
    assert supervisor_pb2.DeleteVmRequest(vm_id="x").keep_port_mappings is False


def test_log_source_has_stderr():
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    assert supervisor_pb2.LogChunk.LOG_SOURCE_STDERR == 4

    from aleph.vm.supervisor_interface.types import LogSource

    assert LogSource.STDERR.value == "stderr"


def test_full_service_surface_pinned():
    """Whole-surface assertion. Update this list intentionally when the
    contract changes (and bump the proto package version when breaking)."""
    from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2

    expected = {
        # Host
        "Health",
        "GetHostInfo",
        # Lifecycle
        "CreateVm",
        "GetVm",
        "GetVmSpec",
        "ListVms",
        "DeleteVm",
        "StopVm",
        "StartVm",
        "RebootVm",
        "RunProgramCode",
        # Port forwarding
        "AddPortForward",
        "RemovePortForward",
        "ListPortForwards",
        # Events
        "WatchEvents",
        # Logs
        "GetLogs",
        "StreamLogs",
        # Guest quiescence
        "FreezeGuest",
        "ThawGuest",
        # Confidential
        "InitializeConfidential",
        "GetMeasurement",
        "InjectSecret",
        # Network
        "RecreateNetwork",
    }
    actual = {m.name for m in supervisor_pb2.DESCRIPTOR.services_by_name["Supervisor"].methods}
    assert actual == expected, f"unexpected drift: missing {expected - actual}, " f"extra {actual - expected}"


def test_vm_info_network_and_lifecycle_fields_default():
    info = supervisor_pb2.VmInfo()
    assert info.ipv4.network_cidr == ""
    assert info.ipv6.network_cidr == ""
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
    from aleph.vm.supervisor_interface.types import (
        Backend,
        IpAssignment,
        VmId,
        VmInfo,
        VmStatus,
    )

    info = VmInfo(
        vm_id=VmId("x"),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )
    assert info.ipv4.network_cidr == ""
    assert info.defined_at_ns == 0
    assert info.stopped_at_ns == 0
    assert not hasattr(info, "is_instance")
    assert info.guest_channel_path == ""
    assert info.guest_ready_payload == b""


def test_host_info_dataclass_host_ipv4_defaults_empty():
    from aleph.vm.supervisor_interface.types import HostInfo

    assert HostInfo().host_ipv4 == ""
