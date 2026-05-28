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
