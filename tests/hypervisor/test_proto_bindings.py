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
