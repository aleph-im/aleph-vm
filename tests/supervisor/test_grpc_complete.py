import inspect

from aleph.vm.supervisor.grpc_server import SupervisorService
from aleph.vm.supervisor_interface import client as grpc_client
from aleph.vm.supervisor_interface.wire._pb import supervisor_pb2_grpc as g


def test_no_phase2_stubs_remain():
    source = inspect.getsource(grpc_client)
    assert "wired in Phase 2" not in source
    assert "NotImplementedError" not in source


def test_every_rpc_has_a_handler():
    # Names declared on the generated servicer base, implemented on SupervisorService.
    rpc_names = [n for n in dir(g.SupervisorServicer) if n[:1].isupper()]
    for name in rpc_names:
        assert hasattr(SupervisorService, name), f"missing handler: {name}"
