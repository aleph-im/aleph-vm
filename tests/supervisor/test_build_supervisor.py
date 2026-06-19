"""Guard the embedded-vs-gRPC supervisor selection in `build_supervisor`.

The factory's only job is the dev/test-vs-production split: with
`SUPERVISOR_GRPC_SOCKET` unset the agent runs the embedded pool-backed
`LocalSupervisor`; with it set the agent talks to the daemon over gRPC via
`GrpcSupervisor`. These tests pin both branches.
"""

from types import SimpleNamespace

from aleph.vm.agent.supervisor import build_supervisor
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.local import LocalSupervisor


def test_build_supervisor_embedded_when_socket_unset():
    supervisor = build_supervisor(SimpleNamespace(SUPERVISOR_GRPC_SOCKET=None), pool=object())
    assert isinstance(supervisor, LocalSupervisor)


def test_build_supervisor_grpc_when_socket_set():
    supervisor = build_supervisor(SimpleNamespace(SUPERVISOR_GRPC_SOCKET="/tmp/x.sock"), pool=None)
    assert isinstance(supervisor, GrpcSupervisor)
