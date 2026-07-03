"""Guard `build_supervisor` and the gRPC socket default.

gRPC is the only supervisor mode: the factory always returns a
`GrpcSupervisor` dialing `settings.SUPERVISOR_GRPC_SOCKET`, and the settings
derive that socket from EXECUTION_ROOT when the environment leaves it unset
(so production, where EXECUTION_ROOT is /var/lib/aleph/vm, matches the
packaged supervisor.env value /var/lib/aleph/vm/supervisor.sock).
"""

from types import SimpleNamespace

from aleph.vm.agent.supervisor import build_supervisor
from aleph.vm.conf import Settings
from aleph.vm.supervisor_interface.client import GrpcSupervisor


def test_build_supervisor_always_returns_the_grpc_client():
    supervisor = build_supervisor(SimpleNamespace(SUPERVISOR_GRPC_SOCKET="/tmp/x.sock"))
    assert isinstance(supervisor, GrpcSupervisor)
    assert supervisor.socket_path == "/tmp/x.sock"


def test_supervisor_grpc_socket_defaults_to_execution_root(monkeypatch):
    monkeypatch.delenv("ALEPH_VM_SUPERVISOR_GRPC_SOCKET", raising=False)
    settings = Settings()
    assert settings.SUPERVISOR_GRPC_SOCKET == settings.EXECUTION_ROOT / "supervisor.sock"


def test_supervisor_grpc_socket_env_override(monkeypatch):
    monkeypatch.setenv("ALEPH_VM_SUPERVISOR_GRPC_SOCKET", "/run/custom/supervisor.sock")
    settings = Settings()
    assert str(settings.SUPERVISOR_GRPC_SOCKET) == "/run/custom/supervisor.sock"
