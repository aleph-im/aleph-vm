"""Agent wiring: gRPC is the only supervisor mode.

The agent web app is built around a `Supervisor` handle; production always
wires `build_supervisor`'s `GrpcSupervisor` (the daemon owns the pool), and
no pool or engine leaks into the app's request-visible state. Tests may
inject `LocalSupervisor(pool)` to drive the views against the daemon's
engine in-process.
"""

from pathlib import Path
from types import SimpleNamespace

from aleph.vm.agent.supervisor import build_supervisor, setup_webapp
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.local import LocalSupervisor


def test_production_wiring_is_grpc_only():
    supervisor = build_supervisor(SimpleNamespace(SUPERVISOR_GRPC_SOCKET=Path("/run/aleph/supervisor.sock")))
    app = setup_webapp(supervisor=supervisor)
    assert isinstance(app["supervisor"], GrpcSupervisor)
    assert app["supervisor"].socket_path == "/run/aleph/supervisor.sock"
    # No pool in the agent app: neither the old public key nor the retired
    # private engine key exist.
    assert "vm_pool" not in app
    assert "_engine_pool" not in app


def test_webapp_accepts_the_local_engine_as_a_test_harness():
    # LocalSupervisor stays as the DAEMON's engine; tests may drive the agent
    # views against it in-process. The app factory takes any Supervisor.
    pool = SimpleNamespace(executions={})
    app = setup_webapp(supervisor=LocalSupervisor(pool))
    assert isinstance(app["supervisor"], LocalSupervisor)
    assert app["supervisor"].pool is pool
