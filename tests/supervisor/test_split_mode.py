"""Agent wiring: gRPC is the only supervisor mode.

The agent web app is built around a `Supervisor` handle; production always
wires `build_supervisor`'s `GrpcSupervisor` (the daemon owns the pool), and
no pool or engine leaks into the app's request-visible state. Tests may
inject `LocalSupervisor(pool)` to drive the views against the daemon's
engine in-process.
"""

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.agent.supervisor import build_supervisor, setup_webapp
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.client import GrpcSupervisor
from aleph.vm.supervisor_interface.types import VmId


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


@pytest.mark.asyncio
async def test_reap_hook_forget_failure_is_logged(caplog):
    """The reap hooks drop guest state with a fire-and-forget task; per the
    codebase convention (create_task_log_exceptions) a failing forget must be
    logged, not swallowed by a bare create_task."""
    app = setup_webapp(supervisor=MagicMock())
    app["program_client"] = MagicMock(forget=AsyncMock(side_effect=RuntimeError("forget exploded")))

    with caplog.at_level(logging.ERROR, logger="aleph.vm.utils"):
        app["expiry"].on_reaped(VmId("vm-under-test"))
        # Let the fire-and-forget task run and fail.
        for _ in range(5):
            await asyncio.sleep(0)

    # The convention helper logs through aleph.vm.utils immediately; a bare
    # create_task only surfaces via asyncio's "Task exception was never
    # retrieved" GC-time handler, which is not a deliberate log.
    assert any(
        record.name == "aleph.vm.utils" and "forget exploded" in (record.exc_text or "") for record in caplog.records
    )
