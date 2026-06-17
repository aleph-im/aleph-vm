"""Mock-backed gRPC-over-UDS round-trip tests for newly-wired RPCs.

This harness complements (rather than duplicates) the real-engine harness in
``test_supervisor_grpc.py``, which wraps a real ``LocalSupervisor`` via
``_ServerHarness`` to verify wire behavior and contract conformance.

Here the gRPC server is fed a ``_Fake`` whose every method is a
per-test-configurable ``AsyncMock``. That lets a test drive an RPC end to end
(client -> UDS -> server -> backend) while controlling the backend's exact
return value and asserting the precise call args it received, all without
standing up a real engine or VM pool. It is the cheapest way to confirm a
freshly-wired RPC is plumbed correctly through the client and server.

Future authors (A6/A7/A8): add a test function here and configure the relevant
mock with ``fake.<method>.return_value = ...`` before calling the client, then
assert on ``fake.<method>`` (e.g. ``assert_awaited_once_with(...)``).
"""

from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.grpc_server import serve_unix

_ASYNC_METHODS = (
    "health",
    "get_host_info",
    "create_vm",
    "get_vm",
    "get_vm_spec",
    "list_vms",
    "delete_vm",
    "stop_vm",
    "start_vm",
    "reboot_vm",
    "reinstall_vm",
    "run_program_code",
    "add_port_forward",
    "remove_port_forward",
    "list_port_forwards",
    "get_logs",
    "start_backup",
    "get_backup_status",
    "list_backups",
    "delete_backup",
    "restore_backup",
    "restore_from_image",
    "initialize_confidential",
    "get_measurement",
    "inject_secret",
    "recreate_network",
    "reserve_resources",
)


class _Fake(Supervisor):
    """A Supervisor whose every method is an AsyncMock, configured per test."""

    def __init__(self):
        for name in _ASYNC_METHODS:
            setattr(self, name, AsyncMock())

    def watch_events(self): ...
    def stream_logs(self, *a, **k): ...
    def download_backup(self, *a, **k): ...


# ABCMeta recomputes __abstractmethods__ from the class body, so clear it after
# the class is built; instances then get their AsyncMocks in __init__.
_Fake.__abstractmethods__ = frozenset()


@pytest_asyncio.fixture
async def grpc_pair(tmp_path):
    fake = _Fake()
    socket = tmp_path / "supervisor.sock"
    server = await serve_unix(fake, socket)
    client = GrpcSupervisor(socket)
    try:
        yield client, fake
    finally:
        await client.close()
        await server.stop(grace=0)


@pytest.mark.asyncio
async def test_recreate_network_roundtrip(grpc_pair):
    client, fake = grpc_pair
    fake.recreate_network.return_value = {"success": True, "recreated_count": 2, "failed_vms": []}
    result = await client.recreate_network()
    assert result == {"success": True, "recreated_count": 2, "failed_vms": []}
    fake.recreate_network.assert_awaited_once()
