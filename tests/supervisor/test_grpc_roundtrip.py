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

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.grpc_server import serve_unix
from aleph.vm.supervisor.types import (
    Backend,
    DirectoryPath,
    GpuSpec,
    IpAssignment,
    PciAddress,
    ReservationRequest,
    VmId,
    VmInfo,
    VmStatus,
)

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


@pytest.fixture
def make_vm_info():
    """Minimal VmInfo factory for round-trip assertions."""

    def _make(vm_id: str) -> VmInfo:
        return VmInfo(
            vm_id=VmId(vm_id),
            status=VmStatus.RUNNING,
            ipv4=IpAssignment(),
            ipv6=IpAssignment(),
            uptime_secs=0,
            backend=Backend.QEMU,
            numa_node=None,
            status_message="",
        )

    return _make


@pytest.mark.asyncio
async def test_recreate_network_roundtrip(grpc_pair):
    client, fake = grpc_pair
    fake.recreate_network.return_value = {"success": True, "recreated_count": 2, "failed_vms": []}
    result = await client.recreate_network()
    assert result == {"success": True, "recreated_count": 2, "failed_vms": []}
    fake.recreate_network.assert_awaited_once()


@pytest.mark.asyncio
async def test_run_program_code_roundtrip(grpc_pair):
    client, fake = grpc_pair
    fake.run_program_code.return_value = b"RESULT"
    # msgpack converts tuples to lists on the wire, so build the scope with lists
    # and assert the server receives those same lists; callers must not rely on
    # tuple identity surviving the round-trip.
    scope = {
        "type": "http",
        "path": "/",
        "query_string": "a=1",
        "headers": [["host", "example"]],
    }
    out = await client.run_program_code(VmId("vm1"), scope, timeout=12.5)
    assert out == b"RESULT"
    args, kwargs = fake.run_program_code.call_args
    assert args[1] == {
        "type": "http",
        "path": "/",
        "query_string": "a=1",
        "headers": [["host", "example"]],
    }
    assert kwargs["timeout"] == 12.5


@pytest.mark.asyncio
async def test_restore_from_image_roundtrip(grpc_pair, make_vm_info):
    client, fake = grpc_pair
    fake.restore_from_image.return_value = make_vm_info("vm1")
    out = await client.restore_from_image(VmId("vm1"), DirectoryPath(Path("/img.qcow2")), max_virtual_size_bytes=42)
    assert out.vm_id == "vm1"
    fake.restore_from_image.assert_awaited_once()
    args, kwargs = fake.restore_from_image.call_args
    assert str(args[1]) == "/img.qcow2"
    assert kwargs.get("max_virtual_size_bytes", args[2] if len(args) > 2 else None) == 42


@pytest.mark.asyncio
async def test_reserve_resources_roundtrip(grpc_pair):
    client, fake = grpc_pair
    expiry = datetime(2030, 1, 1, tzinfo=timezone.utc)
    fake.reserve_resources.return_value = expiry
    req = ReservationRequest(
        user_address="0xUSER",
        vcpus=2,
        memory_mib=2048,
        disk_mib=10,
        is_instance=True,
        gpus=[GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id="10de:2504", model="X")],
    )
    out = await client.reserve_resources(req)
    assert out == expiry
    (sent,), _ = fake.reserve_resources.call_args
    assert sent == req
