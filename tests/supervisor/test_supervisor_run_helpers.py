"""Unit tests for the run.py create-path helpers (no pool, no I/O)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator import run as run_module
from aleph.vm.supervisor.types import Protocol, VmId, VmStatus

_HASH = ItemHash("deadbeef" * 8)
_VM_ID = VmId(str(_HASH))


@pytest.mark.asyncio
async def test_resolve_port_forwards_always_forces_ssh(monkeypatch):
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    content = SimpleNamespace(address="0xabc")

    forwards = await run_module.resolve_port_forwards(_VM_ID, content)

    assert (22, Protocol.TCP) in {(f.vm_port, f.protocol) for f in forwards}
    assert all(f.host_port == 0 and f.vm_id == _VM_ID for f in forwards)


@pytest.mark.asyncio
async def test_resolve_port_forwards_reads_settings(monkeypatch):
    payload = {str(_HASH): {"ports": {"80": {"tcp": True, "udp": False}, "53": {"tcp": False, "udp": True}}}}
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value=payload))
    content = SimpleNamespace(address="0xabc")

    pairs = {(f.vm_port, f.protocol) for f in await run_module.resolve_port_forwards(_VM_ID, content)}

    assert (80, Protocol.TCP) in pairs
    assert (53, Protocol.UDP) in pairs
    assert (80, Protocol.UDP) not in pairs
    assert (22, Protocol.TCP) in pairs  # SSH still forced


@pytest.mark.asyncio
async def test_resolve_port_forwards_tolerates_settings_error(monkeypatch):
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(side_effect=RuntimeError("boom")))
    content = SimpleNamespace(address="0xabc")

    forwards = await run_module.resolve_port_forwards(_VM_ID, content)

    assert [(f.vm_port, f.protocol) for f in forwards] == [(22, Protocol.TCP)]


@pytest.mark.asyncio
async def test_wait_until_running_returns_on_running(monkeypatch):
    booting = SimpleNamespace(status=VmStatus.BOOTING)
    running = SimpleNamespace(status=VmStatus.RUNNING)
    supervisor = SimpleNamespace(get_vm=AsyncMock(side_effect=[booting, running]))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    info = await run_module._wait_until_running(supervisor, _VM_ID, timeout=10, interval=0)

    assert info.status is VmStatus.RUNNING
    assert supervisor.get_vm.await_count == 2


@pytest.mark.asyncio
async def test_wait_until_running_raises_on_terminal_status(monkeypatch):
    supervisor = SimpleNamespace(get_vm=AsyncMock(return_value=SimpleNamespace(status=VmStatus.FAILED)))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    with pytest.raises(RuntimeError):
        await run_module._wait_until_running(supervisor, _VM_ID, timeout=10, interval=0)


@pytest.mark.asyncio
async def test_wait_until_running_times_out(monkeypatch):
    supervisor = SimpleNamespace(get_vm=AsyncMock(return_value=SimpleNamespace(status=VmStatus.BOOTING)))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    with pytest.raises(asyncio.TimeoutError):
        await run_module._wait_until_running(supervisor, _VM_ID, timeout=0, interval=0)
