"""LocalSupervisor.run_program_code: serve a persistent program's code over its
guest channel through the supervisor (no pool access from the agent)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest

from aleph.vm.contract.abc import LifecycleOps, Supervisor
from aleph.vm.contract.errors import VmNotFoundError
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.contract.types import VmId


def test_run_program_code_is_abstract():
    assert "run_program_code" in Supervisor.__abstractmethods__
    assert "run_program_code" in LifecycleOps.__abstractmethods__


@pytest.mark.asyncio
async def test_run_program_code_unknown_vm_raises():
    pool = SimpleNamespace(executions={})
    sup = LocalSupervisor(pool)
    with pytest.raises(VmNotFoundError):
        await sup.run_program_code(VmId("dead" * 16), {"type": "http"}, timeout=5)


@pytest.mark.asyncio
async def test_run_program_code_runs_over_channel(monkeypatch):
    vm_id = VmId("feed" * 16)
    # A spec-program execution exposing a guest channel UDS path.
    fvm = SimpleNamespace(vsock_path="/tmp/aleph-vm-test.vsock")
    vm = SimpleNamespace(fvm=fvm)
    execution = SimpleNamespace(
        vm_hash=vm_id,
        vm=vm,
        is_program=True,
        becomes_ready=lambda: asyncio.sleep(0),
    )
    pool = SimpleNamespace(executions={vm_id: execution})
    sup = LocalSupervisor(pool)

    captured: dict = {}

    async def fake_run(channel_path, scope, *, timeout):
        captured["channel_path"] = channel_path
        captured["scope"] = scope
        captured["timeout"] = timeout
        return b"the-result"

    monkeypatch.setattr("aleph.vm.supervisor.local._run_code_over_channel", fake_run)

    scope = {"type": "http", "path": "/"}
    result = await sup.run_program_code(vm_id, scope, timeout=12.5)

    assert result == b"the-result"
    assert captured["channel_path"] == "/tmp/aleph-vm-test.vsock"
    assert captured["scope"] is scope
    assert captured["timeout"] == 12.5
