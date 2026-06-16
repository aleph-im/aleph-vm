"""Unit tests for the P2P-migration disk/VM seam on LocalSupervisor.

These methods are the disk/VM half of the agent's P2P migration: the agent
owns the network transport (compress, hash, serve, download, rebase), the
supervisor owns stopping the VM, locating its disks, creating the migrated VM
and releasing it.
"""

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.conf import settings
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor.types import VmId

_VM_ID = VmId("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")


@pytest.mark.asyncio
async def test_stop_vm_for_export_stops_and_returns_volumes_dir(mocker, monkeypatch, tmp_path):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    graceful = mocker.patch("aleph.vm.supervisor.local.graceful_shutdown", AsyncMock())

    execution = MagicMock()
    pool = MagicMock(executions={_VM_ID: execution})
    sup = LocalSupervisor(pool)

    volumes_dir = await sup.stop_vm_for_export(_VM_ID)

    graceful.assert_awaited_once_with(execution)
    assert Path(volumes_dir) == tmp_path / str(_VM_ID)


@pytest.mark.asyncio
async def test_stop_vm_for_export_missing_vm_raises(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    sup = LocalSupervisor(MagicMock(executions={}))
    with pytest.raises(VmNotFoundError):
        await sup.stop_vm_for_export(_VM_ID)


@pytest.mark.asyncio
async def test_restart_after_failed_export_restarts_controller():
    execution = MagicMock()
    execution.systemd_manager = MagicMock()
    execution.systemd_manager.enable_and_start = AsyncMock()
    execution.controller_service = "aleph-vm-controller@x.service"
    pool = MagicMock(executions={_VM_ID: execution})
    sup = LocalSupervisor(pool)

    await sup.restart_after_failed_export(_VM_ID)

    execution.systemd_manager.enable_and_start.assert_awaited_once_with("aleph-vm-controller@x.service")


@pytest.mark.asyncio
async def test_restart_after_failed_export_missing_vm_is_noop():
    """The VM may already be gone (forgotten); restart is best-effort."""
    sup = LocalSupervisor(MagicMock(executions={}))
    # Must not raise.
    await sup.restart_after_failed_export(_VM_ID)


@pytest.mark.asyncio
async def test_create_migrated_vm_calls_pool_create_a_vm():
    execution = MagicMock()
    execution.vm_hash = _VM_ID
    execution.persistent = False
    pool = MagicMock(executions={})
    pool.create_a_vm = AsyncMock(return_value=execution)
    sup = LocalSupervisor(pool)

    message = MagicMock()
    original = MagicMock()
    info = await sup.create_migrated_vm(_VM_ID, message, original)

    pool.create_a_vm.assert_awaited_once_with(
        vm_hash=_VM_ID, message=message, original=original, persistent=True
    )
    assert info.vm_id == _VM_ID


@pytest.mark.asyncio
async def test_release_migrated_vm_stops_and_forgets():
    pool = MagicMock(executions={})
    pool.stop_vm = AsyncMock()
    pool.forget_vm = MagicMock()
    sup = LocalSupervisor(pool)

    await sup.release_migrated_vm(_VM_ID)

    pool.stop_vm.assert_awaited_once_with(_VM_ID)
    pool.forget_vm.assert_called_once_with(_VM_ID)
