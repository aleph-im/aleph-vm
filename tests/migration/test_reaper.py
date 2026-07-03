"""Tests for the startup migration reaper.

The reaper takes the set of live vm_ids (sourced from supervisor.list_vms by the
agent hook), not a pool, so it works in both in-process and split mode.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from aleph.vm.agent.migration.reaper import reap_orphan_migration_files
from aleph.vm.conf import settings


@pytest.mark.asyncio
async def test_reaper_deletes_export_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "abc123"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2").write_bytes(b"keep")
    (vm_dir / "rootfs.qcow2.export.qcow2").write_bytes(b"orphan")
    (vm_dir / "data.qcow2.export.qcow2").write_bytes(b"orphan2")

    # The VM is live — the directory itself stays, only orphan exports go.
    await reap_orphan_migration_files({"abc123"})

    assert (vm_dir / "rootfs.qcow2").exists()
    assert not (vm_dir / "rootfs.qcow2.export.qcow2").exists()
    assert not (vm_dir / "data.qcow2.export.qcow2").exists()


@pytest.mark.asyncio
async def test_reaper_removes_orphan_dest_dir_with_part_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "abandoned"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2.part").write_bytes(b"partial")

    await reap_orphan_migration_files(set())

    assert not vm_dir.exists()


@pytest.mark.asyncio
async def test_reaper_keeps_part_dir_of_live_vm(tmp_path, monkeypatch):
    """A .part dir whose vm_hash IS a live VM must be left alone (no rmtree)."""
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "live"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2.part").write_bytes(b"partial")

    await reap_orphan_migration_files({"live"})

    assert vm_dir.exists()


@pytest.mark.asyncio
async def test_reaper_keeps_complete_orphan_volumes(tmp_path, monkeypatch):
    """Directory with completed qcow2 files but no live VM: keep, log a warning."""
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "complete-but-orphan"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2").write_bytes(b"complete")

    await reap_orphan_migration_files(set())

    assert vm_dir.exists()
    assert (vm_dir / "rootfs.qcow2").exists()


@pytest.mark.asyncio
async def test_agent_hook_sources_live_ids_from_supervisor(mocker):
    """The agent on_startup hook builds the live-VM set from supervisor.list_vms
    (over the ABC, so it works in split mode with no in-process pool) and hands
    it to the reaper."""
    from aleph.vm.agent.supervisor import _run_migration_reaper

    captured = {}

    async def fake_reap(known_vm_ids):
        captured["known"] = known_vm_ids

    mocker.patch("aleph.vm.agent.supervisor.reap_orphan_migration_files", new=fake_reap)
    supervisor = SimpleNamespace(
        list_vms=AsyncMock(return_value=[SimpleNamespace(vm_id="vm1"), SimpleNamespace(vm_id="vm2")])
    )

    await _run_migration_reaper({"supervisor": supervisor})

    assert captured["known"] == {"vm1", "vm2"}
