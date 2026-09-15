"""Tests for the startup migration reaper.

The reaper deletes orphan export files and nothing else: directories, with
or without half-imported ``.part`` files, are the storage reconciler's.
"""

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

    await reap_orphan_migration_files()

    assert (vm_dir / "rootfs.qcow2").exists()
    assert not (vm_dir / "rootfs.qcow2.export.qcow2").exists()
    assert not (vm_dir / "data.qcow2.export.qcow2").exists()


@pytest.mark.asyncio
async def test_reaper_leaves_a_half_imported_directory_to_the_reconciler(tmp_path, monkeypatch):
    """A directory holding a ``.part`` file used to be removed whole on the
    supervisor's word alone, before the registry was rehydrated. Whether it
    is an aborted import, a retained volume with a stale download beside it,
    or a create the registry knows about is the reconciler's call."""
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "abandoned"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2.part").write_bytes(b"partial")
    (vm_dir / ".reclaimable").write_text("{}")

    await reap_orphan_migration_files()

    assert (vm_dir / "rootfs.qcow2.part").exists()
    assert (vm_dir / ".reclaimable").exists()


@pytest.mark.asyncio
async def test_reaper_keeps_complete_orphan_volumes(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "complete-but-orphan"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2").write_bytes(b"complete")

    await reap_orphan_migration_files()

    assert (vm_dir / "rootfs.qcow2").exists()


@pytest.mark.asyncio
async def test_agent_hook_needs_nothing_from_the_supervisor(mocker):
    """The hook runs before the registry is rehydrated, so it must not act on
    any live set: it only deletes export files."""
    from aleph.vm.agent.supervisor import _run_migration_reaper

    reap = mocker.patch("aleph.vm.agent.supervisor.reap_orphan_migration_files")

    await _run_migration_reaper({})

    reap.assert_awaited_once_with()
