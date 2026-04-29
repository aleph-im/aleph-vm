"""Tests for the startup migration reaper."""

from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.migration.reaper import reap_orphan_migration_files


@pytest.mark.asyncio
async def test_reaper_deletes_export_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "abc123"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2").write_bytes(b"keep")
    (vm_dir / "rootfs.qcow2.export.qcow2").write_bytes(b"orphan")
    (vm_dir / "data.qcow2.export.qcow2").write_bytes(b"orphan2")

    pool = MagicMock()
    # Pretend the VM is in the pool — directory itself stays.
    pool.executions = {"abc123": MagicMock()}

    await reap_orphan_migration_files(pool)

    assert (vm_dir / "rootfs.qcow2").exists()
    assert not (vm_dir / "rootfs.qcow2.export.qcow2").exists()
    assert not (vm_dir / "data.qcow2.export.qcow2").exists()


@pytest.mark.asyncio
async def test_reaper_removes_orphan_dest_dir_with_part_files(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "abandoned"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2.part").write_bytes(b"partial")

    pool = MagicMock()
    pool.executions = {}

    await reap_orphan_migration_files(pool)

    assert not vm_dir.exists()


@pytest.mark.asyncio
async def test_reaper_keeps_complete_orphan_volumes(tmp_path, monkeypatch):
    """Directory with completed qcow2 files but no execution: keep, log a warning."""
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)
    vm_dir = tmp_path / "complete-but-orphan"
    vm_dir.mkdir()
    (vm_dir / "rootfs.qcow2").write_bytes(b"complete")

    pool = MagicMock()
    pool.executions = {}

    await reap_orphan_migration_files(pool)

    assert vm_dir.exists()
    assert (vm_dir / "rootfs.qcow2").exists()
