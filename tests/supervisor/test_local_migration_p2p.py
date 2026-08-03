"""Migration rides the standard lifecycle RPCs end to end.

There is no dedicated migration method on the Supervisor surface anymore: the
agent stages and rebases the disks, then drives create_vm / stop_vm / start_vm /
delete_vm. The export-time stop is a plain stop_vm, which already powers the
guest down gracefully (the controller's SIGTERM handler ACPI-powers the guest
down and QMP-quits QEMU with a cache flush) and blocks until the controller unit
has stopped, so the exported overlay is consistent with no extra step.
"""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.agent.migration.jobs import (
    ExportJob,
    MigrationState,
    _reset_migration_semaphore_for_tests,
)
from aleph.vm.agent.migration.runner import run_export
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.abc import Supervisor


@pytest.fixture(autouse=True)
def _reset_semaphore():
    _reset_migration_semaphore_for_tests()
    yield
    _reset_migration_semaphore_for_tests()


def test_supervisor_has_no_migration_method():
    """The migration capability folded into the standard lifecycle RPCs."""
    assert not hasattr(Supervisor, "stop_vm_for_export")
    assert "stop_vm_for_export" not in Supervisor.__abstractmethods__


@pytest.mark.asyncio
async def test_export_drives_stop_vm_and_collects_disks(tmp_path, monkeypatch):
    """The export runner stops the VM through the standard stop_vm RPC and
    collects the disks from settings-derived pool paths (no
    migration-specific method)."""
    vm_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", tmp_path)

    volumes_dir = tmp_path / str(vm_hash)
    volumes_dir.mkdir(parents=True)
    (volumes_dir / "rootfs.qcow2").write_bytes(b"x" * 16)

    async def fake_compress(src: Path, dst: Path):
        dst.write_bytes(b"compressed")

    monkeypatch.setattr("aleph.vm.agent.migration.runner.compress_disk", fake_compress)

    supervisor = AsyncMock()
    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )

    await run_export(job, supervisor)

    supervisor.stop_vm.assert_awaited_once_with(vm_hash)
    assert job.export_paths == [volumes_dir / "rootfs.qcow2.export.qcow2"]
    assert job.state == MigrationState.EXPORTED
