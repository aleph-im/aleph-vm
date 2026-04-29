"""Unit tests for ExportJob and ImportJob dataclasses."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.migration.jobs import (
    ExportJob,
    ImportJob,
    _reset_migration_semaphore_for_tests,
    get_migration_semaphore,
)
from aleph.vm.models import MigrationState


def test_export_job_starts_in_exporting_state():
    job = ExportJob(
        vm_hash=ItemHash(settings.FAKE_INSTANCE_ID),
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    assert job.state == MigrationState.EXPORTING
    assert job.finished_at is None
    assert job.token is None
    assert job.disk_files is None
    assert job.export_paths == []
    assert job.error is None


def test_import_job_starts_in_importing_state():
    job = ImportJob(
        vm_hash=ItemHash(settings.FAKE_INSTANCE_ID),
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host="example.com",
        source_port=443,
    )
    assert job.state == MigrationState.IMPORTING
    assert job.bytes_downloaded == 0
    assert job.total_bytes_expected is None
    assert job.current_step is None
    assert job.downloaded_files == []


@pytest.mark.asyncio
async def test_migration_semaphore_uses_settings_capacity(monkeypatch):
    monkeypatch.setattr(settings, "MAX_CONCURRENT_MIGRATIONS", 3)
    _reset_migration_semaphore_for_tests()

    sem = get_migration_semaphore()
    assert isinstance(sem, asyncio.Semaphore)
    # Acquire all three permits without blocking.
    await asyncio.wait_for(
        asyncio.gather(sem.acquire(), sem.acquire(), sem.acquire()),
        timeout=0.1,
    )
    # Fourth acquire should block — confirm via timeout.
    with pytest.raises(asyncio.TimeoutError):
        await asyncio.wait_for(sem.acquire(), timeout=0.05)
    sem.release()
    sem.release()
    sem.release()


@pytest.mark.asyncio
async def test_migration_semaphore_is_singleton():
    _reset_migration_semaphore_for_tests()
    a = get_migration_semaphore()
    b = get_migration_semaphore()
    assert a is b
