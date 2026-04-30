"""Migration job dataclasses and module-level registries."""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from aleph_message.models import ItemHash
from pydantic import BaseModel

from aleph.vm.conf import settings
from aleph.vm.models import MigrationState


class DiskFileInfo(BaseModel):
    """Information about an exported disk file. Returned in the export status payload and consumed by the import request."""

    name: str
    size_bytes: int
    sha256: str
    download_path: str


@dataclass
class ExportJob:
    vm_hash: ItemHash
    state: MigrationState
    started_at: datetime
    finished_at: datetime | None = None
    token: str | None = None
    disk_files: list[DiskFileInfo] | None = None
    export_paths: list[Path] = field(default_factory=list)
    volumes_dir: Path | None = None
    active_downloads: int = 0
    error: str | None = None
    task: asyncio.Task | None = None
    ttl_task: asyncio.Task | None = None


@dataclass
class ImportJob:
    vm_hash: ItemHash
    state: MigrationState
    started_at: datetime
    source_host: str
    source_port: int
    finished_at: datetime | None = None
    bytes_downloaded: int = 0
    total_bytes_expected: int | None = None
    current_step: str | None = None
    transfer_time_ms: int | None = None
    error: str | None = None
    dest_dir: Path | None = None
    downloaded_files: list[Path] = field(default_factory=list)
    task: asyncio.Task | None = None
    ttl_task: asyncio.Task | None = None


# Module-level registries. Reset to empty on supervisor restart.
export_jobs: dict[ItemHash, ExportJob] = {}
import_jobs: dict[ItemHash, ImportJob] = {}

# Lazy-initialised global semaphore. Constructed on first call so the loop
# is running and the settings module is fully loaded.
_migration_semaphore: asyncio.Semaphore | None = None


def get_migration_semaphore() -> asyncio.Semaphore:
    """Return the host-wide migration semaphore, creating it on first call.

    Capacity comes from settings.MAX_CONCURRENT_MIGRATIONS at first-call time.
    """
    global _migration_semaphore
    if _migration_semaphore is None:
        _migration_semaphore = asyncio.Semaphore(settings.MAX_CONCURRENT_MIGRATIONS)
    return _migration_semaphore


def _reset_migration_semaphore_for_tests() -> None:
    """Clear the cached semaphore so tests can change MAX_CONCURRENT_MIGRATIONS between cases."""
    global _migration_semaphore
    _migration_semaphore = None
