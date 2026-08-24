"""The backup record and errors, shared by the agent's backup manager and
its HTTP views."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import NewType

BackupId = NewType("BackupId", str)


class BackupStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass(frozen=True)
class BackupInfo:
    vm_hash: str
    backup_id: BackupId
    status: BackupStatus
    size_bytes: int
    created_at_unix_secs: int
    error_message: str
    # Archive metadata, populated for completed archives on disk. The views
    # turn these into the HTTP response body (checksum, volumes, source_sizes)
    # and the download sidecar headers (X-Backup-Checksum, X-Source-Size). They
    # default to empty so in-flight RUNNING/FAILED jobs construct cleanly.
    checksum: str = ""
    volumes: list[str] = field(default_factory=list)
    source_sizes: dict[str, int] = field(default_factory=dict)


class BackupError(Exception):
    """Base class of the backup manager's errors."""


class BackupNotFoundError(BackupError):
    """No archive or in-flight job with this id belongs to this VM."""

    def __init__(self, backup_id: str):
        super().__init__(backup_id)
        self.backup_id = backup_id


class BackupNotSupportedError(BackupError):
    """The VM has no rootfs disk image to back up or restore (a program
    runs on the shared runtime cache; only QEMU instances are backed up)."""


class BackupInProgressError(BackupError):
    """The operation conflicts with a backup still running for the VM."""


class InvalidRestoreImageError(BackupError):
    """The image to restore is not a valid QCOW2 disk, or would grow the
    rootfs past its declared size."""
