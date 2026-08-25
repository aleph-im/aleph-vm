"""Shared temp-directory fixture for the reclamation tests: two volume pools,
a session directory, and the four download caches."""

from __future__ import annotations

from pathlib import Path

import pytest

import aleph.vm.storage_pools as storage_pools_module
from aleph.vm.conf import settings
from aleph.vm.storage_pools import MediaClass, StoragePool, reset_pools

VM_HASH = "cafe" * 16
OTHER_HASH = "beef" * 16


@pytest.fixture
def pools(tmp_path, monkeypatch):
    execution_root = tmp_path / "execution"
    pool0 = execution_root / "volumes" / "persistent"
    pool1 = tmp_path / "mnt" / "nvme1"
    sessions = execution_root / "sessions"
    caches = {name: tmp_path / "cache" / name for name in ("runtime", "code", "data", "message")}
    for directory in (pool0, pool1, sessions, *caches.values()):
        directory.mkdir(parents=True)
    monkeypatch.setattr(settings, "EXECUTION_ROOT", execution_root)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", pool0)
    monkeypatch.setattr(settings, "CONFIDENTIAL_SESSION_DIRECTORY", sessions)
    monkeypatch.setattr(settings, "RUNTIME_CACHE", caches["runtime"])
    monkeypatch.setattr(settings, "CODE_CACHE", caches["code"])
    monkeypatch.setattr(settings, "DATA_CACHE", caches["data"])
    monkeypatch.setattr(settings, "MESSAGE_CACHE", caches["message"])
    monkeypatch.setattr(settings, "BACKUP_DIRECTORY", execution_root / "backups")
    (execution_root / "backups").mkdir()
    monkeypatch.setattr(
        storage_pools_module,
        "_pools",
        [
            StoragePool(path=pool0, media_class=MediaClass.SSD, index=0),
            StoragePool(path=pool1, media_class=MediaClass.NVME, index=1),
        ],
    )
    yield {"pool0": pool0, "pool1": pool1, "sessions": sessions, "execution_root": execution_root, **caches}
    reset_pools()


def volume(pool: Path, namespace: str, filename: str, size: int = 1) -> Path:
    directory = pool / namespace
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_bytes(b"x" * size)
    return path
