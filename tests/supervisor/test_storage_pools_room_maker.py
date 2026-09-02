"""Placement asks the agent's evictor before refusing a create.

Split out of the old ``tests/supervisor/test_storage_pools.py``, which was
removed with the Python supervisor daemon (one test in it reached into
``aleph.vm.supervisor.daemon``). These cases only exercise
``aleph.vm.storage_pools``, which is unchanged.
"""

from __future__ import annotations

import shutil as shutil_module
from pathlib import Path

import pytest

import aleph.vm.storage_pools as storage_pools_module
from aleph.vm.conf import settings
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.storage_pools import MediaClass, StoragePool, reset_pools, select_pool


@pytest.fixture()
def pool_settings(tmp_path, monkeypatch):
    """Isolated settings roots + a clean module cache; yields the tmp root."""
    execution_root = tmp_path / "execution"
    default_pool = execution_root / "volumes" / "persistent"
    default_pool.mkdir(parents=True)
    monkeypatch.setattr(settings, "EXECUTION_ROOT", execution_root)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", default_pool)
    monkeypatch.setattr(settings, "VOLUME_POOLS", [])
    reset_pools()
    yield tmp_path
    reset_pools()


@pytest.fixture()
def three_pools(pool_settings, monkeypatch):
    """Pool 0 (default) + one NVMe + one SSD pool, module cache primed."""
    pool1 = pool_settings / "mnt" / "nvme1"
    pool2 = pool_settings / "mnt" / "ssd1"
    pool1.mkdir(parents=True)
    pool2.mkdir(parents=True)
    pools = [
        StoragePool(path=Path(settings.PERSISTENT_VOLUMES_DIR), media_class=MediaClass.SSD, index=0),
        StoragePool(path=pool1, media_class=MediaClass.NVME, index=1),
        StoragePool(path=pool2, media_class=MediaClass.SSD, index=2),
    ]
    monkeypatch.setattr(storage_pools_module, "_pools", pools)
    return pools


def _fake_disk_usage(monkeypatch, free_by_path: dict[Path, int], total: int = 10**12):
    """shutil.disk_usage keyed by pool path; unknown paths raise OSError."""

    def fake(path):
        for pool_path, free in free_by_path.items():
            if str(pool_path) == str(path):
                return shutil_module._ntuple_diskusage(total, total - free, free)
        msg = f"no fake usage for {path}"
        raise OSError(msg)

    monkeypatch.setattr(storage_pools_module.shutil, "disk_usage", fake)


@pytest.fixture()
def room_maker():
    """Register an evictor for one test, and always unregister it: the hook is
    module state, and a leaked one would evict from every later test."""
    yield storage_pools_module.set_room_maker
    storage_pools_module.set_room_maker(None)


class TestRoomMaker:
    """Placement asks the agent's evictor before refusing: reclaimable bytes
    are advertised as free, so a create that does not fit must first get the
    chance to take the space back (spec section 1)."""

    def test_the_room_maker_is_asked_before_refusing(self, three_pools, monkeypatch, room_maker):
        calls = []
        monkeypatch.setattr(storage_pools_module, "_pool_free_bytes", lambda pool: 0)
        room_maker(lambda pool, needed: calls.append((pool.index, needed)) or 0)

        with pytest.raises(InsufficientResourcesError):
            select_pool(size_mib=1)

        # The roomiest eligible pool, asked for the placement's own size.
        assert calls == [(0, 1024 * 1024)]

    def test_placement_succeeds_when_the_room_maker_frees_enough(self, three_pools, monkeypatch, room_maker):
        # One reading per pool (nothing fits), then the post-eviction reading.
        frees = iter([0, 0, 0])
        monkeypatch.setattr(storage_pools_module, "_pool_free_bytes", lambda pool: next(frees, 4 * 1024 * 1024))
        room_maker(lambda pool, needed: 4 * 1024 * 1024)

        assert select_pool(size_mib=1) == three_pools[0]

    def test_placement_still_fails_when_eviction_frees_too_little(self, three_pools, monkeypatch, room_maker):
        monkeypatch.setattr(storage_pools_module, "_pool_free_bytes", lambda pool: 1024)
        room_maker(lambda pool, needed: 1024)

        with pytest.raises(InsufficientResourcesError):
            select_pool(size_mib=1)

    def test_the_room_maker_is_not_asked_when_a_pool_already_fits(self, three_pools, monkeypatch, room_maker):
        _fake_disk_usage(monkeypatch, {pool.path: 50 * 1024**3 for pool in three_pools})
        calls = []
        room_maker(lambda pool, needed: calls.append(pool) or 0)

        assert select_pool(size_mib=1024) == three_pools[0]
        assert calls == []

    def test_every_pool_unreachable_still_offers_the_room_maker_a_target(self, three_pools, monkeypatch, room_maker):
        """No pool reports free space (dead disks, unmounted): there is no
        roomiest pool, so the evictor gets the first eligible one rather than
        nothing at all."""
        monkeypatch.setattr(storage_pools_module, "_pool_free_bytes", lambda pool: None)
        calls = []
        room_maker(lambda pool, needed: calls.append(pool.index) or 0)

        with pytest.raises(InsufficientResourcesError):
            select_pool(size_mib=1)

        assert calls == [0]
