"""Agent-side storage pools: media-class detection, pool config, placement,
lookup and pooled accounting (src/aleph/vm/storage_pools.py)."""

from __future__ import annotations

import json
import logging
import re
import shutil as shutil_module
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aleph_message.models.execution.volume import (
    ParentVolume,
    PersistentVolume,
    VolumePersistence,
)

import aleph.vm.storage as storage_module
import aleph.vm.storage_pools as storage_pools_module
from aleph.vm.agent.migration.reaper import reap_orphan_migration_files
from aleph.vm.agent.migration.runner import _collect_export_disks
from aleph.vm.agent.vm.downloader import ProgramDownloader, QemuDownloader
from aleph.vm.conf import settings
from aleph.vm.host_volumes import host_volumes_from_message
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.storage_pools import (
    POOL_MARKER_NAME,
    MediaClass,
    StoragePool,
    StoragePoolConfigError,
    _device_media_class,
    detect_media_class,
    find_existing_volume,
    get_pools,
    iter_namespace_dirs,
    pools_disk_usage,
    reset_pools,
    roomiest_pool_free_bytes,
    select_pool,
    setup_pools,
    volume_path_for,
)


def _make_disk(sys_root: Path, name: str, *, rotational: bool) -> None:
    """A whole-disk node, faithful to sysfs: the real node lives under
    devices/ and class/block/<name> symlinks to it."""
    disk = sys_root / "devices" / name
    (disk / "queue").mkdir(parents=True)
    (disk / "queue" / "rotational").write_text("1\n" if rotational else "0\n")
    class_dir = sys_root / "class" / "block"
    class_dir.mkdir(parents=True, exist_ok=True)
    (class_dir / name).symlink_to(disk)


def _make_partition(sys_root: Path, disk: str, name: str) -> None:
    """A partition node: nested under its disk's devices/ dir (so the
    resolved parent is the disk, which holds queue/)."""
    part = sys_root / "devices" / disk / name
    part.mkdir(parents=True)
    (sys_root / "class" / "block" / name).symlink_to(part)


def _make_stacked(sys_root: Path, name: str, slaves: list[str]) -> None:
    """A dm/md node: has slaves/<member> entries naming its members."""
    node = sys_root / "devices" / "virtual" / name
    (node / "slaves").mkdir(parents=True)
    (node / "queue").mkdir()
    (node / "queue" / "rotational").write_text("0\n")
    for slave in slaves:
        (node / "slaves" / slave).mkdir()
    class_dir = sys_root / "class" / "block"
    class_dir.mkdir(parents=True, exist_ok=True)
    (class_dir / name).symlink_to(node)


class TestMediaClassDetection:
    def test_nvme_disk_and_partition(self, tmp_path):
        _make_disk(tmp_path, "nvme0n1", rotational=False)
        _make_partition(tmp_path, "nvme0n1", "nvme0n1p1")
        assert _device_media_class("nvme0n1", tmp_path) is MediaClass.NVME
        assert _device_media_class("nvme0n1p1", tmp_path) is MediaClass.NVME

    def test_sata_ssd_and_hdd(self, tmp_path):
        _make_disk(tmp_path, "sda", rotational=False)
        _make_disk(tmp_path, "sdb", rotational=True)
        _make_partition(tmp_path, "sda", "sda1")
        assert _device_media_class("sda", tmp_path) is MediaClass.SSD
        assert _device_media_class("sda1", tmp_path) is MediaClass.SSD
        assert _device_media_class("sdb", tmp_path) is MediaClass.HDD

    def test_stacked_device_takes_slowest_member(self, tmp_path):
        _make_disk(tmp_path, "nvme0n1", rotational=False)
        _make_disk(tmp_path, "sdb", rotational=True)
        _make_stacked(tmp_path, "dm-0", ["nvme0n1", "sdb"])
        _make_stacked(tmp_path, "dm-1", ["nvme0n1"])
        assert _device_media_class("dm-0", tmp_path) is MediaClass.HDD
        assert _device_media_class("dm-1", tmp_path) is MediaClass.NVME

    def test_unknown_device_is_none(self, tmp_path):
        (tmp_path / "class" / "block").mkdir(parents=True)
        assert _device_media_class("sdz", tmp_path) is None

    def test_detect_media_class_unknown_mapping_is_none(self, tmp_path):
        # An empty fake /sys has no dev/block/<maj:min> entry for tmp_path's
        # device, so the path-level wrapper reports undetectable.
        (tmp_path / "dev" / "block").mkdir(parents=True)
        assert detect_media_class(tmp_path, sys_root=tmp_path) is None

    def test_slowness_ordering_and_eligibility(self):
        assert MediaClass.NVME.slowness < MediaClass.SSD.slowness < MediaClass.HDD.slowness
        assert MediaClass.NVME.vm_eligible
        assert MediaClass.SSD.vm_eligible
        assert not MediaClass.HDD.vm_eligible


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


def _fake_ssd_sysfs(tmp_path: Path) -> Path:
    """A fake /sys that classifies every real filesystem as an SSD is not
    possible (st_dev is unknowable in advance), so pool tests use explicit
    `=class` overrides instead of detection."""
    sys_root = tmp_path / "sys"
    (sys_root / "dev" / "block").mkdir(parents=True)
    (sys_root / "class" / "block").mkdir(parents=True)
    return sys_root


class TestSetupPools:
    def test_no_extra_pools_is_single_default_pool(self, pool_settings):
        sys_root = _fake_ssd_sysfs(pool_settings)
        pools = setup_pools(sys_root=sys_root)
        assert len(pools) == 1
        assert isinstance(pools[0], StoragePool)
        assert pools[0].path == Path(settings.PERSISTENT_VOLUMES_DIR)
        assert pools[0].index == 0
        assert pools[0].vm_eligible

    def test_default_pool_on_hdd_warns_but_stays_eligible(self, pool_settings, monkeypatch, caplog):
        """Existing nodes with PERSISTENT_VOLUMES_DIR on a spinner must keep
        working: pool 0 warns but is always VM-eligible."""
        sys_root = _fake_ssd_sysfs(pool_settings)
        monkeypatch.setattr("aleph.vm.storage_pools.detect_media_class", lambda *_args: MediaClass.HDD)
        with caplog.at_level(logging.WARNING, logger="aleph.vm.storage_pools"):
            pools = setup_pools(sys_root=sys_root)
        assert pools[0].media_class is MediaClass.HDD
        assert pools[0].vm_eligible is True
        assert any("rotational" in record.message for record in caplog.records)

    def test_extra_pool_with_override_is_adopted(self, pool_settings, monkeypatch):
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "nvme1"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=nvme"])
        pools = setup_pools(sys_root=sys_root)
        assert [pool.index for pool in pools] == [0, 1]
        assert pools[1].path == extra
        assert pools[1].media_class.value == "nvme"
        # Marker written into the pool, path recorded in the registry.
        marker = json.loads((extra / POOL_MARKER_NAME).read_text())
        assert marker["media_class"] == "nvme"
        registry = json.loads((Path(settings.EXECUTION_ROOT) / "volume-pools.json").read_text())
        assert str(extra) in registry

    def test_missing_pool_dir_is_a_hard_error(self, pool_settings, monkeypatch):
        sys_root = _fake_ssd_sysfs(pool_settings)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{pool_settings / 'not-mounted'}=ssd"])
        with pytest.raises(StoragePoolConfigError, match="does not exist"):
            setup_pools(sys_root=sys_root)

    def test_hdd_pool_is_a_hard_error(self, pool_settings, monkeypatch):
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "spinner"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=hdd"])
        with pytest.raises(StoragePoolConfigError, match="rotational"):
            setup_pools(sys_root=sys_root)

    def test_undetectable_class_without_override_is_a_hard_error(self, pool_settings, monkeypatch):
        # tmp dirs sit on real filesystems the empty fake /sys cannot map.
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "mystery"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [str(extra)])
        with pytest.raises(StoragePoolConfigError, match="media class"):
            setup_pools(sys_root=sys_root)

    def test_unknown_override_class_is_a_hard_error(self, pool_settings, monkeypatch):
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "x"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=floppy"])
        with pytest.raises(StoragePoolConfigError, match="media class"):
            setup_pools(sys_root=sys_root)

    def test_adopted_pool_with_missing_marker_is_a_hard_error(self, pool_settings, monkeypatch):
        """The unmounted-disk trap: the registry remembers the adoption, the
        marker vanished with the mount, so startup must refuse."""
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "nvme1"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=nvme"])
        setup_pools(sys_root=sys_root)
        (extra / POOL_MARKER_NAME).unlink()  # simulate the empty mountpoint
        reset_pools()
        with pytest.raises(StoragePoolConfigError, match="not mounted"):
            setup_pools(sys_root=sys_root)

    def test_marker_without_registry_heals_the_registry(self, pool_settings, monkeypatch):
        """EXECUTION_ROOT restored from backup: marker present, registry lost."""
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "nvme1"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=nvme"])
        setup_pools(sys_root=sys_root)
        (Path(settings.EXECUTION_ROOT) / "volume-pools.json").unlink()
        reset_pools()
        setup_pools(sys_root=sys_root)  # must not raise
        registry = json.loads((Path(settings.EXECUTION_ROOT) / "volume-pools.json").read_text())
        assert str(extra) in registry

    def test_dropping_an_adopted_pool_from_config_is_a_hard_error(self, pool_settings, monkeypatch):
        """A pool that holds (or held) VM volumes must not silently vanish
        from the active set when its VOLUME_POOLS entry is removed."""
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "nvme1"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=nvme"])
        setup_pools(sys_root=sys_root)
        reset_pools()
        monkeypatch.setattr(settings, "VOLUME_POOLS", [])
        with pytest.raises(StoragePoolConfigError, match=re.escape(str(extra))):
            setup_pools(sys_root=sys_root)

    def test_cosmetic_path_rewrite_is_not_an_orphan(self, pool_settings, monkeypatch):
        """A lexical rewrite of a configured pool path (.. segments, doubled
        separators) must not trip the orphaned-pool guard: that guard is a
        hard startup failure, and the pool is still the same directory. The
        comparison normalizes lexically but never resolves symlinks."""
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "nvme1"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=nvme"])
        setup_pools(sys_root=sys_root)
        reset_pools()
        rewritten = f"{extra.parent}//elsewhere/../{extra.name}"
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{rewritten}=nvme"])
        pools = setup_pools(sys_root=sys_root)  # must not raise a false orphan
        assert pools[1].path == extra

    def test_unnormalized_registry_entry_still_guards_missing_marker(self, pool_settings, monkeypatch):
        """A hand-edited (or pre-normalization) registry entry must still be
        recognized as this pool: with the marker gone, startup must refuse
        (the unmounted-disk trap), not silently re-adopt."""
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "nvme1"
        extra.mkdir(parents=True)
        registry = Path(settings.EXECUTION_ROOT) / "volume-pools.json"
        registry.write_text(json.dumps([f"{extra.parent}//elsewhere/../{extra.name}"]) + "\n")
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=nvme"])
        with pytest.raises(StoragePoolConfigError, match="not mounted"):
            setup_pools(sys_root=sys_root)

    @pytest.mark.parametrize("entry", ["=ssd", "relative/path=ssd"])
    def test_empty_or_relative_pool_path_is_a_hard_error(self, pool_settings, monkeypatch, entry):
        sys_root = _fake_ssd_sysfs(pool_settings)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [entry])
        with pytest.raises(StoragePoolConfigError, match="absolute"):
            setup_pools(sys_root=sys_root)


class TestAdoptionRegistry:
    def test_corrupt_registry_json_is_a_hard_error(self, pool_settings):
        (Path(settings.EXECUTION_ROOT) / "volume-pools.json").write_text("{not json")
        with pytest.raises(StoragePoolConfigError, match="volume-pools.json"):
            setup_pools(sys_root=_fake_ssd_sysfs(pool_settings))

    def test_non_list_registry_json_is_a_hard_error(self, pool_settings):
        (Path(settings.EXECUTION_ROOT) / "volume-pools.json").write_text('{"pool": "/mnt/nvme1"}')
        with pytest.raises(StoragePoolConfigError, match="volume-pools.json"):
            setup_pools(sys_root=_fake_ssd_sysfs(pool_settings))

    def test_missing_registry_is_first_boot(self, pool_settings):
        assert not (Path(settings.EXECUTION_ROOT) / "volume-pools.json").exists()
        setup_pools(sys_root=_fake_ssd_sysfs(pool_settings))  # must not raise

    def test_record_adopted_writes_atomically(self, pool_settings, monkeypatch):
        """The registry is written via a temp file + os.replace so a crash
        mid-write cannot leave a truncated (corrupt) registry behind."""
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "nvme1"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=nvme"])

        registry = Path(settings.EXECUTION_ROOT) / "volume-pools.json"
        replaced: list[tuple[str, str]] = []
        real_replace = storage_pools_module.os.replace

        def spying_replace(src, dst, *args, **kwargs):
            replaced.append((str(src), str(dst)))
            return real_replace(src, dst, *args, **kwargs)

        monkeypatch.setattr(storage_pools_module.os, "replace", spying_replace)
        setup_pools(sys_root=sys_root)
        assert any(dst == str(registry) for _src, dst in replaced)
        assert not Path(str(registry) + ".tmp").exists()
        assert str(extra) in json.loads(registry.read_text())


class TestGetPools:
    def test_get_pools_without_setup_falls_back_to_pool_zero(self, pool_settings):  # noqa: ARG002 (pool_settings is a fixture)
        pools = get_pools()
        assert len(pools) == 1
        assert pools[0].path == Path(settings.PERSISTENT_VOLUMES_DIR)

    def test_get_pools_returns_the_setup_result(self, pool_settings, monkeypatch):
        sys_root = _fake_ssd_sysfs(pool_settings)
        extra = pool_settings / "mnt" / "ssd1"
        extra.mkdir(parents=True)
        monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{extra}=ssd"])
        setup_pools(sys_root=sys_root)
        assert [pool.path for pool in get_pools()][1] == extra


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


class TestSelectPool:
    def test_picks_the_most_free_eligible_pool(self, three_pools, monkeypatch):
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 10 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 30 * 1024**3},
        )
        assert select_pool(size_mib=1024) == three_pools[1]

    def test_tie_break_is_lowest_index(self, three_pools, monkeypatch):
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 50 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 50 * 1024**3},
        )
        assert select_pool(size_mib=1024) == three_pools[0]

    def test_no_pool_fits_raises(self, three_pools, monkeypatch):
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 1 * 1024**3, three_pools[1].path: 2 * 1024**3, three_pools[2].path: 1 * 1024**3},
        )
        with pytest.raises(InsufficientResourcesError):
            select_pool(size_mib=10 * 1024)  # 10 GiB > every pool's free space

    def test_unreachable_pool_is_skipped(self, three_pools, monkeypatch):
        # Pool 1 raises OSError (dead disk): placement falls to the others.
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 10 * 1024**3, three_pools[2].path: 30 * 1024**3},
        )
        assert select_pool(size_mib=1024) == three_pools[2]


class TestLookup:
    def test_find_existing_scans_pools_in_order(self, three_pools):
        (three_pools[2].path / "vmhash").mkdir()
        (three_pools[2].path / "vmhash" / "rootfs.qcow2").touch()
        assert find_existing_volume("vmhash", "rootfs.qcow2") == three_pools[2].path / "vmhash" / "rootfs.qcow2"
        assert find_existing_volume("vmhash", "other.qcow2") is None

    def test_duplicate_uses_lowest_index_and_warns(self, three_pools, caplog):
        for pool in (three_pools[1], three_pools[2]):
            (pool.path / "vmhash").mkdir()
            (pool.path / "vmhash" / "vol.ext4").touch()
        with caplog.at_level("WARNING"):
            found = find_existing_volume("vmhash", "vol.ext4")
        assert found == three_pools[1].path / "vmhash" / "vol.ext4"
        assert any("found in 2 pools" in record.message for record in caplog.records)

    def test_volume_path_for_prefers_existing_over_placement(self, three_pools, monkeypatch):
        _fake_disk_usage(monkeypatch, {pool.path: 50 * 1024**3 for pool in three_pools})
        (three_pools[2].path / "vmhash").mkdir()
        (three_pools[2].path / "vmhash" / "vol.ext4").touch()
        assert volume_path_for("vmhash", "vol.ext4", size_mib=1024) == three_pools[2].path / "vmhash" / "vol.ext4"

    def test_volume_path_for_places_and_creates_the_namespace_dir(self, three_pools, monkeypatch):
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 1 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 2 * 1024**3},
        )
        path = volume_path_for("vmhash", "new.ext4", size_mib=1024)
        assert path == three_pools[1].path / "vmhash" / "new.ext4"
        assert path.parent.is_dir()
        assert not path.exists()

    def test_pool0_only_placement_ignores_freer_extra_pools(self, three_pools, monkeypatch):
        """Firecracker writable volumes: the jailer hardlink-copies across
        filesystems, so placement must stay on pool 0 even when an extra pool
        has more free space."""
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 10 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 30 * 1024**3},
        )
        path = volume_path_for("vmhash", "vol.ext4", size_mib=1024, pool0_only=True)
        assert path == three_pools[0].path / "vmhash" / "vol.ext4"

    def test_pool0_only_raises_when_pool0_cannot_fit(self, three_pools, monkeypatch):
        # An extra pool could fit the volume, but it must not be used.
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 1 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 30 * 1024**3},
        )
        with pytest.raises(InsufficientResourcesError):
            volume_path_for("vmhash", "vol.ext4", size_mib=10 * 1024, pool0_only=True)

    def test_pool0_only_sticky_reuse_off_pool0_logs_an_error(self, three_pools, caplog):
        """A legacy volume already living on an extra pool must still boot
        (returning its path), but the lost-writes hazard is logged loudly."""
        (three_pools[2].path / "vmhash").mkdir()
        (three_pools[2].path / "vmhash" / "vol.ext4").touch()
        with caplog.at_level(logging.ERROR, logger="aleph.vm.storage_pools"):
            path = volume_path_for("vmhash", "vol.ext4", size_mib=1024, pool0_only=True)
        assert path == three_pools[2].path / "vmhash" / "vol.ext4"
        assert any("lost" in record.message.lower() for record in caplog.records)

    def test_pool0_only_sticky_reuse_on_pool0_is_silent(self, three_pools, caplog):
        (three_pools[0].path / "vmhash").mkdir()
        (three_pools[0].path / "vmhash" / "vol.ext4").touch()
        with caplog.at_level(logging.ERROR, logger="aleph.vm.storage_pools"):
            path = volume_path_for("vmhash", "vol.ext4", size_mib=1024, pool0_only=True)
        assert path == three_pools[0].path / "vmhash" / "vol.ext4"
        assert not caplog.records

    def test_iter_namespace_dirs(self, three_pools):
        (three_pools[0].path / "vm-a").mkdir()
        (three_pools[1].path / "vm-a").mkdir()
        (three_pools[1].path / "vm-b").mkdir()
        (three_pools[1].path / "stray-file").touch()
        assert list(iter_namespace_dirs("vm-a")) == [
            three_pools[0].path / "vm-a",
            three_pools[1].path / "vm-a",
        ]
        every = list(iter_namespace_dirs())
        assert three_pools[1].path / "vm-b" in every
        assert len(every) == 3  # dirs only, the stray file is skipped


class TestPooledAccounting:
    def test_sums_and_dedups_by_st_dev(self, three_pools, monkeypatch):
        _fake_disk_usage(monkeypatch, {pool.path: 10 * 1024**3 for pool in three_pools})
        fake_devs = {
            str(three_pools[0].path): 1,
            str(three_pools[1].path): 2,
            str(three_pools[2].path): 2,  # same filesystem as pool 1
        }
        real_stat = storage_pools_module.os.stat

        def fake_stat(path, *args, **kwargs):
            if str(path) in fake_devs:
                result = list(real_stat(path, *args, **kwargs))
                result[2] = fake_devs[str(path)]  # st_dev
                return storage_pools_module.os.stat_result(result)
            return real_stat(path, *args, **kwargs)

        monkeypatch.setattr(storage_pools_module.os, "stat", fake_stat)
        total, free = pools_disk_usage()
        # Pools 1 and 2 share a filesystem: counted once → 2 filesystems.
        assert free == 2 * 10 * 1024**3

    def test_unreachable_pool_contributes_zero(self, three_pools, monkeypatch):
        _fake_disk_usage(monkeypatch, {three_pools[0].path: 10 * 1024**3})
        total, free = pools_disk_usage()
        assert free == 10 * 1024**3

    def test_roomiest_pool_free_bytes(self, three_pools, monkeypatch):
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 10 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 30 * 1024**3},
        )
        assert roomiest_pool_free_bytes() == 50 * 1024**3


def _persistent_volume(name: str = "data", size_mib: int = 1024) -> PersistentVolume:
    return PersistentVolume(
        mount=f"/{name}",
        name=name,
        persistence=VolumePersistence.host,
        size_mib=size_mib,
    )


class TestStorageWiring:
    @pytest.mark.asyncio
    async def test_get_volume_path_places_a_new_ext4_on_the_best_pool(self, three_pools, monkeypatch, mocker):
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 1 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 2 * 1024**3},
        )
        create_ext4 = mocker.patch.object(storage_module, "create_ext4", new_callable=AsyncMock)
        path = await storage_module.get_volume_path(_persistent_volume(), namespace="vmhash")
        assert path == three_pools[1].path / "vmhash" / "data.ext4"
        create_ext4.assert_awaited_once_with(path, 1024)

    @pytest.mark.asyncio
    async def test_get_volume_path_reuses_an_existing_volume_wherever_it_lives(self, three_pools, monkeypatch, mocker):
        _fake_disk_usage(monkeypatch, {pool.path: 50 * 1024**3 for pool in three_pools})
        existing = three_pools[2].path / "vmhash"
        existing.mkdir()
        (existing / "data.ext4").touch()
        mocker.patch.object(storage_module, "create_ext4", new_callable=AsyncMock)
        path = await storage_module.get_volume_path(_persistent_volume(), namespace="vmhash")
        assert path == existing / "data.ext4"


class TestFirecrackerPool0Wiring:
    """Firecracker writable volumes must stay on pool 0 (the jailer
    hardlink-copies drive files across filesystems, losing guest writes)."""

    @pytest.mark.asyncio
    async def test_get_volume_path_pool0_only_places_ext4_on_pool0(self, three_pools, monkeypatch, mocker):
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 10 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 2 * 1024**3},
        )
        create_ext4 = mocker.patch.object(storage_module, "create_ext4", new_callable=AsyncMock)
        path = await storage_module.get_volume_path(_persistent_volume(), namespace="vmhash", pool0_only=True)
        assert path == three_pools[0].path / "vmhash" / "data.ext4"
        create_ext4.assert_awaited_once_with(path, 1024)

    @pytest.mark.asyncio
    async def test_get_volume_path_devmapper_threads_pool0_only(self, three_pools, mocker):  # noqa: ARG002
        """The devmapper branch must forward pool0_only into the
        create_devmapper -> create_volume_file -> volume_path_for chain, so a
        hypothetical Firecracker parent volume could never place its backing
        file off pool 0 (the jailer hardlink-copy would lose guest writes)."""
        devmapper = mocker.patch.object(
            storage_module, "create_devmapper", new_callable=AsyncMock, return_value=Path("/dev/mapper/vmhash_data")
        )
        volume = _persistent_volume().model_copy(update={"parent": ParentVolume(ref="cafe" * 16, use_latest=False)})
        await storage_module.get_volume_path(volume, namespace="vmhash", pool0_only=True)
        assert devmapper.await_args.kwargs["pool0_only"] is True

    @pytest.mark.asyncio
    async def test_create_volume_file_pool0_only_places_on_pool0(self, three_pools, monkeypatch, mocker):
        """create_volume_file (the devmapper backing file) must honor
        pool0_only even when an extra pool has more free space."""
        _fake_disk_usage(
            monkeypatch,
            {three_pools[0].path: 10 * 1024**3, three_pools[1].path: 50 * 1024**3, three_pools[2].path: 2 * 1024**3},
        )
        mocker.patch.object(storage_module, "run_in_subprocess", new_callable=AsyncMock)
        mocker.patch.object(storage_module, "chown_to_jailman", new_callable=AsyncMock)
        path = await storage_module.create_volume_file(_persistent_volume(), "vmhash", pool0_only=True)
        assert path == three_pools[0].path / "vmhash" / "data.btrfs"

    @pytest.mark.asyncio
    async def test_host_volumes_from_message_threads_pool0_only(self, mocker):
        get_path = mocker.patch(
            "aleph.vm.host_volumes.get_volume_path", new_callable=AsyncMock, return_value=Path("/pool0/vm/data.ext4")
        )
        message_content = SimpleNamespace(volumes=[_persistent_volume()])
        await host_volumes_from_message(message_content, "vmhash", pool0_only=True)
        assert get_path.await_args.kwargs["pool0_only"] is True

    @pytest.mark.asyncio
    async def test_program_downloader_pins_volumes_to_pool0(self, mocker):
        resolver = mocker.patch(
            "aleph.vm.agent.vm.downloader.host_volumes_from_message", new_callable=AsyncMock, return_value=[]
        )
        message_content = SimpleNamespace(
            volumes=[], code=SimpleNamespace(encoding="zip", entrypoint="main:app", interface=None)
        )
        downloader = ProgramDownloader(message_content, "vmhash")
        await downloader.download_volumes()
        assert resolver.await_args.kwargs["pool0_only"] is True

    @pytest.mark.asyncio
    async def test_qemu_downloader_keeps_all_pools(self, mocker):
        resolver = mocker.patch(
            "aleph.vm.agent.vm.downloader.host_volumes_from_message", new_callable=AsyncMock, return_value=[]
        )
        downloader = QemuDownloader(SimpleNamespace(volumes=[]), "vmhash")
        await downloader.download_volumes()
        assert resolver.await_args.kwargs["pool0_only"] is False


class TestDaemonStartup:
    """The standalone Python supervisor daemon must run setup_pools() so its
    capacity accounting sees every configured pool (and misconfigurations
    abort startup instead of degrading silently)."""

    @pytest.fixture()
    def daemon_main(self, monkeypatch, tmp_path):
        from aleph.vm.supervisor import daemon

        fake_settings = SimpleNamespace(
            setup=lambda: None,
            check=lambda: None,
            SUPERVISOR_GRPC_SOCKET=str(tmp_path / "supervisor.sock"),
        )
        monkeypatch.setattr(daemon, "settings", fake_settings)
        monkeypatch.setattr(daemon.asyncio, "run", lambda coro: coro.close())
        return daemon

    def test_daemon_main_runs_setup_pools(self, daemon_main, monkeypatch):
        calls: list[bool] = []
        monkeypatch.setattr(storage_pools_module, "setup_pools", lambda: calls.append(True))
        assert daemon_main.main([]) == 0
        assert calls == [True]

    def test_daemon_main_aborts_on_pool_config_error(self, daemon_main, monkeypatch):
        def broken_setup_pools():
            msg = "pool misconfigured"
            raise StoragePoolConfigError(msg)

        monkeypatch.setattr(storage_pools_module, "setup_pools", broken_setup_pools)
        with pytest.raises(StoragePoolConfigError):
            daemon_main.main([])


class TestMigrationPools:
    @pytest.mark.asyncio
    async def test_reaper_sweeps_every_pool(self, three_pools):
        # An aborted import (.part) in pool 1, an orphan export in pool 2.
        aborted = three_pools[1].path / "dead-vm"
        aborted.mkdir()
        (aborted / "rootfs.qcow2.part").touch()
        exported = three_pools[2].path / "live-vm"
        exported.mkdir()
        (exported / "rootfs.qcow2.export.qcow2").touch()
        await reap_orphan_migration_files(known_vm_ids={"live-vm"})
        assert not aborted.exists()
        assert not (exported / "rootfs.qcow2.export.qcow2").exists()
        assert exported.exists()

    def test_export_collects_each_volume_from_one_pool_only(self, three_pools, caplog):
        """A duplicated basename (e.g. a preserved orphan from a failed import
        plus a retried staging in another pool) must export exactly one copy:
        the lowest-index pool's, matching the boot-time volume lookup rule."""
        for pool in (three_pools[1], three_pools[2]):
            namespace = pool.path / "vm-x"
            namespace.mkdir()
            (namespace / "rootfs.qcow2").touch()
        (three_pools[2].path / "vm-x" / "extra.qcow2").touch()
        with caplog.at_level("WARNING"):
            disks = _collect_export_disks("vm-x")
        assert disks == [
            three_pools[1].path / "vm-x" / "rootfs.qcow2",
            three_pools[2].path / "vm-x" / "extra.qcow2",
        ]
        assert any("multiple pools" in record.message for record in caplog.records)
