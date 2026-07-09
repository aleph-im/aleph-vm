"""Agent-side storage pools: media-class detection, pool config, placement,
lookup and pooled accounting (src/aleph/vm/storage_pools.py)."""

from __future__ import annotations

from pathlib import Path

from aleph.vm.storage_pools import (
    MediaClass,
    _device_media_class,
    detect_media_class,
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
