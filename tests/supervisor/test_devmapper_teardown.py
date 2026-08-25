"""remove_devmapper: the inverse of create_devmapper for one volume."""

from __future__ import annotations

from pathlib import Path

import pytest
from reclaim_fixtures import VM_HASH, pools, volume  # noqa: F401

import aleph.vm.storage as storage_module
from aleph.vm.storage import detach_loop_devices, remove_devmapper

real_glob = Path.glob


@pytest.fixture
def commands(mocker):
    """Record every subprocess call; losetup -j answers with two loop devices."""
    calls: list[list[str]] = []

    async def fake_run(command, check=True, stdin_input=None):
        calls.append([str(c) for c in command])
        if command[:2] == ["losetup", "-j"]:
            return b"/dev/loop7: []: (/some/file)\n/dev/loop9: []: (/some/file)\n"
        return b""

    mocker.patch.object(storage_module, "run_in_subprocess", side_effect=fake_run)
    return calls


def _present_devices(monkeypatch, present: set[Path], siblings: list[Path]) -> None:
    """Pretend ``present`` are the live /dev/mapper block devices."""
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self in present or real_is_block_device(self))
    monkeypatch.setattr(
        Path,
        "glob",
        lambda self, pattern: iter(siblings) if str(self) == "/dev/mapper" else real_glob(self, pattern),
    )


@pytest.mark.asyncio
async def test_detach_loop_devices_detaches_every_loop_of_the_file(commands):
    detached = await detach_loop_devices(Path("/some/file"))

    assert detached == ["/dev/loop7", "/dev/loop9"]
    assert ["losetup", "-d", "/dev/loop7"] in commands
    assert ["losetup", "-d", "/dev/loop9"] in commands


@pytest.mark.asyncio
async def test_remove_devmapper_tears_down_in_order(pools, commands, monkeypatch, tmp_path):  # noqa: F811
    backing = volume(pools["pool0"], VM_HASH, "data.btrfs")
    mapped = Path("/dev/mapper") / f"{VM_HASH}_data"
    base = Path("/dev/mapper") / f"{VM_HASH}_base"
    _present_devices(monkeypatch, {mapped, base}, [])
    mount_root = tmp_path / "mnt"
    (mount_root / f"{VM_HASH}_data").mkdir(parents=True)
    monkeypatch.setattr(storage_module, "MOUNT_ROOT", mount_root)

    await remove_devmapper(VM_HASH, "data")

    dm_removes = [c for c in commands if c[:2] == ["dmsetup", "remove"]]
    assert dm_removes == [
        ["dmsetup", "remove", f"{VM_HASH}_data"],
        ["dmsetup", "remove", f"{VM_HASH}_base"],
    ]
    assert ["losetup", "-j", str(backing)] in commands
    assert not (mount_root / f"{VM_HASH}_data").exists()


@pytest.mark.asyncio
async def test_remove_devmapper_keeps_base_while_a_sibling_snapshot_exists(pools, commands, monkeypatch):  # noqa: F811
    volume(pools["pool0"], VM_HASH, "data.btrfs")
    mapped = Path("/dev/mapper") / f"{VM_HASH}_data"
    sibling = Path("/dev/mapper") / f"{VM_HASH}_other"
    base = Path("/dev/mapper") / f"{VM_HASH}_base"
    _present_devices(monkeypatch, {mapped, sibling, base}, [sibling])

    await remove_devmapper(VM_HASH, "data")

    dm_removes = [c for c in commands if c[:2] == ["dmsetup", "remove"]]
    assert dm_removes == [["dmsetup", "remove", f"{VM_HASH}_data"]]


@pytest.mark.asyncio
async def test_remove_devmapper_never_touches_the_shared_parent_device(pools, commands, monkeypatch):  # noqa: F811
    """The parent image's dm device is shared across VMs: only the cache
    eviction pass may remove it."""
    volume(pools["pool0"], VM_HASH, "data.btrfs")
    mapped = Path("/dev/mapper") / f"{VM_HASH}_data"
    parent = Path("/dev/mapper") / "parent-image-ref"
    _present_devices(monkeypatch, {mapped, parent}, [])

    await remove_devmapper(VM_HASH, "data")

    assert ["dmsetup", "remove", "parent-image-ref"] not in commands


@pytest.mark.asyncio
async def test_remove_devmapper_is_a_no_op_without_devices(pools, commands):  # noqa: F811
    await remove_devmapper(VM_HASH, "data")

    assert [c for c in commands if c[0] == "dmsetup"] == []


@pytest.mark.asyncio
async def test_remove_devmapper_refuses_an_implausible_name(commands, monkeypatch):
    """A name that could never have been created is never composed into a
    dmsetup argument."""
    _present_devices(monkeypatch, set(), [])

    await remove_devmapper("../../etc", "data")
    await remove_devmapper(VM_HASH, "../data")

    assert commands == []
