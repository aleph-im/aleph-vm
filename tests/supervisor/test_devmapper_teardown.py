"""remove_devmapper: the inverse of create_devmapper for one volume."""

from __future__ import annotations

from fnmatch import fnmatch
from pathlib import Path

import pytest
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

import aleph.vm.storage as storage_module
from aleph.vm.agent.vm.retire import teardown_namespace_devices
from aleph.vm.storage import (
    DEVICE_MAPPER_DIRECTORY,
    detach_loop_devices,
    remove_devmapper,
)

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
        ["dmsetup", "remove", "--retry", f"{VM_HASH}_data"],
        ["dmsetup", "remove", "--retry", f"{VM_HASH}_base"],
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
    assert dm_removes == [["dmsetup", "remove", "--retry", f"{VM_HASH}_data"]]


@pytest.mark.asyncio
async def test_remove_devmapper_never_touches_the_shared_parent_device(pools, commands, monkeypatch):  # noqa: F811
    """The parent image's dm device is shared across VMs: only the cache
    eviction pass may remove it."""
    volume(pools["pool0"], VM_HASH, "data.btrfs")
    mapped = Path("/dev/mapper") / f"{VM_HASH}_data"
    parent = Path("/dev/mapper") / "parent-image-ref"
    _present_devices(monkeypatch, {mapped, parent}, [])

    await remove_devmapper(VM_HASH, "data")

    assert ["dmsetup", "remove", "--retry", "parent-image-ref"] not in commands


@pytest.mark.asyncio
async def test_remove_devmapper_runs_nothing_without_a_device_or_a_file(pools, commands):  # noqa: F811
    await remove_devmapper(VM_HASH, "data")

    assert commands == []


@pytest.mark.asyncio
async def test_remove_devmapper_detaches_a_stale_loop_without_a_dm_device(pools, commands):  # noqa: F811
    """A create interrupted between the losetup and the dmsetup create leaves
    a loop device on the volume file and no dm target above it."""
    backing = volume(pools["pool0"], VM_HASH, "data.btrfs")

    await remove_devmapper(VM_HASH, "data")

    assert commands == [
        ["losetup", "-j", str(backing)],
        ["losetup", "-d", "/dev/loop7"],
        ["losetup", "-d", "/dev/loop9"],
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("volume_name", ["data.1", "my data"])
async def test_remove_devmapper_tears_down_an_awkward_but_valid_name(
    pools,  # noqa: F811
    commands,
    monkeypatch,
    volume_name,
):
    """dmsetup only rejects "/", "." and ".."; a volume named "data.1" or
    "my data" creates fine, so it has to tear down fine too."""
    backing = volume(pools["pool0"], VM_HASH, f"{volume_name}.btrfs")  # noqa: F811
    mapped = Path("/dev/mapper") / f"{VM_HASH}_{volume_name}"
    _present_devices(monkeypatch, {mapped}, [])

    await remove_devmapper(VM_HASH, volume_name)

    assert ["dmsetup", "remove", "--retry", f"{VM_HASH}_{volume_name}"] in commands
    assert ["losetup", "-j", str(backing)] in commands


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "namespace, volume_name",
    [
        ("../../etc", "data"),  # not an item hash
        (VM_HASH, "a/b"),  # dmsetup rejects "/"
        (VM_HASH, "."),
        (VM_HASH, ".."),
        (VM_HASH, ""),
        (VM_HASH, "d" * 128),  # over the 127 byte device-mapper name limit
    ],
)
async def test_remove_devmapper_refuses_a_name_dmsetup_could_not_have_created(
    commands, monkeypatch, namespace, volume_name
):
    """A name that could never have been created is never composed into a
    dmsetup argument."""
    _present_devices(monkeypatch, set(), [])

    await remove_devmapper(namespace, volume_name)

    assert commands == []


@pytest.fixture
def live_mapper(mocker, monkeypatch):
    """A /dev/mapper whose contents `dmsetup remove` actually changes.

    The teardown decides what to remove from what is there and
    ``remove_devmapper`` decides whether the base device may go from what is
    left, so a static listing would not exercise either.
    """
    present: set[str] = set()
    commands: list[list[str]] = []
    mapper = Path(DEVICE_MAPPER_DIRECTORY)

    async def fake_run(command, check=True, stdin_input=None):
        command = [str(argument) for argument in command]
        commands.append(command)
        if command[:3] == ["dmsetup", "remove", "--retry"]:
            present.discard(command[3])
        return b""

    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(storage_module, "run_in_subprocess", fake_run)
    monkeypatch.setattr(
        Path,
        "is_block_device",
        lambda self: self.name in present if self.parent == mapper else real_is_block_device(self),
    )
    monkeypatch.setattr(
        Path,
        "glob",
        lambda self, pattern: (
            iter([mapper / name for name in sorted(present) if fnmatch(name, pattern)])
            if self == mapper
            else real_glob(self, pattern)
        ),
    )
    return {"present": present, "commands": commands}


@pytest.mark.asyncio
async def test_teardown_namespace_devices_removes_every_snapshot_then_the_base(pools, live_mapper):  # noqa: F811
    """The record-less inverse: a create that failed before its registry
    commit leaves these behind and no message names the volumes any more."""
    volume(pools["pool0"], VM_HASH, "rootfs.btrfs")
    volume(pools["pool0"], VM_HASH, "data.btrfs")
    live_mapper["present"].update({f"{VM_HASH}_rootfs", f"{VM_HASH}_data", f"{VM_HASH}_base"})

    await teardown_namespace_devices(VM_HASH)

    removed = [command[3] for command in live_mapper["commands"] if command[:2] == ["dmsetup", "remove"]]
    assert removed == [f"{VM_HASH}_data", f"{VM_HASH}_rootfs", f"{VM_HASH}_base"]
    assert live_mapper["present"] == set()


@pytest.mark.asyncio
async def test_teardown_namespace_devices_never_touches_another_vm(pools, live_mapper):  # noqa: F811
    live_mapper["present"].update({f"{VM_HASH}_rootfs", f"{OTHER_HASH}_rootfs", f"{OTHER_HASH}_base"})

    await teardown_namespace_devices(VM_HASH)

    assert live_mapper["present"] == {f"{OTHER_HASH}_rootfs", f"{OTHER_HASH}_base"}


@pytest.mark.asyncio
async def test_teardown_namespace_devices_refuses_an_implausible_namespace(live_mapper):
    with pytest.raises(ValueError):
        await teardown_namespace_devices("../../etc")

    assert live_mapper["commands"] == []


@pytest.mark.asyncio
async def test_a_failing_snapshot_removal_does_not_stop_the_others(pools, live_mapper, mocker):  # noqa: F811
    """Best effort, one volume at a time: a dm target that refuses to go must
    not strand the volumes that would have."""
    live_mapper["present"].update({f"{VM_HASH}_data", f"{VM_HASH}_rootfs"})
    calls: list[str] = []

    async def refuse_one(namespace, volume_name):
        calls.append(volume_name)
        if volume_name == "data":
            msg = "device busy"
            raise RuntimeError(msg)

    mocker.patch("aleph.vm.agent.vm.retire.remove_devmapper", side_effect=refuse_one)

    await teardown_namespace_devices(VM_HASH)

    assert calls == ["data", "rootfs"]
