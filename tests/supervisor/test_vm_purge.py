"""Agent-side deallocation of a VM's storage (src/aleph/vm/agent/vm/purge.py).

The agent allocates every volume and hands the supervisor resolved paths, so
the agent is the side that deletes them. These tests pin that ownership: what
a purge covers, what it must never reach, and that a purged volume is
recreated at the same path (the reinstall round trip).
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from aleph_message.models import InstanceContent, ProgramContent

import aleph.vm.storage_pools as storage_pools_module
from aleph.vm.agent.vm.purge import (
    iter_volume_files,
    purge_vm_storage,
    purge_vm_volumes,
)
from aleph.vm.conf import settings
from aleph.vm.storage_pools import (
    MediaClass,
    StoragePool,
    pin_layout,
    reset_pools,
    volume_path_for,
)
from aleph.vm.supervisor_interface.errors import VmSetupError

VM_HASH = "cafe" * 16  # 64 hex chars, the shape of an item hash
OTHER_HASH = "beef" * 16


@pytest.fixture
def pools(tmp_path, monkeypatch):
    """Two volume pools plus a runtime cache and a session directory."""
    execution_root = tmp_path / "execution"
    pool0 = execution_root / "volumes" / "persistent"
    pool1 = tmp_path / "mnt" / "nvme1"
    sessions = execution_root / "sessions"
    runtime_cache = tmp_path / "cache" / "runtime"
    for directory in (pool0, pool1, sessions, runtime_cache):
        directory.mkdir(parents=True)
    monkeypatch.setattr(settings, "EXECUTION_ROOT", execution_root)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", pool0)
    monkeypatch.setattr(settings, "CONFIDENTIAL_SESSION_DIRECTORY", sessions)
    monkeypatch.setattr(settings, "RUNTIME_CACHE", runtime_cache)
    monkeypatch.setattr(
        storage_pools_module,
        "_pools",
        [
            StoragePool(path=pool0, media_class=MediaClass.SSD, index=0),
            StoragePool(path=pool1, media_class=MediaClass.NVME, index=1),
        ],
    )
    yield {"pool0": pool0, "pool1": pool1, "sessions": sessions, "runtime_cache": runtime_cache}
    reset_pools()


def _volume(pool: Path, namespace: str, filename: str) -> Path:
    directory = pool / namespace
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_bytes(b"x")
    return path


def test_purge_volumes_spans_every_pool(pools):
    rootfs = _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    data = _volume(pools["pool1"], VM_HASH, "data.ext4")

    assert len(purge_vm_volumes(VM_HASH)) == 2

    assert not rootfs.exists()
    assert not data.exists()


def test_purge_volumes_can_keep_the_data_volumes(pools):
    """The reinstall path's ?erase_volumes=false: the rootfs is reset, the
    user's data volumes survive."""
    rootfs = _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    data = _volume(pools["pool0"], VM_HASH, "data.ext4")

    assert len(purge_vm_volumes(VM_HASH, include_data_volumes=False)) == 1

    assert not rootfs.exists()
    assert data.exists()


def test_purge_volumes_can_keep_the_rootfs(pools):
    rootfs = _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    data = _volume(pools["pool0"], VM_HASH, "data.ext4")

    assert len(purge_vm_volumes(VM_HASH, include_rootfs=False)) == 1

    assert rootfs.exists()
    assert not data.exists()


def test_purge_never_reaches_the_shared_runtime_cache(pools):
    """A program's rootfs path IS the shared runtime cache entry, so the
    supervisor could not safely delete it. The agent's purge is scoped to
    {pool}/{vm_hash}/, which cannot name a cache file at all."""
    runtime = pools["runtime_cache"] / "some-runtime-ref"
    runtime.write_bytes(b"squashfs")
    _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")

    purge_vm_storage(VM_HASH)

    assert runtime.exists()


def test_purge_never_reaches_another_vm(pools):
    mine = _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    theirs = _volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")

    purge_vm_storage(VM_HASH)

    assert not mine.exists()
    assert theirs.exists()


def test_purge_storage_removes_the_directories_and_session_dir(pools):
    _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _volume(pools["pool1"], VM_HASH, "data.ext4")
    session_dir = pools["sessions"] / VM_HASH
    session_dir.mkdir(parents=True)
    (session_dir / "vm_session.b64").write_bytes(b"session")

    purge_vm_storage(VM_HASH)

    assert not (pools["pool0"] / VM_HASH).exists()
    assert not (pools["pool1"] / VM_HASH).exists()
    assert not session_dir.exists()


def test_purge_is_idempotent(pools):
    assert purge_vm_storage(VM_HASH) == 0
    assert purge_vm_storage(VM_HASH) == 0


@pytest.mark.parametrize("namespace", ["..", "../../etc", "", "a/b", "short"])
def test_purge_refuses_an_implausible_namespace(pools, namespace):
    """A delete path must never join an unvalidated string onto a pool path."""
    with pytest.raises(ValueError):
        purge_vm_volumes(namespace)


def test_only_regular_files_directly_in_the_directory_are_volumes(pools):
    _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    nested = pools["pool0"] / VM_HASH / "subdir"
    nested.mkdir()
    (nested / "not-a-volume").write_bytes(b"x")

    assert [path.name for path in iter_volume_files(VM_HASH)] == ["rootfs.qcow2"]


def test_purged_volumes_are_rebuilt_on_the_pools_they_came_from(pools):
    """The reinstall round trip. Placement is per volume, so a VM can span
    pools; after the purge each volume must return to its own pool, since
    the running VM's spec still names those exact paths."""
    rootfs = _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    data = _volume(pools["pool1"], VM_HASH, "data.qcow2")

    deleted = purge_vm_volumes(VM_HASH)
    assert sorted(deleted) == sorted([rootfs, data])

    with pin_layout(VM_HASH, deleted):
        assert volume_path_for(VM_HASH, "rootfs.qcow2", size_mib=1) == rootfs
        assert volume_path_for(VM_HASH, "data.qcow2", size_mib=1) == data
        # A volume the VM never had is not pinned and places normally.
        fresh = volume_path_for(VM_HASH, "new.qcow2", size_mib=1)
        assert fresh.parent.parent in (pools["pool0"], pools["pool1"])

    # Outside the context nothing is pinned any more.
    assert VM_HASH not in storage_pools_module._pinned_layouts.get()


def test_a_volume_still_held_by_device_mapper_is_not_deleted(pools, monkeypatch, caplog):
    """A parent-backed (.btrfs) volume whose dm target is still present must
    not be unlinked: the loop device would pin the inode (no space freed) and
    create_devmapper would skip the rebuild (no reset). Fail loud instead."""
    held = _volume(pools["pool0"], VM_HASH, "data.btrfs")
    free = _volume(pools["pool0"], VM_HASH, "other.ext4")
    dm_path = Path("/dev/mapper") / f"{VM_HASH}_data"
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self == dm_path or real_is_block_device(self))

    assert len(purge_vm_volumes(VM_HASH)) == 1

    assert held.exists()
    assert not free.exists()
    assert "device-mapper target is still present" in caplog.text


# ---------------------------------------------------------------------------
# recreate_vm_volumes: the rebuild half of the reinstall round trip
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recreate_dispatches_an_instance_to_the_qemu_downloader(mocker):
    from aleph.vm.agent.vm import downloader

    qemu = mocker.patch.object(downloader, "QemuDownloader")
    qemu.return_value.download_all = AsyncMock()
    content = mocker.MagicMock(spec=InstanceContent)

    await downloader.recreate_vm_volumes(content, VM_HASH)

    qemu.assert_called_once_with(content, VM_HASH)
    qemu.return_value.download_all.assert_awaited_once()


@pytest.mark.asyncio
async def test_recreate_dispatches_a_program_to_the_program_downloader(mocker):
    from aleph.vm.agent.vm import downloader

    program = mocker.patch.object(downloader, "ProgramDownloader")
    program.return_value.download_all = AsyncMock()
    content = mocker.MagicMock(spec=ProgramContent)

    await downloader.recreate_vm_volumes(content, VM_HASH)

    program.assert_called_once_with(content, VM_HASH)
    program.return_value.download_all.assert_awaited_once()


@pytest.mark.asyncio
async def test_recreate_refuses_anything_else():
    from aleph.vm.agent.vm.downloader import recreate_vm_volumes

    with pytest.raises(VmSetupError):
        await recreate_vm_volumes(object(), VM_HASH)  # type: ignore[arg-type]


def test_erase_leaves_a_directory_that_still_holds_a_dm_backed_volume(pools, monkeypatch, caplog):
    """The full erase must not rmtree its way around the device-mapper guard."""
    held = _volume(pools["pool0"], VM_HASH, "data.btrfs")
    other_pool_dir = _volume(pools["pool1"], VM_HASH, "extra.ext4").parent
    dm_path = Path("/dev/mapper") / f"{VM_HASH}_data"
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self == dm_path or real_is_block_device(self))

    purge_vm_storage(VM_HASH)

    assert held.exists()
    assert held.parent.exists(), "the directory holding the dm-backed volume must survive"
    assert not other_pool_dir.exists(), "directories with nothing held are still removed"
    assert "still holds device-mapper-backed volumes" in caplog.text


def test_purge_side_dirs_leaves_the_volumes(pools):
    from aleph.vm.agent.vm.purge import purge_vm_side_dirs

    rootfs = _volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    session_dir = pools["sessions"] / VM_HASH
    session_dir.mkdir(parents=True)

    purge_vm_side_dirs(VM_HASH)

    assert rootfs.exists()
    assert not session_dir.exists()
