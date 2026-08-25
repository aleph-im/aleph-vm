"""The agent's BackupManager (src/aleph/vm/agent/vm/backup.py): the archive
lifecycle over the real tar machinery with the qemu-img calls stubbed out,
and the supervisor reduced to quiescence (freeze/thaw) plus stop/start."""

from __future__ import annotations

import asyncio
import subprocess
import tarfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

import aleph.vm.storage_pools as storage_pools_module
from aleph.vm.agent.vm import backup as backup_module
from aleph.vm.agent.vm.backup import BackupManager, vm_disks
from aleph.vm.backup import staging as staging_module
from aleph.vm.backup.types import (
    BackupId,
    BackupInProgressError,
    BackupNotFoundError,
    BackupNotSupportedError,
    BackupStatus,
    InvalidRestoreImageError,
)
from aleph.vm.conf import settings
from aleph.vm.storage_pools import MediaClass, StoragePool, reset_pools
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId, VmStatus

VM_HASH = "cafe" * 16
OTHER_HASH = "beef" * 16


@pytest.fixture
def pools(tmp_path, monkeypatch):
    """Two volume pools, so a VM's disks can span them."""
    pool0 = tmp_path / "volumes" / "persistent"
    pool1 = tmp_path / "mnt" / "nvme1"
    for directory in (pool0, pool1):
        directory.mkdir(parents=True)
    monkeypatch.setattr(settings, "EXECUTION_ROOT", tmp_path)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", pool0)
    monkeypatch.setattr(
        storage_pools_module,
        "_pools",
        [
            StoragePool(path=pool0, media_class=MediaClass.SSD, index=0),
            StoragePool(path=pool1, media_class=MediaClass.NVME, index=1),
        ],
    )
    yield {"pool0": pool0, "pool1": pool1}
    reset_pools()


@pytest.fixture
def backup_dir(tmp_path, monkeypatch) -> Path:
    backups = tmp_path / "backups"
    monkeypatch.setattr(staging_module.settings, "BACKUP_DIRECTORY", backups)
    return backups


@pytest.fixture
def quiet_qemu_img(monkeypatch):
    """Stub the qemu-img invocations; everything else stays real."""

    async def fake_disk_backup(vm_hash: str, source_disk_path: Path, destination_dir: Path) -> Path:
        dest = destination_dir / f"{vm_hash}-{source_disk_path.stem}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr(backup_module, "create_qemu_disk_backup", fake_disk_backup)
    monkeypatch.setattr(backup_module, "verify_qemu_disk", noop)
    monkeypatch.setattr(backup_module, "check_disk_space_for_multiple", noop)


def _volume(pool: Path, namespace: str, filename: str, content: bytes = b"x") -> Path:
    directory = pool / namespace
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / filename
    path.write_bytes(content)
    return path


def _rootfs(pools, content: bytes = b"ORIGINAL-ROOTFS-BYTES" * 64) -> Path:
    return _volume(pools["pool0"], VM_HASH, "rootfs.qcow2", content)


def _supervisor(status: VmStatus = VmStatus.RUNNING, *, frozen: bool = True) -> MagicMock:
    info = MagicMock(status=status)
    return MagicMock(
        get_vm=AsyncMock(return_value=info),
        stop_vm=AsyncMock(),
        start_vm=AsyncMock(),
        freeze_guest=AsyncMock(return_value=frozen),
        thaw_guest=AsyncMock(),
    )


async def _finished(manager: BackupManager) -> None:
    task = manager._tasks.get(VM_HASH)
    if task is not None:
        await task


def _make_archive(backup_dir: Path, backup_id: str, member: str = "rootfs.qcow2", content: bytes = b"RESTORED") -> Path:
    backup_dir.mkdir(parents=True, exist_ok=True)
    payload = backup_dir / "payload.qcow2"
    payload.write_bytes(content)
    tar_path = backup_dir / f"{backup_id}.tar"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(str(payload), arcname=member)
    payload.unlink()
    return tar_path


# ---------------------------------------------------------------------------
# vm_disks: what a backup copies
# ---------------------------------------------------------------------------


def test_vm_disks_finds_the_rootfs_and_the_writable_volumes(pools):
    rootfs = _rootfs(pools)
    data = _volume(pools["pool1"], VM_HASH, "data.ext4")

    only_rootfs = vm_disks(VM_HASH, include_volumes=False)
    assert only_rootfs.rootfs == rootfs
    assert only_rootfs.members == {"rootfs.qcow2": rootfs}

    with_volumes = vm_disks(VM_HASH, include_volumes=True)
    assert with_volumes.members == {"rootfs.qcow2": rootfs, "data.qcow2": data}


def test_vm_disks_reads_a_device_mapper_volume_through_its_device(pools, monkeypatch):
    """A parent-backed volume's file is only the snapshot's copy-on-write
    store; the volume's content is the mapped device."""
    _rootfs(pools)
    _volume(pools["pool0"], VM_HASH, "data.btrfs")
    dm_path = Path("/dev/mapper") / f"{VM_HASH}_data"
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self == dm_path or real_is_block_device(self))

    disks = vm_disks(VM_HASH, include_volumes=True)

    assert disks.members["data.qcow2"] == dm_path


def test_vm_disks_refuses_a_vm_without_a_rootfs_image(pools):
    """A program boots the shared runtime cache file; there is nothing of
    its own to back up."""
    _volume(pools["pool0"], VM_HASH, "data.ext4")
    with pytest.raises(BackupNotSupportedError):
        vm_disks(VM_HASH, include_volumes=True)


def test_vm_disks_never_sees_another_vm(pools):
    _rootfs(pools)
    _volume(pools["pool0"], OTHER_HASH, "theirs.ext4")

    disks = vm_disks(VM_HASH, include_volumes=True)

    assert "theirs.qcow2" not in disks.members


# ---------------------------------------------------------------------------
# start_backup / get_backup_status / list_backups
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_backup_without_rootfs_is_not_supported(pools, backup_dir):
    manager = BackupManager(_supervisor())
    with pytest.raises(BackupNotSupportedError):
        await manager.start_backup(VM_HASH)


@pytest.mark.asyncio
async def test_start_backup_creates_archive_and_completes(pools, backup_dir, quiet_qemu_img):
    _rootfs(pools)
    manager = BackupManager(_supervisor())

    job = await manager.start_backup(VM_HASH)
    assert job.status is BackupStatus.RUNNING
    assert job.backup_id.startswith(f"{VM_HASH}-")
    assert job.vm_hash == VM_HASH

    await _finished(manager)

    info = manager.get_backup_status(VM_HASH, job.backup_id)
    assert info.status is BackupStatus.COMPLETE
    assert info.size_bytes > 0
    assert info.created_at_unix_secs > 0

    tar_path = backup_dir / f"{job.backup_id}.tar"
    assert tar_path.exists()
    assert tar_path.with_suffix(".tar.sha256").exists()
    assert tar_path.with_suffix(".tar.meta.json").exists()
    with tarfile.open(tar_path) as tar:
        assert [m.name for m in tar.getmembers()] == ["rootfs.qcow2"]
    # The intermediate qcow2 copy is removed once archived.
    assert not list(backup_dir.glob("*-disk-copy.qcow2"))

    assert [b.backup_id for b in manager.list_backups(VM_HASH)] == [job.backup_id]
    assert [b.backup_id for b in manager.list_backups()] == [job.backup_id]


@pytest.mark.asyncio
async def test_completed_backup_info_carries_metadata(pools, backup_dir, quiet_qemu_img):
    """get_backup_status surfaces checksum, volumes and source_sizes so the
    views can build the HTTP body and the download sidecar headers."""
    rootfs = _rootfs(pools)
    manager = BackupManager(_supervisor())

    job = await manager.start_backup(VM_HASH)
    await _finished(manager)

    info = manager.get_backup_status(VM_HASH, job.backup_id)
    assert info.status is BackupStatus.COMPLETE
    assert info.checksum.startswith("sha256:")
    assert info.volumes == ["rootfs.qcow2"]
    assert info.source_sizes == {"rootfs.qcow2": rootfs.stat().st_size}


@pytest.mark.asyncio
async def test_start_backup_include_volumes_archives_the_data_volumes(pools, backup_dir, quiet_qemu_img):
    _rootfs(pools)
    _volume(pools["pool1"], VM_HASH, "data.ext4", b"DATA-VOLUME-BYTES" * 16)
    manager = BackupManager(_supervisor())

    job = await manager.start_backup(VM_HASH, include_volumes=True)
    await _finished(manager)

    info = manager.get_backup_status(VM_HASH, job.backup_id)
    assert info.status is BackupStatus.COMPLETE
    assert set(info.volumes) == {"rootfs.qcow2", "data.qcow2"}
    with tarfile.open(backup_dir / f"{job.backup_id}.tar") as tar:
        assert {m.name for m in tar.getmembers()} == {"rootfs.qcow2", "data.qcow2"}


@pytest.mark.asyncio
async def test_start_backup_is_idempotent_while_running(pools, backup_dir, quiet_qemu_img, monkeypatch):
    _rootfs(pools)
    manager = BackupManager(_supervisor())
    release = asyncio.Event()

    async def blocking_disk_backup(vm_hash: str, source_disk_path: Path, destination_dir: Path) -> Path:
        await release.wait()
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    monkeypatch.setattr(backup_module, "create_qemu_disk_backup", blocking_disk_backup)

    first = await manager.start_backup(VM_HASH)
    await asyncio.sleep(0)
    second = await manager.start_backup(VM_HASH)
    assert second.backup_id == first.backup_id
    assert second.status is BackupStatus.RUNNING

    release.set()
    await _finished(manager)
    assert manager.get_backup_status(VM_HASH, first.backup_id).status is BackupStatus.COMPLETE


@pytest.mark.asyncio
async def test_start_backup_returns_existing_fresh_archive(pools, backup_dir, quiet_qemu_img):
    _rootfs(pools)
    manager = BackupManager(_supervisor())
    existing = _make_archive(backup_dir, f"{VM_HASH}-20260611T000000Z")

    info = await manager.start_backup(VM_HASH)

    assert info.status is BackupStatus.COMPLETE
    assert info.backup_id == existing.stem
    assert VM_HASH not in manager._tasks  # no new job spawned


@pytest.mark.asyncio
async def test_backup_failure_is_reported_and_superseded(pools, backup_dir, quiet_qemu_img, monkeypatch):
    _rootfs(pools)
    manager = BackupManager(_supervisor())

    async def exploding_disk_backup(vm_hash, source_disk_path, destination_dir):
        raise RuntimeError("qemu-img exploded")

    monkeypatch.setattr(backup_module, "create_qemu_disk_backup", exploding_disk_backup)
    failed_job = await manager.start_backup(VM_HASH)
    await _finished(manager)

    info = manager.get_backup_status(VM_HASH, failed_job.backup_id)
    assert info.status is BackupStatus.FAILED
    assert "qemu-img exploded" in info.error_message
    assert [b.backup_id for b in manager.list_backups(VM_HASH)] == [failed_job.backup_id]

    # A new (successful) run supersedes the failed record.
    async def fresh_disk_backup(vm_hash, source_disk_path, destination_dir):
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    monkeypatch.setattr(backup_module, "create_qemu_disk_backup", fresh_disk_backup)
    new_job = await manager.start_backup(VM_HASH)
    assert new_job.backup_id != failed_job.backup_id
    await _finished(manager)
    with pytest.raises(BackupNotFoundError):
        manager.get_backup_status(VM_HASH, failed_job.backup_id)


# ---------------------------------------------------------------------------
# Quiescence: the supervisor's only part in a backup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_quiesce_guest_freezes_and_thaws_around_the_copy(pools, backup_dir, quiet_qemu_img, monkeypatch):
    _rootfs(pools)
    supervisor = _supervisor(frozen=True)
    manager = BackupManager(supervisor)
    order: list[str] = []

    async def record_freeze(vm_id):
        order.append("freeze")
        return True

    async def record_thaw(vm_id):
        order.append("thaw")

    supervisor.freeze_guest.side_effect = record_freeze
    supervisor.thaw_guest.side_effect = record_thaw

    async def recording_disk_backup(vm_hash, source_disk_path, destination_dir):
        order.append("copy")
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    monkeypatch.setattr(backup_module, "create_qemu_disk_backup", recording_disk_backup)

    await manager.start_backup(VM_HASH, quiesce_guest=True)
    await _finished(manager)

    assert order == ["freeze", "copy", "thaw"]
    supervisor.freeze_guest.assert_awaited_once_with(VmId(VM_HASH))
    supervisor.thaw_guest.assert_awaited_once_with(VmId(VM_HASH))
    assert manager.list_backups(VM_HASH)[0].status is BackupStatus.COMPLETE


@pytest.mark.asyncio
async def test_guest_is_thawed_even_when_the_copy_fails(pools, backup_dir, quiet_qemu_img, monkeypatch):
    _rootfs(pools)
    supervisor = _supervisor(frozen=True)
    manager = BackupManager(supervisor)

    async def exploding_disk_backup(vm_hash, source_disk_path, destination_dir):
        raise RuntimeError("qemu-img exploded")

    monkeypatch.setattr(backup_module, "create_qemu_disk_backup", exploding_disk_backup)

    await manager.start_backup(VM_HASH, quiesce_guest=True)
    await _finished(manager)

    supervisor.thaw_guest.assert_awaited_once_with(VmId(VM_HASH))
    assert manager.list_backups(VM_HASH)[0].status is BackupStatus.FAILED


@pytest.mark.asyncio
async def test_no_thaw_when_the_guest_was_not_frozen(pools, backup_dir, quiet_qemu_img):
    """No guest agent (or the VM is unknown to the supervisor): the copy
    proceeds crash-consistent and nothing is thawed."""
    _rootfs(pools)
    supervisor = _supervisor(frozen=False)
    supervisor.freeze_guest.side_effect = VmNotFoundError(VM_HASH)
    manager = BackupManager(supervisor)

    await manager.start_backup(VM_HASH, quiesce_guest=True)
    await _finished(manager)

    supervisor.thaw_guest.assert_not_awaited()
    assert manager.list_backups(VM_HASH)[0].status is BackupStatus.COMPLETE


@pytest.mark.asyncio
async def test_skip_fsfreeze_never_asks_the_supervisor(pools, backup_dir, quiet_qemu_img):
    _rootfs(pools)
    supervisor = _supervisor()
    manager = BackupManager(supervisor)

    await manager.start_backup(VM_HASH, quiesce_guest=False)
    await _finished(manager)

    supervisor.freeze_guest.assert_not_awaited()
    supervisor.thaw_guest.assert_not_awaited()


# ---------------------------------------------------------------------------
# Archive registry: ids, download, delete
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("bad_id", ["", "../etc/passwd", "othervm-20260611T000000Z", f"{VM_HASH}/../x"])
def test_backup_ids_are_validated(backup_dir, bad_id):
    manager = BackupManager(_supervisor())
    with pytest.raises(BackupNotFoundError):
        manager.get_backup_status(VM_HASH, BackupId(bad_id))
    with pytest.raises(BackupNotFoundError):
        manager.delete_backup(VM_HASH, BackupId(bad_id))


def test_get_backup_status_unknown_id_raises(backup_dir):
    manager = BackupManager(_supervisor())
    with pytest.raises(BackupNotFoundError):
        manager.get_backup_status(VM_HASH, BackupId(f"{VM_HASH}-20990101T000000Z"))


@pytest.mark.asyncio
async def test_download_backup_streams_the_archive(backup_dir):
    manager = BackupManager(_supervisor())
    content = bytes(range(256)) * 4096 * 2 + b"tail"  # 2 MiB + 4 bytes
    backup_id = f"{VM_HASH}-20260611T000000Z"
    backup_dir.mkdir(parents=True)
    (backup_dir / f"{backup_id}.tar").write_bytes(content)

    chunks = [chunk async for chunk in manager.download_backup(VM_HASH, BackupId(backup_id))]

    assert [len(c) for c in chunks] == [1024 * 1024, 1024 * 1024, 4]
    assert b"".join(chunks) == content


@pytest.mark.asyncio
async def test_download_backup_unknown_id_raises(backup_dir):
    manager = BackupManager(_supervisor())
    with pytest.raises(BackupNotFoundError):
        async for _ in manager.download_backup(VM_HASH, BackupId(f"{VM_HASH}-20990101T000000Z")):
            pass


def test_delete_backup_removes_archive_and_sidecars(backup_dir):
    manager = BackupManager(_supervisor())
    backup_id = f"{VM_HASH}-20260611T000000Z"
    tar_path = _make_archive(backup_dir, backup_id)
    tar_path.with_suffix(".tar.sha256").write_text("digest  file\n")
    tar_path.with_suffix(".tar.meta.json").write_text("{}")

    manager.delete_backup(VM_HASH, BackupId(backup_id))

    assert not tar_path.exists()
    assert not tar_path.with_suffix(".tar.sha256").exists()
    assert not tar_path.with_suffix(".tar.meta.json").exists()
    with pytest.raises(BackupNotFoundError):
        manager.delete_backup(VM_HASH, BackupId(backup_id))


@pytest.mark.asyncio
async def test_delete_backup_refuses_running_job(pools, backup_dir, quiet_qemu_img, monkeypatch):
    _rootfs(pools)
    manager = BackupManager(_supervisor())
    release = asyncio.Event()

    async def blocking_disk_backup(vm_hash, source_disk_path, destination_dir):
        await release.wait()
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    monkeypatch.setattr(backup_module, "create_qemu_disk_backup", blocking_disk_backup)
    job = await manager.start_backup(VM_HASH)

    with pytest.raises(BackupInProgressError):
        manager.delete_backup(VM_HASH, job.backup_id)

    release.set()
    await _finished(manager)
    manager.delete_backup(VM_HASH, job.backup_id)  # gone once complete


def test_forget_drops_the_in_memory_state_but_not_the_archives(backup_dir):
    manager = BackupManager(_supervisor())
    tar_path = _make_archive(backup_dir, f"{VM_HASH}-20260611T000000Z")
    manager._jobs[BackupId(f"{VM_HASH}-failed")] = MagicMock(vm_hash=VM_HASH, status=BackupStatus.FAILED)
    manager._lock(VM_HASH)

    manager.forget(VM_HASH)

    assert manager._jobs == {}
    assert VM_HASH not in manager._locks
    assert tar_path.exists()


# ---------------------------------------------------------------------------
# restore_backup / restore_from_image: stop, swap the rootfs, start
# ---------------------------------------------------------------------------


@pytest.fixture
def quiet_verify(monkeypatch):
    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr(backup_module, "verify_qemu_disk", noop)


@pytest.mark.asyncio
async def test_restore_backup_swaps_rootfs_and_restarts(pools, backup_dir, quiet_verify):
    rootfs = _rootfs(pools)
    supervisor = _supervisor(VmStatus.RUNNING)
    manager = BackupManager(supervisor)
    backup_id = f"{VM_HASH}-20260611T000000Z"
    _make_archive(backup_dir, backup_id, content=b"RESTORED-ROOTFS")

    await manager.restore_backup(VM_HASH, BackupId(backup_id))

    supervisor.stop_vm.assert_awaited_once_with(VmId(VM_HASH))
    supervisor.start_vm.assert_awaited_once_with(VmId(VM_HASH))
    assert rootfs.read_bytes() == b"RESTORED-ROOTFS"
    # The previous rootfs is kept for manual reversal.
    pre_restore = list(rootfs.parent.glob("*.pre-restore-*.qcow2"))
    assert len(pre_restore) == 1
    assert pre_restore[0].read_bytes().startswith(b"ORIGINAL-ROOTFS-BYTES")
    # The extraction staging file is cleaned up.
    assert not list(backup_dir.glob("*.restore.qcow2"))


@pytest.mark.asyncio
async def test_restore_of_a_stopped_vm_does_not_stop_it_again(pools, backup_dir, quiet_verify):
    _rootfs(pools)
    supervisor = _supervisor(VmStatus.STOPPED)
    manager = BackupManager(supervisor)
    backup_id = f"{VM_HASH}-20260611T000000Z"
    _make_archive(backup_dir, backup_id)

    await manager.restore_backup(VM_HASH, BackupId(backup_id))

    supervisor.stop_vm.assert_not_awaited()
    supervisor.start_vm.assert_awaited_once_with(VmId(VM_HASH))


@pytest.mark.asyncio
async def test_restore_backup_unknown_backup_raises(pools, backup_dir, quiet_verify):
    _rootfs(pools)
    manager = BackupManager(_supervisor())
    with pytest.raises(BackupNotFoundError):
        await manager.restore_backup(VM_HASH, BackupId(f"{VM_HASH}-20990101T000000Z"))


@pytest.mark.asyncio
async def test_restore_backup_requires_a_rootfs_image(pools, backup_dir, quiet_verify):
    manager = BackupManager(_supervisor())
    backup_id = f"{VM_HASH}-20260611T000000Z"
    _make_archive(backup_dir, backup_id)
    with pytest.raises(BackupNotSupportedError):
        await manager.restore_backup(VM_HASH, BackupId(backup_id))


@pytest.mark.asyncio
async def test_restore_backup_rejects_archive_without_rootfs_member(pools, backup_dir, quiet_verify):
    rootfs = _rootfs(pools)
    supervisor = _supervisor()
    manager = BackupManager(supervisor)
    backup_id = f"{VM_HASH}-20260611T000000Z"
    _make_archive(backup_dir, backup_id, member="something-else.qcow2")
    original = rootfs.read_bytes()

    with pytest.raises(InvalidRestoreImageError):
        await manager.restore_backup(VM_HASH, BackupId(backup_id))

    supervisor.stop_vm.assert_not_awaited()
    assert rootfs.read_bytes() == original
    assert not list(backup_dir.glob("*.restore.qcow2"))


@pytest.mark.asyncio
async def test_restore_from_image_swaps_rootfs_and_restarts(pools, backup_dir, quiet_verify, monkeypatch, tmp_path):
    rootfs = _rootfs(pools)
    supervisor = _supervisor()
    manager = BackupManager(supervisor)
    monkeypatch.setattr(backup_module, "get_qemu_disk_virtual_size", AsyncMock(return_value=10))
    staged = tmp_path / "staged-upload.qcow2"
    staged.write_bytes(b"UPLOADED-ROOTFS")

    await manager.restore_from_image(VM_HASH, staged, max_virtual_size_bytes=100)

    supervisor.stop_vm.assert_awaited_once_with(VmId(VM_HASH))
    supervisor.start_vm.assert_awaited_once_with(VmId(VM_HASH))
    assert rootfs.read_bytes() == b"UPLOADED-ROOTFS"


@pytest.mark.asyncio
async def test_restore_from_image_rejects_oversized_disk(pools, backup_dir, quiet_verify, monkeypatch, tmp_path):
    rootfs = _rootfs(pools)
    supervisor = _supervisor()
    manager = BackupManager(supervisor)
    monkeypatch.setattr(backup_module, "get_qemu_disk_virtual_size", AsyncMock(return_value=1000))
    original = rootfs.read_bytes()
    staged = tmp_path / "staged-upload.qcow2"
    staged.write_bytes(b"TOO-BIG")

    with pytest.raises(InvalidRestoreImageError):
        await manager.restore_from_image(VM_HASH, staged, max_virtual_size_bytes=100)

    supervisor.stop_vm.assert_not_awaited()
    assert rootfs.read_bytes() == original


@pytest.mark.asyncio
async def test_restore_from_image_rejects_invalid_qcow2(pools, backup_dir, monkeypatch, tmp_path):
    """A non-QCOW2 upload makes qemu-img exit non-zero (CalledProcessError).
    That must surface as a client error (a 400), not a crash (a 500).
    Regression test for aleph-vm#948."""
    rootfs = _rootfs(pools)
    supervisor = _supervisor()
    manager = BackupManager(supervisor)
    original = rootfs.read_bytes()
    staged = tmp_path / "staged-upload.qcow2"
    staged.write_bytes(b"not-a-qcow2-image")

    async def boom(*args, **kwargs):
        raise subprocess.CalledProcessError(1, ["qemu-img", "check"])

    monkeypatch.setattr(backup_module, "verify_qemu_disk", boom)

    with pytest.raises(InvalidRestoreImageError):
        await manager.restore_from_image(VM_HASH, staged, max_virtual_size_bytes=100)

    supervisor.stop_vm.assert_not_awaited()
    assert rootfs.read_bytes() == original


@pytest.mark.asyncio
async def test_restore_from_image_of_an_unknown_vm_propagates_not_found(pools, backup_dir, quiet_verify, tmp_path):
    """The rootfs file exists on disk but the supervisor does not know the
    VM: the views turn this into a 404."""
    _rootfs(pools)
    supervisor = _supervisor()
    supervisor.get_vm.side_effect = VmNotFoundError(VM_HASH)
    manager = BackupManager(supervisor)
    staged = tmp_path / "staged.qcow2"
    staged.write_bytes(b"X")

    with pytest.raises(VmNotFoundError):
        await manager.restore_from_image(VM_HASH, staged)
