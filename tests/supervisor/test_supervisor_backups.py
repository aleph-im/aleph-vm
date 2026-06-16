"""BackupOps on InProcessSupervisor: archive lifecycle over the real tar
machinery, with the qemu-img calls stubbed out."""

from __future__ import annotations

import asyncio
import tarfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from test_supervisor_inprocess_query import FakePool, FakeSystemd, make_execution

from aleph.vm.controllers.qemu import backup as backup_module
from aleph.vm.supervisor.errors import (
    BackupNotFoundError,
    InternalSupervisorError,
    InvalidBackendError,
    NotImplementedSupervisorError,
    VmNotFoundError,
)
from aleph.vm.supervisor.inprocess import InProcessSupervisor
from aleph.vm.supervisor.types import BackupId, BackupStatus, VmId, VmStatus

VM_ID = VmId("itemhash123")


@pytest.fixture
def backup_dir(tmp_path, monkeypatch) -> Path:
    backups = tmp_path / "backups"
    monkeypatch.setattr(backup_module.settings, "BACKUP_DIRECTORY", backups)
    return backups


@pytest.fixture
def quiet_qemu_img(monkeypatch):
    """Stub the qemu-img invocations; everything else stays real."""

    async def fake_disk_backup(vm_hash: str, source_disk_path: Path, destination_dir: Path) -> Path:
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr("aleph.vm.supervisor.inprocess.create_qemu_disk_backup", fake_disk_backup)
    monkeypatch.setattr("aleph.vm.supervisor.inprocess.verify_qemu_disk", noop)
    monkeypatch.setattr("aleph.vm.supervisor.inprocess.check_disk_space_for_multiple", noop)


def _qemu_execution(tmp_path, *, running=True, persistent=True):
    execution = make_execution(running=running)
    execution.persistent = persistent
    rootfs = tmp_path / "vm-rootfs.qcow2"
    rootfs.write_bytes(b"ORIGINAL-ROOTFS-BYTES" * 64)
    execution.vm.resources = SimpleNamespace(rootfs_path=rootfs)
    return execution


def _pool_for(execution, *, running=True):
    return FakePool(
        executions={str(execution.vm_hash): execution},
        systemd=FakeSystemd({execution.controller_service: running}),
    )


async def _finished_backup(supervisor) -> None:
    task = supervisor._backup_tasks.get(VM_ID)
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
# start_backup / get_backup_status / list_backups
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_backup_unknown_vm_raises(backup_dir):
    sup = InProcessSupervisor(pool=FakePool(executions={}))
    with pytest.raises(VmNotFoundError):
        await sup.start_backup(VmId("missing"))


@pytest.mark.asyncio
async def test_start_backup_firecracker_vm_is_invalid_backend(backup_dir, tmp_path):
    execution = make_execution(running=True, hypervisor=None)
    execution.is_program = True
    sup = InProcessSupervisor(pool=_pool_for(execution))
    with pytest.raises(InvalidBackendError):
        await sup.start_backup(VM_ID)


@pytest.mark.asyncio
async def test_start_backup_creates_archive_and_completes(backup_dir, tmp_path, quiet_qemu_img):
    execution = _qemu_execution(tmp_path)
    sup = InProcessSupervisor(pool=_pool_for(execution))

    job = await sup.start_backup(VM_ID)
    assert job.status is BackupStatus.RUNNING
    assert job.backup_id.startswith(f"{VM_ID}-")
    assert job.vm_id == VM_ID

    await _finished_backup(sup)

    info = await sup.get_backup_status(VM_ID, job.backup_id)
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

    listed = await sup.list_backups(VM_ID)
    assert [b.backup_id for b in listed] == [job.backup_id]
    listed_all = await sup.list_backups()
    assert [b.backup_id for b in listed_all] == [job.backup_id]


@pytest.mark.asyncio
async def test_start_backup_is_idempotent_while_running(backup_dir, tmp_path, quiet_qemu_img, monkeypatch):
    execution = _qemu_execution(tmp_path)
    sup = InProcessSupervisor(pool=_pool_for(execution))
    release = asyncio.Event()

    async def blocking_disk_backup(vm_hash: str, source_disk_path: Path, destination_dir: Path) -> Path:
        await release.wait()
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    monkeypatch.setattr("aleph.vm.supervisor.inprocess.create_qemu_disk_backup", blocking_disk_backup)

    first = await sup.start_backup(VM_ID)
    await asyncio.sleep(0)
    second = await sup.start_backup(VM_ID)
    assert second.backup_id == first.backup_id
    assert second.status is BackupStatus.RUNNING

    release.set()
    await _finished_backup(sup)
    info = await sup.get_backup_status(VM_ID, first.backup_id)
    assert info.status is BackupStatus.COMPLETE


@pytest.mark.asyncio
async def test_start_backup_returns_existing_fresh_archive(backup_dir, tmp_path, quiet_qemu_img):
    execution = _qemu_execution(tmp_path)
    sup = InProcessSupervisor(pool=_pool_for(execution))
    existing = _make_archive(backup_dir, f"{VM_ID}-20260611T000000Z")

    info = await sup.start_backup(VM_ID)

    assert info.status is BackupStatus.COMPLETE
    assert info.backup_id == existing.stem
    assert VM_ID not in sup._backup_tasks  # no new job spawned


@pytest.mark.asyncio
async def test_backup_failure_is_reported_and_superseded(backup_dir, tmp_path, quiet_qemu_img, monkeypatch):
    execution = _qemu_execution(tmp_path)
    sup = InProcessSupervisor(pool=_pool_for(execution))

    async def exploding_disk_backup(vm_hash, source_disk_path, destination_dir):
        raise RuntimeError("qemu-img exploded")

    monkeypatch.setattr("aleph.vm.supervisor.inprocess.create_qemu_disk_backup", exploding_disk_backup)
    failed_job = await sup.start_backup(VM_ID)
    await _finished_backup(sup)

    info = await sup.get_backup_status(VM_ID, failed_job.backup_id)
    assert info.status is BackupStatus.FAILED
    assert "qemu-img exploded" in info.error_message
    assert [b.backup_id for b in await sup.list_backups(VM_ID)] == [failed_job.backup_id]

    # A new (successful) run supersedes the failed record.
    async def fresh_disk_backup(vm_hash, source_disk_path, destination_dir):
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    monkeypatch.setattr("aleph.vm.supervisor.inprocess.create_qemu_disk_backup", fresh_disk_backup)
    new_job = await sup.start_backup(VM_ID)
    assert new_job.backup_id != failed_job.backup_id
    await _finished_backup(sup)
    with pytest.raises(BackupNotFoundError):
        await sup.get_backup_status(VM_ID, failed_job.backup_id)


@pytest.mark.asyncio
async def test_quiesce_guest_freezes_and_thaws(backup_dir, tmp_path, quiet_qemu_img, monkeypatch):
    execution = _qemu_execution(tmp_path)
    sup = InProcessSupervisor(pool=_pool_for(execution))
    client = MagicMock(guest_fsfreeze_thaw=AsyncMock())
    freeze = AsyncMock(return_value=(client, True))
    monkeypatch.setattr(sup, "_try_fsfreeze", freeze)

    await sup.start_backup(VM_ID, quiesce_guest=True)
    await _finished_backup(sup)

    freeze.assert_awaited_once()
    client.guest_fsfreeze_thaw.assert_awaited_once()
    info = await sup.get_backup_status(VM_ID, (await sup.list_backups(VM_ID))[0].backup_id)
    assert info.status is BackupStatus.COMPLETE


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_id", ["", "../etc/passwd", "othervm-20260611T000000Z", "itemhash123/../x"])
async def test_backup_ids_are_validated(backup_dir, bad_id):
    sup = InProcessSupervisor(pool=FakePool(executions={}))
    with pytest.raises(BackupNotFoundError):
        await sup.get_backup_status(VM_ID, BackupId(bad_id))
    with pytest.raises(BackupNotFoundError):
        await sup.delete_backup(VM_ID, BackupId(bad_id))


@pytest.mark.asyncio
async def test_get_backup_status_unknown_id_raises(backup_dir):
    sup = InProcessSupervisor(pool=FakePool(executions={}))
    with pytest.raises(BackupNotFoundError):
        await sup.get_backup_status(VM_ID, BackupId(f"{VM_ID}-20990101T000000Z"))


# ---------------------------------------------------------------------------
# download_backup / delete_backup
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_download_backup_streams_chunks_with_offsets(backup_dir):
    sup = InProcessSupervisor(pool=FakePool(executions={}))
    content = bytes(range(256)) * 4096 * 2 + b"tail"  # 2 MiB + 4 bytes
    backup_id = f"{VM_ID}-20260611T000000Z"
    backup_dir.mkdir(parents=True)
    (backup_dir / f"{backup_id}.tar").write_bytes(content)

    chunks = [chunk async for chunk in sup.download_backup(VM_ID, BackupId(backup_id))]

    assert [c.offset for c in chunks] == [0, 1024 * 1024, 2 * 1024 * 1024]
    assert b"".join(c.data for c in chunks) == content


@pytest.mark.asyncio
async def test_download_backup_unknown_id_raises(backup_dir):
    sup = InProcessSupervisor(pool=FakePool(executions={}))
    with pytest.raises(BackupNotFoundError):
        async for _ in sup.download_backup(VM_ID, BackupId(f"{VM_ID}-20990101T000000Z")):
            pass


@pytest.mark.asyncio
async def test_delete_backup_removes_archive_and_sidecars(backup_dir):
    sup = InProcessSupervisor(pool=FakePool(executions={}))
    backup_id = f"{VM_ID}-20260611T000000Z"
    tar_path = _make_archive(backup_dir, backup_id)
    tar_path.with_suffix(".tar.sha256").write_text("digest  file\n")
    tar_path.with_suffix(".tar.meta.json").write_text("{}")

    await sup.delete_backup(VM_ID, BackupId(backup_id))

    assert not tar_path.exists()
    assert not tar_path.with_suffix(".tar.sha256").exists()
    assert not tar_path.with_suffix(".tar.meta.json").exists()
    with pytest.raises(BackupNotFoundError):
        await sup.delete_backup(VM_ID, BackupId(backup_id))


@pytest.mark.asyncio
async def test_delete_backup_refuses_running_job(backup_dir, tmp_path, quiet_qemu_img, monkeypatch):
    execution = _qemu_execution(tmp_path)
    sup = InProcessSupervisor(pool=_pool_for(execution))
    release = asyncio.Event()

    async def blocking_disk_backup(vm_hash, source_disk_path, destination_dir):
        await release.wait()
        dest = destination_dir / f"{vm_hash}-disk-copy.qcow2"
        dest.write_bytes(source_disk_path.read_bytes())
        return dest

    monkeypatch.setattr("aleph.vm.supervisor.inprocess.create_qemu_disk_backup", blocking_disk_backup)
    job = await sup.start_backup(VM_ID)

    with pytest.raises(InternalSupervisorError):
        await sup.delete_backup(VM_ID, job.backup_id)

    release.set()
    await _finished_backup(sup)
    await sup.delete_backup(VM_ID, job.backup_id)  # gone once complete


# ---------------------------------------------------------------------------
# restore_backup
# ---------------------------------------------------------------------------


def _restorable_supervisor(backup_dir, tmp_path, monkeypatch):
    execution = _qemu_execution(tmp_path)
    pool = _pool_for(execution)
    pool.stop_vm = AsyncMock()
    pool.restart_persistent_vm = AsyncMock()
    sup = InProcessSupervisor(pool=pool)

    async def noop(*args, **kwargs):
        return None

    monkeypatch.setattr("aleph.vm.supervisor.inprocess.verify_qemu_disk", noop)
    return sup, pool, execution


@pytest.mark.asyncio
async def test_restore_backup_swaps_rootfs_and_restarts(backup_dir, tmp_path, monkeypatch):
    sup, pool, execution = _restorable_supervisor(backup_dir, tmp_path, monkeypatch)
    sup._emit_event = MagicMock()
    backup_id = f"{VM_ID}-20260611T000000Z"
    _make_archive(backup_dir, backup_id, content=b"RESTORED-ROOTFS")
    rootfs = Path(execution.vm.resources.rootfs_path)

    info = await sup.restore_backup(VM_ID, BackupId(backup_id))

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    pool.restart_persistent_vm.assert_awaited_once_with(execution)
    assert rootfs.read_bytes() == b"RESTORED-ROOTFS"
    # The previous rootfs is kept for manual reversal.
    pre_restore = list(rootfs.parent.glob("*.pre-restore-*.qcow2"))
    assert len(pre_restore) == 1
    assert pre_restore[0].read_bytes().startswith(b"ORIGINAL-ROOTFS-BYTES")
    # The extraction staging file is cleaned up.
    assert not list(backup_dir.glob("*.restore.qcow2"))
    assert info.status is VmStatus.RUNNING
    emitted = [(call.args[1], call.args[2]) for call in sup._emit_event.call_args_list]
    assert emitted == [(VmStatus.RUNNING, VmStatus.STOPPED), (VmStatus.STOPPED, VmStatus.RUNNING)]


@pytest.mark.asyncio
async def test_restore_backup_unknown_backup_raises(backup_dir, tmp_path, monkeypatch):
    sup, _, _ = _restorable_supervisor(backup_dir, tmp_path, monkeypatch)
    with pytest.raises(BackupNotFoundError):
        await sup.restore_backup(VM_ID, BackupId(f"{VM_ID}-20990101T000000Z"))


@pytest.mark.asyncio
async def test_restore_backup_requires_persistent_vm(backup_dir, tmp_path, monkeypatch):
    execution = _qemu_execution(tmp_path, persistent=False)
    sup = InProcessSupervisor(pool=_pool_for(execution))
    backup_id = f"{VM_ID}-20260611T000000Z"
    _make_archive(backup_dir, backup_id)
    with pytest.raises(NotImplementedSupervisorError):
        await sup.restore_backup(VM_ID, BackupId(backup_id))


@pytest.mark.asyncio
async def test_restore_backup_rejects_archive_without_rootfs_member(backup_dir, tmp_path, monkeypatch):
    sup, pool, execution = _restorable_supervisor(backup_dir, tmp_path, monkeypatch)
    backup_id = f"{VM_ID}-20260611T000000Z"
    _make_archive(backup_dir, backup_id, member="something-else.qcow2")
    rootfs = Path(execution.vm.resources.rootfs_path)
    original = rootfs.read_bytes()

    with pytest.raises(InternalSupervisorError):
        await sup.restore_backup(VM_ID, BackupId(backup_id))

    pool.stop_vm.assert_not_awaited()
    assert rootfs.read_bytes() == original
    assert not list(backup_dir.glob("*.restore.qcow2"))
