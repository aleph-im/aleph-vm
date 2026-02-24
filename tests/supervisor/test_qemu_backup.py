import json
import os
import subprocess
import tarfile
import time
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from aleph.vm.controllers.qemu.backup import (
    InsufficientDiskSpaceError,
    _sha256_file,
    backup_metadata,
    check_disk_space_for_multiple,
    cleanup_expired_backups,
    create_backup_archive,
    create_qemu_disk_backup,
    find_existing_backup,
    get_backup_directory,
    get_qemu_disk_virtual_size,
    restore_rootfs,
    verify_qemu_disk,
)

# --- get_backup_directory ---


def test_get_backup_directory_default(mocker, tmp_path):
    exec_root = tmp_path / "exec"
    exec_root.mkdir()
    mock_settings = mocker.patch("aleph.vm.controllers.qemu.backup.settings")
    mock_settings.BACKUP_DIRECTORY = None
    mock_settings.EXECUTION_ROOT = exec_root

    result = get_backup_directory()

    assert result == exec_root / "backups"
    assert result.is_dir()


def test_get_backup_directory_custom(mocker, tmp_path):
    custom_dir = tmp_path / "my-backup-volume"
    mock_settings = mocker.patch("aleph.vm.controllers.qemu.backup.settings")
    mock_settings.BACKUP_DIRECTORY = custom_dir

    result = get_backup_directory()

    assert result == custom_dir
    assert result.is_dir()


def test_get_backup_directory_idempotent(mocker, tmp_path):
    """Calling twice doesn't raise even though the dir already exists."""
    exec_root = tmp_path / "exec"
    exec_root.mkdir()
    mock_settings = mocker.patch("aleph.vm.controllers.qemu.backup.settings")
    mock_settings.BACKUP_DIRECTORY = None
    mock_settings.EXECUTION_ROOT = exec_root

    first = get_backup_directory()
    second = get_backup_directory()

    assert first == second
    assert first.is_dir()


# --- check_disk_space_for_multiple ---


@pytest.mark.asyncio
async def test_check_disk_space_multiple_sufficient(mocker, tmp_path):
    d1 = tmp_path / "a.qcow2"
    d2 = tmp_path / "b.qcow2"
    d1.write_bytes(b"\x00" * 512)
    d2.write_bytes(b"\x00" * 512)

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.get_qemu_disk_virtual_size",
        AsyncMock(return_value=1024),
    )
    fake_usage = mocker.MagicMock(free=1024 * 1024)
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.disk_usage",
        return_value=fake_usage,
    )

    await check_disk_space_for_multiple([d1, d2], tmp_path)


@pytest.mark.asyncio
async def test_check_disk_space_multiple_insufficient(mocker, tmp_path):
    d1 = tmp_path / "a.qcow2"
    d2 = tmp_path / "b.qcow2"
    d1.write_bytes(b"\x00" * 512)
    d2.write_bytes(b"\x00" * 512)

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.get_qemu_disk_virtual_size",
        AsyncMock(return_value=1024),
    )

    fake_usage = mocker.MagicMock(free=500)
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.disk_usage",
        return_value=fake_usage,
    )

    with pytest.raises(InsufficientDiskSpaceError, match="2 disk"):
        await check_disk_space_for_multiple([d1, d2], tmp_path)


# --- create_qemu_disk_backup ---


@pytest.mark.asyncio
async def test_create_backup_success(mocker, tmp_path):
    source = tmp_path / "disk.qcow2"
    source.write_bytes(b"\x00" * 64)
    dest_dir = tmp_path / "backups"
    dest_dir.mkdir()

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value="/usr/bin/qemu-img",
    )
    mock_run = AsyncMock(return_value=b"")
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.run_in_subprocess",
        mock_run,
    )

    vm_hash = "abc123"
    result = await create_qemu_disk_backup(vm_hash, source, dest_dir)

    assert result.parent == dest_dir
    assert result.name.startswith("abc123-")
    assert result.name.endswith(".qcow2")

    mock_run.assert_called_once()
    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "/usr/bin/qemu-img"
    assert cmd[1] == "convert"
    assert "-U" in cmd
    assert "-c" in cmd
    assert "-f" not in cmd  # auto-detect source format
    assert str(source) in cmd
    assert str(result) in cmd


@pytest.mark.asyncio
async def test_create_backup_qemu_img_missing(mocker, tmp_path):
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value=None,
    )

    with pytest.raises(FileNotFoundError, match="qemu-img not found"):
        await create_qemu_disk_backup("abc123", tmp_path / "disk.qcow2", tmp_path)


@pytest.mark.asyncio
async def test_create_backup_subprocess_failure(mocker, tmp_path):
    source = tmp_path / "disk.qcow2"
    source.write_bytes(b"\x00" * 64)

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value="/usr/bin/qemu-img",
    )
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.run_in_subprocess",
        AsyncMock(side_effect=subprocess.CalledProcessError(1, "qemu-img", "error")),
    )

    with pytest.raises(subprocess.CalledProcessError):
        await create_qemu_disk_backup("abc123", source, tmp_path)


# --- verify_qemu_disk ---


@pytest.mark.asyncio
async def test_verify_qemu_disk_success(mocker, tmp_path):
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"\x00" * 64)

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value="/usr/bin/qemu-img",
    )
    mock_run = AsyncMock(return_value=b"No errors were found")
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.run_in_subprocess",
        mock_run,
    )

    await verify_qemu_disk(disk)

    mock_run.assert_called_once()
    cmd = mock_run.call_args[0][0]
    assert cmd == ["/usr/bin/qemu-img", "check", str(disk)]


@pytest.mark.asyncio
async def test_verify_qemu_disk_missing_tool(mocker, tmp_path):
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value=None,
    )

    with pytest.raises(FileNotFoundError, match="qemu-img not found"):
        await verify_qemu_disk(tmp_path / "disk.qcow2")


@pytest.mark.asyncio
async def test_verify_qemu_disk_failure(mocker, tmp_path):
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"\x00" * 64)

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value="/usr/bin/qemu-img",
    )
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.run_in_subprocess",
        AsyncMock(side_effect=subprocess.CalledProcessError(1, "qemu-img", "corrupt")),
    )

    with pytest.raises(subprocess.CalledProcessError):
        await verify_qemu_disk(disk)


# --- get_qemu_disk_virtual_size ---


@pytest.mark.asyncio
async def test_get_qemu_disk_virtual_size(mocker, tmp_path):
    disk = tmp_path / "disk.qcow2"
    disk.write_bytes(b"\x00" * 64)

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value="/usr/bin/qemu-img",
    )
    mock_run = AsyncMock(return_value=b'{"virtual-size": 10737418240, "format": "qcow2"}')
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.run_in_subprocess",
        mock_run,
    )

    size = await get_qemu_disk_virtual_size(disk)

    assert size == 10737418240
    cmd = mock_run.call_args[0][0]
    assert cmd == [
        "/usr/bin/qemu-img",
        "info",
        "--force-share",
        "--output=json",
        str(disk),
    ]


@pytest.mark.asyncio
async def test_get_qemu_disk_virtual_size_missing_tool(mocker, tmp_path):
    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.which",
        return_value=None,
    )

    with pytest.raises(FileNotFoundError, match="qemu-img not found"):
        await get_qemu_disk_virtual_size(tmp_path / "disk.qcow2")


# --- create_backup_archive ---


@pytest.mark.asyncio
async def test_create_backup_archive(tmp_path):
    f1 = tmp_path / "rootfs.qcow2"
    f2 = tmp_path / "data.qcow2"
    f1.write_bytes(b"rootfs-content")
    f2.write_bytes(b"data-content")

    dest = tmp_path / "out"
    dest.mkdir()

    tar_path = await create_backup_archive(
        vm_hash="vm123",
        backup_files={"rootfs.qcow2": f1, "data.qcow2": f2},
        destination_dir=dest,
    )

    assert tar_path.exists()
    assert tar_path.suffix == ".tar"
    assert tar_path.name.startswith("vm123-")

    sidecar = tar_path.with_suffix(".tar.sha256")
    assert sidecar.exists()
    checksum_line = sidecar.read_text()
    assert tar_path.name in checksum_line
    assert len(checksum_line.split()[0]) == 64

    with tarfile.open(tar_path, "r") as tar:
        names = tar.getnames()
    assert "rootfs.qcow2" in names
    assert "data.qcow2" in names


@pytest.mark.asyncio
async def test_create_backup_archive_single_file(tmp_path):
    f1 = tmp_path / "rootfs.qcow2"
    f1.write_bytes(b"content")

    dest = tmp_path / "out"
    dest.mkdir()

    tar_path = await create_backup_archive(
        vm_hash="vm456",
        backup_files={"rootfs.qcow2": f1},
        destination_dir=dest,
    )

    with tarfile.open(tar_path, "r") as tar:
        assert tar.getnames() == ["rootfs.qcow2"]


@pytest.mark.asyncio
async def test_create_backup_archive_with_source_sizes(tmp_path):
    f1 = tmp_path / "rootfs.qcow2"
    f1.write_bytes(b"rootfs-content")

    dest = tmp_path / "out"
    dest.mkdir()

    sizes = {"rootfs.qcow2": 1073741824}
    tar_path = await create_backup_archive(
        vm_hash="vm789",
        backup_files={"rootfs.qcow2": f1},
        destination_dir=dest,
        source_sizes=sizes,
    )

    meta_file = tar_path.with_suffix(".tar.meta.json")
    assert meta_file.exists()
    stored = json.loads(meta_file.read_text())
    assert stored["source_sizes"] == {"rootfs.qcow2": 1073741824}
    assert stored["vm_hash"] == "vm789"


# --- cleanup_expired_backups ---


def test_cleanup_expired_backups_removes_old(tmp_path):
    old_tar = tmp_path / "vm1-20240101T000000Z.tar"
    old_sidecar = tmp_path / "vm1-20240101T000000Z.tar.sha256"
    old_meta = tmp_path / "vm1-20240101T000000Z.tar.meta.json"
    old_tar.write_bytes(b"old")
    old_sidecar.write_text("abc  vm1-20240101T000000Z.tar\n")
    old_meta.write_text('{"vm_hash": "vm1"}')

    old_mtime = time.time() - (25 * 3600)
    os.utime(old_tar, (old_mtime, old_mtime))

    fresh_tar = tmp_path / "vm2-20240102T000000Z.tar"
    fresh_tar.write_bytes(b"fresh")

    deleted = cleanup_expired_backups(tmp_path, ttl_hours=24)

    assert deleted == 1
    assert not old_tar.exists()
    assert not old_sidecar.exists()
    assert not old_meta.exists()
    assert fresh_tar.exists()


def test_cleanup_expired_backups_none_expired(tmp_path):
    tar = tmp_path / "vm1-20240101T000000Z.tar"
    tar.write_bytes(b"fresh")

    deleted = cleanup_expired_backups(tmp_path, ttl_hours=24)

    assert deleted == 0
    assert tar.exists()


def test_cleanup_expired_backups_empty_dir(tmp_path):
    deleted = cleanup_expired_backups(tmp_path)
    assert deleted == 0


# --- find_existing_backup ---


def test_find_existing_backup_found(tmp_path):
    tar = tmp_path / "vm1-20240101T000000Z.tar"
    tar.write_bytes(b"backup-data")

    result = find_existing_backup(tmp_path, "vm1")

    assert result == tar


def test_find_existing_backup_expired(tmp_path):
    tar = tmp_path / "vm1-20240101T000000Z.tar"
    tar.write_bytes(b"old-data")
    old_mtime = time.time() - (25 * 3600)
    os.utime(tar, (old_mtime, old_mtime))

    result = find_existing_backup(tmp_path, "vm1")

    assert result is None


def test_find_existing_backup_wrong_vm(tmp_path):
    tar = tmp_path / "vm1-20240101T000000Z.tar"
    tar.write_bytes(b"data")

    result = find_existing_backup(tmp_path, "vm2")

    assert result is None


# --- backup_metadata ---


def test_backup_metadata(tmp_path):
    f1 = tmp_path / "rootfs.qcow2"
    f1.write_bytes(b"content")

    tar_path = tmp_path / "vm1-20240101T000000Z.tar"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(str(f1), arcname="rootfs.qcow2")

    checksum = _sha256_file(tar_path)
    sidecar = tar_path.with_suffix(".tar.sha256")
    sidecar.write_text(f"{checksum}  {tar_path.name}\n")

    meta = backup_metadata(tar_path)

    assert meta["backup_id"] == "vm1-20240101T000000Z"
    assert meta["size"] == tar_path.stat().st_size
    assert meta["checksum"] == f"sha256:{checksum}"
    assert meta["volumes"] == ["rootfs.qcow2"]
    assert "expires_at" in meta


def test_backup_metadata_no_sidecar(tmp_path):
    f1 = tmp_path / "rootfs.qcow2"
    f1.write_bytes(b"content")

    tar_path = tmp_path / "vm1-20240101T000000Z.tar"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(str(f1), arcname="rootfs.qcow2")

    meta = backup_metadata(tar_path)

    assert "checksum" not in meta
    assert meta["backup_id"] == "vm1-20240101T000000Z"


def test_backup_metadata_with_source_sizes(tmp_path):
    f1 = tmp_path / "rootfs.qcow2"
    f1.write_bytes(b"content")

    tar_path = tmp_path / "vm1-20240101T000000Z.tar"
    with tarfile.open(tar_path, "w") as tar:
        tar.add(str(f1), arcname="rootfs.qcow2")

    meta_file = tar_path.with_suffix(".tar.meta.json")
    meta_file.write_text(
        json.dumps(
            {
                "vm_hash": "vm1",
                "source_sizes": {"rootfs.qcow2": 2048},
            }
        )
    )

    meta = backup_metadata(tar_path)

    assert meta["source_sizes"] == {"rootfs.qcow2": 2048}


# --- restore_rootfs ---


@pytest.mark.asyncio
async def test_restore_rootfs(tmp_path):
    current = tmp_path / "rootfs.qcow2"
    current.write_bytes(b"old-rootfs")

    new = tmp_path / "new-rootfs.qcow2"
    new.write_bytes(b"new-rootfs")

    old_backup = await restore_rootfs(new, current)

    assert current.exists()
    assert current.read_bytes() == b"new-rootfs"
    assert old_backup.exists()
    assert old_backup.read_bytes() == b"old-rootfs"
    assert "pre-restore" in old_backup.name
    # Staging file should be cleaned up
    staging_files = list(tmp_path.glob("*.restore-staging.*"))
    assert len(staging_files) == 0


@pytest.mark.asyncio
async def test_restore_rootfs_preserves_old(tmp_path):
    """The old rootfs is saved with a unique timestamp name."""
    current = tmp_path / "rootfs.qcow2"
    current.write_bytes(b"original")

    new = tmp_path / "replacement.qcow2"
    new.write_bytes(b"replacement")

    old_backup = await restore_rootfs(new, current)

    assert old_backup.parent == tmp_path
    assert old_backup.read_bytes() == b"original"
    pre_restore_files = list(tmp_path.glob("*.pre-restore-*.qcow2"))
    assert len(pre_restore_files) == 1


@pytest.mark.asyncio
async def test_restore_rootfs_rollback_on_copy_failure(mocker, tmp_path):
    """If the staging copy fails, the original rootfs is preserved."""
    current = tmp_path / "rootfs.qcow2"
    current.write_bytes(b"original-data")

    new = tmp_path / "bad-source.qcow2"
    new.write_bytes(b"new-data")

    mocker.patch(
        "aleph.vm.controllers.qemu.backup.shutil.copy2",
        side_effect=OSError("disk full"),
    )

    with pytest.raises(OSError, match="disk full"):
        await restore_rootfs(new, current)

    assert current.exists()
    assert current.read_bytes() == b"original-data"
    staging_files = list(tmp_path.glob("*.restore-staging.*"))
    assert len(staging_files) == 0
