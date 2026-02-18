import subprocess
from unittest.mock import AsyncMock

import pytest

from aleph.vm.controllers.qemu.snapshots import (
    check_disk_space_for_snapshot,
    create_qemu_disk_snapshot,
    get_snapshots_directory,
)


def test_get_snapshots_directory(mocker, tmp_path):
    exec_root = tmp_path / "exec"
    exec_root.mkdir()
    mocker.patch("aleph.vm.controllers.qemu.snapshots.settings").EXECUTION_ROOT = exec_root

    result = get_snapshots_directory()

    assert result == exec_root / "snapshots"
    assert result.is_dir()


def test_get_snapshots_directory_idempotent(mocker, tmp_path):
    """Calling twice doesn't raise even though the dir already exists."""
    exec_root = tmp_path / "exec"
    exec_root.mkdir()
    mocker.patch("aleph.vm.controllers.qemu.snapshots.settings").EXECUTION_ROOT = exec_root

    first = get_snapshots_directory()
    second = get_snapshots_directory()

    assert first == second
    assert first.is_dir()


def test_check_disk_space_sufficient(tmp_path):
    source = tmp_path / "disk.qcow2"
    source.write_bytes(b"\x00" * 1024)

    ok, msg = check_disk_space_for_snapshot(source, tmp_path)

    assert ok is True
    assert msg == ""


def test_check_disk_space_insufficient(mocker, tmp_path):
    source = tmp_path / "disk.qcow2"
    source.write_bytes(b"\x00" * 1024)

    fake_usage = mocker.MagicMock(free=512)
    mocker.patch(
        "aleph.vm.controllers.qemu.snapshots.shutil.disk_usage",
        return_value=fake_usage,
    )

    ok, msg = check_disk_space_for_snapshot(source, tmp_path)

    assert ok is False
    assert "512 bytes available" in msg
    assert "1024 bytes required" in msg


def test_check_disk_space_source_missing(tmp_path):
    missing = tmp_path / "nonexistent.qcow2"

    with pytest.raises(FileNotFoundError):
        check_disk_space_for_snapshot(missing, tmp_path)


@pytest.mark.asyncio
async def test_create_snapshot_success(mocker, tmp_path):
    source = tmp_path / "disk.qcow2"
    source.write_bytes(b"\x00" * 64)
    dest_dir = tmp_path / "snapshots"
    dest_dir.mkdir()

    mocker.patch(
        "aleph.vm.controllers.qemu.snapshots.shutil.which",
        return_value="/usr/bin/qemu-img",
    )
    mock_run = AsyncMock(return_value=b"")
    mocker.patch(
        "aleph.vm.controllers.qemu.snapshots.run_in_subprocess",
        mock_run,
    )

    vm_hash = "abc123"
    result = await create_qemu_disk_snapshot(vm_hash, source, dest_dir)

    assert result.parent == dest_dir
    assert result.name.startswith("abc123-")
    assert result.name.endswith(".qcow2")

    mock_run.assert_called_once()
    cmd = mock_run.call_args[0][0]
    assert cmd[0] == "/usr/bin/qemu-img"
    assert cmd[1] == "convert"
    assert "-c" in cmd
    assert str(source) in cmd
    assert str(result) in cmd


@pytest.mark.asyncio
async def test_create_snapshot_qemu_img_missing(mocker, tmp_path):
    mocker.patch(
        "aleph.vm.controllers.qemu.snapshots.shutil.which",
        return_value=None,
    )

    with pytest.raises(FileNotFoundError, match="qemu-img not found"):
        await create_qemu_disk_snapshot("abc123", tmp_path / "disk.qcow2", tmp_path)


@pytest.mark.asyncio
async def test_create_snapshot_subprocess_failure(mocker, tmp_path):
    source = tmp_path / "disk.qcow2"
    source.write_bytes(b"\x00" * 64)

    mocker.patch(
        "aleph.vm.controllers.qemu.snapshots.shutil.which",
        return_value="/usr/bin/qemu-img",
    )
    mocker.patch(
        "aleph.vm.controllers.qemu.snapshots.run_in_subprocess",
        AsyncMock(side_effect=subprocess.CalledProcessError(1, "qemu-img", "error")),
    )

    with pytest.raises(subprocess.CalledProcessError):
        await create_qemu_disk_snapshot("abc123", source, tmp_path)
