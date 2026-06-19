"""Unit tests for the neutral modules extracted in the controller split (PR-2).

These modules (``aleph.vm.host_volumes``, ``aleph.vm.backup_staging``,
``aleph.vm.program_config`` and the agent-side ``aleph.vm.agent.vm.downloader``)
sit on the shared, hardware-free side of the agent/supervisor boundary: the
download paths resolve resources to on-host paths through ``aleph.vm.storage``,
which is mocked here. No QEMU/Firecracker/SEV is exercised.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import ClientResponseError
from aleph_message.models.execution.base import Encoding
from aleph_message.models.execution.volume import PersistentVolume

from aleph.vm import backup_staging, host_volumes, program_config
from aleph.vm.agent.vm import downloader
from aleph.vm.program_config import (
    ConfigurationPayloadV1,
    ConfigurationPayloadV2,
    Interface,
    ProgramConfiguration,
    read_input_data,
)
from aleph.vm.supervisor_interface.errors import (
    FileTooLargeError,
    ResourceDownloadError,
    VmSetupError,
)


def _client_response_error() -> ClientResponseError:
    return ClientResponseError(request_info=MagicMock(), history=())


# --------------------------------------------------------------------------- #
# host_volumes.host_volumes_from_message
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_host_volumes_from_message_names_and_resolves(monkeypatch, tmp_path):
    """An unnamed persistent volume gets a generated name/mount and resolves to a host path."""
    volume = MagicMock()
    volume.__class__ = PersistentVolume
    volume.name = None  # falsy -> generated as unamed_volume_0
    volume.mount = None  # falsy -> generated as /mnt/<name>
    volume.is_read_only.return_value = True
    volume.size_mib = 256

    message_content = MagicMock()
    message_content.volumes = [volume]

    resolved = tmp_path / "vol.qcow2"
    monkeypatch.setattr(host_volumes, "get_volume_path", AsyncMock(return_value=resolved))

    result = await host_volumes.host_volumes_from_message(message_content, namespace="ns")

    assert len(result) == 1
    hv = result[0]
    assert volume.name == "unamed_volume_0"
    assert hv.mount == "/mnt/unamed_volume_0"
    assert hv.path_on_host == resolved
    assert hv.read_only is True
    assert hv.size_mib == 256


@pytest.mark.asyncio
async def test_host_volumes_from_message_keeps_explicit_name(monkeypatch, tmp_path):
    """A persistent volume that already carries a name/mount is left untouched."""
    volume = MagicMock()
    volume.__class__ = PersistentVolume
    volume.name = "data"
    volume.mount = "/srv/data"
    volume.is_read_only.return_value = False
    volume.size_mib = 512

    message_content = MagicMock()
    message_content.volumes = [volume]
    monkeypatch.setattr(host_volumes, "get_volume_path", AsyncMock(return_value=tmp_path / "data.qcow2"))

    result = await host_volumes.host_volumes_from_message(message_content, namespace="ns")

    assert volume.name == "data"  # not regenerated
    assert result[0].mount == "/srv/data"
    assert result[0].read_only is False


# --------------------------------------------------------------------------- #
# backup_staging
# --------------------------------------------------------------------------- #


def test_get_backup_directory_default(monkeypatch, tmp_path):
    """With no BACKUP_DIRECTORY set, backups live under EXECUTION_ROOT and the dir is created."""
    monkeypatch.setattr(backup_staging.settings, "BACKUP_DIRECTORY", None, raising=False)
    monkeypatch.setattr(backup_staging.settings, "EXECUTION_ROOT", tmp_path, raising=False)

    path = backup_staging.get_backup_directory()

    assert path == tmp_path / "backups"
    assert path.is_dir()


def test_get_backup_directory_explicit(monkeypatch, tmp_path):
    explicit = tmp_path / "custom-backups"
    monkeypatch.setattr(backup_staging.settings, "BACKUP_DIRECTORY", explicit, raising=False)

    path = backup_staging.get_backup_directory()

    assert path == explicit
    assert path.is_dir()


@pytest.mark.asyncio
async def test_download_volume_by_ref(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "aleph.vm.storage._get_content_url",
        AsyncMock(return_value="http://example/volume"),
    )
    download_file = AsyncMock()
    monkeypatch.setattr("aleph.vm.storage.download_file", download_file)

    dest = await backup_staging.download_volume_by_ref("abc123", tmp_path)

    assert dest == tmp_path / "abc123.qcow2"
    download_file.assert_awaited_once_with("http://example/volume", dest)


# --------------------------------------------------------------------------- #
# downloader._make_writable_volume
# --------------------------------------------------------------------------- #


def _persistent_volume(name="vol1", size_mib=8, persistence="store"):
    volume = MagicMock()
    volume.__class__ = PersistentVolume
    volume.name = name
    volume.size_mib = size_mib
    volume.persistence = persistence
    return volume


@pytest.mark.asyncio
async def test_make_writable_volume_requires_qemu_img(monkeypatch):
    monkeypatch.setattr(downloader.shutil, "which", lambda _: None)
    with pytest.raises(VmSetupError, match="qemu-img not found"):
        await downloader._make_writable_volume(Path("/parent.qcow2"), _persistent_volume(), "ns")


@pytest.mark.asyncio
async def test_make_writable_volume_unknown_format(monkeypatch):
    monkeypatch.setattr(downloader.shutil, "which", lambda _: "/usr/bin/qemu-img")
    monkeypatch.setattr(downloader, "run_in_subprocess", AsyncMock(return_value=json.dumps({})))
    with pytest.raises(VmSetupError, match="Failed to detect format"):
        await downloader._make_writable_volume(Path("/parent.qcow2"), _persistent_volume(), "ns")


@pytest.mark.asyncio
async def test_make_writable_volume_unhandled_format(monkeypatch):
    monkeypatch.setattr(downloader.shutil, "which", lambda _: "/usr/bin/qemu-img")
    monkeypatch.setattr(downloader, "run_in_subprocess", AsyncMock(return_value=json.dumps({"format": "vmdk"})))
    with pytest.raises(VmSetupError, match="unhandled by QEMU"):
        await downloader._make_writable_volume(Path("/parent.qcow2"), _persistent_volume(), "ns")


@pytest.mark.asyncio
async def test_make_writable_volume_creates_image(monkeypatch, tmp_path):
    monkeypatch.setattr(downloader.shutil, "which", lambda _: "/usr/bin/qemu-img")
    monkeypatch.setattr(downloader.settings, "PERSISTENT_VOLUMES_DIR", tmp_path, raising=False)
    run = AsyncMock(return_value=json.dumps({"format": "qcow2"}))
    monkeypatch.setattr(downloader, "run_in_subprocess", run)

    dest = await downloader._make_writable_volume(Path("/parent.qcow2"), _persistent_volume(name="data"), "ns")

    assert dest == tmp_path / "ns" / "data.qcow2"
    assert dest.parent.is_dir()
    # second call is the create; verify the destination is one of its args
    create_args = run.await_args_list[-1].args[0]
    assert "create" in create_args
    assert str(dest) in create_args


@pytest.mark.asyncio
async def test_make_writable_volume_keeps_host_persisted(monkeypatch, tmp_path):
    """A host-persisted volume that already exists is returned untouched (no create)."""
    from aleph_message.models.execution.volume import VolumePersistence

    monkeypatch.setattr(downloader.shutil, "which", lambda _: "/usr/bin/qemu-img")
    monkeypatch.setattr(downloader.settings, "PERSISTENT_VOLUMES_DIR", tmp_path, raising=False)
    run = AsyncMock(return_value=json.dumps({"format": "qcow2"}))
    monkeypatch.setattr(downloader, "run_in_subprocess", run)

    existing = tmp_path / "ns" / "vol1.qcow2"
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"keep me")

    volume = _persistent_volume(name="vol1", persistence=VolumePersistence.host)
    dest = await downloader._make_writable_volume(Path("/parent.qcow2"), volume, "ns")

    assert dest == existing
    assert dest.read_bytes() == b"keep me"  # untouched
    # only the info call ran, never the create
    assert run.await_count == 1


# --------------------------------------------------------------------------- #
# downloader.ProgramDownloader / QemuDownloader
# --------------------------------------------------------------------------- #


def _program_content(*, with_data: bool, entrypoint="main:app", interface=None):
    content = MagicMock()
    content.code.encoding = Encoding.zip
    content.code.entrypoint = entrypoint
    content.code.interface = interface
    content.code.ref = "code-ref"
    content.runtime.ref = "runtime-ref"
    if with_data:
        content.data.ref = "data-ref"
    else:
        content.data = None
    return content


@pytest.mark.asyncio
async def test_program_downloader_kernel(monkeypatch, tmp_path):
    kernel = tmp_path / "vmlinux.bin"
    kernel.write_bytes(b"kernel")
    monkeypatch.setattr(downloader.settings, "LINUX_PATH", str(kernel), raising=False)

    pd = downloader.ProgramDownloader(_program_content(with_data=False), "ns")
    await pd.download_kernel()

    assert pd.kernel_image_path == kernel
    assert pd.code_interface is Interface.asgi  # "main:app" -> colon -> asgi


@pytest.mark.asyncio
async def test_program_downloader_code_and_runtime(monkeypatch, tmp_path):
    code = tmp_path / "code.zip"
    code.write_bytes(b"code")
    runtime = tmp_path / "runtime.squashfs"
    runtime.write_bytes(b"runtime")
    monkeypatch.setattr(downloader, "get_code_path", AsyncMock(return_value=code))
    monkeypatch.setattr(downloader, "get_runtime_path", AsyncMock(return_value=runtime))

    pd = downloader.ProgramDownloader(_program_content(with_data=False), "ns")
    await pd.download_code()
    await pd.download_runtime()

    assert pd.code_path == code
    assert pd.rootfs_path == runtime


@pytest.mark.asyncio
async def test_program_downloader_code_wraps_download_error(monkeypatch):
    monkeypatch.setattr(downloader, "get_code_path", AsyncMock(side_effect=_client_response_error()))
    pd = downloader.ProgramDownloader(_program_content(with_data=False), "ns")
    with pytest.raises(ResourceDownloadError):
        await pd.download_code()


@pytest.mark.asyncio
async def test_program_downloader_runtime_wraps_download_error(monkeypatch):
    monkeypatch.setattr(downloader, "get_runtime_path", AsyncMock(side_effect=_client_response_error()))
    pd = downloader.ProgramDownloader(_program_content(with_data=False), "ns")
    with pytest.raises(ResourceDownloadError):
        await pd.download_runtime()


@pytest.mark.asyncio
async def test_program_downloader_data_present(monkeypatch, tmp_path):
    data = tmp_path / "data.zip"
    data.write_bytes(b"data")
    monkeypatch.setattr(downloader, "get_data_path", AsyncMock(return_value=data))

    pd = downloader.ProgramDownloader(_program_content(with_data=True), "ns")
    await pd.download_data()

    assert pd.data_path == data


@pytest.mark.asyncio
async def test_program_downloader_data_absent():
    pd = downloader.ProgramDownloader(_program_content(with_data=False), "ns")
    await pd.download_data()
    assert pd.data_path is None


@pytest.mark.asyncio
async def test_program_downloader_data_wraps_download_error(monkeypatch):
    monkeypatch.setattr(downloader, "get_data_path", AsyncMock(side_effect=_client_response_error()))
    pd = downloader.ProgramDownloader(_program_content(with_data=True), "ns")
    with pytest.raises(ResourceDownloadError):
        await pd.download_data()


@pytest.mark.asyncio
async def test_program_downloader_download_all(monkeypatch, tmp_path):
    kernel = tmp_path / "vmlinux.bin"
    kernel.write_bytes(b"kernel")
    code = tmp_path / "code.zip"
    code.write_bytes(b"code")
    runtime = tmp_path / "runtime.squashfs"
    runtime.write_bytes(b"runtime")
    monkeypatch.setattr(downloader.settings, "LINUX_PATH", str(kernel), raising=False)
    monkeypatch.setattr(downloader, "get_code_path", AsyncMock(return_value=code))
    monkeypatch.setattr(downloader, "get_runtime_path", AsyncMock(return_value=runtime))
    monkeypatch.setattr(downloader, "host_volumes_from_message", AsyncMock(return_value=["v"]))

    pd = downloader.ProgramDownloader(_program_content(with_data=False), "ns")
    await pd.download_all()

    assert pd.rootfs_path == runtime
    assert pd.code_path == code
    assert pd.volumes == ["v"]
    assert pd.data_path is None


@pytest.mark.asyncio
async def test_qemu_downloader_download_all(monkeypatch, tmp_path):
    rootfs_parent = tmp_path / "base.qcow2"
    rootfs_parent.write_bytes(b"base")
    writable = tmp_path / "rootfs.qcow2"

    content = MagicMock()
    content.rootfs.parent.ref = "parent-ref"

    monkeypatch.setattr(downloader, "get_rootfs_base_path", AsyncMock(return_value=rootfs_parent))
    monkeypatch.setattr(downloader, "_make_writable_volume", AsyncMock(return_value=writable))
    monkeypatch.setattr(downloader, "host_volumes_from_message", AsyncMock(return_value=["v"]))

    qd = downloader.QemuDownloader(content, "ns")
    await qd.download_all()

    assert qd.rootfs_path == writable
    assert qd.volumes == ["v"]


# --------------------------------------------------------------------------- #
# program_config
# --------------------------------------------------------------------------- #


def test_read_input_data_none():
    assert read_input_data(None) is None


def test_read_input_data_reads_bytes(tmp_path):
    f = tmp_path / "data.bin"
    f.write_bytes(b"payload")
    assert read_input_data(f) == b"payload"


def test_read_input_data_too_large(monkeypatch, tmp_path):
    f = tmp_path / "big.bin"
    f.write_bytes(b"x" * 100)
    monkeypatch.setattr(program_config.settings, "MAX_DATA_ARCHIVE_SIZE", 10, raising=False)
    with pytest.raises(FileTooLargeError):
        read_input_data(f)


@pytest.mark.parametrize(
    "entrypoint, hint, expected",
    [
        ("main:app", None, Interface.asgi),
        ("runnable", None, Interface.executable),
        ("anything", "binary", Interface.executable),  # aleph-message alias
        ("anything", "asgi", Interface.asgi),
        ("main:app", "bogus", Interface.asgi),  # invalid hint -> auto-detect
    ],
)
def test_interface_from_entrypoint(entrypoint, hint, expected):
    assert Interface.from_entrypoint(entrypoint=entrypoint, interface_hint=hint) is expected


def _program_configuration() -> ProgramConfiguration:
    return ProgramConfiguration(
        input_data=None,
        interface=Interface.asgi,
        vm_hash="vm",
        encoding=Encoding.zip,
        entrypoint="main:app",
    )


def test_to_runtime_format_v1():
    payload = _program_configuration().to_runtime_format(MagicMock(version="1.0.0"))
    assert isinstance(payload, ConfigurationPayloadV1)
    assert not isinstance(payload, ConfigurationPayloadV2)


def test_to_runtime_format_v2():
    payload = _program_configuration().to_runtime_format(MagicMock(version="2.0.0"))
    assert isinstance(payload, ConfigurationPayloadV2)


def test_to_runtime_format_unknown_version_falls_back_to_v2():
    payload = _program_configuration().to_runtime_format(MagicMock(version="9.9.9"))
    assert isinstance(payload, ConfigurationPayloadV2)
