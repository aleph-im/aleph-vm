from __future__ import annotations

import os
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.vm.storage import download_file, download_file_in_chunks
from aleph.vm.supervisor_interface.errors import FileTooLargeError


def _session(chunks: list[bytes], content_length: int | None):
    resp = MagicMock()
    resp.raise_for_status = MagicMock()
    resp.content_length = content_length
    reads = iter(chunks + [b""])
    resp.content.read = AsyncMock(side_effect=lambda n: next(reads))
    session = MagicMock()
    session.get = AsyncMock(return_value=resp)
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)
    return session, resp


@pytest.mark.asyncio
async def test_content_length_above_the_cap_is_refused_before_writing(tmp_path):
    session, resp = _session([b"x" * 10], content_length=10)
    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        with pytest.raises(FileTooLargeError):
            await download_file_in_chunks("http://x/f", tmp_path / "f.part", max_bytes=5)
    resp.content.read.assert_not_called()


@pytest.mark.asyncio
async def test_stream_past_the_cap_is_aborted(tmp_path):
    session, _ = _session([b"x" * 4, b"x" * 4], content_length=None)
    part = tmp_path / "f.part"
    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        with pytest.raises(FileTooLargeError):
            await download_file_in_chunks("http://x/f", part, max_bytes=5)


@pytest.mark.asyncio
async def test_download_file_unlinks_the_part_and_does_not_retry(tmp_path):
    attempts = []

    async def too_large(url, tmp_path_, max_bytes=None):
        attempts.append(1)
        tmp_path_.write_bytes(b"partial")
        raise FileTooLargeError("too big")

    with patch("aleph.vm.storage.download_file_in_chunks", side_effect=too_large):
        with pytest.raises(FileTooLargeError):
            await download_file("http://x/f", tmp_path / "f", max_bytes=5)
    assert attempts == [1]
    assert not (tmp_path / "f.part").exists()
    assert not (tmp_path / "f").exists()


@pytest.mark.asyncio
async def test_existing_file_is_touched_on_hit(tmp_path):
    target = tmp_path / "f"
    target.write_bytes(b"cached")
    old = time.time() - 100_000
    os.utime(target, (old, old))

    await download_file("http://x/f", target)

    assert target.stat().st_mtime > old + 50_000


@pytest.mark.asyncio
async def test_existing_file_touch_failure_does_not_fail_the_cache_hit(tmp_path):
    """A cache hit served by a non-owning, non-jailman user can't utime the
    cached file (chown_to_jailman ran after the original download); that must
    not turn a perfectly usable cache hit into a failure."""
    target = tmp_path / "f"
    target.write_bytes(b"cached")

    with patch("aleph.vm.storage.os.utime", side_effect=PermissionError("no permission")):
        await download_file("http://x/f", target)

    assert target.is_file()
    assert target.read_bytes() == b"cached"


@pytest.mark.asyncio
async def test_get_existing_file_passes_the_data_cap(mocker, tmp_path):
    import aleph.vm.storage as storage_module
    from aleph.vm.conf import settings

    mocker.patch.object(settings, "DATA_CACHE", tmp_path / "data")
    mocker.patch.object(settings, "FAKE_DATA_PROGRAM", None)
    mocker.patch.object(storage_module, "_get_content_url", AsyncMock(return_value="http://x/f"))
    mocker.patch.object(storage_module, "chown_to_jailman", AsyncMock())
    download = mocker.patch.object(storage_module, "download_file", AsyncMock())

    await storage_module.get_existing_file("ref")

    download.assert_awaited_once_with("http://x/f", tmp_path / "data" / "ref", max_bytes=settings.MAX_DATA_ARCHIVE_SIZE)


@pytest.mark.asyncio
async def test_getters_pass_their_caps(mocker, tmp_path):
    import aleph.vm.storage as storage_module
    from aleph.vm.conf import settings

    mocker.patch.object(settings, "CODE_CACHE", tmp_path / "code")
    mocker.patch.object(settings, "DATA_CACHE", tmp_path / "data")
    mocker.patch.object(settings, "RUNTIME_CACHE", tmp_path / "runtime")
    mocker.patch.object(settings, "FAKE_DATA_PROGRAM", None)
    mocker.patch.object(storage_module, "_get_content_url", AsyncMock(return_value="http://x/f"))
    mocker.patch.object(storage_module, "check_squashfs_integrity", AsyncMock())
    mocker.patch.object(storage_module, "chown_to_jailman", AsyncMock())
    download = mocker.patch.object(storage_module, "download_file", AsyncMock())

    await storage_module.get_code_path("ref")
    await storage_module.get_data_path("ref")
    await storage_module.get_runtime_path("ref")
    await storage_module.get_rootfs_base_path("ref")

    caps = [call.kwargs["max_bytes"] for call in download.await_args_list]
    assert caps == [
        settings.MAX_PROGRAM_ARCHIVE_SIZE,
        settings.MAX_DATA_ARCHIVE_SIZE,
        settings.MAX_RUNTIME_ARCHIVE_SIZE,
        settings.MAX_RUNTIME_ARCHIVE_SIZE,
    ]
