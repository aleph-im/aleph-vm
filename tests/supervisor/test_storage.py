import asyncio
from pathlib import Path
from subprocess import CalledProcessError
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from aleph.vm.storage import (
    _tune_with_recovery,
    download_file,
    download_file_in_chunks,
    get_latest_amend,
)

ORIGINAL_HASH = "a" * 64
AMEND_HASH = "b" * 64
OWNER = "0xOWNER"
DELEGATE = "0xDELEGATE"
OTHER_OWNER = "0xOTHER"


def _make_response(payload: dict) -> MagicMock:
    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.json = AsyncMock(return_value=payload)
    return response


def _build_session_mock(responses: list[dict], captured_urls: list[str] | None = None) -> MagicMock:
    """Return a mock aiohttp.ClientSession that yields the given JSON responses in order."""
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)

    response_iter = iter([_make_response(p) for p in responses])

    def _get(url: str):
        if captured_urls is not None:
            captured_urls.append(url)
        return next(response_iter)

    session.get = AsyncMock(side_effect=_get)
    return session


def _original_message(*, sender: str, owner: str) -> dict:
    return {
        "messages": [
            {
                "item_hash": ORIGINAL_HASH,
                "sender": sender,
                "content": {"address": owner},
            }
        ]
    }


def _amend_message(*, item_hash: str, sender: str, owner: str, ref: str) -> dict:
    return {
        "item_hash": item_hash,
        "sender": sender,
        "content": {"address": owner, "ref": ref},
    }


@pytest.mark.asyncio
async def test_get_latest_amend_returns_original_when_no_amend_exists():
    """No follow-up STORE → return the original hash."""
    session = _build_session_mock(
        [
            _original_message(sender=OWNER, owner=OWNER),
            {"messages": []},
        ]
    )

    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        result = await get_latest_amend(ORIGINAL_HASH)

    assert result == ORIGINAL_HASH


@pytest.mark.asyncio
async def test_get_latest_amend_accepts_delegated_signer():
    """Original signed by owner, amend signed by a delegate but with matching content.address — accept."""
    session = _build_session_mock(
        [
            _original_message(sender=OWNER, owner=OWNER),
            {"messages": [_amend_message(item_hash=AMEND_HASH, sender=DELEGATE, owner=OWNER, ref=ORIGINAL_HASH)]},
        ]
    )

    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        result = await get_latest_amend(ORIGINAL_HASH)

    assert result == AMEND_HASH


@pytest.mark.asyncio
async def test_get_latest_amend_rejects_mismatched_owner():
    """Amend's content.address differs from the original's owner — reject."""
    session = _build_session_mock(
        [
            _original_message(sender=OWNER, owner=OWNER),
            {
                "messages": [
                    _amend_message(item_hash=AMEND_HASH, sender=OTHER_OWNER, owner=OTHER_OWNER, ref=ORIGINAL_HASH)
                ]
            },
        ]
    )

    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        result = await get_latest_amend(ORIGINAL_HASH)

    assert result == ORIGINAL_HASH


@pytest.mark.asyncio
async def test_get_latest_amend_queries_by_owner_not_sender():
    """The amend lookup must filter via `owners=<content.address>`, not `addresses=<sender>`."""
    captured_urls: list[str] = []
    session = _build_session_mock(
        [
            _original_message(sender=DELEGATE, owner=OWNER),
            {"messages": []},
        ],
        captured_urls=captured_urls,
    )

    with patch("aleph.vm.storage.aiohttp.ClientSession", return_value=session):
        await get_latest_amend(ORIGINAL_HASH)

    amend_lookup_url = captured_urls[1]
    assert f"owners={OWNER}" in amend_lookup_url
    assert "addresses=" not in amend_lookup_url


def _empty_body_session_mock() -> MagicMock:
    """Mock aiohttp.ClientSession that serves an immediately-empty response body."""
    session = MagicMock()
    session.__aenter__ = AsyncMock(return_value=session)
    session.__aexit__ = AsyncMock(return_value=False)

    response = MagicMock()
    response.raise_for_status = MagicMock()
    response.content = MagicMock()
    response.content.read = AsyncMock(return_value=b"")  # empty -> loop ends immediately
    session.get = AsyncMock(return_value=response)
    return session


@pytest.mark.asyncio
async def test_download_file_in_chunks_does_not_cap_total_time(tmp_path):
    """A large but steady download must not be killed by aiohttp's default total=300s timeout.

    The session must be built with no total cap and a sock_read stall guard instead, so a
    legitimately slow multi-hundred-MB download from a slow gateway can still complete.
    """
    captured_timeout: list = []

    def _session_factory(**kwargs):
        captured_timeout.append(kwargs.get("timeout"))
        return _empty_body_session_mock()

    with patch("aleph.vm.storage.aiohttp.ClientSession", side_effect=_session_factory):
        await download_file_in_chunks("http://example.com/file", tmp_path / "out.part")

    timeout = captured_timeout[0]
    assert isinstance(timeout, aiohttp.ClientTimeout)
    assert timeout.total is None, "total time must be uncapped for large downloads"
    assert timeout.sock_read is not None, "a sock_read stall guard must be set"


@pytest.mark.asyncio
async def test_download_file_retries_on_timeout(tmp_path):
    """A timed-out chunk download must be retried, not aborted on the first failure."""
    local_path = tmp_path / "runtime"
    calls = {"n": 0}

    async def _flaky(_url, _target_path):
        calls["n"] += 1
        if calls["n"] < 3:
            raise TimeoutError
        # success: download_file already created the .part file via touch()

    with patch("aleph.vm.storage.download_file_in_chunks", side_effect=_flaky):
        await download_file("http://example.com/runtime", local_path)

    assert calls["n"] == 3
    assert local_path.is_file()


@pytest.mark.asyncio
async def test_download_file_aborts_after_exhausting_retries_on_timeout(tmp_path):
    """If every attempt times out, the error propagates after the retries are exhausted."""
    local_path = tmp_path / "runtime"

    async def _always_timeout(_url, _target_path):
        raise TimeoutError

    with patch("aleph.vm.storage.download_file_in_chunks", side_effect=_always_timeout):
        with pytest.raises(asyncio.TimeoutError):
            await download_file("http://example.com/runtime", local_path)

    assert not local_path.is_file()
    assert not (tmp_path / "runtime.part").exists()


# --- BTRFS log-tree auto-recovery ------------------------------------------
#
# Unclean stops of a running VM (SIGKILL before BTRFS flushed its write cache)
# leave the rootfs with a log tree that points at blocks with older transids.
# btrfstune -m then fails with "open ctree failed" and the VM is permanently
# unstartable. _tune_with_recovery detects that specific failure, runs
# `btrfs rescue zero-log`, and retries once so the VM self-heals.


def _corruption_error(stderr: str = "parent transid verify failed on 2589589504") -> CalledProcessError:
    err = CalledProcessError(1, ["btrfstune", "-m", "/dev/mapper/x"])
    # run_in_subprocess stashes stderr in `.output` (not `.stderr`).
    err.output = stderr + "\nopen ctree failed\n"
    return err


def _generic_error() -> CalledProcessError:
    err = CalledProcessError(1, ["btrfstune", "-m", "/dev/mapper/x"])
    err.output = "some unrelated failure"
    return err


@pytest.mark.asyncio
async def test_tune_with_recovery_zeros_log_and_retries_on_corruption(mocker):
    calls: list[list[str]] = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        # First btrfstune fails with corruption; zero-log succeeds; retry succeeds.
        if cmd[0] == "btrfstune" and len(calls) == 1:
            raise _corruption_error()
        return b""

    mocker.patch("aleph.vm.storage.run_in_subprocess", side_effect=fake_run)

    await _tune_with_recovery(Path("/dev/mapper/x"))

    assert [cmd[:2] for cmd in calls] == [
        ["btrfstune", "-m"],
        ["btrfs", "rescue"],
        ["btrfstune", "-m"],
    ]


@pytest.mark.asyncio
async def test_tune_with_recovery_reraises_non_corruption_errors(mocker):
    calls: list[list[str]] = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        raise _generic_error()

    mocker.patch("aleph.vm.storage.run_in_subprocess", side_effect=fake_run)

    with pytest.raises(CalledProcessError):
        await _tune_with_recovery(Path("/dev/mapper/x"))

    # No zero-log attempt — only the initial btrfstune ran.
    assert calls == [["btrfstune", "-m", "/dev/mapper/x"]]


@pytest.mark.asyncio
async def test_tune_with_recovery_propagates_when_zero_log_itself_fails(mocker):
    calls: list[list[str]] = []

    async def fake_run(cmd, *args, **kwargs):
        calls.append(list(cmd))
        if cmd[0] == "btrfstune" and len(calls) == 1:
            raise _corruption_error()
        if cmd[:2] == ["btrfs", "rescue"]:
            err = CalledProcessError(1, cmd)
            err.output = "rescue failed"
            raise err
        return b""

    mocker.patch("aleph.vm.storage.run_in_subprocess", side_effect=fake_run)

    with pytest.raises(CalledProcessError):
        await _tune_with_recovery(Path("/dev/mapper/x"))

    # Bailed after zero-log; did NOT loop trying btrfstune a third time.
    assert [cmd[:2] for cmd in calls] == [["btrfstune", "-m"], ["btrfs", "rescue"]]
