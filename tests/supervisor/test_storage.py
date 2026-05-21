from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.vm.storage import get_latest_amend

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
