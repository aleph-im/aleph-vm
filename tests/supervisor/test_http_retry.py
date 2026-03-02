import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
import pytest

from aleph.vm.orchestrator.http import (
    MAX_CONCURRENT_REQUESTS,
    MAX_RETRIES,
    RetrySession,
    _parse_retry_delay,
    _request_with_retry,
)


def _make_response(status, headers=None):
    resp = MagicMock(spec=aiohttp.ClientResponse)
    resp.status = status
    resp.headers = headers or {}
    resp.release = MagicMock()
    resp.request_info = MagicMock()
    resp.history = ()
    return resp


class TestParseRetryDelay:
    def test_x_retry_in_milliseconds(self):
        resp = _make_response(429, {"x-retry-in": "105.849351ms"})
        assert abs(_parse_retry_delay(resp) - 0.105849351) < 1e-9

    def test_x_retry_in_seconds(self):
        resp = _make_response(429, {"x-retry-in": "2.5s"})
        assert _parse_retry_delay(resp) == 2.5

    def test_x_retry_in_no_unit_defaults_to_seconds(self):
        resp = _make_response(429, {"x-retry-in": "3"})
        assert _parse_retry_delay(resp) == 3.0

    def test_retry_after_header(self):
        resp = _make_response(429, {"Retry-After": "5"})
        assert _parse_retry_delay(resp) == 5.0

    def test_x_retry_in_takes_precedence(self):
        resp = _make_response(429, {"x-retry-in": "200ms", "Retry-After": "5"})
        assert abs(_parse_retry_delay(resp) - 0.2) < 1e-9

    def test_no_headers_defaults_to_1s(self):
        resp = _make_response(429)
        assert _parse_retry_delay(resp) == 1.0


@pytest.mark.asyncio
async def test_request_with_retry_success_on_first_try():
    ok_resp = _make_response(200)
    session = MagicMock()
    session.closed = False
    session.request = AsyncMock(return_value=ok_resp)

    result = await _request_with_retry("GET", "http://example.com", session)
    assert result is ok_resp
    session.request.assert_called_once()


@pytest.mark.asyncio
async def test_request_with_retry_succeeds_after_429():
    rate_limited = _make_response(429, {"Retry-After": "0"})
    ok_resp = _make_response(200)
    session = MagicMock()
    session.closed = False
    session.request = AsyncMock(side_effect=[rate_limited, ok_resp])

    with patch("aleph.vm.orchestrator.http.asyncio.sleep", new_callable=AsyncMock):
        result = await _request_with_retry("GET", "http://example.com", session)

    assert result is ok_resp
    assert session.request.call_count == 2


@pytest.mark.asyncio
async def test_request_with_retry_exhausts_retries():
    rate_limited = _make_response(429, {"Retry-After": "0"})
    session = MagicMock()
    session.closed = False
    session.request = AsyncMock(return_value=rate_limited)

    with patch("aleph.vm.orchestrator.http.asyncio.sleep", new_callable=AsyncMock):
        with pytest.raises(aiohttp.ClientResponseError) as exc_info:
            await _request_with_retry("GET", "http://example.com", session)

    assert exc_info.value.status == 429
    assert session.request.call_count == MAX_RETRIES


@pytest.mark.asyncio
async def test_retry_session_limits_concurrency():
    """Verify the semaphore limits concurrent requests."""
    session = MagicMock(spec=aiohttp.ClientSession)
    session.closed = False
    active = 0
    max_active = 0

    async def slow_request(method, url, **kwargs):
        nonlocal active, max_active
        active += 1
        max_active = max(max_active, active)
        await asyncio.sleep(0.01)
        active -= 1
        return _make_response(200)

    session.request = slow_request
    retry_session = RetrySession(session)

    tasks = [retry_session.get(f"http://example.com/{i}") for i in range(20)]
    await asyncio.gather(*tasks)

    assert max_active <= MAX_CONCURRENT_REQUESTS
