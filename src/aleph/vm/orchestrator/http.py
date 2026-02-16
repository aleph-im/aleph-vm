"""Shared HTTP client session for outbound API calls.

Provides a singleton aiohttp.ClientSession with automatic 429
rate-limit handling using Retry-After and x-retry-in headers.
"""

import asyncio
import logging
import re

import aiohttp
from aiohttp import web

logger = logging.getLogger(__name__)

_session: aiohttp.ClientSession | None = None

MAX_RETRIES = 3


def _parse_retry_delay(response: aiohttp.ClientResponse) -> float:
    """Extract retry delay from 429 response headers.

    Checks x-retry-in first (more precise, e.g. "105.849351ms"),
    then falls back to Retry-After (integer seconds).
    Returns delay in seconds, defaulting to 1.0.
    """
    x_retry_in = response.headers.get("x-retry-in")
    if x_retry_in:
        match = re.match(r"([\d.]+)(ms|s)?", x_retry_in.strip())
        if match:
            value = float(match.group(1))
            unit = match.group(2) or "s"
            return value / 1000.0 if unit == "ms" else value

    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return float(retry_after)
        except ValueError:
            pass

    return 1.0


async def _request_with_retry(
    method: str,
    url: str,
    session: aiohttp.ClientSession,
    **kwargs,
) -> aiohttp.ClientResponse:
    """Execute an HTTP request with automatic 429 retry."""
    for attempt in range(MAX_RETRIES):
        resp = await session.request(method, url, **kwargs)
        if resp.status != 429:
            return resp

        delay = _parse_retry_delay(resp)
        logger.warning(
            "Rate limited (429) on %s %s, retrying in %.3fs " "(attempt %d/%d)",
            method,
            url,
            delay,
            attempt + 1,
            MAX_RETRIES,
        )
        resp.release()
        await asyncio.sleep(delay)

    return resp


class RetrySession:
    """Wrapper around aiohttp.ClientSession that retries on 429."""

    def __init__(self, session: aiohttp.ClientSession):
        self._session = session

    async def get(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        return await _request_with_retry("GET", url, self._session, **kwargs)

    async def post(self, url: str, **kwargs) -> aiohttp.ClientResponse:
        return await _request_with_retry("POST", url, self._session, **kwargs)

    def ws_connect(self, url: str, **kwargs):
        return self._session.ws_connect(url, **kwargs)

    @property
    def closed(self) -> bool:
        return self._session.closed

    async def close(self) -> None:
        await self._session.close()


def get_session() -> RetrySession:
    """Return the shared HTTP client session with 429 retry support.

    Creates a session lazily on first call. Must be called after
    the event loop is running.
    """
    global _session  # noqa: PLW0603
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession()
    return RetrySession(_session)


async def close_session(app: web.Application) -> None:
    """Cleanup hook: close the shared HTTP session on app shutdown."""
    global _session  # noqa: PLW0603
    if _session and not _session.closed:
        await _session.close()
        _session = None
