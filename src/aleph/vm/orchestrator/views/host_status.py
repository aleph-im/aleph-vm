import logging
import socket
from collections.abc import Awaitable, Callable
from typing import Any

import aiohttp

from aleph.vm.conf import settings

logger = logging.getLogger(__name__)


def return_false_on_timeout(func: Callable[..., Awaitable[Any]]) -> Callable[..., Awaitable[bool]]:
    async def wrapper(*args: Any, **kwargs: Any) -> bool:
        try:
            return await func(*args, **kwargs)
        except TimeoutError:
            logger.warning(f"Timeout while checking {func.__name__}")
            return False

    return wrapper


async def check_http_endpoint(
    url: str,
    socket_family: socket.AddressFamily = socket.AF_UNSPEC,
    session: aiohttp.ClientSession | None = None,
) -> bool:
    """Return True if url responds with any valid HTTP status code."""
    timeout = aiohttp.ClientTimeout(total=5)

    async def _do_get(s: aiohttp.ClientSession) -> bool:
        try:
            async with s.get(url) as resp:
                # Any HTTP response confirms connectivity — the status code is
                # irrelevant since probe endpoints may return 200, 204, 400, or 404.
                return True
        except aiohttp.ClientConnectorError:
            return False

    if session is not None:
        return await _do_get(session)

    connector = aiohttp.TCPConnector(family=socket_family)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as new_session:
        return await _do_get(new_session)


@return_false_on_timeout
async def check_host_egress_ipv4() -> bool:
    """Check if the host has IPv4 connectivity (raw IP, no DNS required)."""
    return await check_http_endpoint(settings.CONNECTIVITY_IPV4_URL, socket.AF_INET)


@return_false_on_timeout
async def check_host_egress_ipv6() -> bool:
    """Check if the host has IPv6 connectivity (raw IP, no DNS required)."""
    return await check_http_endpoint(settings.CONNECTIVITY_IPV6_URL, socket.AF_INET6)


async def check_http_connectivity_with_fallback(
    urls: list[str],
    socket_family: socket.AddressFamily,
) -> bool:
    """Try each URL in order using a single session, returning True on first success."""
    timeout = aiohttp.ClientTimeout(total=5)
    connector = aiohttp.TCPConnector(family=socket_family)
    async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
        for url in urls:
            if await check_http_endpoint(url, session=session):
                return True
            logger.debug("HTTP connectivity check failed for %s, trying next", url)
    return False


@return_false_on_timeout
async def check_host_http_ipv4() -> bool:
    """Check DNS resolution + IPv4 HTTP egress end-to-end, with fallback URLs."""
    return await check_http_connectivity_with_fallback(
        settings.CONNECTIVITY_HTTP_URLS,
        socket.AF_INET,
    )


@return_false_on_timeout
async def check_host_http_ipv6() -> bool:
    """Check DNS resolution + IPv6 HTTP egress end-to-end, with fallback URLs."""
    return await check_http_connectivity_with_fallback(
        settings.CONNECTIVITY_HTTP_URLS,
        socket.AF_INET6,
    )


async def resolve_dns(hostname: str) -> tuple[str | None, str | None]:
    """Resolve a hostname to an IPv4 and IPv6 address."""
    ipv4: str | None = None
    ipv6: str | None = None

    info = socket.getaddrinfo(hostname, 80, proto=socket.IPPROTO_TCP)
    if not info:
        logger.error("DNS resolution failed")

    # Iterate over the results to find the IPv4 and IPv6 addresses they may not all be present.
    # The function returns a list of 5-tuples with the following structure:
    # (family, type, proto, canonname, sockaddr)
    for info_tuple in info:
        if info_tuple[0] == socket.AF_INET:
            ipv4 = info_tuple[4][0]
        elif info_tuple[0] == socket.AF_INET6:
            ipv6 = info_tuple[4][0]

    if ipv4 and not ipv6:
        logger.warning(f"DNS resolution for {hostname} returned only an IPv4 address")
    elif ipv6 and not ipv4:
        logger.warning(f"DNS resolution for {hostname} returned only an IPv6 address")

    return ipv4, ipv6


async def check_dns_ipv4() -> bool:
    """Check if DNS resolution is working via IPv4."""
    ipv4, _ = await resolve_dns(settings.CONNECTIVITY_DNS_HOSTNAME)
    return bool(ipv4)


async def check_dns_ipv6() -> bool:
    """Check if DNS resolution is working via IPv6."""
    _, ipv6 = await resolve_dns(settings.CONNECTIVITY_DNS_HOSTNAME)
    return bool(ipv6)


async def check_domain_resolution_ipv4() -> bool:
    """Check if the host's hostname resolves to an IPv4 address."""
    ipv4, _ = await resolve_dns(settings.DOMAIN_NAME)
    return bool(ipv4)


async def check_domain_resolution_ipv6() -> bool:
    """Check if the host's hostname resolves to an IPv6 address."""
    _, ipv6 = await resolve_dns(settings.DOMAIN_NAME)
    return bool(ipv6)


@return_false_on_timeout
async def check_domain_ipv4() -> bool:
    """Check if the host's hostname is accessible via IPv4."""
    return await check_http_endpoint(settings.DOMAIN_NAME, socket.AF_INET)


@return_false_on_timeout
async def check_domain_ipv6() -> bool:
    """Check if the host's hostname is accessible via IPv6."""
    return await check_http_endpoint(settings.DOMAIN_NAME, socket.AF_INET6)
