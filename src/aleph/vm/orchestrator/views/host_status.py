import logging
import socket
from typing import Any, Awaitable, Callable, Tuple

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


async def check_ip_connectivity(url: str, socket_family: socket.AddressFamily = socket.AF_UNSPEC) -> bool:
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(family=socket_family), timeout=timeout) as session:
        try:
            async with session.get(url) as resp:
                # We expect the Quad9 endpoints to return a 404 error, but other endpoints may return a 200
                if resp.status not in (200, 404):
                    resp.raise_for_status()
                return True
        except aiohttp.ClientConnectorError:
            return False


@return_false_on_timeout
async def check_host_egress_ipv4() -> bool:
    """Check if the host has IPv4 connectivity."""
    return await check_ip_connectivity(settings.CONNECTIVITY_IPV4_URL)


@return_false_on_timeout
async def check_host_egress_ipv6() -> bool:
    """Check if the host has IPv6 connectivity."""
    return await check_ip_connectivity(settings.CONNECTIVITY_IPV6_URL)


async def resolve_dns(hostname: str) -> Tuple[str, str]:
    info_inet, info_inet6 = socket.getaddrinfo(hostname, 80, proto=socket.IPPROTO_TCP)
    ipv4 = info_inet[4][0]
    ipv6 = info_inet6[4][0]
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
    return await check_ip_connectivity(settings.DOMAIN_NAME, socket.AF_INET)


@return_false_on_timeout
async def check_domain_ipv6() -> bool:
    """Check if the host's hostname is accessible via IPv6."""
    return await check_ip_connectivity(settings.DOMAIN_NAME, socket.AF_INET6)
