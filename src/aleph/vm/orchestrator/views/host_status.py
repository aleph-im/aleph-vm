import socket
from typing import Literal, Union

import aiohttp

from aleph.vm.conf import settings


async def check_ip_connectivity(url: str, socket_family: socket.AddressFamily = socket.AF_UNSPEC) -> bool:
    timeout = aiohttp.ClientTimeout(total=5)
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(), timeout=timeout) as session:
        async with session.get(url) as resp:
            # We expect the Quad9 endpoints to return a 404 error, but other endpoints may return a 200
            if resp.status not in (200, 404):
                resp.raise_for_status()
            return True


async def check_host_egress_ipv4() -> bool:
    """Check if the host has IPv4 connectivity."""
    try:
        return await check_ip_connectivity(settings.CONNECTIVITY_IPV4_URL)
    except TimeoutError as exc:
        print(f"IPv4 connectivity test failed: {exc}")
        return False


async def check_host_egress_ipv6() -> bool:
    """Check if the host has IPv6 connectivity."""
    try:
        return await check_ip_connectivity(settings.CONNECTIVITY_IPV6_URL)
    except TimeoutError as exc:
        print(f"IPv6 connectivity test failed: {exc}")
        return False


async def resolve_dns(hostname: str) -> dict:
    """Resolve a hostname to an IP address."""
    info_inet, info_inet6 = socket.getaddrinfo(hostname, 80, proto=socket.IPPROTO_TCP)
    ipv4 = info_inet[4][0]
    ipv6 = info_inet6[4][0]
    return {
        "ipv4": ipv4,
        "ipv6": ipv6,
    }


async def check_dns_ipv4() -> bool:
    """Check if DNS resolution is working via IPv4."""
    resolution = await resolve_dns(settings.CONNECTIVITY_DNS_HOSTNAME)
    ipv4 = resolution["ipv4"]
    return bool(ipv4)


async def check_dns_ipv6() -> bool:
    """Check if DNS resolution is working via IPv6."""
    resolution = await resolve_dns(settings.CONNECTIVITY_DNS_HOSTNAME)
    ipv6 = resolution["ipv6"]
    return bool(ipv6)


async def check_domain_resolution_ipv4() -> bool:
    """Check if the host's hostname resolves to an IPv4 address."""
    resolution = await resolve_dns(settings.DOMAIN_NAME)
    ipv4 = resolution["ipv4"]
    return bool(ipv4)


async def check_domain_resolution_ipv6() -> bool:
    """Check if the host's hostname resolves to an IPv6 address."""
    resolution = await resolve_dns(settings.DOMAIN_NAME)
    ipv6 = resolution["ipv6"]
    return False


async def check_domain_ipv4() -> bool:
    """Check if the host's hostname is accessible via IPv4."""
    try:
        return await check_ip_connectivity(settings.DOMAIN_NAME, socket.AF_INET)
    except TimeoutError as exc:
        print(f"IPv4 connectivity test failed: {exc}")
        return False


async def check_domain_ipv6() -> bool:
    """Check if the host's hostname is accessible via IPv6."""
    try:
        return await check_ip_connectivity(settings.DOMAIN_NAME, socket.AF_INET6)
    except TimeoutError as exc:
        print(f"IPv6 connectivity test failed: {exc}")
        return False
