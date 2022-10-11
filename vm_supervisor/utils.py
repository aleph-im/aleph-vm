import asyncio
import json
import logging
from base64 import b32decode, b16encode
from dataclasses import is_dataclass, asdict as dataclass_as_dict
from typing import Any, Optional, Coroutine, Tuple, Iterable

import aiodns

logger = logging.getLogger(__name__)


def b32_to_b16(hash: str) -> bytes:
    """Convert base32 encoded bytes to base16 encoded bytes."""
    # Add padding
    hash_b32: str = hash.upper() + "=" * (56 - len(hash))
    hash_bytes: bytes = b32decode(hash_b32.encode())
    return b16encode(hash_bytes).lower()


async def get_ref_from_dns(domain):
    resolver = aiodns.DNSResolver()
    record = await resolver.query(domain, "TXT")
    return record[0].text


def to_json(o: Any):
    if hasattr(o, "to_dict"):  # default method
        return o.to_dict()
    elif hasattr(o, "dict"):  # Pydantic
        return o.dict()
    elif is_dataclass(o):
        return dataclass_as_dict(o)
    else:
        return str(o)


def dumps_for_json(o: Any, indent: Optional[int] = None):
    return json.dumps(o, default=to_json, indent=indent)


async def run_and_log_exception(coro: Coroutine):
    """Exceptions in coroutines may go unnoticed if they are not handled."""
    try:
        return await coro
    except Exception as error:
        logger.exception(error)
        raise


def create_task_log_exceptions(coro: Coroutine, *, name=None):
    """Ensure that exceptions running in coroutines are logged."""
    return asyncio.create_task(run_and_log_exception(coro), name=name)


def ipstr_to_int(ip_string: str) -> Tuple[int, int]:
    """Convert an IP address string with subnet mask to an integer
    representation of the IP and the mask separately.
    """
    ip, mask = ip_string.split("/")
    ip_int = sum(
        int(octet) * 256**idx for idx, octet in enumerate(reversed(ip.split(".")))
    )
    for idx, octet in enumerate(reversed(ip.split("."))):
        ip_int += int(octet) * 256**idx
    return ip_int, int(mask)


def int_to_ipstr(ip_int: int, mask: int) -> str:
    """Converts an integer representation of an IP address and a subnetmask
    and turns it into a string representation
    """
    ip_integers: Iterable[int] = (
        (ip_int >> (8 * i)) & 0xFF for i in reversed(range(4))
    )
    ip_string: str = ".".join(str(i) for i in ip_integers)
    return f"{ip_string}/{mask}"


def get_ip_addresses(
    vm_id: int, address_pool: str, ip_network_size: int
) -> Tuple[str, str]:
    """Calculates the host and guest ip from vm_id and returns it as their string representations with subnetmask"""
    network_pool, pool_size = ipstr_to_int(address_pool)
    pool_netmask = 0xFFFFFFFF << 32 - pool_size
    network_part = vm_id << 32 - ip_network_size
    network_part_mask = 2 ** (ip_network_size - pool_size) - 1 << 32 - ip_network_size
    host = 1
    guest = 2
    hosts_mask = 2 ** (32 - ip_network_size) - 1

    host_ip = (
        (network_pool & pool_netmask)
        | (network_part & network_part_mask)
        | (host & hosts_mask)
    )
    guest_ip = (
        (network_pool & pool_netmask)
        | (network_part & network_part_mask)
        | (guest & hosts_mask)
    )

    return int_to_ipstr(host_ip, ip_network_size), int_to_ipstr(
        guest_ip, ip_network_size
    )
