import ipaddress
import logging

import netifaces

logger = logging.getLogger(__name__)


def get_interface_ipv4(interface_name: str) -> str:
    """
    Get the main IPv4 address from a network interface, preferring global scope.

    First tries to find an address with global scope. If no global address is found,
    falls back to the first available IPv4 address.

    Args:
        interface_name: Name of the network interface (e.g., 'eth0', 'wlan0')

    Returns:
        str: The IPv4 address of the interface (global scope preferred, fallback to first available)

    Raises:
        ValueError: If the interface doesn't exist or has no IPv4 address
    """
    try:
        # Check if the interface exists
        if interface_name not in netifaces.interfaces():
            raise ValueError(f"Interface {interface_name} does not exist")

        # Get addresses for the interface
        addrs = netifaces.ifaddresses(interface_name)

        # Check for IPv4 addresses (AF_INET is IPv4)
        if netifaces.AF_INET not in addrs:
            raise ValueError(f"No IPv4 address found for interface {interface_name}")

        ipv4_addresses = addrs[netifaces.AF_INET]

        # Find the first IPv4 address with global scope
        for ipv4_info in ipv4_addresses:
            ipv4_addr = ipv4_info["addr"]
            addr = ipaddress.IPv4Address(ipv4_addr)
            if addr.is_global:
                return ipv4_addr

        # Fallback: return the first available address if no global address found
        fallback_addr = ipv4_addresses[0]["addr"]
        logger.warning(
            f"No global IPv4 address found for interface {interface_name}, "
            f"falling back to non-global address: {fallback_addr}"
        )
        return fallback_addr

    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Error getting IPv4 address: {str(e)}")
