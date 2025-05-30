import ipaddress

import netifaces


def get_interface_ipv4(interface_name: str) -> str:
    """
    Get the main IPv4 address from a network interface.

    Args:
        interface_name: Name of the network interface (e.g., 'eth0', 'wlan0')

    Returns:
        str: The IPv4 address of the interface

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

        # Get the first IPv4 address
        ipv4_info = addrs[netifaces.AF_INET][0]
        ipv4_addr = ipv4_info["addr"]

        # Validate that it's a proper IPv4 address
        ipaddress.IPv4Address(ipv4_addr)

        return ipv4_addr

    except Exception as e:
        raise ValueError(f"Error getting IPv4 address: {str(e)}")
