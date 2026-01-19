import ipaddress

import netifaces


def get_interface_ipv4(interface_name: str) -> str:
    """
    Get the main IPv4 address with global scope from a network interface.

    Skips link-local addresses (169.254.x.x) and returns the first address
    that has global or private scope.

    Args:
        interface_name: Name of the network interface (e.g., 'eth0', 'wlan0')

    Returns:
        str: The IPv4 address of the interface with global scope

    Raises:
        ValueError: If the interface doesn't exist or has no IPv4 address with global scope
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

        # Find the first IPv4 address with global scope (skip link-local addresses)
        for ipv4_info in addrs[netifaces.AF_INET]:
            ipv4_addr = ipv4_info["addr"]
            addr = ipaddress.IPv4Address(ipv4_addr)
            if addr.is_global or addr.is_private:
                return ipv4_addr

        raise ValueError(f"No IPv4 address with global scope found for interface {interface_name}")

    except Exception as e:
        raise ValueError(f"Error getting IPv4 address: {str(e)}")
