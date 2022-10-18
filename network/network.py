import asyncio
from os import system
from typing import Tuple, Iterable, Dict
import logging

from .firewall import Firewall

logger = logging.getLogger(__name__)


class Network:
    ipv4_forward_state_before_setup = None
    address_pool = "172.16.0.0/12"
    network_size = 24
    network_initialized = False
    external_interface = "eth0"
    vm_info: Dict = {}

    @staticmethod
    def ipstr_to_int(ip_string: str) -> Tuple[int, int]:
        """Convert an IP address string with subnet mask to an integer
        representation of the IP and the mask separately.
        """
        ip, mask = ip_string.split("/")
        ip_int = sum(
            int(octet) * 256**idx for idx, octet in enumerate(reversed(ip.split(".")))
        )
        return ip_int, int(mask)

    @staticmethod
    def int_to_ipstr(ip_int: int, mask: int) -> str:
        """Converts an integer representation of an IP address and a subnetmask
        and turns it into a string representation
        """
        ip_integers: Iterable[int] = (
            (ip_int >> (8 * i)) & 0xFF for i in reversed(range(4))
        )
        ip_string: str = ".".join(str(i) for i in ip_integers)
        return f"{ip_string}/{mask}"

    @classmethod
    def assign_ip_addresses(cls, vm_id: int) -> None:
        """Calculates the host and guest ip from vm_id and
        sets the results in the class info as their string representations with subnetmask"""
        logger.debug(f"Determining IP addresses for vm {vm_id}")
        if vm_id not in cls.vm_info:
            cls.vm_info[vm_id] = {}

        if "ip_addresses" in cls.vm_info[vm_id]:
            logger.error(f"IP Addresses already defined for {vm_id}")
            return
        else:
            cls.vm_info[vm_id]["ip_addresses"] = {}

        network_pool, pool_size = cls.ipstr_to_int(cls.address_pool)
        pool_netmask = 0xFFFFFFFF << 32 - pool_size
        network_part = vm_id << 32 - cls.network_size
        network_part_mask = (
            2 ** (cls.network_size - pool_size) - 1 << 32 - cls.network_size
        )
        host = 1
        guest = 2
        hosts_mask = 2 ** (32 - cls.network_size) - 1

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
        cls.vm_info[vm_id]["ip_addresses"]["host"] = cls.int_to_ipstr(
            host_ip, cls.network_size
        )
        cls.vm_info[vm_id]["ip_addresses"]["guest"] = cls.int_to_ipstr(
            guest_ip, cls.network_size
        )

        logger.debug(
            f"IP addresses for {vm_id}: supervisor: {host_ip}, guest: {guest_ip}"
        )
        return

    @classmethod
    def get_ipv4_forwarding_state(cls) -> int:
        """Reads the current ipv4 forwarding setting from the hosts, converts it to int and returns it"""
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            return int(f.read())

    @classmethod
    def enable_ipv4_forwarding(cls) -> None:
        """Saves the hosts IPv4 forwarding state, and if it was disabled, enables it"""
        logger.debug(f"Enabling IPv4 forwarding")
        cls.ipv4_forward_state_before_setup = cls.get_ipv4_forwarding_state()
        if not cls.ipv4_forward_state_before_setup:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")

    @classmethod
    def reset_ipv4_forwarding_state(cls) -> None:
        """Returns the hosts IPv4 forwarding state how it was before we enabled it"""
        logger.debug("Resetting IPv4 forwarding state to state before we enabled it")
        if cls.ipv4_forward_state_before_setup != cls.get_ipv4_forwarding_state():
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(str(cls.ipv4_forward_state_before_setup))

    @classmethod
    def initialize(
        cls, vm_address_pool_range: str, vm_network_size: int, external_interface: str
    ) -> None:
        """Sets up the Network class with some information it needs so future function calls work as expected"""
        cls.address_pool = vm_address_pool_range
        cls.network_size = vm_network_size
        cls.external_interface = external_interface
        cls.network_initialized = True

    @classmethod
    def create_tap_interface(cls, vm_id: int) -> str:
        """Create a new TAP interface on the host and returns the device name.
        It also instructs the firewall to set up basic rules for this interface."""
        if vm_id not in cls.vm_info or "ip_addresses" not in cls.vm_info[vm_id]:
            cls.assign_ip_addresses(vm_id)
        logger.debug("Create network interface")
        host_dev_name = f"vmtap{vm_id}"

        system(f"ip tuntap add {host_dev_name} mode tap")
        system(
            f"ip addr add {cls.vm_info[vm_id]['ip_addresses']['host']} dev {host_dev_name}"
        )
        system(f"ip link set {host_dev_name} up")
        cls.vm_info[vm_id]["tap_interface"] = host_dev_name
        logger.debug(f"Network interface created: {host_dev_name}")

        Firewall.setup_nftables_for_vm(vm_id)

        return host_dev_name

    @classmethod
    async def remove_tap_interface(cls, vm_id: int) -> None:
        """Asks the firewall to teardown any rules for the VM with id provided.
        Then removes the interface from the host."""
        Firewall.teardown_nftables_for_vm(vm_id)

        if "tap_interface" in cls.vm_info[vm_id]:
            logger.debug(f"Removing interface {cls.vm_info[vm_id]['tap_interface']}")
            await asyncio.sleep(0.1)  # Avoids Device/Resource busy bug
            system(f"ip tuntap del {cls.vm_info[vm_id]['tap_interface']} mode tap")
            del cls.vm_info[vm_id]["tap_interface"]
