from __future__ import annotations

import asyncio
import logging
from subprocess import run
from typing import Tuple, Iterable, Dict, Type

from .firewall import Firewall

logger = logging.getLogger(__name__)


def ipstr_to_int(ip_string: str) -> Tuple[int, int]:
    """Convert an IP address string with subnet mask to an integer
    representation of the IP and the mask separately.
    """
    ip, mask = ip_string.split("/")
    ip_int = sum(
        int(octet) * 256 ** idx for idx, octet in enumerate(reversed(ip.split(".")))
    )
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


def get_ipv4_forwarding_state() -> int:
    """Reads the current ipv4 forwarding setting from the hosts, converts it to int and returns it"""
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        return int(f.read())


class Network:
    ipv4_forward_state_before_setup = None
    address_pool = "172.16.0.0/12"
    network_size = 24
    network_initialized = False
    external_interface = "eth0"
    vm_info: Dict = {}

    def assign_ip_addresses(self, vm_id: int) -> None:
        """Calculates the host and guest ip from vm_id and
        sets the results in the class info as their string representations with subnetmask"""
        logger.debug(f"Determining IP addresses for vm {vm_id}")
        if vm_id not in self.vm_info:
            self.vm_info[vm_id] = {}

        if "ip_addresses" in self.vm_info[vm_id]:
            logger.error(f"IP Addresses already defined for {vm_id}")
            return
        else:
            self.vm_info[vm_id]["ip_addresses"] = {}

        network_pool, pool_size = ipstr_to_int(self.address_pool)
        pool_netmask = 0xFFFFFFFF << 32 - pool_size
        network_part = vm_id << 32 - self.network_size
        network_part_mask = (
            2 ** (self.network_size - pool_size) - 1 << 32 - self.network_size
        )
        host = 1
        guest = 2
        hosts_mask = 2 ** (32 - self.network_size) - 1

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
        self.vm_info[vm_id]["ip_addresses"]["host"] = int_to_ipstr(
            host_ip, self.network_size
        )
        self.vm_info[vm_id]["ip_addresses"]["guest"] = int_to_ipstr(
            guest_ip, self.network_size
        )

        logger.debug(
            f"IP addresses for {vm_id}: supervisor: {host_ip}, guest: {guest_ip}"
        )
        return

    def enable_ipv4_forwarding(self) -> None:
        """Saves the hosts IPv4 forwarding state, and if it was disabled, enables it"""
        logger.debug(f"Enabling IPv4 forwarding")
        self.ipv4_forward_state_before_setup = get_ipv4_forwarding_state()
        if not self.ipv4_forward_state_before_setup:
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write("1")

    def reset_ipv4_forwarding_state(self) -> None:
        """Returns the hosts IPv4 forwarding state how it was before we enabled it"""
        logger.debug("Resetting IPv4 forwarding state to state before we enabled it")
        if self.ipv4_forward_state_before_setup != get_ipv4_forwarding_state():
            with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
                f.write(str(self.ipv4_forward_state_before_setup))

    def initialize(
        self, vm_address_pool_range: str, vm_network_size: int, external_interface: str
    ) -> None:
        """Sets up the Network class with some information it needs so future function calls work as expected"""
        self.address_pool = vm_address_pool_range
        self.network_size = vm_network_size
        self.external_interface = external_interface
        self.network_initialized = True


class TapInterface:
    device_name: str
    ip_addr: str
    vm_id: int

    def __init__(self, device_name: str, ip_addr: str, vm_id: int):
        self.device_name = device_name
        self.ip_addr = ip_addr
        self.vm_id = vm_id

    @classmethod
    def from_vm_id(cls: Type[TapInterface], vm_id: int) -> TapInterface:
        """Create a Tap network interface from a sequential VM id.
        """
        network_instance.assign_ip_addresses(vm_id)
        device_name = network_instance.vm_info[vm_id]["tap_interface"]
        ip_addr = network_instance.vm_info[vm_id]['ip_addresses']['host']
        return cls(device_name=device_name, ip_addr=ip_addr, vm_id=vm_id)

    async def create(self):
        """Create a new TAP interface on the host and returns the device name.
        It also instructs the firewall to set up basic rules for this interface."""
        logger.debug("Create network interface")

        run(["/usr/bin/ip", "tuntap", "add", self.device_name, "mode", "tap"])
        run(["/usr/bin/ip", "addr", "add", self.ip_addr, "dev", self.device_name])
        run(["/usr/bin/ip", "link", "set", self.device_name, "up"])
        logger.debug(f"Network interface created: {self.device_name}")

        Firewall.setup_nftables_for_vm(self.vm_id)

    async def delete(self):
        """Asks the firewall to teardown any rules for the VM with id provided.
        Then removes the interface from the host."""
        Firewall.teardown_nftables_for_vm(self.vm_id)

        logger.debug(f"Removing interface {self.device_name}")
        await asyncio.sleep(0.1)  # Avoids Device/Resource busy bug
        run(["ip", "tuntap", "del", self.device_name, "mode", "tap"])


# Network singleton
network_instance = Network()
