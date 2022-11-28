import logging
from typing import Optional, Dict
from ipaddress import IPv6Network, IPv6Address

from .firewall import initialize_nftables, teardown_nftables, setup_nftables_for_vm
from .interfaces import TapInterface
from .ipaddresses import IPv4NetworkWithInterfaces

logger = logging.getLogger(__name__)


def get_current_proc_config(configitem: str) -> int:
    """Reads the current ipv4 forwarding setting from the hosts, converts it to int and returns it"""
    if not configitem.startswith("/proc/"):
        logger.error(f"{configitem} is not a configuration item in /proc/")
        raise ValueError

    with open(configitem) as f:
        return int(f.read())


def get_host_ipv6_network(interface: str) -> IPv6Network:
    """Gets the first global ipv6 from the interface, and returns its /64 network"""
    network = None
    with open("/proc/net/if_inet6") as f:
        while not network:
            line = f.readline()
            if not line:
                break

            addr, scope, line_interface = line[0:32], line[39:41], line[45:].strip()
            if scope == "00" and line_interface == interface:
                network = IPv6Network((int(addr, 16), 64), strict=False)

    return network


class Network:
    proc_config: Dict[str, int]
    address_pool: IPv4NetworkWithInterfaces = IPv4NetworkWithInterfaces("172.16.0.0/12")
    network_size: int
    ipv6_address_pool: Optional[IPv6Network]
    external_interface: str

    def get_ipv4_network_for_tap(self, vm_id: int) -> IPv4NetworkWithInterfaces:
        subnets = list(self.address_pool.subnets(new_prefix=self.network_size))
        return subnets[vm_id]

    def get_ipv6_address(self, vm_id: int) -> Optional[IPv6Address]:
        return self.ipv6_address_pool[vm_id] if self.ipv6_address_pool else None

    def set_proc_config(self, configitem: str, value: int) -> None:
        """Saves the existing configuration, and then sets it to the specified value"""
        if not configitem.startswith("/proc/"):
            logger.error(f"{configitem} is not a configuration item in /proc/")
            raise ValueError

        logger.debug(f"Setting {configitem} to {value}")
        if configitem not in self.proc_config:
            self.proc_config[configitem] = get_current_proc_config(configitem)

        if not self.proc_config[configitem] == value:
            with open(configitem, "w") as f:
                f.write(str(value))

    def reset_proc_config(self, configitem: str) -> None:
        """Returns the proc config option to state how it was before we modified it"""
        if configitem not in self.proc_config:
            logger.warning(
                f"{configitem} has no previous configuration set, so we can't reset it"
            )
            return

        logger.debug(f"Resetting {configitem} back to {self.proc_config[configitem]}")
        if self.proc_config[configitem] != get_current_proc_config(configitem):
            with open(configitem, "w") as f:
                f.write(str(self.proc_config[configitem]))

        del self.proc_config[configitem]
        return

    def __init__(
        self,
        vm_address_pool_range: str,
        vm_network_size: int,
        ipv6_address_pool: str,
        external_interface: str,
    ) -> None:
        """Sets up the Network class with some information it needs so future function calls work as expected"""
        self.proc_config = {}
        self.external_interface = external_interface

        if vm_address_pool_range:
            self.address_pool = IPv4NetworkWithInterfaces(vm_address_pool_range)
            if not self.address_pool.is_private:
                logger.warning(
                    f"Using a network range that is not private: {self.address_pool}"
                )
            self.network_size = vm_network_size
            self.set_proc_config("/proc/sys/net/ipv4/ip_forward", 1)

        if ipv6_address_pool:
            self.ipv6_address_pool = (
                IPv6Network(ipv6_address_pool)
                if ipv6_address_pool != "host"
                else get_host_ipv6_network(external_interface)
            )
            self.set_proc_config(f"/proc/sys/net/ipv6/conf/all/forwarding", 1)
            self.set_proc_config(f"/proc/sys/net/ipv6/conf/all/proxy_ndp", 1)

        initialize_nftables()

    def teardown(self) -> None:
        teardown_nftables()
        for configitem in list(self.proc_config):
            self.reset_proc_config(configitem)

    async def create_tap(self, vm_id: int) -> TapInterface:
        """Create TAP interface to be used by VM"""
        interface = TapInterface(
            f"vmtap{vm_id}",
            self.get_ipv4_network_for_tap(vm_id),
            self.get_ipv6_address(vm_id),
        )
        await interface.create(external_interface=self.external_interface)
        setup_nftables_for_vm(vm_id, interface)
        return interface
