import logging
from ipaddress import IPv6Network
from pathlib import Path
from typing import Protocol, Optional

from .firewall import initialize_nftables, setup_nftables_for_vm, teardown_nftables
from .interfaces import TapInterface
from .ipaddresses import IPv4NetworkWithInterfaces

logger = logging.getLogger(__name__)


def _read_proc_file_value(config_file: Path) -> int:
    return int(config_file.read_text())


def get_ipv4_forwarding_state() -> int:
    """Reads the current IPv4 forwarding setting from the host, converts it to int and returns it"""
    return _read_proc_file_value(Path("/proc/sys/net/ipv4/ip_forward"))


def get_ipv6_forwarding_state() -> int:
    """Reads the current IPv6 forwarding setting from the host, converts it to int and returns it"""
    return _read_proc_file_value(Path("/proc/sys/net/ipv6/conf/all/forwarding"))


class IPv6Allocator(Protocol):
    def allocate_vm_ipv6_range(self, vm_id: int, vm_hash: str) -> IPv6Network:
        ...


class StaticIPv6Allocator(IPv6Allocator):
    def __init__(self, ipv6_range: IPv6Network):
        if ipv6_range.prefixlen != 64:
            raise ValueError(
                "The static IP address allocation scheme requires a /64 subnet"
            )
        self.ipv6_range = ipv6_range

    def allocate_vm_ipv6_range(self, vm_id: int, vm_hash: str) -> IPv6Network:
        ...


class DynamicIPv6Allocator(IPv6Allocator):
    def __init__(self, ipv6_range: IPv6Network, vm_subnet_prefix: int):
        self.ipv6_range = ipv6_range
        self.vm_subnet_prefix = vm_subnet_prefix

        self.subnets_generator = ipv6_range.subnets(new_prefix=vm_subnet_prefix)
        # Assume the first two subnets are reserved
        _ = next(self.subnets_generator)
        _ = next(self.subnets_generator)

    def allocate_vm_ipv6_range(self, vm_id: int, vm_hash: str) -> IPv6Network:
        return next(self.subnets_generator)


class Network:
    ipv4_forward_state_before_setup: Optional[int]
    ipv6_forward_state_before_setup: Optional[int]
    ipv4_address_pool: IPv4NetworkWithInterfaces = IPv4NetworkWithInterfaces(
        "172.16.0.0/12"
    )
    ipv6_address_pool: IPv6Network
    network_size: int
    external_interface: str

    def get_network_for_tap(self, vm_id: int) -> IPv4NetworkWithInterfaces:
        subnets = list(self.ipv4_address_pool.subnets(new_prefix=self.network_size))
        return subnets[vm_id]

    def enable_ipv4_forwarding(self) -> None:
        """Saves the hosts IPv4 forwarding state, and if it was disabled, enables it"""
        logger.debug("Enabling IPv4 forwarding")
        self.ipv4_forward_state_before_setup = get_ipv4_forwarding_state()
        if not self.ipv4_forward_state_before_setup:
            Path("/proc/sys/net/ipv4/ip_forward").write_text("1")

    def reset_ipv4_forwarding_state(self) -> None:
        """Returns the hosts IPv4 forwarding state how it was before we enabled it"""
        logger.debug("Resetting IPv4 forwarding state to state before we enabled it")
        if self.ipv4_forward_state_before_setup is None:
            return

        if self.ipv4_forward_state_before_setup != get_ipv4_forwarding_state():
            Path("/proc/sys/net/ipv4/ip_forward").write_text(
                str(self.ipv4_forward_state_before_setup)
            )

    def enable_ipv6_forwarding(self) -> None:
        """Saves the host IPv6 forwarding state, and if it was disabled, enables it"""
        logger.debug("Enabling IPv6 forwarding")
        self.ipv6_forward_state_before_setup = get_ipv6_forwarding_state()
        if not self.ipv6_forward_state_before_setup:
            Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text("1")

    def reset_ipv6_forwarding_state(self) -> None:
        """Returns the host IPv6 forwarding state how it was before we enabled it"""
        logger.debug("Resetting IPv6 forwarding state to state before we enabled it")
        if self.ipv6_forward_state_before_setup is None:
            return

        if self.ipv6_forward_state_before_setup != get_ipv6_forwarding_state():
            Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text(
                str(self.ipv6_forward_state_before_setup)
            )

    def __init__(
        self,
        vm_ipv4_address_pool_range: str,
        vm_ipv6_address_range: str,
        vm_network_size: int,
        external_interface: str,
    ) -> None:
        """Sets up the Network class with some information it needs so future function calls work as expected"""
        self.ipv4_address_pool = IPv4NetworkWithInterfaces(vm_ipv4_address_pool_range)
        if not self.ipv4_address_pool.is_private:
            logger.warning(
                f"Using a network range that is not private: {self.ipv4_address_pool}"
            )
        self.ipv6_allocator = DynamicIPv6Allocator(
            ipv6_range=IPv6Network(vm_ipv6_address_range, strict=False),
            vm_subnet_prefix=127,
        )

        self.ipv4_forward_state_before_setup = None
        self.ipv6_forward_state_before_setup = None

        self.network_size = vm_network_size
        self.external_interface = external_interface
        self.enable_ipv4_forwarding()
        initialize_nftables()

    def teardown(self) -> None:
        teardown_nftables()
        self.reset_ipv4_forwarding_state()
        self.reset_ipv6_forwarding_state()

    async def create_tap(self, vm_id: int, vm_hash: str) -> TapInterface:
        """Create TAP interface to be used by VM"""
        interface = TapInterface(
            f"vmtap{vm_id}",
            self.get_network_for_tap(vm_id),
            ipv6_network=self.ipv6_allocator.allocate_vm_ipv6_range(
                vm_id=vm_id, vm_hash=vm_hash
            ),
        )
        await interface.create()
        setup_nftables_for_vm(vm_id, interface)
        return interface
