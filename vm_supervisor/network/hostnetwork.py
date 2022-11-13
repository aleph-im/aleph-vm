import logging

from .firewall import initialize_nftables, teardown_nftables, setup_nftables_for_vm
from .interfaces import TapInterface
from .ipaddresses import IPv4NetworkWithInterfaces

logger = logging.getLogger(__name__)


def get_ipv4_forwarding_state() -> int:
    """Reads the current ipv4 forwarding setting from the hosts, converts it to int and returns it"""
    with open("/proc/sys/net/ipv4/ip_forward") as f:
        return int(f.read())


class Network:
    ipv4_forward_state_before_setup: int
    address_pool: IPv4NetworkWithInterfaces = IPv4NetworkWithInterfaces("172.16.0.0/12")
    network_size: int
    external_interface: str

    def get_network_for_tap(self, vm_id: int) -> IPv4NetworkWithInterfaces:
        subnets = list(self.address_pool.subnets(new_prefix=self.network_size))
        return subnets[vm_id]

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

    def __init__(self, vm_address_pool_range: str, vm_network_size: int, external_interface: str) -> None:
        """Sets up the Network class with some information it needs so future function calls work as expected"""
        self.address_pool = IPv4NetworkWithInterfaces(vm_address_pool_range)
        if not self.address_pool.is_private:
            logger.warning(
                f"Using a network range that is not private: {self.address_pool}"
            )
        self.network_size = vm_network_size
        self.external_interface = external_interface
        self.enable_ipv4_forwarding()
        initialize_nftables()

    def teardown(self) -> None:
        teardown_nftables()
        self.reset_ipv4_forwarding_state()

    async def create_tap(self, vm_id: int) -> TapInterface:
        """ Create TAP interface to be used by VM
        """
        interface = TapInterface(f"vmtap{vm_id}", self.get_network_for_tap(vm_id))
        await interface.create()
        setup_nftables_for_vm(vm_id, interface)
        return interface
