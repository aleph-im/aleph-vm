import logging
from ipaddress import IPv6Network
from pathlib import Path
from typing import Protocol

import pyroute2
from aleph_message.models import ItemHash

from aleph.vm.conf import IPv6AllocationPolicy
from aleph.vm.vm_type import VmType

from .firewall import initialize_nftables, setup_nftables_for_vm, teardown_nftables
from .get_interface_ipv4 import get_interface_ipv4
from .interfaces import TapInterface
from .ipaddresses import IPv4NetworkWithInterfaces
from .ndp_proxy import NdpProxy

logger = logging.getLogger(__name__)


def _read_file_as_int(config_file: Path) -> int:
    return int(config_file.read_text())


def get_ipv4_forwarding_state() -> int:
    """Reads the current IPv4 forwarding setting from the host, converts it to int and returns it"""
    return _read_file_as_int(Path("/proc/sys/net/ipv4/ip_forward"))


def get_ipv6_forwarding_state() -> int:
    """Reads the current IPv6 forwarding setting from the host, converts it to int and returns it"""
    return _read_file_as_int(Path("/proc/sys/net/ipv6/conf/all/forwarding"))


class IPv6Allocator(Protocol):
    def allocate_vm_ipv6_subnet(self, vm_id: int, vm_hash: ItemHash, vm_type: VmType) -> IPv6Network: ...


class StaticIPv6Allocator(IPv6Allocator):
    """
    Static IPv6 allocator.
    Computes IPv6 addresses based on the machine type and VM hash. The algorithm works
    as follows:

    | Component | CRN /64 range | VM type | Item hash prefix | Instance range |
    |-----------|---------------|---------|------------------|----------------|
    | Length    | 64 bits       | 16 bits | 44 bits          | 4 bits         |
    """

    VM_TYPE_PREFIX = {
        VmType.microvm: "1",
        VmType.persistent_program: "2",
        VmType.instance: "3",
    }

    def __init__(self, ipv6_range: IPv6Network, subnet_prefix: int):
        if ipv6_range.prefixlen not in (56, 64):
            msg = "The static IP address allocation scheme requires a /64 or /56 subnet"
            raise ValueError(msg)
        if subnet_prefix < 124:
            msg = "The IPv6 subnet prefix cannot be larger than /124."
            raise ValueError(msg)

        self.ipv6_range = ipv6_range
        self.subnet_prefix = subnet_prefix

    def allocate_vm_ipv6_subnet(self, vm_id: int, vm_hash: ItemHash, vm_type: VmType) -> IPv6Network:
        ipv6_elems = self.ipv6_range.exploded.split(":")[:4]
        ipv6_elems += [self.VM_TYPE_PREFIX[vm_type]]

        # Add the item hash of the VM as the last 44 bits of the IPv6 address.
        # The last 4 bits are left for use to the VM owner as a /124 subnet.
        ipv6_elems += [vm_hash[0:4], vm_hash[4:8], vm_hash[8:11] + "0"]

        return IPv6Network(":".join(ipv6_elems) + "/124")


class DynamicIPv6Allocator(IPv6Allocator):
    """
    A dynamic allocator, for testing purposes.
    This allocator slices the input IPv6 address range in subnets of the same size
    and iterates through them. The first subnet is assumed to be reserved for use by the host,
    as we use this allocator in situations where the address range is small and the host
    subnet cannot be isolated from the VM subnets (ex: /124 network on Digital Ocean for the CI).
    """

    def __init__(self, ipv6_range: IPv6Network, subnet_prefix: int):
        self.ipv6_range = ipv6_range
        self.vm_subnet_prefix = subnet_prefix

        self.subnets_generator = ipv6_range.subnets(new_prefix=subnet_prefix)
        # Assume the first subnet is reserved for the host
        _ = next(self.subnets_generator)

    def allocate_vm_ipv6_subnet(self, vm_id: int, vm_hash: ItemHash, vm_type: VmType) -> IPv6Network:
        return next(self.subnets_generator)


def make_ipv6_allocator(
    allocation_policy: IPv6AllocationPolicy, address_pool: str, subnet_prefix: int
) -> IPv6Allocator:
    if allocation_policy == IPv6AllocationPolicy.static:
        return StaticIPv6Allocator(ipv6_range=IPv6Network(address_pool), subnet_prefix=subnet_prefix)

    return DynamicIPv6Allocator(ipv6_range=IPv6Network(address_pool), subnet_prefix=subnet_prefix)


class Network:
    ipv4_forward_state_before_setup: int | None = None
    ipv6_forward_state_before_setup: int | None = None
    external_interface: str
    ipv4_forwarding_enabled: bool
    ipv6_forwarding_enabled: bool
    use_ndp_proxy: bool
    ipv4_address_pool: IPv4NetworkWithInterfaces = IPv4NetworkWithInterfaces("172.16.0.0/12")
    ipv6_address_pool: IPv6Network
    network_size: int
    ndp_proxy: NdpProxy | None = None
    host_ipv4: str

    IPV6_SUBNET_PREFIX: int = 124

    def __init__(
        self,
        vm_ipv4_address_pool_range: str,
        vm_network_size: int,
        external_interface: str,
        ipv6_allocator: IPv6Allocator,
        use_ndp_proxy: bool,
        ipv4_forwarding_enabled: bool = True,
        ipv6_forwarding_enabled: bool = True,
    ) -> None:
        """Initialize the Network class with the relevant configuration."""
        self.ipv4_address_pool = IPv4NetworkWithInterfaces(vm_ipv4_address_pool_range)
        self.ipv6_allocator = ipv6_allocator

        self.network_size = vm_network_size
        self.external_interface = external_interface
        self.ipv4_forwarding_enabled = ipv4_forwarding_enabled
        self.ipv6_forwarding_enabled = ipv6_forwarding_enabled
        self.use_ndp_proxy = use_ndp_proxy
        self.ndb = pyroute2.NDB()
        self.host_ipv4 = get_interface_ipv4(external_interface)

        if not self.ipv4_address_pool.is_private:
            logger.warning(f"Using a network range that is not private: {self.ipv4_address_pool}")

    def setup(self) -> None:
        """Set up the network for use by the VMs"""
        logger.debug("Enabling IPv4 forwarding")
        if self.ipv4_forwarding_enabled:
            self.enable_ipv4_forwarding()
        else:
            logger.warning("IPv4 forwarding is disabled, VMs will not have internet access on IPv4")
        logger.debug("Enabling IPv6 forwarding")
        if self.ipv6_forwarding_enabled:
            self.enable_ipv6_forwarding()
        else:
            logger.warning("IPv6 forwarding is disabled, VMs will not have internet access on IPv6")

        logger.debug("Enabling NDP proxy")
        if self.use_ndp_proxy:
            self.ndp_proxy = NdpProxy(host_network_interface=self.external_interface)

        logger.debug("Initializing nftables")
        initialize_nftables()
        logger.debug("Network setup complete")

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
            Path("/proc/sys/net/ipv4/ip_forward").write_text(str(self.ipv4_forward_state_before_setup))

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
            Path("/proc/sys/net/ipv6/conf/all/forwarding").write_text(str(self.ipv6_forward_state_before_setup))

    def teardown(self) -> None:
        teardown_nftables()
        self.reset_ipv4_forwarding_state()
        self.reset_ipv6_forwarding_state()

    async def prepare_tap(self, vm_id: int, vm_hash: ItemHash, vm_type: VmType) -> TapInterface:
        """Prepare TAP interface to be used by VM"""
        interface = TapInterface(
            f"vmtap{vm_id}",
            ip_network=self.get_network_for_tap(vm_id),
            ipv6_network=self.ipv6_allocator.allocate_vm_ipv6_subnet(
                vm_id=vm_id,
                vm_hash=vm_hash,
                vm_type=vm_type,
            ),
            ndp_proxy=self.ndp_proxy,
        )
        return interface

    async def create_tap(self, vm_id: int, interface: TapInterface):
        """Create TAP interface to be used by VM"""
        await interface.create()
        setup_nftables_for_vm(vm_id, interface)

    def interface_exists(self, vm_id: int):
        interface_name = f"vmtap{vm_id}"
        return self.ndb.interfaces.exists(interface_name)
