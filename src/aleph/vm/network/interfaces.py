import asyncio
import errno
import logging
import shutil
from ipaddress import IPv4Interface, IPv6Interface, IPv6Network
from typing import Optional, Union

from pyroute2 import IPRoute, NetlinkError

from .ipaddresses import IPv4NetworkWithInterfaces
from .ndp_proxy import NdpProxy

logger = logging.getLogger(__name__)


class MissingInterfaceError(Exception):
    """The interface is missing."""

    pass


class InterfaceBusyError(Exception):
    """The interface is busy."""

    pass


def create_tap_interface(ipr: IPRoute, device_name: str):
    """Create a TAP interface with the given name. If the interface already exists, which should not happen, a warning
    is logged and the function returns without error."""
    try:
        ipr.link("add", ifname=device_name, kind="tuntap", mode="tap")
    except NetlinkError as error:
        if error.code == 17:
            logger.warning(f"Interface {device_name} already exists")
        elif error.code == 16:
            logger.warning(f"Interface {device_name} is busy - is there another process using it ?")
        else:
            logger.error(f"Unknown exception while creating interface {device_name}: {error}")
    except OSError as error:
        if error.errno == errno.EBUSY:
            logger.warning(f"Interface {device_name} is busy - is there another process using it ?")
        else:
            logger.error(f"Unknown exception while creating interface {device_name}: {error}")


def add_ip_address(ipr: IPRoute, device_name: str, ip: Union[IPv4Interface, IPv6Interface]):
    """Add an IP address to the given interface. If the address already exists, a warning is logged and the function
    returns without error."""
    interface_index: list[int] = ipr.link_lookup(ifname=device_name)
    if not interface_index:
        raise MissingInterfaceError(f"Interface {device_name} does not exist, can't add address {ip} to it.")
    try:
        ipr.addr("add", index=interface_index[0], address=str(ip.ip), mask=ip.network.prefixlen)
    except NetlinkError as e:
        if e.code == 17:
            logger.warning(f"Address {ip} already exists")
        else:
            logger.error(f"Unknown exception while adding address {ip} to interface {device_name}: {e}")
    except OSError as e:
        logger.error(f"Unknown exception while adding address {ip} to interface {device_name}: {e}")


def delete_ip_address(ipr: IPRoute, device_name: str, ip: Union[IPv4Interface, IPv6Interface]):
    """Delete an IP address to the given interface."""
    interface_index: list[int] = ipr.link_lookup(ifname=device_name)
    if not interface_index:
        raise MissingInterfaceError(f"Interface {device_name} does not exist, can't delete address {ip} to it.")
    try:
        ipr.addr("del", index=interface_index[0], address=str(ip.ip), mask=ip.network.prefixlen)
    except NetlinkError as e:
        logger.error(f"Unknown exception while deleting address {ip} to interface {device_name}: {e}")
    except OSError as e:
        logger.error(f"Unknown exception while deleting address {ip} to interface {device_name}: {e}")


def set_link_up(ipr: IPRoute, device_name: str):
    """Set the given interface up."""
    interface_index: list[int] = ipr.link_lookup(ifname=device_name)
    if not interface_index:
        raise MissingInterfaceError(f"Interface {device_name} does not exist, can't set it up.")
    try:
        ipr.link("set", index=interface_index[0], state="up")
    except NetlinkError as e:
        logger.error(f"Unknown exception while setting link up to interface {device_name}: {e}")
    except OSError as e:
        logger.error(f"Unknown exception while setting link up to interface {device_name}: {e}")


def delete_tap_interface(ipr: IPRoute, device_name: str):
    interface_index: list[int] = ipr.link_lookup(ifname=device_name)
    if not interface_index:
        logger.debug(f"Interface {device_name} does not exist, won't be deleted.")
        return
    try:
        ipr.link("del", index=interface_index[0])
    except NetlinkError as error:
        logger.warning(f"Interface {device_name} cannot be deleted: {error}")
    except OSError as error:
        logger.warning(f"Interface {device_name} cannot be deleted: {error}")


class TapInterface:
    device_name: str
    ip_network: IPv4NetworkWithInterfaces
    ipv6_network: IPv6Network

    def __init__(
        self,
        device_name: str,
        ip_network: IPv4NetworkWithInterfaces,
        ipv6_network: IPv6Network,
        ndp_proxy: Optional[NdpProxy],
    ):
        self.device_name: str = device_name
        self.ip_network: IPv4NetworkWithInterfaces = ip_network
        self.ipv6_network = ipv6_network
        self.ndp_proxy = ndp_proxy

    @property
    def guest_ip(self) -> IPv4Interface:
        return self.ip_network[2]

    @property
    def host_ip(self) -> IPv4Interface:
        return self.ip_network[1]

    @property
    def guest_ipv6(self) -> IPv6Interface:
        return IPv6Interface(f"{self.ipv6_network[1]}/{self.ipv6_network.prefixlen}")

    @property
    def host_ipv6(self) -> IPv6Interface:
        return IPv6Interface(f"{self.ipv6_network[0]}/{self.ipv6_network.prefixlen}")

    def to_dict(self):
        return {
            "device": self.device_name,
            "ipv4": str(self.ip_network),
            "ipv6": str(self.ipv6_network),
        }

    async def create(self):
        logger.debug("Create network interface")

        ip_command = shutil.which("ip")
        if not ip_command:
            raise FileNotFoundError("ip command not found")

        ipv6_gateway = self.host_ipv6

        with IPRoute() as ipr:
            create_tap_interface(ipr, self.device_name)
            add_ip_address(ipr, self.device_name, self.host_ip)
            add_ip_address(ipr, self.device_name, self.host_ipv6)
            set_link_up(ipr, self.device_name)

        if self.ndp_proxy:
            await self.ndp_proxy.add_range(self.device_name, ipv6_gateway.network)
        logger.debug(f"Network interface created: {self.device_name}")

    async def delete(self) -> None:
        """Asks the firewall to teardown any rules for the VM with id provided.
        Then removes the interface from the host."""
        logger.debug(f"Removing interface {self.device_name}")
        await asyncio.sleep(0.1)  # Avoids Device/Resource busy bug
        if self.ndp_proxy:
            await self.ndp_proxy.delete_range(self.device_name)
        with IPRoute() as ipr:
            delete_ip_address(ipr, self.device_name, self.host_ip)
            delete_ip_address(ipr, self.device_name, self.host_ipv6)
            delete_tap_interface(ipr, self.device_name)
