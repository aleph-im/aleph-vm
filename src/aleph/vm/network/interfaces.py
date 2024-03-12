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
            raise InterfaceBusyError(
                f"Interface {device_name} is busy - is there another process using it ?"
            ) from error
        else:
            raise
    except OSError as error:
        if error.errno == errno.EBUSY:
            raise InterfaceBusyError(f"Interface {device_name} is busy. Is another process using it ?") from error


def add_ip_address(ipr: IPRoute, device_name: str, ip: Union[IPv4Interface, IPv6Interface]):
    """Add an IP address to the given interface. If the address already exists, a warning is logged and the function
    returns without error."""
    try:
        ipr.addr("add", index=ipr.link_lookup(ifname=device_name)[0], address=str(ip.ip), mask=ip.network.prefixlen)
    except NetlinkError as e:
        if e.code == 17:
            logger.warning(f"Address {ip} already exists")
        else:
            raise


def set_link_up(ipr: IPRoute, device_name: str):
    """Set the given interface up."""
    ipr.link("set", index=ipr.link_lookup(ifname=device_name)[0], state="up")


def delete_tap_interface(ipr: IPRoute, device_name: str):
    ipr.link("del", index=ipr.link_lookup(ifname=device_name)[0])


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
            delete_tap_interface(ipr, self.device_name)
