import asyncio
import logging
import shutil
from ipaddress import IPv4Interface, IPv6Interface, IPv6Network
from subprocess import run
from typing import Optional

from .ipaddresses import IPv4NetworkWithInterfaces
from .ndp_proxy import NdpProxy

logger = logging.getLogger(__name__)


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

        run([ip_command, "tuntap", "add", self.device_name, "mode", "tap"])
        run(
            [
                ip_command,
                "addr",
                "add",
                str(self.host_ip.with_prefixlen),
                "dev",
                self.device_name,
            ]
        )
        ipv6_gateway = self.host_ipv6
        run(
            [
                ip_command,
                "addr",
                "add",
                str(ipv6_gateway),
                "dev",
                self.device_name,
            ]
        )
        run([ip_command, "link", "set", self.device_name, "up"])
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
        run(["ip", "tuntap", "del", self.device_name, "mode", "tap"])
