import asyncio
import logging
from ipaddress import IPv4Interface
from subprocess import run

from .ipaddresses import IPv4NetworkWithInterfaces
import shutil

logger = logging.getLogger(__name__)


class TapInterface:
    device_name: str
    ip_network: IPv4NetworkWithInterfaces

    def __init__(self, device_name: str, ip_network: IPv4NetworkWithInterfaces):
        self.device_name: str = device_name
        self.ip_network: IPv4NetworkWithInterfaces = ip_network

    @property
    def guest_ip(self) -> IPv4Interface:
        return self.ip_network[2]

    @property
    def host_ip(self) -> IPv4Interface:
        return self.ip_network[1]

    async def create(self):
        logger.debug("Create network interface")

        ip_command = shutil.which("ip")
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
        run([ip_command, "link", "set", self.device_name, "up"])
        logger.debug(f"Network interface created: {self.device_name}")

    async def delete(self) -> None:
        """Asks the firewall to teardown any rules for the VM with id provided.
        Then removes the interface from the host."""
        logger.debug(f"Removing interface {self.device_name}")
        await asyncio.sleep(0.1)  # Avoids Device/Resource busy bug
        run(["ip", "tuntap", "del", self.device_name, "mode", "tap"])
