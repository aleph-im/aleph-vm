"""
Neighbourhood Discovery Proxy (NDP) functionalities.

Some cloud providers do not route the whole advertised IPv6 address range to servers, but instead
only route one address. They will issue NDP requests to the network to determine if the other
addresses in the range are used. This means that our server (be it the hypervisor or the VMs)
has to answer to these requests to make the VMs routable.

To achieve this, we use ndppd. Each time an update is required, we overwrite /etc/ndppd.conf
and restart the service.
"""
import logging
from dataclasses import dataclass
from ipaddress import IPv6Network
from pathlib import Path

from aleph.vm.utils import run_in_subprocess

logger = logging.getLogger(__name__)


@dataclass
class NdpRule:
    address_range: IPv6Network


class NdpProxy:
    def __init__(self, host_network_interface: str):
        self.host_network_interface = host_network_interface
        self.interface_address_range_mapping: dict[str, IPv6Network] = {}

    @staticmethod
    async def _restart_ndppd():
        logger.debug("Restarting ndppd")
        await run_in_subprocess(["systemctl", "restart", "ndppd"])

    async def _update_ndppd_conf(self):
        config = f"proxy {self.host_network_interface} {{\n"
        for interface, address_range in self.interface_address_range_mapping.items():
            config += f"  rule {address_range} {{\n    iface {interface}\n  }}\n"
        config += "}\n"
        Path("/etc/ndppd.conf").write_text(config)
        await self._restart_ndppd()

    async def add_range(self, interface: str, address_range: IPv6Network):
        logger.debug("Proxying range %s -> %s", address_range, interface)
        self.interface_address_range_mapping[interface] = address_range
        await self._update_ndppd_conf()

    async def delete_range(self, interface: str):
        try:
            address_range = self.interface_address_range_mapping.pop(interface)
            logger.debug("Deactivated proxying for %s (%s)", interface, address_range)
        except KeyError:
            return

        await self._update_ndppd_conf()
