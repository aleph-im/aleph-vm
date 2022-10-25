from __future__ import annotations

import asyncio
from subprocess import run
from typing import Type

from vm_supervisor.network.firewall import Firewall
from vm_supervisor.network.ip import network_instance, logger


class TapInterface:
    device_name: str
    ip_addr: str
    vm_id: int
    firewall: Firewall

    def __init__(self, device_name: str, ip_addr: str, vm_id: int, firewall: Firewall):
        self.device_name = device_name
        self.ip_addr = ip_addr
        self.vm_id = vm_id
        self.firewall = firewall

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

        self.firewall.setup_nftables_for_vm(self.vm_id)

    async def delete(self):
        """Asks the firewall to teardown any rules for the VM with id provided.
        Then removes the interface from the host."""
        self.firewall.teardown_nftables_for_vm(self.vm_id)

        logger.debug(f"Removing interface {self.device_name}")
        await asyncio.sleep(0.1)  # Avoids Device/Resource busy bug
        run(["ip", "tuntap", "del", self.device_name, "mode", "tap"])
