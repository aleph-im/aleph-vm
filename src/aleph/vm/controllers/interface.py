import asyncio
import logging
from abc import ABC
from asyncio.subprocess import Process
from typing import Any, Optional, Coroutine

from aleph.vm.controllers.firecracker.snapshots import CompressedDiskVolumeSnapshot
from aleph.vm.network.interfaces import TapInterface
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources

logger = logging.getLogger(__name__)


class AlephControllerInterface(ABC):
    vm_id: int
    "id in the VMPool, attributed at execution"
    vm_hash: ItemHash
    "identifier for the VM definition, linked to an Aleph Message"
    resources: Any
    "local resource for the machine"
    enable_console: bool
    enable_networking: bool
    "enable networking for this VM"
    hardware_resources: MachineResources
    support_snapshot: bool
    "Does this controller support snapshotting"
    guest_api_process: Optional[Process] = None
    tap_interface: Optional[TapInterface] = None
    "Network interface used for this VM"

    def get_vm_ip(self) -> Optional[str]:
        if self.tap_interface:
            return self.tap_interface.guest_ip.with_prefixlen
        return None

    def get_vm_route(self) -> Optional[str]:
        if self.tap_interface:
            return str(self.tap_interface.host_ip).split("/", 1)[0]
        return None

    def get_vm_ipv6(self) -> Optional[str]:
        if self.tap_interface:
            return self.tap_interface.guest_ipv6.with_prefixlen
        return None

    def get_vm_ipv6_gateway(self) -> Optional[str]:
        if self.tap_interface:
            return str(self.tap_interface.host_ipv6.ip)
        return None

    def to_dict(self):
        """Dict representation of the virtual machine. Used to record resource usage and for JSON serialization."""
        raise NotImplementedError()

    async def setup(self):
        """Configuration done before the VM process is started"""
        raise NotImplementedError()

    async def start(self):
        """Start the VM process"""
        raise NotImplementedError()

    async def wait_for_init(self) -> None:
        """Wait for the init process of the virtual machine to be ready.
        May be empty."""
        pass

    async def configure(self) -> None:
        """Configuration done after the VM process is started"""
        raise NotImplementedError()

    async def start_guest_api(self):
        raise NotImplementedError()

    async def stop_guest_api(self):
        raise NotImplementedError()

    async def teardown(self) -> Coroutine:
        raise NotImplementedError()

    async def create_snapshot(self) -> CompressedDiskVolumeSnapshot:
        "Must be implement if self.support_snapshot is True"
        raise NotImplementedError()

    async def get_log_queue(self) -> asyncio.Queue:
        raise NotImplementedError()

    async def unregister_queue(self, queue: asyncio.Queue):
        raise NotImplementedError()
