import logging
from abc import ABC
from asyncio.subprocess import Process
from typing import Any, Optional, Coroutine

from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources

from aleph.vm.controllers.firecracker.snapshots import CompressedDiskVolumeSnapshot
from aleph.vm.network.interfaces import TapInterface

logger = logging.getLogger(__name__)


class AlephControllerInterface(ABC):
    tap_interface: Optional[TapInterface] = None
    resources: Any
    vm_id: int
    vm_hash: ItemHash
    enable_console: bool
    enable_networking: bool
    hardware_resources: MachineResources
    support_snapshot: bool
    guest_api_process: Optional[Process] = None

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
        raise NotImplementedError()

    async def start(self):
        raise NotImplementedError()

    async def wait_for_init(self) -> None:
        """Wait for the init process of the virtual machine to be ready.
        May be empty."""
        raise NotImplementedError()

    async def configure(self):
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
