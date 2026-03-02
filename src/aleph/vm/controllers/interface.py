import asyncio
import logging
from abc import ABC
from asyncio.subprocess import Process
from collections.abc import Callable, Coroutine
from typing import Any

from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import MachineResources

from aleph.vm.controllers.firecracker.snapshots import CompressedDiskVolumeSnapshot
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.utils.logs import get_past_vm_logs, make_logs_queue

logger = logging.getLogger(__name__)


class AlephVmControllerInterface(ABC):
    log_queues: list[asyncio.Queue] = []
    _queue_cancellers: dict[asyncio.Queue, Callable] = {}

    vm_id: int
    """id in the VMPool, attributed at execution"""
    vm_hash: ItemHash
    """identifier for the VM definition, linked to an Aleph Message"""
    resources: Any
    """local resource for the machine"""
    enable_console: bool
    enable_networking: bool
    """enable networking for this VM"""
    hardware_resources: MachineResources
    support_snapshot: bool
    """Does this controller support snapshotting"""
    guest_api_process: Process | None = None
    tap_interface: TapInterface | None = None
    """Network interface used for this VM"""

    def get_ip(self) -> str | None:
        if self.tap_interface:
            return self.tap_interface.guest_ip.with_prefixlen
        return None

    def get_ip_route(self) -> str | None:
        if self.tap_interface:
            return str(self.tap_interface.host_ip).split("/", 1)[0]
        return None

    def get_ipv6(self) -> str | None:
        if self.tap_interface:
            return self.tap_interface.guest_ipv6.with_prefixlen
        return None

    def get_ipv6_gateway(self) -> str | None:
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

    async def configure(self, incoming_migration_port: int | None = None) -> None:
        """Configuration done after the VM process is started.

        :param incoming_migration_port: Optional port for incoming migration (QEMU only).
            When set, the VM is configured to wait for migration data instead of booting normally.
        """
        raise NotImplementedError()

    async def load_configuration(self) -> None:
        """Load configuration just after the VM process is started"""
        raise NotImplementedError()

    async def start_guest_api(self):
        raise NotImplementedError()

    async def stop_guest_api(self):
        raise NotImplementedError()

    async def teardown(self) -> Coroutine:
        raise NotImplementedError()

    async def create_snapshot(self) -> CompressedDiskVolumeSnapshot:
        """Must be implement if self.support_snapshot is True"""
        raise NotImplementedError()

    def get_log_queue(self) -> asyncio.Queue:
        queue, canceller = make_logs_queue(self._journal_stdout_name, self._journal_stderr_name)
        self._queue_cancellers[queue] = canceller
        # Limit the number of queues per VM
        # TODO : fix
        if len(self.log_queues) > 20:
            logger.warning("Too many log queues, dropping the oldest one")
            self.unregister_queue(self.log_queues[1])
        self.log_queues.append(queue)
        return queue

    def unregister_queue(self, queue: asyncio.Queue) -> None:
        if queue in self.log_queues:
            self._queue_cancellers[queue]()
            del self._queue_cancellers[queue]
            self.log_queues.remove(queue)
        queue.empty()

    @property
    def _journal_stdout_name(self) -> str:
        return f"vm-{self.vm_hash}-stdout"

    @property
    def _journal_stderr_name(self) -> str:
        return f"vm-{self.vm_hash}-stderr"

    def past_logs(self):
        yield from get_past_vm_logs(self._journal_stdout_name, self._journal_stderr_name)
