import asyncio
import logging
from collections.abc import Iterable
from typing import Optional

from aleph_message.models import ExecutableMessage, ItemHash
from aleph_message.models.execution.instance import InstanceContent

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.snapshot_manager import SnapshotManager
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator
from aleph.vm.systemd import SystemDManager
from aleph.vm.vm_type import VmType

from .models import ExecutableContent, VmExecution

logger = logging.getLogger(__name__)


class VmPool:
    """Pool of VMs already started and used to decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.

    The counter is used by the VMs to set their tap interface name and the corresponding
    IPv4 subnet.
    """

    counter: int  # Used to provide distinct ids to network interfaces
    executions: dict[ItemHash, VmExecution]
    message_cache: dict[str, ExecutableMessage] = {}
    network: Optional[Network]
    snapshot_manager: SnapshotManager
    systemd_manager: SystemDManager

    def __init__(self):
        self.counter = settings.START_ID_INDEX
        self.executions = {}

        self.network = (
            Network(
                vm_ipv4_address_pool_range=settings.IPV4_ADDRESS_POOL,
                vm_network_size=settings.IPV4_NETWORK_PREFIX_LENGTH,
                external_interface=settings.NETWORK_INTERFACE,
                ipv6_allocator=make_ipv6_allocator(
                    allocation_policy=settings.IPV6_ALLOCATION_POLICY,
                    address_pool=settings.IPV6_ADDRESS_POOL,
                    subnet_prefix=settings.IPV6_SUBNET_PREFIX,
                ),
                use_ndp_proxy=settings.USE_NDP_PROXY,
                ipv6_forwarding_enabled=settings.IPV6_FORWARDING_ENABLED,
            )
            if settings.ALLOW_VM_NETWORKING
            else None
        )
        self.systemd_manager = SystemDManager()
        self.snapshot_manager = SnapshotManager()
        logger.debug("Initializing SnapshotManager ...")
        self.snapshot_manager.run_snapshots()

    def setup(self) -> None:
        """Set up the VM pool and the network."""
        if self.network:
            self.network.setup()

    def teardown(self) -> None:
        """Stop the VM pool and the network properly."""
        if self.network:
            self.network.teardown()

    async def create_a_vm(
        self, vm_hash: ItemHash, message: ExecutableContent, original: ExecutableContent, persistent: bool
    ) -> VmExecution:
        """Create a new Aleph Firecracker VM from an Aleph function message."""

        # Check if an execution is already present for this VM, then return it.
        # Do not `await` in this section.
        try:
            return self.executions[vm_hash]
        except KeyError:
            execution = VmExecution(
                vm_hash=vm_hash,
                message=message,
                original=original,
                snapshot_manager=self.snapshot_manager,
                persistent=persistent,
            )
            self.executions[vm_hash] = execution

        try:
            await execution.prepare()
            vm_id = self.get_unique_vm_id()

            if self.network:
                vm_type = VmType.from_message_content(message)
                tap_interface = await self.network.create_tap(vm_id, vm_hash, vm_type)
            else:
                tap_interface = None

            await execution.create(vm_id=vm_id, tap_interface=tap_interface)

            # Start VM and snapshots automatically
            if execution.persistent:
                self.systemd_manager.enable_and_start(execution.controller_service)
                await execution.wait_for_init()

            if execution.vm.support_snapshot:
                await self.snapshot_manager.start_for(vm=execution.vm)
        except Exception:
            # ensure the VM is removed from the pool on creation error
            self.forget_vm(vm_hash)
            raise

        async def forget_on_stop(stop_event: asyncio.Event):
            await stop_event.wait()
            self.forget_vm(vm_hash)

        asyncio.create_task(forget_on_stop(stop_event=execution.stop_event))

        return execution

    def get_unique_vm_id(self) -> int:
        """Get a unique identifier for the VM.

        This identifier is used to name the network interface and in the IPv4 range
        dedicated to the VM.
        """
        _, network_range = settings.IPV4_ADDRESS_POOL.split("/")
        available_bits = int(network_range) - settings.IPV4_NETWORK_PREFIX_LENGTH
        self.counter += 1
        if self.counter < 2**available_bits:
            # In common cases, use the counter itself as the vm_id. This makes it
            # easier to debug.
            return self.counter
        else:
            # The value of the counter is too high and some functions such as the
            # IPv4 range dedicated to the VM do not support such high values.
            #
            # We therefore recycle vm_id values from executions that are not running
            # anymore.
            currently_used_vm_ids = {execution.vm_id for execution in self.executions.values() if execution.is_running}
            for i in range(settings.START_ID_INDEX, 255**2):
                if i not in currently_used_vm_ids:
                    return i
            else:
                msg = "No available value for vm_id."
                raise ValueError(msg)

    async def get_running_vm(self, vm_hash: ItemHash) -> Optional[VmExecution]:
        """Return a running VM or None. Disables the VM expiration task."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running:
            execution.cancel_expiration()
            return execution
        else:
            return None

    async def stop_vm(self, vm_hash: ItemHash) -> Optional[VmExecution]:
        """Stop a VM."""
        execution = self.executions.get(vm_hash)
        if execution:
            if execution.persistent:
                await self.stop_persistent_execution(execution)
            else:
                await execution.stop()
            return execution
        else:
            return None

    async def stop_persistent_execution(self, execution):
        """Stop persistent VMs in the pool."""
        assert execution.persistent, "Execution isn't persistent"
        self.systemd_manager.stop_and_disable(execution.controller_service)
        await execution.stop()
        execution.persistent = False

    def forget_vm(self, vm_hash: ItemHash) -> None:
        """Remove a VM from the executions pool.

        Used after self.create_a_vm(...) raised an error in order to
        completely forget about the execution and enforce a new execution
        when attempted again.
        """
        try:
            del self.executions[vm_hash]
        except KeyError:
            pass

    async def stop(self):
        """Stop ephemeral VMs in the pool."""
        # Stop executions in parallel:
        await asyncio.gather(*(execution.stop() for vm_hash, execution in self.get_ephemeral_executions()))

    def get_ephemeral_executions(self) -> Iterable[VmExecution]:
        for _vm_hash, execution in self.executions.items():
            if not execution.persistent and execution.is_running:
                yield execution

    def get_persistent_executions(self) -> Iterable[VmExecution]:
        for _vm_hash, execution in self.executions.items():
            if execution.persistent and execution.is_running:
                yield execution

    def get_instance_executions(self) -> Iterable[VmExecution]:
        for _vm_hash, execution in self.executions.items():
            if execution.is_instance and execution.is_running:
                yield execution
