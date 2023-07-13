import asyncio
import logging
from typing import Dict, Iterable, Optional

from aleph_message.models import ExecutableMessage, ItemHash

from vm_supervisor.network.hostnetwork import Network, make_ipv6_allocator

from .conf import settings
from .models import ExecutableContent, VmExecution
from .snapshots import SnapshotManager
from .vm.vm_type import VmType

logger = logging.getLogger(__name__)


class VmPool:
    """Pool of VMs already started and used to decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.

    The counter is used by the VMs to set their tap interface name and the corresponding
    IPv4 subnet.
    """

    counter: int  # Used to provide distinct ids to network interfaces
    executions: Dict[ItemHash, VmExecution]
    message_cache: Dict[str, ExecutableMessage] = {}
    network: Optional[Network]
    snapshot_manager: SnapshotManager

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
        self.snapshot_manager = SnapshotManager()

    async def create_a_vm(
        self, vm_hash: ItemHash, message: ExecutableContent, original: ExecutableContent
    ) -> VmExecution:
        """Create a new Aleph Firecracker VM from an Aleph function message."""
        execution = VmExecution(vm_hash=vm_hash, message=message, original=original)
        self.executions[vm_hash] = execution
        await execution.prepare()
        vm_id = self.get_unique_vm_id()

        if self.network:
            vm_type = VmType.from_message_content(message)
            tap_interface = await self.network.create_tap(vm_id, vm_hash, vm_type)
        else:
            tap_interface = None

        await execution.create(vm_id=vm_id, tap_interface=tap_interface)

        # Start VM snapshots automatically
        self.snapshot_manager.start_for(execution=execution)

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
            currently_used_vm_ids = set(
                execution.vm_id
                for execution in self.executions.values()
                if execution.is_running
            )
            for i in range(settings.START_ID_INDEX, 255**2):
                if i not in currently_used_vm_ids:
                    return i
            else:
                raise ValueError("No available value for vm_id.")

    async def get_running_vm(self, vm_hash: ItemHash) -> Optional[VmExecution]:
        """Return a running VM or None. Disables the VM expiration task."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running:
            execution.cancel_expiration()
            return execution
        else:
            return None

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
        """Stop all VMs in the pool."""

        # Stop executions in parallel:
        await asyncio.gather(
            *(execution.stop() for vm_hash, execution in self.executions.items())
        )

        # Stop instance snapshot executions in parallel:
        await asyncio.gather(
            *(
                self.snapshot_manager.stop_for(vm_hash)
                for vm_hash, execution in self.get_instance_executions()
            )
        )

    def get_persistent_executions(self) -> Iterable[VmExecution]:
        for vm_hash, execution in self.executions.items():
            if execution.persistent and execution.is_running:
                yield execution

    def get_instance_executions(self) -> Iterable[VmExecution]:
        for vm_hash, execution in self.executions.items():
            if execution.is_instance and execution.is_running:
                yield execution
