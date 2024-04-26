from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Optional

from aleph_message.models import (
    Chain,
    ExecutableMessage,
    ItemHash,
    Payment,
    PaymentType,
)

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.snapshot_manager import SnapshotManager
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator
from aleph.vm.orchestrator.metrics import get_execution_records
from aleph.vm.systemd import SystemDManager
from aleph.vm.utils import get_message_executable_content
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
    message_cache: dict[str, ExecutableMessage]
    network: Optional[Network]
    snapshot_manager: Optional[SnapshotManager] = None
    systemd_manager: SystemDManager
    creation_lock: asyncio.Lock

    def __init__(self, loop: asyncio.AbstractEventLoop):
        self.counter = settings.START_ID_INDEX
        self.executions = {}
        self.message_cache = {}

        asyncio.set_event_loop(loop)
        self.creation_lock = asyncio.Lock()

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
        if settings.SNAPSHOT_FREQUENCY > 0:
            self.snapshot_manager = SnapshotManager()

    def setup(self) -> None:
        """Set up the VM pool and the network."""
        if self.network:
            self.network.setup()

        if self.snapshot_manager:
            logger.debug("Initializing SnapshotManager ...")
            self.snapshot_manager.run_in_thread()

    def teardown(self) -> None:
        """Stop the VM pool and the network properly."""
        if self.network:
            self.network.teardown()

    async def create_a_vm(
        self, vm_hash: ItemHash, message: ExecutableContent, original: ExecutableContent, persistent: bool
    ) -> VmExecution:
        """Create a new Aleph Firecracker VM from an Aleph function message."""
        async with self.creation_lock:
            # Check if an execution is already present for this VM, then return it.
            # Do not `await` in this section.
            current_execution = self.get_running_vm(vm_hash)
            if current_execution:
                return current_execution
            else:
                execution = VmExecution(
                    vm_hash=vm_hash,
                    message=message,
                    original=original,
                    snapshot_manager=self.snapshot_manager,
                    systemd_manager=self.systemd_manager,
                    persistent=persistent,
                )
                self.executions[vm_hash] = execution

            try:
                await execution.prepare()
                vm_id = self.get_unique_vm_id()

                if self.network:
                    vm_type = VmType.from_message_content(message)
                    tap_interface = await self.network.prepare_tap(vm_id, vm_hash, vm_type)
                    await self.network.create_tap(vm_id, tap_interface)
                else:
                    tap_interface = None

                execution.create(vm_id=vm_id, tap_interface=tap_interface)
                await execution.start()

                # Start VM and snapshots automatically
                if execution.persistent:
                    self.systemd_manager.enable_and_start(execution.controller_service)
                    await execution.wait_for_init()
                    if execution.is_program and execution.vm:
                        await execution.vm.load_configuration()

                if execution.vm and execution.vm.support_snapshot and self.snapshot_manager:
                    await self.snapshot_manager.start_for(vm=execution.vm)
            except Exception:
                # ensure the VM is removed from the pool on creation error
                self.forget_vm(vm_hash)
                raise

            self._schedule_forget_on_stop(execution)

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

    def get_running_vm(self, vm_hash: ItemHash) -> Optional[VmExecution]:
        """Return a running VM or None. Disables the VM expiration task."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running and not execution.is_stopping:
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

    async def stop_persistent_execution(self, execution: VmExecution):
        """Stop persistent VMs in the pool."""
        assert execution.persistent, "Execution isn't persistent"
        self.systemd_manager.stop_and_disable(execution.controller_service)
        await execution.stop()

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

    def _schedule_forget_on_stop(self, execution: VmExecution):
        """Create a task that will remove the VM from the pool after it stops."""

        async def forget_on_stop(stop_event: asyncio.Event):
            await stop_event.wait()
            self.forget_vm(execution.vm_hash)

        _ = asyncio.create_task(forget_on_stop(stop_event=execution.stop_event))

    async def load_persistent_executions(self):
        """Load persistent executions from the database."""
        saved_executions = await get_execution_records()
        for saved_execution in saved_executions:
            vm_hash = ItemHash(saved_execution.vm_hash)

            if vm_hash in self.executions:
                # The execution is already loaded, skip it
                continue

            vm_id = saved_execution.vm_id

            message_dict = json.loads(saved_execution.message)
            original_dict = json.loads(saved_execution.original_message)

            execution = VmExecution(
                vm_hash=vm_hash,
                message=get_message_executable_content(message_dict),
                original=get_message_executable_content(original_dict),
                snapshot_manager=self.snapshot_manager,
                systemd_manager=self.systemd_manager,
                persistent=saved_execution.persistent,
            )

            if execution.is_running:
                # TODO: Improve the way that we re-create running execution
                await execution.prepare()
                if self.network:
                    vm_type = VmType.from_message_content(execution.message)
                    tap_interface = await self.network.prepare_tap(vm_id, vm_hash, vm_type)
                else:
                    tap_interface = None

                vm = execution.create(vm_id=vm_id, tap_interface=tap_interface, prepare=False)
                await vm.start_guest_api()
                execution.ready_event.set()
                execution.times.started_at = datetime.now(tz=timezone.utc)

                self._schedule_forget_on_stop(execution)

                # Start the snapshot manager for the VM
                if vm.support_snapshot and self.snapshot_manager:
                    await self.snapshot_manager.start_for(vm=execution.vm)

                self.executions[vm_hash] = execution
            else:
                execution.uuid = saved_execution.uuid
                await execution.record_usage()

        logger.debug(f"Loaded {len(self.executions)} executions")

    async def stop(self):
        """Stop ephemeral VMs in the pool."""
        # Stop executions in parallel:
        await asyncio.gather(*(execution.stop() for execution in self.get_ephemeral_executions()))

    def get_ephemeral_executions(self) -> Iterable[VmExecution]:
        executions = (
            execution for _, execution in self.executions.items() if execution.is_running and not execution.persistent
        )
        return executions or []

    def get_persistent_executions(self) -> Iterable[VmExecution]:
        executions = (
            execution
            for _vm_hash, execution in self.executions.items()
            if execution.is_running and execution.persistent
        )
        return executions or []

    def get_instance_executions(self) -> Iterable[VmExecution]:
        executions = (
            execution
            for _vm_hash, execution in self.executions.items()
            if execution.is_running and execution.is_instance
        )
        return executions or []

    def get_executions_by_sender(self, payment_type: PaymentType) -> dict[str, dict[str, list[VmExecution]]]:
        """Return all executions of the given type, grouped by sender and by chain."""
        executions_by_sender: dict[str, dict[str, list[VmExecution]]] = {}
        for vm_hash, execution in self.executions.items():
            if execution.vm_hash in (settings.CHECK_FASTAPI_VM_ID, settings.LEGACY_CHECK_FASTAPI_VM_ID):
                # Ignore Diagnostic VM execution
                continue

            if not execution.is_running:
                # Ignore the execution that is stopping or not running anymore
                continue
            if execution.vm_hash == settings.CHECK_FASTAPI_VM_ID:
                # Ignore Diagnostic VM execution
                continue
            execution_payment = (
                execution.message.payment
                if execution.message.payment
                else Payment(chain=Chain.ETH, type=PaymentType.hold)
            )
            if execution_payment.type == payment_type:
                sender = execution.message.address
                chain = execution_payment.chain
                executions_by_sender.setdefault(sender, {})
                executions_by_sender[sender].setdefault(chain, []).append(execution)
        return executions_by_sender
