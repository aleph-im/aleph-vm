from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import shutil
from collections.abc import Iterable
from datetime import datetime, timedelta, timezone
from typing import Any

import psutil
from aleph_message.models import (
    Chain,
    ExecutableMessage,
    InstanceContent,
    ItemHash,
    Payment,
    PaymentType,
)
from pydantic import TypeAdapter

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.snapshot_manager import SnapshotManager
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.orchestrator.metrics import (
    ExecutionRecord,
    get_execution_records,
    get_port_mappings,
)
from aleph.vm.orchestrator.utils import update_aggregate_settings
from aleph.vm.resources import (
    GpuDevice,
    HostGPU,
    InsufficientResourcesError,
    get_gpu_devices,
)
from aleph.vm.systemd import SystemDManager
from aleph.vm.utils import get_message_executable_content
from aleph.vm.vm_type import VmType

from .haproxy import fetch_list_and_update
from .models import ExecutableContent, VmExecution
from .network.firewall import (
    get_existing_nftables_ruleset,
    get_orphan_vm_chain_ids,
    remove_orphan_port_redirect_rules,
    setup_nftables_for_vm,
    teardown_nftables_for_vm,
)
from .network.interfaces import remove_orphan_tap_interfaces

logger = logging.getLogger(__name__)


class VmPool:
    """Pool of existing VMs

    For function VM we keep the VM a while after they  have run, so we can reuse them  and thus decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.
    """

    executions: dict[ItemHash, VmExecution]
    message_cache: dict[str, ExecutableMessage]
    network: Network | None
    snapshot_manager: SnapshotManager | None = None
    systemd_manager: SystemDManager
    creation_lock: asyncio.Lock
    gpus: list[GpuDevice]
    reservations: dict[Any, Reservation]
    """Resources reserved by an user, before launching (only GPU atm)"""

    _draining: bool

    def __init__(self):
        self.executions = {}
        self.message_cache = {}
        self.reservations = {}
        self.gpus = []
        self._draining = False

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

    async def setup(self) -> None:
        """Set up the VM pool and the network."""
        if self.network:
            self.network.setup()

        if self.snapshot_manager:
            logger.debug("Initializing SnapshotManager ...")
            self.snapshot_manager.run_in_thread()
        if settings.ENABLE_GPU_SUPPORT:
            # Refresh and get latest settings aggregate
            await update_aggregate_settings()
            logger.debug("Detecting GPU devices ...")
            self.gpus = get_gpu_devices()

    def teardown(self) -> None:
        """Stop the VM pool and the network properly.

        Network teardown is intentionally skipped: persistent VMs run
        inside systemd controllers and retain their tap interfaces
        across supervisor restarts. Tearing down the shared nftables
        chains and forwarding rules would break their connectivity.
        Per-VM cleanup (tap + nft rules) happens in execution.stop().
        """

    def check_admission(
        self,
        message: ExecutableContent,
        current_vm_hash: ItemHash | None = None,
    ) -> None:
        """Refuse to host ``message`` when doing so would exceed host capacity.

        Memory is accounted in two separate buckets with strict floors:

        - **Instance bucket**: ``physical_ram - HOST_MEMORY_RESERVED_MIB -
          PROGRAM_MEMORY_RESERVED_MIB``. No overcommit. Instance allocations
          are admitted only up to this ceiling.
        - **Program bucket**: ``PROGRAM_MEMORY_RESERVED_MIB``. Ephemeral
          programs (Firecracker microVMs) are admitted against this bucket
          so there is always headroom for a program trigger regardless of
          how full the instance pool is.

        The ``HOST_MEMORY_RESERVED_MIB`` slice is reserved for the host
        kernel, supervisor, HAProxy and system services, and is never
        visible to any VM bucket.

        vCPU accounting uses ``VCPU_OVERCOMMIT_FACTOR`` across all running
        executions because CPU is time-sliced and safe to overcommit.

        Disk is strict: the required rootfs and volume sizes must fit
        within :meth:`calculate_available_disk`, which is already
        reservation-aware.

        The check is advisory when called from the HTTP layer and
        authoritative when called from :meth:`create_a_vm` (which holds
        ``creation_lock``). Reading ``self.executions`` is safe without
        locking because this method does not ``await``.

        Args:
            message: The executable content being evaluated for admission.
            current_vm_hash: When a caller re-evaluates an already-known VM
                (re-notification of an existing instance), passing its hash
                makes the check idempotent: the existing VM is excluded
                from the committed sum, and if it is already running the
                check is skipped entirely.

        Raises:
            InsufficientResourcesError: One or more resources would be
                exceeded. The exception carries structured ``required`` and
                ``available`` dicts so callers can surface a detailed error
                to server logs.
        """
        if not message.resources:
            return
        if current_vm_hash is not None and current_vm_hash in self.executions:
            return

        required_memory_mib = message.resources.memory
        required_vcpus = message.resources.vcpus
        required_disk_mib = 0
        if isinstance(message, InstanceContent) and message.rootfs:
            required_disk_mib += message.rootfs.size_mib
        if message.volumes:
            # Immutable volumes reference a file on Aleph storage via
            # ``ref`` and do not carry a ``size_mib`` field, so they are
            # not counted here and the admission estimate is best-effort
            # for messages that include them. The authoritative disk
            # check happens later via ``calculate_available_disk`` /
            # ``get_disk_usage_delta``, which measures the real on-disk
            # size of each downloaded file.
            for volume in message.volumes:
                required_disk_mib += getattr(volume, "size_mib", 0) or 0

        is_instance_request = isinstance(message, InstanceContent)

        committed_instance_memory_mib = 0
        committed_program_memory_mib = 0
        committed_vcpus = 0
        for execution in tuple(self.executions.values()):
            if current_vm_hash is not None and execution.vm_hash == current_vm_hash:
                continue
            resources = execution.message.resources
            if not resources:
                continue
            if execution.is_instance:
                committed_instance_memory_mib += resources.memory
            else:
                committed_program_memory_mib += resources.memory
            committed_vcpus += resources.vcpus

        physical_memory_mib = psutil.virtual_memory().total // (1024 * 1024)
        physical_cores = psutil.cpu_count() or 1
        host_reserved_mib = settings.HOST_MEMORY_RESERVED_MIB
        program_reserved_mib = settings.PROGRAM_MEMORY_RESERVED_MIB

        instance_memory_cap_mib = max(physical_memory_mib - host_reserved_mib - program_reserved_mib, 0)
        program_memory_cap_mib = program_reserved_mib

        # vCPU overcommit: CPU time is safe to oversubscribe because the
        # kernel scheduler time-slices it, so the cap is the physical core
        # count multiplied by the configured factor (e.g. 4 vCPUs per core
        # with VCPU_OVERCOMMIT_FACTOR=4.0).
        vcpu_cap = int(physical_cores * settings.VCPU_OVERCOMMIT_FACTOR)

        if is_instance_request:
            bucket_name = "instance"
            committed_memory_mib = committed_instance_memory_mib
            memory_cap_mib = instance_memory_cap_mib
        else:
            bucket_name = "program"
            committed_memory_mib = committed_program_memory_mib
            memory_cap_mib = program_memory_cap_mib

        available_disk_mib = self.calculate_available_disk() // (1024 * 1024)

        errors: list[str] = []

        if committed_memory_mib + required_memory_mib > memory_cap_mib:
            errors.append(
                f"Memory ({bucket_name} bucket): "
                f"required {required_memory_mib} MiB, "
                f"committed {committed_memory_mib} MiB, "
                f"cap {memory_cap_mib} MiB "
                f"(physical {physical_memory_mib} MiB, "
                f"host_reserved {host_reserved_mib} MiB, "
                f"program_reserved {program_reserved_mib} MiB)"
            )

        if committed_vcpus + required_vcpus > vcpu_cap:
            errors.append(
                f"vCPUs: required {required_vcpus}, "
                f"committed {committed_vcpus}, "
                f"cap {vcpu_cap} "
                f"(physical {physical_cores} x factor {settings.VCPU_OVERCOMMIT_FACTOR})"
            )

        if required_disk_mib > 0 and required_disk_mib > available_disk_mib:
            errors.append(f"Disk: required {required_disk_mib} MiB, " f"available {available_disk_mib} MiB")

        if errors:
            detail = "Insufficient capacity to create VM. " + "; ".join(errors)
            available_memory_mib = max(memory_cap_mib - committed_memory_mib, 0)
            available_vcpus = max(vcpu_cap - committed_vcpus, 0)
            raise InsufficientResourcesError(
                detail,
                required={
                    "vcpus": required_vcpus,
                    "memory_mib": required_memory_mib,
                    "disk_mib": required_disk_mib,
                },
                available={
                    "vcpus": available_vcpus,
                    "memory_mib": available_memory_mib,
                    "disk_mib": available_disk_mib,
                },
            )

    def calculate_available_disk(self) -> int:
        """Disk available for the creation of new VM.

        This takes into account the disk request (but not used) for Volume of executions in the pool
        Result in bytes."""
        free_space = shutil.disk_usage(str(settings.PERSISTENT_VOLUMES_DIR)).free
        # Free disk space reported by the system

        # Calculate the reservation
        total_delta = 0
        for execution in self.executions.values():
            if not execution.resources:
                continue
            delta = execution.resources.get_disk_usage_delta()
            logger.debug("Disk usage delta: %d for %s", delta, execution.vm_hash)
            total_delta += delta
        available_space = free_space + total_delta

        logger.info(
            "Disk: freespace : %.f Mb,   available space (non reserved) %.f Mb",
            free_space / 1024**2,
            available_space / 1024**2,
        )
        available_space = max(available_space, 0)
        # floor value to zero to avoid negative values
        return available_space

    async def create_a_vm(
        self, vm_hash: ItemHash, message: ExecutableContent, original: ExecutableContent, persistent: bool
    ) -> VmExecution:
        """Create a new VM from an Aleph function or instance message."""
        async with self.creation_lock:
            # Check if an execution is already present for this VM, then return it.
            # Do not `await` in this section.
            current_execution = self.get_running_vm(vm_hash)
            if current_execution:
                return current_execution

            # Check if there are sufficient resources available before creating the VM
            self.check_admission(message, current_vm_hash=vm_hash)

            execution = VmExecution(
                vm_hash=vm_hash,
                message=message,
                original=original,
                snapshot_manager=self.snapshot_manager,
                systemd_manager=self.systemd_manager,
                persistent=persistent,
            )
            self.executions[vm_hash] = execution

            resources = set()
            tap_interface = None
            vm_id = None
            try:
                if message.requirements and message.requirements.gpu:
                    # Ensure we have the necessary GPU for the user by reserving them
                    resources = self.find_resources_available_for_user(message, message.address)
                    # First assign Host GPUs from the available
                    execution.prepare_gpus(list(resources))
                    # Prepare VM general Resources and also the GPUs
                await execution.prepare()

                vm_id = self.get_unique_vm_id()

                if self.network:
                    vm_type = VmType.from_message_content(message)
                    tap_interface = await self.network.prepare_tap(vm_id, vm_hash, vm_type)
                    # If the network interface already exists, remove it and then re-create it.
                    if self.network.interface_exists(vm_id):
                        await tap_interface.delete()
                    await self.network.create_tap(vm_id, tap_interface)

                else:
                    tap_interface = None

                execution.create(vm_id=vm_id, tap_interface=tap_interface)
                await execution.start()
                if execution.is_instance:
                    await execution.fetch_port_redirect_config_and_setup()

                # clear the user reservations
                for resource in resources:
                    if resource in self.reservations:
                        del self.reservations[resource]
            except Exception:
                if execution.is_instance:
                    await execution.removed_all_ports_redirection()
                if execution.vm:
                    await execution.vm.teardown()
                elif tap_interface and vm_id is not None:
                    teardown_nftables_for_vm(vm_id)
                    await tap_interface.delete()
                self.forget_vm(vm_hash)

                raise

            self._schedule_forget_on_stop(execution)

            return execution

    def get_unique_vm_id(self) -> int:
        """Get a unique identifier for the VM.

        This identifier is used to name the network interface and in the IPv4 range
        dedicated to the VM.
        """
        # Take the first id that is not already taken
        currently_used_vm_ids = {execution.vm_id for execution in self.executions.values()}
        for i in range(settings.START_ID_INDEX, 255**2):
            if i not in currently_used_vm_ids:
                return i
        msg = "No available value for vm_id."
        raise ValueError(msg)

    def get_running_or_starting_vm(self, vm_hash: ItemHash) -> VmExecution | None:
        """Return a running VM or None. Disables the VM expiration task."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running and not execution.is_stopping:
            execution.cancel_expiration()
            return execution
        else:
            return None

    def get_running_vm(self, vm_hash: ItemHash) -> VmExecution | None:
        """Return a running VM or None. Disables the VM expiration task."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running and not execution.is_stopping:
            execution.cancel_expiration()
            return execution
        else:
            return None

    async def stop_vm(self, vm_hash: ItemHash) -> VmExecution | None:
        """Stop a VM."""
        execution = self.executions.get(vm_hash)
        if not execution:
            logger.info("stop_vm No execution found for %s", vm_hash)
            return None
        await execution.stop()
        return execution

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
            # If the execution was re-registered with a new stop_event
            # (e.g. reinstall/restore), this old task should not remove it.
            if execution.stop_event is not stop_event:
                return
            self.forget_vm(execution.vm_hash)

        execution._forget_task = asyncio.create_task(forget_on_stop(stop_event=execution.stop_event))

    async def load_persistent_executions(self):
        """Load persistent executions from the database.

        For each saved execution whose systemd controller is still active,
        rebuild the in-memory state (network, ports, snapshots). For dead
        executions, record usage and clean up the stale controller service.
        After loading, remove any orphan host resources (nft rules, chains,
        tap interfaces) left behind by previous crashes.

        Uses batch D-Bus calls to check service states (1 call for all VMs
        instead of 3+ per VM).
        """
        saved_executions = await get_execution_records()

        # Filter to persistent executions not already loaded
        persistent_saved = [
            se for se in saved_executions if se.persistent and ItemHash(se.vm_hash) not in self.executions
        ]

        # Batch-fetch active states: 1 D-Bus ListUnits() call for all VMs
        all_services = [f"aleph-vm-controller@{ItemHash(se.vm_hash)}.service" for se in persistent_saved]
        service_active_states = self.systemd_manager.get_services_active_states(all_services)

        # Track claimed vm_ids to detect duplicates in the DB.
        # Multiple records can share a vm_id (stale records from old
        # executions). Only the first active one should be restored —
        # others are treated as dead to avoid tap interface conflicts.
        claimed_vm_ids: set[int] = set()

        for saved_execution in persistent_saved:
            vm_hash = ItemHash(saved_execution.vm_hash)
            vm_id = saved_execution.vm_id
            logger.info(f"Loading execution {vm_hash} for VM {vm_id}")

            # Skip if another execution already claimed this vm_id.
            # This prevents two instances from sharing the same tap
            # interface, which causes network loss when one is cleaned up.
            if vm_id in claimed_vm_ids:
                logger.warning(
                    "Skipping execution %s: vm_id %d already claimed by another execution",
                    vm_hash,
                    vm_id,
                )
                # Clean up the stale DB record
                execution = VmExecution(
                    vm_hash=vm_hash,
                    message=get_message_executable_content(json.loads(saved_execution.message)),
                    original=get_message_executable_content(json.loads(saved_execution.original_message)),
                    snapshot_manager=self.snapshot_manager,
                    systemd_manager=self.systemd_manager,
                    persistent=saved_execution.persistent,
                )
                await self._handle_dead_execution(execution, saved_execution)
                continue

            execution = VmExecution(
                vm_hash=vm_hash,
                message=get_message_executable_content(json.loads(saved_execution.message)),
                original=get_message_executable_content(json.loads(saved_execution.original_message)),
                snapshot_manager=self.snapshot_manager,
                systemd_manager=self.systemd_manager,
                persistent=saved_execution.persistent,
            )

            service_name = execution.controller_service
            is_active = service_active_states.get(service_name, False)

            if is_active:
                claimed_vm_ids.add(vm_id)
                await self._restore_running_execution(execution, saved_execution, vm_id, vm_hash)
            else:
                await self._handle_dead_execution(execution, saved_execution)

        self._cleanup_orphan_resources()

        if self.executions:
            await self.update_domain_mapping(force_update=True)
        logger.info(f"Loaded {len(self.executions)} executions")

    async def _restore_running_execution(
        self, execution: VmExecution, saved_execution: ExecutionRecord, vm_id: int, vm_hash: ItemHash
    ) -> None:
        """Rebuild in-memory state for a persistent execution whose controller is active."""
        execution.gpus = (
            TypeAdapter(list[HostGPU]).validate_python(json.loads(saved_execution.gpus)) if saved_execution.gpus else []
        )

        execution.mapped_ports = await get_port_mappings(vm_hash)
        execution.mode = saved_execution.mode or "normal"
        logger.info("Loading existing mapped_ports %s", execution.mapped_ports)
        if execution.mode != "normal":
            logger.info("Execution %s is in %s mode", vm_hash, execution.mode)

        await execution.prepare()
        tap_interface = await self._restore_network(execution, vm_id, vm_hash)

        vm = execution.create(vm_id=vm_id, tap_interface=tap_interface, prepare=False)
        await vm.start_guest_api()
        execution.ready_event.set()
        execution.times.started_at = datetime.now(tz=timezone.utc)
        execution.times.starting_at = saved_execution.time_prepared
        execution.times.prepared_at = saved_execution.time_defined

        self._schedule_forget_on_stop(execution)

        if vm.support_snapshot and self.snapshot_manager:
            await self.snapshot_manager.start_for(vm=execution.vm)

        if execution.mapped_ports:
            await execution.recreate_port_redirect_rules()
        await execution.fetch_port_redirect_config_and_setup()

        self.executions[vm_hash] = execution
        execution.record = saved_execution

    async def _restore_network(self, execution: VmExecution, vm_id: int, vm_hash: ItemHash) -> TapInterface | None:
        """Restore tap interface, NDP proxy, and nftables rules for a VM."""
        if not self.network:
            return None

        vm_type = VmType.from_message_content(execution.message)
        tap_interface = await self.network.prepare_tap(vm_id, vm_hash, vm_type)

        if not self.network.interface_exists(vm_id):
            await self.network.create_tap(vm_id, tap_interface)

        if self.network.ndp_proxy and self.network.interface_exists(vm_id):
            await self.network.ndp_proxy.add_range(
                interface=tap_interface.device_name,
                address_range=tap_interface.host_ipv6.network,
                update_service=False,
            )
            logger.debug("Re-added ndp_proxy rule for existing interface %s", tap_interface.device_name)

        setup_nftables_for_vm(vm_id, interface=tap_interface)
        return tap_interface

    async def _handle_dead_execution(self, execution: VmExecution, saved_execution: ExecutionRecord) -> None:
        """Record usage for a dead execution and stop its controller service."""
        execution.uuid = saved_execution.uuid
        try:
            await execution.record_usage()
        except Exception:
            logger.warning("Failed to record usage for %s", execution.vm_hash, exc_info=True)
        try:
            self.systemd_manager.stop_and_disable(execution.controller_service)
            logger.info("Stopped and disabled stale controller service %s", execution.controller_service)
        except Exception:
            logger.warning("Failed to stop/disable stale controller %s", execution.controller_service, exc_info=True)

    def _cleanup_orphan_resources(self):
        """Remove orphan nft rules, nft chains, tap interfaces, and controller configs.

        Compares host resources against active executions in the pool
        and removes anything that doesn't belong to a running VM.
        Fetches the nftables ruleset once and passes it to both nft cleanup methods.
        """
        active_vm_ids = {execution.vm_id for execution in self.executions.values() if execution.vm_id is not None}
        active_vm_hashes = {str(vm_hash) for vm_hash in self.executions}

        nft_ruleset = get_existing_nftables_ruleset()
        self._cleanup_orphan_port_redirects(nft_ruleset)
        self._cleanup_orphan_nft_chains(active_vm_ids, nft_ruleset)
        self._cleanup_orphan_tap_interfaces(active_vm_ids)
        self._cleanup_orphan_controller_configs(active_vm_hashes)

    def _cleanup_orphan_controller_configs(self, active_vm_hashes: set[str]):
        """Stop controller services and delete controller configs for forgotten VMs.

        A VM removed from ``self.executions`` may leave behind:
          - A running ``aleph-vm-controller@<hash>.service`` with an active
            qemu process that still consumes host RAM the admission check
            does not see, so the host's real free memory is lower than
            ``check_admission`` assumes.
          - A ``<hash>-controller.json`` file on disk that systemd would
            reuse on the next boot, reviving the orphan.

        Removing both keeps the host's actual free memory aligned with
        what the admission check computes.
        """
        try:
            config_files = list(settings.EXECUTION_ROOT.glob("*-controller.json"))
        except Exception:
            logger.warning("Failed to enumerate controller configs", exc_info=True)
            return

        removed = 0
        for config_path in config_files:
            vm_hash = config_path.name[: -len("-controller.json")]
            if vm_hash in active_vm_hashes:
                continue
            service_name = f"aleph-vm-controller@{vm_hash}.service"
            try:
                self.systemd_manager.stop_and_disable(service_name)
            except Exception:
                logger.warning("Failed to stop orphan controller %s", service_name, exc_info=True)
            try:
                config_path.unlink()
                removed += 1
                logger.info("Removed orphan controller config %s", config_path)
            except FileNotFoundError:
                pass
            except Exception:
                logger.warning("Failed to remove orphan controller config %s", config_path, exc_info=True)

        if removed:
            logger.info("Removed %d orphan controller configs", removed)

    def _cleanup_orphan_port_redirects(self, nft_ruleset: list[dict]):
        """Remove DNAT prerouting rules with no matching active execution."""
        known_good: set[tuple[int, str, int, str]] = set()
        for execution in self.executions.values():
            tap = execution.vm.tap_interface if execution.vm else None
            if not tap or not execution.mapped_ports:
                continue
            guest_ip = str(tap.guest_ip.ip)
            for vm_port, mapping in execution.mapped_ports.items():
                host_port = int(mapping["host"])
                for proto in ("tcp", "udp"):
                    if mapping.get(proto):
                        known_good.add((host_port, guest_ip, int(vm_port), proto))
        removed = remove_orphan_port_redirect_rules(known_good, nft_ruleset=nft_ruleset)
        if removed:
            logger.info("Removed %d orphan port redirect rules", removed)

    def _cleanup_orphan_nft_chains(self, active_vm_ids: set[int], nft_ruleset: list[dict]):
        """Remove per-VM nft chains whose vm_id is not in any active execution."""
        try:
            orphan_vm_ids = get_orphan_vm_chain_ids(active_vm_ids, nft_ruleset=nft_ruleset)
            for vm_id in orphan_vm_ids:
                try:
                    teardown_nftables_for_vm(vm_id)
                    logger.info("Removed orphan nft chains for vm_id=%d", vm_id)
                except Exception:
                    logger.warning("Failed to remove orphan nft chains for vm_id=%d", vm_id, exc_info=True)
        except Exception:
            logger.warning("Failed to query nftables for orphan chains", exc_info=True)

    def _cleanup_orphan_tap_interfaces(self, active_vm_ids: set[int]):
        """Remove vmtap interfaces whose vm_id is not in any active execution."""
        if not self.network:
            return
        try:
            removed = remove_orphan_tap_interfaces(active_vm_ids)
            if removed:
                logger.info("Removed %d orphan tap interfaces", removed)
        except Exception:
            logger.warning("Failed to clean orphan tap interfaces", exc_info=True)

    @property
    def is_draining(self) -> bool:
        return self._draining

    async def drain(self, timeout: float | None = None) -> None:
        """Stop accepting new requests and wait for in-flight ones.

        Sets the drain flag so the middleware rejects new VM execution
        requests with 503. Then waits up to ``timeout`` seconds for all
        running ephemeral executions to finish their current requests
        before returning.  Persistent VMs are left untouched — they run
        via systemd controllers and survive supervisor restarts.
        """
        if timeout is None:
            timeout = settings.DRAIN_TIMEOUT

        self._draining = True
        logger.info(
            "Drain started — rejecting new requests, waiting up to %.0fs for in-flight requests",
            timeout,
        )

        # A request that passed the middleware before _draining was set can
        # still increment concurrent_runs after this snapshot.  That is a
        # single event-loop turn window and is covered by the double safety
        # net: stop() calls all_runs_complete() on each execution anyway.
        in_flight = [
            execution
            for execution in self.executions.values()
            if not execution.persistent and execution.concurrent_runs > 0
        ]

        if not in_flight:
            logger.info("Drain complete — no in-flight requests")
            return

        logger.info(
            "Waiting for %d execution(s) with in-flight requests",
            len(in_flight),
        )

        # Wait for each execution's runs to complete, with a timeout
        try:
            await asyncio.wait_for(
                asyncio.gather(*(ex.runs_done_event.wait() for ex in in_flight)),
                timeout=timeout,
            )
            logger.info("Drain complete — all in-flight requests finished")
        except TimeoutError:
            remaining = sum(1 for ex in in_flight if ex.concurrent_runs > 0)
            logger.warning(
                "Drain timeout after %.0fs — %d execution(s) still have "
                "in-flight requests, proceeding with shutdown",
                timeout,
                remaining,
            )

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

    def get_available_gpus(self) -> list[GpuDevice]:
        available_gpus = []
        for gpu in self.gpus:
            used = False
            for _, execution in self.executions.items():
                if execution.uses_gpu(gpu.pci_host):
                    used = True
                    break
            if not used:
                available_gpus.append(gpu)
        return available_gpus

    def get_executions_by_address(self, payment_type: PaymentType) -> dict[str, dict[str, list[VmExecution]]]:
        """Return all executions of the given type, grouped by sender and by chain."""
        executions_by_address: dict[str, dict[str, list[VmExecution]]] = {}
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
                address = execution.message.address
                chain = execution_payment.chain
                executions_by_address.setdefault(address, {})
                executions_by_address[address].setdefault(chain, []).append(execution)
        return executions_by_address

    def get_valid_reservation(self, resource) -> Reservation | None:
        if resource in self.reservations and self.reservations[resource].is_expired():
            del self.reservations[resource]
        return self.reservations.get(resource)

    async def reserve_resources(self, message: ExecutableContent, user):
        gpu_to_reserve = message.requirements.gpu if message.requirements and message.requirements.gpu else []
        expiration_date = datetime.now(tz=timezone.utc) + timedelta(seconds=60)
        if not gpu_to_reserve:
            return expiration_date

        # Use the creation lock, to avoid racing issues, with VM creation
        async with self.creation_lock:
            # Will raise Exception if not all resources are found.
            resources = self.find_resources_available_for_user(message, user)

            for resource in resources:
                # Existing reservation for that user will be overwritten by fresher one
                self.reservations[resource] = Reservation(user=user, expiration=expiration_date, resource=resource)

        return expiration_date

    def find_resources_available_for_user(self, message: ExecutableContent, user) -> set[GpuDevice]:
        """Find the required resource to run ExecutableContent from reserved resources by user or free resources.

        Only implement GPU for now"""
        # Calling function should use the creation_lock to avoid resource being stollem
        gpu_to_reserve = message.requirements.gpu if message.requirements and message.requirements.gpu else []

        # Available GPU are those unused regardless of reservation status
        available_gpus = self.get_available_gpus()
        resources = set()
        # Use the creation lock, to avoid racing issue the gpu for nothing
        for gpu in gpu_to_reserve:
            for available_gpu in available_gpus:
                if available_gpu.device_id != gpu.device_id:
                    continue
                existing_reservation = self.get_valid_reservation(available_gpu)
                if existing_reservation is not None and existing_reservation.user != user:
                    # Already has that resource for the user reserved
                    continue
                # Found a gpu, reserve it.
                available_gpus.remove(available_gpu)
                resources.add(available_gpu)
                break
            else:  # for-else No reservation was found
                logger.debug("Failed to found resource %s, no available, unreserved GPU", gpu)
                err = f"Failed to find available GPU matching spec {gpu}"
                raise Exception(err)
        return resources

    async def update_domain_mapping(self, force_update=False):
        socket = settings.HAPROXY_SOCKET
        if not pathlib.Path(socket).exists():
            logger.info("HAProxy not running? socket not found, skip domain mapping update")
            return False

        local_vms = list(self.executions.keys())

        await fetch_list_and_update(
            socket,
            local_vms,
            force_update=force_update,
        )


class Reservation:
    def __init__(self, user, resource, expiration):
        self.user = user
        self.resource = resource
        self.expiration = expiration

    def is_expired(self):
        logger.info(f"{datetime.now(tz=timezone.utc)}, {datetime.now(tz=timezone.utc) > self.expiration}")
        return datetime.now(tz=timezone.utc) > self.expiration
