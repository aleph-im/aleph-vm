from __future__ import annotations

import asyncio
import logging
import shutil
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

import psutil

from aleph.vm.conf import settings
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.resources import (
    GpuDevice,
    HostGPU,
    InsufficientResourcesError,
    get_gpu_devices,
)
from aleph.vm.supervisor.networking_db import (
    create_supervisor_tables,
    get_port_mappings,
    migrate_port_mappings_from_legacy_db,
    setup_supervisor_engine,
)
from aleph.vm.supervisor.qemu_build import (
    build_qemu_confidential_configuration,
    build_qemu_configuration,
    spec_from_controller_configuration,
)
from aleph.vm.supervisor_interface.configuration import (
    Configuration,
    get_controller_configuration_path,
    load_controller_configuration,
    remove_controller_configuration,
    save_controller_configuration,
)
from aleph.vm.supervisor_interface.errors import (
    InternalSupervisorError,
    InvalidBackendError,
    VmAlreadyExistsError,
)
from aleph.vm.supervisor_interface.types import Backend, CreateVmSpec, GpuSpec, VmId
from aleph.vm.systemd import SystemDManager
from aleph.vm.vm_type import VmType

from .models import VmExecution
from .network.firewall import (
    get_existing_nftables_ruleset,
    get_orphan_vm_chain_ids,
    remove_orphan_port_redirect_rules,
    setup_nftables_for_vm,
    teardown_nftables_for_vm,
)
from .network.interfaces import remove_orphan_tap_interfaces

logger = logging.getLogger(__name__)

# Background retry of VMs whose reattach failed at startup (their controller is
# still running but the supervisor could not rebuild its in-memory state). A
# transient cause (e.g. host networking not ready yet) heals on a later pass.
REATTACH_RETRY_INTERVAL_SECONDS = 30
REATTACH_RETRY_MAX_ATTEMPTS = 5


@dataclass
class _FailedReattach:
    """A VM left running-but-untracked after a failed reattach, pending retry.

    ``attempts`` starts at 1 (the startup attempt). Once it reaches
    ``REATTACH_RETRY_MAX_ATTEMPTS`` the VM is ``exhausted``: the supervisor stops
    retrying and leaves the live controller alone (operator intervention needed).
    """

    config: Configuration
    vm_index: int
    attempts: int = 1
    exhausted: bool = False


class VmPool:
    """Pool of existing VMs

    For function VM we keep the VM a while after they  have run, so we can reuse them  and thus decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.
    """

    executions: dict[VmId, VmExecution]
    network: Network | None
    systemd_manager: SystemDManager
    creation_lock: asyncio.Lock
    gpus: list[GpuDevice]

    _draining: bool
    # VMs whose reattach failed and that are awaiting background retry. Keyed by
    # vm_id; entries are removed once re-adopted, kept (exhausted) once given up.
    _failed_reattach: dict[VmId, _FailedReattach]

    def __init__(self):
        self.executions = {}
        self.gpus = []
        self._draining = False
        self._failed_reattach = {}

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

    async def setup(self) -> None:
        """Set up the VM pool and the network."""
        # This process runs the pool, so it owns the supervisor DB (port
        # mappings). Set up its engine, create the schema, and on first start
        # after the agent/supervisor DB split, migrate any pre-split rows so
        # live VMs keep their host-port forwards.
        engine = setup_supervisor_engine()
        await create_supervisor_tables(engine)
        migrate_port_mappings_from_legacy_db()

        if self.network:
            self.network.setup()

        if settings.ENABLE_GPU_SUPPORT:
            # Raw hardware inventory (lspci): network annotation (model name,
            # compatibility) is applied agent-side from the settings aggregate.
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
            logger.debug("Disk usage delta: %d for %s", delta, execution.vm_id)
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

    async def create_vm_from_spec(self, spec: CreateVmSpec) -> VmExecution:
        """Create a VM from a message-free CreateVmSpec.

        The supervisor's creation path: no Aleph message, no download. The
        spec carries resolved on-disk paths. The controller config is written
        by build_qemu_configuration (0.C), so the message-coupled
        vm.configure() is skipped (start(write_config=False)).
        """
        if spec.backend is Backend.FIRECRACKER:
            return await self._create_firecracker_from_spec(spec)

        vm_id = spec.vm_id
        async with self.creation_lock:
            current_execution = self.executions.get(vm_id)
            if current_execution and current_execution.is_running and not current_execution.is_stopping:
                self._require_same_spec(current_execution, spec)
                return current_execution

            # The VM may already be running without a pool entry: a prior
            # reattach failed and was isolated (#1001), leaving the live
            # controller protected but untracked. Re-adopt it rather than
            # building a fresh VM on top -- a fresh create reuses the index/tap
            # and control sockets the live qemu still holds (it never wipes the
            # disks, but it bounces or collides with a running instance).
            readopted = await self._readopt_live_controller(vm_id)
            if readopted is not None:
                # Same idempotency contract as the tracked-running branch
                # above: a retry with the identical spec returns the live VM,
                # a different spec is a conflict, never a silent old-spec VM.
                self._require_same_spec(readopted, spec)
                return readopted

            # Mechanism backstops, atomic with the registration below: never
            # oversubscribe physical memory, never double-attach a GPU. The
            # admission POLICY (memory buckets, vCPU overcommit, user-scoped
            # reservations) is the client's business and runs agent-side
            # before create_vm.
            self._check_memory_backstop(spec.memory_mib)
            resolved_host_gpus: list[HostGPU] = []
            if spec.gpus:
                resolved_host_gpus = self._validate_spec_gpus(spec.gpus)

            execution = VmExecution.from_spec(spec, systemd_manager=self.systemd_manager)
            # Attach the validated GPUs so uses_gpu() holds them against other
            # creates and _to_vm_info reports them.
            execution.gpus = resolved_host_gpus
            self.executions[vm_id] = execution

            tap_interface = None
            vm_index = None
            try:
                await execution.prepare()  # builds resources from the spec; no download

                vm_index = self.get_unique_vm_index()

                if self.network:
                    tap_interface = await self.network.prepare_tap(vm_index, vm_id, VmType.instance)
                    if self.network.interface_exists(vm_index):
                        await tap_interface.delete()
                    await self.network.create_tap(vm_index, tap_interface)

                # Confidential VMs get a QemuConfidentialVMConfiguration;
                # spec.gpus already carries concrete pci_hosts (validated
                # above), so the confidential config carries the resolved
                # GPUs too. SAFETY-CRITICAL: a build failure (e.g. missing
                # firmware) propagates and aborts the create; we never fall back
                # to the plain QemuVMConfiguration, which would boot the VM
                # unprotected.
                if spec.tee is not None:
                    config = await build_qemu_confidential_configuration(spec, vm_index, tap_interface)
                else:
                    config = await build_qemu_configuration(spec, vm_index, tap_interface)
                save_controller_configuration(spec.vm_id, config)

                execution.create(vm_index=vm_index, tap_interface=tap_interface)
                # start(write_config=False): the controller config was just
                # written above. For a confidential VM, VmExecution.start leaves
                # it in awaiting_confidential_init (is_confidential is True, so
                # it does NOT enable_and_start the controller); the owner starts
                # it later via initialize_confidential.
                await execution.start(write_config=False)
                # Reuse persisted host ports across restarts. The agent then
                # reconciles the aggregate settings through add_port_forward,
                # which merges with these preloaded mappings.
                execution.mapped_ports = await get_port_mappings(vm_id)
                if execution.mapped_ports:
                    await execution.recreate_port_redirect_rules()
            except Exception:
                if execution.vm:
                    await execution.vm.teardown()
                elif tap_interface and vm_index is not None:
                    teardown_nftables_for_vm(vm_index)
                    await tap_interface.delete()
                self.forget_vm(vm_id)
                raise

            self._schedule_forget_on_stop(execution)
            return execution

    async def _readopt_live_controller(self, vm_id: VmId) -> VmExecution | None:
        """Re-adopt a VM whose controller is still running but is absent from the
        pool (a reattach that failed and was isolated by load_persistent_executions).

        Returns the re-adopted execution, or None when there is positively
        nothing live to adopt (no on-disk config, or the controller unit is
        inactive, failed, or not loaded), in which case the caller proceeds
        with a normal create (an inactive controller is a clean
        restart-from-disk, which is safe).

        Fail-closed: when systemd cannot report a definitive unit state (a
        D-Bus error, or a transitional activating/deactivating state), or when
        the VM's on-disk vm_index is meanwhile claimed by another tracked
        execution, this raises InternalSupervisorError so the create fails and
        the agent retries later, instead of falling through to a fresh create
        over a possibly live controller.

        Called under ``creation_lock``. If re-adoption itself fails (the original
        transient cause persists), the exception propagates: the caller must NOT
        fall through to a fresh create over the live controller. The VM stays
        untracked until the next attempt, never clobbered.
        """
        # Probe for the config file before calling the loader: for a genuinely
        # new VM there is no file and load_controller_configuration would log
        # a spurious "not found" warning on every create.
        if not get_controller_configuration_path(str(vm_id)).exists():
            return None
        config = load_controller_configuration(str(vm_id))
        if config is None:
            return None
        service_name = f"aleph-vm-controller@{vm_id}.service"
        state = self.systemd_manager.get_service_active_state(service_name)
        if state in ("inactive", "failed", "not-loaded"):
            # Positively not running: a fresh create is a clean restart.
            return None
        if state != "active":
            # "unknown" (a D-Bus failure) or a transitional state: we cannot
            # tell whether the controller is live, so refuse to create.
            msg = (
                f"Cannot determine the state of controller {service_name} (ActiveState: {state}); "
                f"refusing to create VM {vm_id} over a possibly live controller, retry later"
            )
            raise InternalSupervisorError(msg)

        # The on-disk vm_index may have been handed to a newer VM after the
        # failed reattach (get_unique_vm_index only sees tracked executions).
        # Restoring on it would rewire that VM's tap/nftables (the restore
        # path trusts the index), and a fresh create over the live controller
        # is forbidden, so the only safe outcome is to fail.
        claimed_by = next(
            (other_id for other_id, execution in self.executions.items() if execution.vm_index == config.vm_id),
            None,
        )
        if claimed_by is not None:
            msg = (
                f"Cannot re-adopt VM {vm_id}: its on-disk vm_index {config.vm_id} is now claimed by "
                f"running VM {claimed_by}; refusing to rewire that VM's networking or to create a "
                f"duplicate, operator intervention required"
            )
            raise InternalSupervisorError(msg)

        logger.warning(
            "create requested for %s but its controller is already running and untracked "
            "(a previous reattach failed); re-adopting it instead of creating a duplicate",
            vm_id,
        )
        await self._restore_running_execution_from_config(config, config.vm_id, vm_id)
        # The VM may also be queued for background retry (or given up on):
        # both paths run under creation_lock, so drop the entry here instead
        # of leaving it to linger in unmanaged_vm_ids and hold its vm_index.
        self._failed_reattach.pop(vm_id, None)
        return self.executions[vm_id]

    async def _create_firecracker_from_spec(self, spec: CreateVmSpec) -> VmExecution:
        """Message-free Firecracker boot.

        Boots the VM from the spec's resolved paths and, when the spec carries
        a guest channel, waits for the guest's ready signal as part of boot.
        The guest-level protocols spoken over the channel are the client's
        business (VmInfo.guest_channel_path). The engine only enforces its
        physical-memory backstop, atomically inside this create path.
        """
        if spec.guest_channel is None:
            # Firecracker VMs without a guest channel (full instances under
            # FC) have no spec-path boot flow yet; they keep the legacy path.
            msg = "Firecracker spec VMs require a guest_channel"
            raise InvalidBackendError(msg)

        vm_id = spec.vm_id
        async with self.creation_lock:
            current_execution = self.executions.get(vm_id)
            if current_execution and current_execution.is_running and not current_execution.is_stopping:
                self._require_same_spec(current_execution, spec)
                return current_execution

            # Physical-memory backstop, atomic with the registration below
            # (spec programs carry no GPUs, so there is nothing to validate).
            self._check_memory_backstop(spec.memory_mib)

            execution = VmExecution.from_spec(spec, systemd_manager=self.systemd_manager)
            self.executions[vm_id] = execution

            tap_interface = None
            vm_index = None
            try:
                await execution.prepare()  # resolves resources from the spec; no download

                vm_index = self.get_unique_vm_index()

                if self.network and spec.network.internet_access:
                    tap_interface = await self.network.prepare_tap(vm_index, vm_id, VmType.microvm)
                    if self.network.interface_exists(vm_index):
                        await tap_interface.delete()
                    await self.network.create_tap(vm_index, tap_interface)

                execution.create(vm_index=vm_index, tap_interface=tap_interface)
                # start() boots the program: ephemeral programs run the VMM
                # directly and block through the init-ready handshake;
                # persistent programs save the controller config and boot under
                # systemd, then wait for init (VmExecution.start branches on
                # self.persistent).
                await execution.start()
            except Exception:
                if execution.vm:
                    await execution.vm.teardown()
                elif tap_interface and vm_index is not None:
                    teardown_nftables_for_vm(vm_index)
                    await tap_interface.delete()
                self.forget_vm(vm_id)
                raise

            self._schedule_forget_on_stop(execution)
            return execution

    @staticmethod
    def _require_same_spec(current_execution: VmExecution, spec: CreateVmSpec) -> None:
        """CreateVm idempotency: a retry with the identical spec returns the
        live VM; a different spec for a live vm_index is a conflict."""
        if current_execution.vm_spec != spec:
            msg = f"VM {spec.vm_id} already exists with a different spec"
            raise VmAlreadyExistsError(msg)

    def get_unique_vm_index(self) -> int:
        """Get a unique identifier for the VM.

        This identifier is used to name the network interface and in the IPv4 range
        dedicated to the VM.
        """
        # Take the first id that is not already taken. Failed-reattach VMs are
        # not in self.executions but their live controllers still own their
        # vm_index (tap interface, nft chains): handing one of those to a new
        # create would let it delete the live VM's networking.
        currently_used_vm_ids = {execution.vm_index for execution in self.executions.values()}
        currently_used_vm_ids |= {state.vm_index for state in self._failed_reattach.values()}
        for i in range(settings.START_ID_INDEX, 255**2):
            if i not in currently_used_vm_ids:
                return i
        msg = "No available value for vm_index."
        raise ValueError(msg)

    def get_running_or_starting_vm(self, vm_id: VmId) -> VmExecution | None:
        """Return a running VM or None."""
        execution = self.executions.get(vm_id)
        if execution and execution.is_running and not execution.is_stopping:
            return execution
        else:
            return None

    def get_running_vm(self, vm_id: VmId) -> VmExecution | None:
        """Return a running VM or None."""
        execution = self.executions.get(vm_id)
        if execution and execution.is_running and not execution.is_stopping:
            return execution
        else:
            return None

    async def stop_vm(self, vm_id: VmId) -> VmExecution | None:
        """Stop a VM."""
        execution = self.executions.get(vm_id)
        if not execution:
            logger.info("stop_vm No execution found for %s", vm_id)
            return None
        await execution.stop()
        return execution

    def forget_vm(self, vm_id: VmId) -> None:
        """Remove a VM from the executions pool.

        Used after VM creation raised an error in order to completely
        forget about the execution and enforce a new execution when
        attempted again.
        """
        try:
            del self.executions[vm_id]
        except KeyError:
            pass

    async def restart_persistent_vm(self, execution: VmExecution) -> None:
        """Re-register a stopped persistent VM and restart it via systemd.

        Re-registers the execution in the pool immediately (before any async
        work) so the periodic allocation loop cannot create a duplicate
        execution with a new vm_index.
        """
        execution.times.stopping_at = None
        execution.times.stopped_at = None
        execution.stop_event = asyncio.Event()
        self.executions[execution.vm_id] = execution
        self._schedule_forget_on_stop(execution)

        if self.network and execution.vm:
            if not self.network.interface_exists(execution.vm.vm_index):
                await self.network.create_tap(execution.vm.vm_index, execution.vm.tap_interface)
            else:
                # Interface exists but nftables rules may have been flushed —
                # always re-apply them.
                setup_nftables_for_vm(execution.vm.vm_index, interface=execution.vm.tap_interface)
        self.systemd_manager.restart(execution.controller_service)
        # RestartUnit only queues a job: wait until the unit is confirmed
        # active (with the crash-loop re-check) so callers get a truthful
        # RUNNING status and a flapping controller fails the start loudly.
        await execution.wait_for_controller_ready()
        execution.times.started_at = datetime.now(tz=timezone.utc)
        # Reload port mappings from DB — stop() clears them in memory
        # but the DB retains them for persistent VMs.
        execution.mapped_ports = await get_port_mappings(execution.vm_id)
        if execution.mapped_ports:
            await execution.recreate_port_redirect_rules()

    def _schedule_forget_on_stop(self, execution: VmExecution):
        """Create a task that will remove the VM from the pool after it stops."""

        async def forget_on_stop(stop_event: asyncio.Event):
            await stop_event.wait()
            # If the execution was re-registered with a new stop_event
            # (e.g. reinstall/restore), this old task should not remove it.
            if execution.stop_event is not stop_event:
                return
            # Forget by identity, not by hash: the same vm_index may already be
            # a new execution (reboot and delete+create recreate it while
            # this task races the old stop); only this task's own execution
            # may be removed.
            if self.executions.get(execution.vm_id) is execution:
                self.forget_vm(execution.vm_id)

        execution._forget_task = asyncio.create_task(forget_on_stop(stop_event=execution.stop_event))

    async def load_persistent_executions(self):
        """Reattach VMs whose controllers survived a supervisor restart.

        Scans EXECUTION_ROOT for <hash>-controller.json files, checks which
        aleph-vm-controller@<hash>.service units are active (one batch D-Bus
        call), and rebuilds in-memory state from each active config. Dead
        controllers are stopped; their orphan configs are removed by
        _cleanup_orphan_resources. Entirely message-free: nothing is read
        from the database.
        """
        try:
            config_paths = sorted(settings.EXECUTION_ROOT.glob("*-controller.json"))
        except OSError:
            logger.warning("Failed to enumerate controller configs", exc_info=True)
            config_paths = []

        configs: list[Configuration] = []
        for config_path in config_paths:
            vm_id = config_path.name[: -len("-controller.json")]
            if VmId(vm_id) in self.executions:
                continue
            config = load_controller_configuration(vm_id)
            if config is None:
                continue
            configs.append(config)

        # Batch-fetch active states: 1 D-Bus ListUnits() call for all VMs.
        all_services = [f"aleph-vm-controller@{config.vm_hash}.service" for config in configs]
        service_active_states = self.systemd_manager.get_services_active_states(all_services)

        # Track claimed vm_ids to detect duplicates across configs. A stale
        # config can reuse a vm_index; only the first active one is restored to
        # avoid two VMs sharing a tap interface.
        claimed_vm_ids: set[int] = set()

        # A controller that is alive but whose in-memory reattach failed. Its
        # vm_index/hash are protected from the orphan sweep below: the VM is
        # still running, so stopping its service or deleting its config would
        # destroy a live instance -- far worse than not tracking it this cycle.
        failed_vm_ids: set[int] = set()
        failed_vm_hashes: set[str] = set()

        for config in configs:
            vm_id = VmId(str(config.vm_hash))
            vm_index = config.vm_id
            service_name = f"aleph-vm-controller@{config.vm_hash}.service"
            is_active = service_active_states.get(service_name, False)

            if not is_active:
                await self._handle_dead_controller(config)
                continue

            if vm_index in claimed_vm_ids:
                logger.warning(
                    "Skipping reattach of %s: vm_index %d already claimed by another config",
                    vm_id,
                    vm_index,
                )
                await self._handle_dead_controller(config)
                continue

            logger.info("Reattaching execution %s for VM %d", vm_id, vm_index)
            claimed_vm_ids.add(vm_index)
            try:
                await self._restore_running_execution_from_config(config, vm_index, vm_id)
            except Exception:
                # One VM's reattach must never deny reattach to the rest of the
                # node (and, in-process, must never crash startup). The
                # controller is alive and the VM is running; only our in-memory
                # rebuild failed -- e.g. an unsupported config (confidential),
                # or a transient prepare/network error. Leave the live VM and
                # its on-disk artifacts untouched and carry on with the others.
                logger.exception(
                    "Failed to reattach %s (vm_index %d); leaving its controller running and untracked this cycle",
                    vm_id,
                    vm_index,
                )
                failed_vm_ids.add(vm_index)
                failed_vm_hashes.add(str(config.vm_hash))
                # Queue it for background retry (run_reattach_retry_loop): a
                # transient cause may clear and let us adopt it without downtime.
                self._failed_reattach[vm_id] = _FailedReattach(config=config, vm_index=vm_index)

        self._cleanup_orphan_resources(protected_vm_ids=failed_vm_ids, protected_vm_hashes=failed_vm_hashes)

        logger.info("Loaded %d executions", len(self.executions))

    @property
    def unmanaged_vm_ids(self) -> set[VmId]:
        """VMs whose controller is running but which the supervisor gave up
        reattaching (Option B). Surfaced for operators; these need manual action."""
        return {vm_id for vm_id, state in self._failed_reattach.items() if state.exhausted}

    async def discard_failed_reattach(self, vm_id: VmId) -> bool:
        """Dequeue a failed-reattach VM (pending or exhausted) and stop its controller.

        The delete path for a VM the supervisor never re-adopted: its
        controller is running but the VM is not in ``self.executions``.
        Without this, a delete raises VmNotFoundError while the retry loop
        (or the next startup) resurrects the controller as an unmanageable,
        still-billed VM.

        Returns True if an entry was discarded (the controller was stopped
        and its on-disk definition removed), False if nothing was queued.

        Deliberately takes ``creation_lock``: the retry pass holds it around
        its liveness check + restore, so acquiring it here guarantees we
        never stop a controller that a concurrent retry pass is halfway
        through adopting. If that pass wins the lock and adopts the VM
        first, the entry is already gone and this returns False; the caller
        then falls back to its not-found handling and a follow-up delete
        goes through the tracked path.
        """
        async with self.creation_lock:
            state = self._failed_reattach.pop(vm_id, None)
            if state is None:
                return False
            logger.info(
                "Discarding failed-reattach VM %s on delete: stopping its untracked controller",
                vm_id,
            )
            # Same cleanup as a dead controller found at startup: stop and
            # disable the unit, then drop the on-disk definition so neither
            # the next startup nor systemd revives it.
            await self._handle_dead_controller(state.config)
            remove_controller_configuration(str(vm_id))
            return True

    async def run_reattach_retry_loop(self) -> None:
        """Background loop: retry VMs whose reattach failed at startup.

        Each pass re-attempts adoption for every VM not yet exhausted; a VM that
        succeeds is dropped, one that fails has its attempt count bumped. After
        REATTACH_RETRY_MAX_ATTEMPTS the VM is marked exhausted and left alone --
        its controller keeps running, the supervisor just cannot manage it
        (operator intervention required). The loop exits once nothing is left to
        retry, so a clean startup (no failures) returns immediately.
        """
        while any(not state.exhausted for state in self._failed_reattach.values()):
            await asyncio.sleep(REATTACH_RETRY_INTERVAL_SECONDS)
            await self._retry_failed_reattachments_once()

    async def _retry_failed_reattachments_once(self) -> None:
        for vm_id, state in list(self._failed_reattach.items()):
            if vm_id in self.executions:
                # Adopted in the meantime (e.g. by an on-demand create). Checked
                # before the exhausted skip so even a given-up entry is dropped
                # once another path tracks the VM.
                del self._failed_reattach[vm_id]
                continue
            if state.exhausted:
                continue
            # Serialize with create_vm_from_spec so the two adoption paths never
            # rebuild the same VM concurrently.
            async with self.creation_lock:
                if vm_id in self.executions:
                    # Adopted while we waited for the lock.
                    del self._failed_reattach[vm_id]
                    continue
                # Liveness gate: the controller was alive at startup, but it may
                # have died since. Restoring a dead one would register a phantom
                # "running" execution (the restore never talks to the guest).
                service_name = f"aleph-vm-controller@{vm_id}.service"
                active_state = self.systemd_manager.get_service_active_state(service_name)
                if active_state in ("inactive", "failed", "not-loaded"):
                    # Positively dead: clean up the stale unit and stop retrying.
                    logger.warning(
                        "Controller of queued VM %s is %s; it died since startup. "
                        "Cleaning it up and dropping it from reattach retries.",
                        vm_id,
                        active_state,
                    )
                    await self._handle_dead_controller(state.config)
                    del self._failed_reattach[vm_id]
                    continue
                if active_state != "active":
                    # "unknown" (D-Bus error) or a transitional state
                    # (activating/deactivating): not proof of death, so treat it
                    # exactly like a failed restore attempt and retry later.
                    self._note_reattach_retry_failure(vm_id, state)
                    continue
                try:
                    await self._restore_running_execution_from_config(state.config, state.vm_index, vm_id)
                except Exception:
                    self._note_reattach_retry_failure(vm_id, state)
                else:
                    del self._failed_reattach[vm_id]
                    logger.info("Re-adopted previously-failed VM %s on retry", vm_id)

    def _note_reattach_retry_failure(self, vm_id: VmId, state: _FailedReattach) -> None:
        """Spend one reattach attempt for ``vm_id``; mark it exhausted at the cap.

        ``attempts`` counts TOTAL attempts, including the one made at startup.
        """
        state.attempts += 1
        if state.attempts >= REATTACH_RETRY_MAX_ATTEMPTS:
            state.exhausted = True
            logger.error(
                "Giving up reattaching %s after %d attempts. Its controller is still "
                "running but the supervisor cannot manage it; the VM is NOT auto-stopped "
                "-- operator intervention required.",
                vm_id,
                state.attempts,
            )
        else:
            logger.warning(
                "Reattach attempt %d/%d for %s failed; will retry",
                state.attempts,
                REATTACH_RETRY_MAX_ATTEMPTS,
                vm_id,
            )

    async def _restore_network(self, vm_index: int, vm_id: VmId) -> TapInterface | None:
        """Restore tap interface, NDP proxy, and nftables rules for a VM."""
        if not self.network:
            return None

        # Reattach is QEMU-instance only; the message is gone by design.
        vm_type = VmType.instance
        tap_interface = await self.network.prepare_tap(vm_index, vm_id, vm_type)

        if not self.network.interface_exists(vm_index):
            await self.network.create_tap(vm_index, tap_interface)

        if self.network.ndp_proxy and self.network.interface_exists(vm_index):
            await self.network.ndp_proxy.add_range(
                interface=tap_interface.device_name,
                address_range=tap_interface.host_ipv6.network,
                update_service=False,
            )
            logger.debug("Re-added ndp_proxy rule for existing interface %s", tap_interface.device_name)

        setup_nftables_for_vm(vm_index, interface=tap_interface)
        return tap_interface

    async def _restore_running_execution_from_config(self, config: Configuration, vm_index: int, vm_id: VmId) -> None:
        """Rebuild in-memory state for a VM whose controller is still active.

        Sourced entirely from the on-disk controller config -- message-free.
        """
        spec = spec_from_controller_configuration(config)
        execution = VmExecution.from_spec(spec, systemd_manager=self.systemd_manager)

        execution.mapped_ports = await get_port_mappings(vm_id)
        logger.info("Loading existing mapped_ports %s", execution.mapped_ports)

        await execution.prepare()  # builds resources from the spec; no download
        tap_interface = await self._restore_network(vm_index, vm_id)

        vm = execution.create(vm_index=vm_index, tap_interface=tap_interface, prepare=False)
        await vm.start_guest_api()
        execution.ready_event.set()
        execution.times.started_at = datetime.now(tz=timezone.utc)

        self._schedule_forget_on_stop(execution)

        if execution.mapped_ports:
            await execution.recreate_port_redirect_rules()

        self.executions[vm_id] = execution

    async def _handle_dead_controller(self, config: Configuration) -> None:
        """Stop the stale controller service for a VM that is no longer active.

        The orphan controller config is removed by _cleanup_orphan_resources
        once the VM is absent from self.executions.
        """
        service_name = f"aleph-vm-controller@{config.vm_hash}.service"
        try:
            self.systemd_manager.stop_and_disable(service_name)
            logger.info("Stopped and disabled stale controller service %s", service_name)
        except Exception:
            logger.warning("Failed to stop/disable stale controller %s", service_name, exc_info=True)

    def _cleanup_orphan_resources(
        self,
        protected_vm_ids: set[int] | None = None,
        protected_vm_hashes: set[str] | None = None,
    ):
        """Remove orphan nft rules, nft chains, tap interfaces, and controller configs.

        Compares host resources against active executions in the pool
        and removes anything that doesn't belong to a running VM.
        Fetches the nftables ruleset once and passes it to both nft cleanup methods.

        ``protected_vm_ids``/``protected_vm_hashes`` are VMs whose controllers
        are alive but which are not in ``self.executions`` (a reattach that
        failed): they are treated as active so the sweep does not stop their
        services, delete their configs, or tear down their networking.
        """
        active_vm_ids = {execution.vm_index for execution in self.executions.values() if execution.vm_index is not None}
        active_vm_hashes = {str(vm_id) for vm_id in self.executions}
        if protected_vm_ids:
            active_vm_ids |= protected_vm_ids
        if protected_vm_hashes:
            active_vm_hashes |= protected_vm_hashes

        nft_ruleset = get_existing_nftables_ruleset()
        self._cleanup_orphan_port_redirects(nft_ruleset)
        self._cleanup_orphan_nft_chains(active_vm_ids, nft_ruleset)
        self._cleanup_orphan_tap_interfaces(active_vm_ids)
        self._cleanup_orphan_controller_configs(active_vm_hashes)

    def _cleanup_orphan_controller_configs(self, active_vm_hashes: set[str]):
        """Stop controller services and delete controller configs for forgotten VMs.

        A VM removed from ``self.executions`` may leave behind:
          - A running ``aleph-vm-controller@<hash>.service`` with an active
            qemu process that still consumes host RAM the memory backstop
            does not see, so the host's real free memory is lower than
            ``_check_memory_backstop`` assumes.
          - A ``<hash>-controller.json`` file on disk that systemd would
            reuse on the next boot, reviving the orphan.

        Removing both keeps the host's actual free memory aligned with
        what the admission check computes.
        """
        try:
            config_files = list(settings.EXECUTION_ROOT.glob("*-controller.json"))
        except OSError:
            logger.warning("Failed to enumerate controller configs", exc_info=True)
            return

        removed = 0
        for config_path in config_files:
            vm_id = config_path.name[: -len("-controller.json")]
            if vm_id in active_vm_hashes:
                continue
            service_name = f"aleph-vm-controller@{vm_id}.service"
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
        """Remove per-VM nft chains whose vm_index is not in any active execution."""
        try:
            orphan_vm_ids = get_orphan_vm_chain_ids(active_vm_ids, nft_ruleset=nft_ruleset)
            for vm_index in orphan_vm_ids:
                try:
                    teardown_nftables_for_vm(vm_index)
                    logger.info("Removed orphan nft chains for vm_index=%d", vm_index)
                except Exception:
                    logger.warning("Failed to remove orphan nft chains for vm_index=%d", vm_index, exc_info=True)
        except Exception:
            logger.warning("Failed to query nftables for orphan chains", exc_info=True)

    def _cleanup_orphan_tap_interfaces(self, active_vm_ids: set[int]):
        """Remove vmtap interfaces whose vm_index is not in any active execution."""
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
        # Stop executions in parallel. return_exceptions=True ensures one
        # failing VM cleanup does not abort the rest, and does not propagate
        # a non-zero exit to systemd (which would trigger a restart loop).
        results = await asyncio.gather(
            *(execution.stop() for execution in self.get_ephemeral_executions()),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, BaseException):
                logger.warning(
                    "Error stopping execution during pool shutdown",
                    exc_info=(type(result), result, result.__traceback__),
                )

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

    def _check_memory_backstop(self, required_memory_mib: int) -> None:
        """Physical-memory invariant: committed plus requested must fit in
        physical memory minus the host reserve.

        No buckets, no overcommit factors: those are client (agent) policy.
        This only keeps the host itself alive. Called inside the create paths
        under ``creation_lock`` so the check and the registration are atomic.

        Raises:
            InsufficientResourcesError: the request would exceed physical
                memory; carries structured ``required`` / ``available`` dicts.
        """
        committed_memory_mib = sum(execution.allocated_memory_mib for execution in tuple(self.executions.values()))
        physical_memory_mib = psutil.virtual_memory().total // (1024 * 1024)
        memory_cap_mib = max(physical_memory_mib - settings.HOST_MEMORY_RESERVED_MIB, 0)
        if committed_memory_mib + required_memory_mib > memory_cap_mib:
            detail = (
                f"Insufficient memory to create VM: required {required_memory_mib} MiB, "
                f"committed {committed_memory_mib} MiB, cap {memory_cap_mib} MiB "
                f"(physical {physical_memory_mib} MiB, "
                f"host_reserved {settings.HOST_MEMORY_RESERVED_MIB} MiB)"
            )
            raise InsufficientResourcesError(
                detail,
                required={"memory_mib": required_memory_mib},
                available={"memory_mib": max(memory_cap_mib - committed_memory_mib, 0)},
            )

    def _validate_spec_gpus(self, requested: list[GpuSpec]) -> list[HostGPU]:
        """GPU attach invariant: every spec entry names a pci_host that exists
        in the host inventory and is not attached to any current execution.

        Which card serves which workload is the client's decision (the agent
        resolves device_ids to concrete cards in its own ledger); the
        supervisor only refuses impossible attachments. Called inside
        create_vm_from_spec under ``creation_lock`` so validation and the
        subsequent registration are atomic (no card is double-assigned).

        Raises:
            InsufficientResourcesError: a pci_host is unknown to the inventory
                or already attached to a VM (or claimed twice by this spec).
        """
        inventory = {gpu.pci_host: gpu for gpu in self.gpus}
        validated: list[HostGPU] = []
        claimed: set[str] = set()
        for request in requested:
            pci_host = str(request.pci_host)
            device = inventory.get(pci_host)
            if device is None:
                detail = f"No GPU at pci_host {pci_host!r} in the host inventory"
                logger.warning(detail)
                raise InsufficientResourcesError(
                    detail,
                    required={"gpu_pci_host": pci_host},
                    available={"gpus": [gpu.pci_host for gpu in self.get_available_gpus()]},
                )
            attached = any(execution.uses_gpu(pci_host) for execution in self.executions.values())
            if attached or pci_host in claimed:
                if pci_host in claimed:
                    detail = f"GPU at pci_host {pci_host!r} is claimed twice in this spec"
                else:
                    detail = f"GPU at pci_host {pci_host!r} is already attached to a VM"
                logger.warning(detail)
                raise InsufficientResourcesError(
                    detail,
                    required={"gpu_pci_host": pci_host},
                    available={"gpus": [gpu.pci_host for gpu in self.get_available_gpus()]},
                )
            claimed.add(pci_host)
            validated.append(
                HostGPU(
                    pci_host=device.pci_host,
                    supports_x_vga=device.has_x_vga_support,
                    device_id=device.device_id,
                    model=None,
                )
            )
        return validated
