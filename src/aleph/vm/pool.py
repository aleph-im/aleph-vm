from __future__ import annotations

import asyncio
import logging
import shutil
from collections.abc import Iterable
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Any

import psutil

from aleph.vm.conf import settings
from aleph.vm.controllers.configuration import (
    Configuration,
    load_controller_configuration,
    save_controller_configuration,
)
from aleph.vm.controllers.firecracker.snapshot_manager import SnapshotManager
from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.orchestrator.metrics import get_port_mappings
from aleph.vm.orchestrator.utils import update_aggregate_settings
from aleph.vm.resources import (
    GpuDevice,
    HostGPU,
    InsufficientResourcesError,
    get_gpu_devices,
)
from aleph.vm.supervisor.errors import InvalidBackendError, VmAlreadyExistsError
from aleph.vm.supervisor.qemu_build import (
    build_qemu_confidential_configuration,
    build_qemu_configuration,
    spec_from_controller_configuration,
)
from aleph.vm.supervisor.types import Backend, CreateVmSpec, GpuSpec, PciAddress, VmId
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


class VmPool:
    """Pool of existing VMs

    For function VM we keep the VM a while after they  have run, so we can reuse them  and thus decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.
    """

    executions: dict[VmId, VmExecution]
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

    def check_capacity(self, *, memory_mib: int, vcpus: int, disk_mib: int, is_instance: bool) -> None:
        """Raise InsufficientResourcesError if these requirements exceed the host caps.

        The numbers-only core of capacity admission, reached via
        :meth:`check_spec_admission` (the spec path), which reduces its input to
        scalar requirements and delegates here. It is also reached by the reserve
        path, via :meth:`LocalSupervisor.reserve_resources`, which keeps the
        dry-run honest before holding GPUs.

        This is part of the pool's public contract: ``LocalSupervisor`` calls it
        cross-module against a message-free resources DTO.
        """
        required_memory_mib = memory_mib
        required_vcpus = vcpus
        required_disk_mib = disk_mib

        committed_instance_memory_mib = 0
        committed_program_memory_mib = 0
        committed_vcpus = 0
        for execution in tuple(self.executions.values()):
            memory = execution.allocated_memory_mib
            vcpus = execution.allocated_vcpus
            if not memory and not vcpus:
                continue
            if execution.is_instance:
                committed_instance_memory_mib += memory
            else:
                committed_program_memory_mib += memory
            committed_vcpus += vcpus

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

        if is_instance:
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

    def check_spec_admission(self, spec: CreateVmSpec) -> None:
        """Refuse a message-free CreateVmSpec when it would exceed host capacity.

        Built on the same two-bucket memory accounting and vCPU overcommit
        ceiling as :meth:`check_capacity`, but reads its requirements from the
        spec (``spec.memory_mib`` / ``spec.vcpus``). The bucket follows the
        spec backend: QEMU specs are instances (instance bucket), Firecracker
        specs are programs (program bucket), so a program routed through the
        spec path is not starved by the instance ceiling, which can be 0 on a
        small host with a large program reserve.

        Disk admission is deferred: ``DiskSpec`` carries no ``size_mib`` today,
        so there is nothing to sum against ``calculate_available_disk``. Revisit
        when the spec carries disk sizes.

        Called inside :meth:`create_vm_from_spec` under ``creation_lock`` so the
        check and the subsequent registration are atomic. Reading
        ``self.executions`` here is safe without locking because this method
        does not ``await``.

        Raises:
            InsufficientResourcesError: The memory or vCPU bucket would be
                exceeded; carries structured ``required`` / ``available`` dicts.
        """
        # QEMU specs are instances; Firecracker specs are programs.
        is_instance = spec.backend is not Backend.FIRECRACKER
        # Disk admission is deferred (DiskSpec has no size_mib today), so 0 is
        # passed: check_capacity's disk branch only fires for disk_mib > 0, so
        # the disk check is skipped and the structured dicts carry disk_mib 0,
        # exactly as the standalone spec check did.
        self.check_capacity(
            memory_mib=spec.memory_mib,
            vcpus=spec.vcpus,
            disk_mib=0,
            is_instance=is_instance,
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

    async def create_vm_from_spec(self, spec: CreateVmSpec) -> VmExecution:
        """Create a VM from a message-free CreateVmSpec.

        The supervisor's creation path: no Aleph message, no download. The
        spec carries resolved on-disk paths. The controller config is written
        by build_qemu_configuration (0.C), so the message-coupled
        vm.configure() is skipped (start(write_config=False)).
        """
        if spec.backend is Backend.FIRECRACKER:
            return await self._create_firecracker_from_spec(spec)

        vm_hash = spec.vm_id
        async with self.creation_lock:
            current_execution = self.executions.get(vm_hash)
            if current_execution and current_execution.is_running and not current_execution.is_stopping:
                self._require_same_spec(current_execution, spec)
                return current_execution

            # Authoritative capacity admission, folded into the create path so
            # the check and the registration below are atomic under the lock.
            self.check_spec_admission(spec)

            # GPU reservation, atomic with the registration below. The spec
            # carries GPU REQUESTS (device_id, empty pci_host); resolve each to
            # a concrete available host card and rewrite the spec with the
            # resolved pci_host so build_qemu_configuration / from_spec see it.
            # The engine
            # owns reservation handling end to end: it consumes this OWNER's own
            # reservation (spec.owner_address, made via reserve_resources) and
            # skips reservations still held by OTHER users.
            resolved_host_gpus: list[HostGPU] = []
            if spec.gpus:
                resolved_devices = self._resolve_spec_gpus(spec.gpus, owner=spec.owner_address)
                spec = replace(
                    spec,
                    gpus=[
                        GpuSpec(
                            pci_host=PciAddress(device.pci_host),
                            supports_x_vga=device.has_x_vga_support,
                            device_id=device.device_id,
                            model=device.model or "",
                        )
                        for device in resolved_devices
                    ],
                )
                resolved_host_gpus = [
                    HostGPU(
                        pci_host=device.pci_host,
                        supports_x_vga=device.has_x_vga_support,
                        device_id=device.device_id,
                        model=device.model,
                    )
                    for device in resolved_devices
                ]

            execution = VmExecution.from_spec(
                spec,
                snapshot_manager=self.snapshot_manager,
                systemd_manager=self.systemd_manager,
            )
            # Attach the resolved GPUs so uses_gpu() holds them against other
            # creates and _to_vm_info reports them, exactly like the message path.
            execution.gpus = resolved_host_gpus
            self.executions[vm_hash] = execution

            tap_interface = None
            vm_id = None
            try:
                await execution.prepare()  # builds resources from the spec; no download

                vm_id = self.get_unique_vm_id()

                if self.network:
                    tap_interface = await self.network.prepare_tap(vm_id, vm_hash, VmType.instance)
                    if self.network.interface_exists(vm_id):
                        await tap_interface.delete()
                    await self.network.create_tap(vm_id, tap_interface)

                # Confidential VMs get a QemuConfidentialVMConfiguration; the
                # GPU resolution above already rewrote spec.gpus with concrete
                # pci_hosts, so the confidential config carries the resolved
                # GPUs too. SAFETY-CRITICAL: a build failure (e.g. missing
                # firmware) propagates and aborts the create; we never fall back
                # to the plain QemuVMConfiguration, which would boot the VM
                # unprotected.
                if spec.tee is not None:
                    config = await build_qemu_confidential_configuration(spec, vm_id, tap_interface)
                else:
                    config = await build_qemu_configuration(spec, vm_id, tap_interface)
                save_controller_configuration(spec.vm_id, config)

                execution.create(vm_id=vm_id, tap_interface=tap_interface)
                # start(write_config=False): the controller config was just
                # written above. For a confidential VM, VmExecution.start leaves
                # it in awaiting_confidential_init (is_confidential is True, so
                # it does NOT enable_and_start the controller); the owner starts
                # it later via initialize_confidential.
                await execution.start(write_config=False)
                # Reuse persisted host ports across restarts. The agent then
                # reconciles the aggregate settings through add_port_forward,
                # which merges with these preloaded mappings.
                execution.mapped_ports = await get_port_mappings(vm_hash)
                if execution.mapped_ports:
                    await execution.recreate_port_redirect_rules()
            except Exception:
                if execution.vm:
                    await execution.vm.teardown()
                elif tap_interface and vm_id is not None:
                    teardown_nftables_for_vm(vm_id)
                    await tap_interface.delete()
                self.forget_vm(vm_hash)
                raise

            self._schedule_forget_on_stop(execution)
            return execution

    async def _create_firecracker_from_spec(self, spec: CreateVmSpec) -> VmExecution:
        """Message-free Firecracker boot.

        Boots the VM from the spec's resolved paths and, when the spec carries
        a guest channel, waits for the guest's ready signal as part of boot.
        The guest-level protocols spoken over the channel are the client's
        business (VmInfo.guest_channel_path). Capacity admission is enforced by
        the engine via check_spec_admission, atomically inside this create path.
        """
        if spec.guest_channel is None:
            # Firecracker VMs without a guest channel (full instances under
            # FC) have no spec-path boot flow yet; they keep the legacy path.
            msg = "Firecracker spec VMs require a guest_channel"
            raise InvalidBackendError(msg)

        vm_hash = spec.vm_id
        async with self.creation_lock:
            current_execution = self.executions.get(vm_hash)
            if current_execution and current_execution.is_running and not current_execution.is_stopping:
                self._require_same_spec(current_execution, spec)
                return current_execution

            # Authoritative capacity admission, atomic with the registration
            # below. GPU reservation stays on the message path (see the note in
            # create_vm_from_spec); spec programs carry no GPUs.
            self.check_spec_admission(spec)

            execution = VmExecution.from_spec(
                spec,
                snapshot_manager=self.snapshot_manager,
                systemd_manager=self.systemd_manager,
            )
            self.executions[vm_hash] = execution

            tap_interface = None
            vm_id = None
            try:
                await execution.prepare()  # resolves resources from the spec; no download

                vm_id = self.get_unique_vm_id()

                if self.network and spec.network.internet_access:
                    tap_interface = await self.network.prepare_tap(vm_id, vm_hash, VmType.microvm)
                    if self.network.interface_exists(vm_id):
                        await tap_interface.delete()
                    await self.network.create_tap(vm_id, tap_interface)

                execution.create(vm_id=vm_id, tap_interface=tap_interface)
                # start() boots the program: ephemeral programs run the VMM
                # directly and block through the init-ready handshake;
                # persistent programs save the controller config and boot under
                # systemd, then wait for init (VmExecution.start branches on
                # self.persistent).
                await execution.start()
            except Exception:
                if execution.vm:
                    await execution.vm.teardown()
                elif tap_interface and vm_id is not None:
                    teardown_nftables_for_vm(vm_id)
                    await tap_interface.delete()
                self.forget_vm(vm_hash)
                raise

            self._schedule_forget_on_stop(execution)
            return execution

    @staticmethod
    def _require_same_spec(current_execution: VmExecution, spec: CreateVmSpec) -> None:
        """CreateVm idempotency: a retry with the identical spec returns the
        live VM; a different spec for a live vm_id is a conflict (also covers
        colliding with a message-built execution, whose vm_spec is None)."""
        if current_execution.vm_spec != spec:
            msg = f"VM {spec.vm_id} already exists with a different spec"
            raise VmAlreadyExistsError(msg)

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

    def get_running_or_starting_vm(self, vm_hash: VmId) -> VmExecution | None:
        """Return a running VM or None."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running and not execution.is_stopping:
            return execution
        else:
            return None

    def get_running_vm(self, vm_hash: VmId) -> VmExecution | None:
        """Return a running VM or None."""
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running and not execution.is_stopping:
            return execution
        else:
            return None

    async def stop_vm(self, vm_hash: VmId) -> VmExecution | None:
        """Stop a VM."""
        execution = self.executions.get(vm_hash)
        if not execution:
            logger.info("stop_vm No execution found for %s", vm_hash)
            return None
        await execution.stop()
        return execution

    def forget_vm(self, vm_hash: VmId) -> None:
        """Remove a VM from the executions pool.

        Used after VM creation raised an error in order to completely
        forget about the execution and enforce a new execution when
        attempted again.
        """
        try:
            del self.executions[vm_hash]
        except KeyError:
            pass

    async def restart_persistent_vm(self, execution: VmExecution) -> None:
        """Re-register a stopped persistent VM and restart it via systemd.

        Re-registers the execution in the pool immediately (before any async
        work) so the periodic allocation loop cannot create a duplicate
        execution with a new vm_id.
        """
        execution.times.stopping_at = None
        execution.times.stopped_at = None
        execution.stop_event = asyncio.Event()
        self.executions[execution.vm_hash] = execution
        self._schedule_forget_on_stop(execution)

        if self.network and execution.vm:
            if not self.network.interface_exists(execution.vm.vm_id):
                await self.network.create_tap(execution.vm.vm_id, execution.vm.tap_interface)
            else:
                # Interface exists but nftables rules may have been flushed —
                # always re-apply them.
                setup_nftables_for_vm(execution.vm.vm_id, interface=execution.vm.tap_interface)
        self.systemd_manager.restart(execution.controller_service)
        # RestartUnit only queues a job: wait until the unit is confirmed
        # active (with the crash-loop re-check) so callers get a truthful
        # RUNNING status and a flapping controller fails the start loudly.
        await execution.wait_for_controller_ready()
        execution.times.started_at = datetime.now(tz=timezone.utc)
        # Reload port mappings from DB — stop() clears them in memory
        # but the DB retains them for persistent VMs.
        execution.mapped_ports = await get_port_mappings(execution.vm_hash)
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
            # Forget by identity, not by hash: the same vm_id may already be
            # a new execution (reboot and delete+create recreate it while
            # this task races the old stop); only this task's own execution
            # may be removed.
            if self.executions.get(execution.vm_hash) is execution:
                self.forget_vm(execution.vm_hash)

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
            vm_hash = config_path.name[: -len("-controller.json")]
            if VmId(vm_hash) in self.executions:
                continue
            config = load_controller_configuration(vm_hash)
            if config is None:
                continue
            configs.append(config)

        # Batch-fetch active states: 1 D-Bus ListUnits() call for all VMs.
        all_services = [f"aleph-vm-controller@{config.vm_hash}.service" for config in configs]
        service_active_states = self.systemd_manager.get_services_active_states(all_services)

        # Track claimed vm_ids to detect duplicates across configs. A stale
        # config can reuse a vm_id; only the first active one is restored to
        # avoid two VMs sharing a tap interface.
        claimed_vm_ids: set[int] = set()

        for config in configs:
            vm_hash = VmId(str(config.vm_hash))
            vm_id = config.vm_id
            service_name = f"aleph-vm-controller@{config.vm_hash}.service"
            is_active = service_active_states.get(service_name, False)

            if not is_active:
                await self._handle_dead_controller(config)
                continue

            if vm_id in claimed_vm_ids:
                logger.warning(
                    "Skipping reattach of %s: vm_id %d already claimed by another config",
                    vm_hash,
                    vm_id,
                )
                await self._handle_dead_controller(config)
                continue

            logger.info("Reattaching execution %s for VM %d", vm_hash, vm_id)
            claimed_vm_ids.add(vm_id)
            await self._restore_running_execution_from_config(config, vm_id, vm_hash)

        self._cleanup_orphan_resources()

        logger.info("Loaded %d executions", len(self.executions))

    async def _restore_network(self, vm_id: int, vm_hash: VmId) -> TapInterface | None:
        """Restore tap interface, NDP proxy, and nftables rules for a VM."""
        if not self.network:
            return None

        # Reattach is QEMU-instance only; the message is gone by design.
        vm_type = VmType.instance
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

    async def _restore_running_execution_from_config(self, config: Configuration, vm_id: int, vm_hash: VmId) -> None:
        """Rebuild in-memory state for a VM whose controller is still active.

        Sourced entirely from the on-disk controller config -- message-free.
        """
        spec = spec_from_controller_configuration(config)
        execution = VmExecution.from_spec(
            spec,
            snapshot_manager=self.snapshot_manager,
            systemd_manager=self.systemd_manager,
        )

        execution.mapped_ports = await get_port_mappings(vm_hash)
        logger.info("Loading existing mapped_ports %s", execution.mapped_ports)

        await execution.prepare()  # builds resources from the spec; no download
        tap_interface = await self._restore_network(vm_id, vm_hash)

        vm = execution.create(vm_id=vm_id, tap_interface=tap_interface, prepare=False)
        await vm.start_guest_api()
        execution.ready_event.set()
        execution.times.started_at = datetime.now(tz=timezone.utc)

        self._schedule_forget_on_stop(execution)

        if vm.support_snapshot and self.snapshot_manager:
            await self.snapshot_manager.start_for(vm=execution.vm)

        if execution.mapped_ports:
            await execution.recreate_port_redirect_rules()

        self.executions[vm_hash] = execution

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
            ``check_capacity`` assumes.
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

    def get_persistent_executions(
        self,
        running_states: dict[str, bool] | None = None,
    ) -> Iterable[VmExecution]:
        """Yield persistent executions that are currently running.

        Args:
            running_states: Optional pre-computed mapping of
                controller_service name -> active state (e.g. the result
                of ``SystemDManager.get_services_active_states()``). When
                provided, replaces the per-VM ``is_running`` D-Bus round-
                trip with a dict lookup. Callers iterating over many
                executions should pass this to avoid stalling the event
                loop, same shortcut used by ``load_persistent_executions``
                and ``get_executions_by_address``.
        """
        for _vm_hash, execution in self.executions.items():
            if not execution.persistent:
                continue
            if running_states is not None:
                is_running_now = running_states.get(execution.controller_service, False)
            else:
                is_running_now = execution.is_running
            if is_running_now:
                yield execution

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

    def get_valid_reservation(self, resource) -> Reservation | None:
        if resource in self.reservations and self.reservations[resource].is_expired():
            del self.reservations[resource]
        return self.reservations.get(resource)

    async def reserve_gpus(self, requested: list[GpuSpec], user: str) -> datetime:
        """Hold message-free GPU REQUESTS for ``user``, keyed by ``device_id``.

        The message-free twin of reserve_resources: each request matches an
        available card by device_id, skipping cards held
        by ANOTHER user. Atomic like the message path: cards are resolved first
        and committed to ``self.reservations`` only once every request is matched,
        so a partial request leaves no stray holds. Returns the reservation
        expiry."""
        expiration_date = datetime.now(tz=timezone.utc) + timedelta(seconds=60)
        if not requested:
            return expiration_date
        async with self.creation_lock:
            available_gpus = self.get_available_gpus()
            resolved: list[GpuDevice] = []
            for request in requested:
                for available_gpu in available_gpus:
                    if available_gpu.device_id != request.device_id:
                        continue
                    reservation = self.get_valid_reservation(available_gpu)
                    if reservation is not None and reservation.user != user:
                        continue
                    available_gpus.remove(available_gpu)
                    resolved.append(available_gpu)
                    break
                else:
                    raise InsufficientResourcesError(
                        f"No available GPU matching device_id {request.device_id!r}",
                        required={"gpu_device_id": request.device_id},
                        available={"gpus": [g.device_id for g in self.get_available_gpus()]},
                    )
            for gpu in resolved:
                self.reservations[gpu] = Reservation(user=user, expiration=expiration_date, resource=gpu)
        return expiration_date

    def _resolve_spec_gpus(self, requested: list[GpuSpec], *, owner: str = "") -> list[GpuDevice]:
        """Resolve message-free GPU REQUESTS to concrete available host cards.

        Matches
        each request by device_id against get_available_gpus() (cards not used by
        any current execution). The engine owns reservation handling end to end:
        a reservation held by THIS owner (``owner`` == spec.owner_address, made
        via the reserve_resources endpoint) is consumed - the card is taken and
        its reservation dropped - while a reservation held by ANOTHER user blocks
        the card. get_valid_reservation drops expired reservations as a side
        effect, so a stale hold never blocks a request.

        Called inside create_vm_from_spec under creation_lock so resolution and
        the subsequent registration are atomic (no card is double-assigned).

        Raises:
            InsufficientResourcesError: a requested device_id has no available
                host card free of another user's reservation.
        """
        available_gpus = self.get_available_gpus()
        resolved: list[GpuDevice] = []
        for request in requested:
            for available_gpu in available_gpus:
                if available_gpu.device_id != request.device_id:
                    continue
                reservation = self.get_valid_reservation(available_gpu)
                if reservation is not None and reservation.user != owner:
                    # Reserved by another user: not available to this owner.
                    continue
                if reservation is not None:
                    # This owner's own reservation: consume it.
                    del self.reservations[available_gpu]
                available_gpus.remove(available_gpu)
                resolved.append(available_gpu)
                break
            else:  # for-else: no match for this request
                detail = f"No available GPU matching device_id {request.device_id!r}"
                logger.warning(detail)
                raise InsufficientResourcesError(
                    detail,
                    required={"gpu_device_id": request.device_id},
                    available={"gpus": [gpu.device_id for gpu in self.get_available_gpus()]},
                )
        return resolved


class Reservation:
    def __init__(self, user, resource, expiration):
        self.user = user
        self.resource = resource
        self.expiration = expiration

    def is_expired(self):
        logger.info(f"{datetime.now(tz=timezone.utc)}, {datetime.now(tz=timezone.utc) > self.expiration}")
        return datetime.now(tz=timezone.utc) > self.expiration
