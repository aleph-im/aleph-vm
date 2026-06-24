import asyncio
import logging
import uuid
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

from aleph.vm.agent.metrics import save_execution_data
from aleph.vm.conf import settings
from aleph.vm.network.firewall import (
    add_entities_if_not_present,
    add_port_redirect_rule,
    build_port_redirect_entities,
    check_port_redirect_exists,
    execute_json_nft_commands,
    get_existing_nftables_ruleset,
    get_table_for_hook,
    remove_port_redirect_rule,
)
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.network.port_availability_checker import (
    fast_get_available_host_port,
    is_host_port_available,
)
from aleph.vm.resources import HostGPU
from aleph.vm.supervisor.controllers.firecracker.executable import (
    AlephFirecrackerExecutable,
)
from aleph.vm.supervisor.controllers.firecracker.program import AlephProgramResources
from aleph.vm.supervisor.controllers.firecracker.snapshot_manager import SnapshotManager
from aleph.vm.supervisor.controllers.firecracker.spec_program import (
    SpecFirecrackerProgram,
    SpecProgramResources,
)
from aleph.vm.supervisor.controllers.interface import AlephVmControllerInterface
from aleph.vm.supervisor.controllers.qemu.instance import (
    AlephQemuInstance,
    AlephQemuResources,
)
from aleph.vm.supervisor.controllers.qemu_confidential.instance import (
    AlephQemuConfidentialInstance,
    AlephQemuConfidentialResources,
)
from aleph.vm.supervisor.networking_db import delete_port_mappings, save_port_mappings
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    HardwareResources,
    VmId,
)
from aleph.vm.systemd import SystemDManager
from aleph.vm.utils import dumps_for_json

SUPPORTED_PROTOCOL_FOR_REDIRECT = ["udp", "tcp"]

logger = logging.getLogger(__name__)


class MigrationState(str, Enum):
    """State of VM migration process. Source-side states begin with EXPORT_, destination-side with IMPORT_."""

    NONE = "none"
    EXPORTING = "exporting"
    EXPORTED = "exported"
    EXPORT_FAILED = "export_failed"
    IMPORTING = "importing"
    IMPORTED = "imported"
    IMPORT_FAILED = "import_failed"


@dataclass
class VmExecutionTimes:
    defined_at: datetime
    preparing_at: datetime | None = None
    prepared_at: datetime | None = None
    starting_at: datetime | None = None
    started_at: datetime | None = None
    stopping_at: datetime | None = None
    stopped_at: datetime | None = None

    def to_dict(self):
        return self.__dict__


class VmExecution:
    """
    Control the execution of a VM on a high level.

    Implementation agnostic (Firecracker, maybe WASM in the future, ...).
    """

    uuid: uuid.UUID  # Unique identifier of this execution
    vm_id: VmId
    # The message-free description this execution is built from.
    spec: CreateVmSpec
    resources: (
        AlephProgramResources | AlephQemuResources | AlephQemuConfidentialInstance | SpecProgramResources | None
    ) = None
    vm: AlephFirecrackerExecutable | AlephQemuInstance | AlephQemuConfidentialInstance | None = None
    gpus: list[HostGPU]

    times: VmExecutionTimes

    ready_event: asyncio.Event
    concurrent_runs: int
    runs_done_event: asyncio.Event
    stop_pending_lock: asyncio.Lock
    stop_event: asyncio.Event
    init_task: asyncio.Task | None
    _forget_task: asyncio.Task | None = None

    snapshot_manager: SnapshotManager | None
    systemd_manager: SystemDManager | None

    persistent: bool = False
    mapped_ports: dict[int, dict]  # Port redirect to the VM

    async def update_port_redirects(self, requested_ports: dict[int, dict[str, bool]]):
        assert self.vm, "The VM attribute has to be set before calling update_port_redirects()"

        logger.info("Updating port redirect. Current %s, New %s", self.mapped_ports, requested_ports)
        redirect_to_remove = set(self.mapped_ports.keys()) - set(requested_ports.keys())
        redirect_to_add = set(requested_ports.keys()) - set(self.mapped_ports.keys())
        redirect_to_check = set(requested_ports.keys()).intersection(set(self.mapped_ports.keys()))
        interface = self.vm.tap_interface
        changed = False

        for vm_port in redirect_to_remove:
            current = self.mapped_ports[vm_port]
            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if current[protocol]:
                    host_port = int(current["host"])
                    remove_port_redirect_rule(interface, host_port, vm_port, protocol)
            del self.mapped_ports[int(vm_port)]
            changed = True
        for vm_port in redirect_to_add:
            target = requested_ports[vm_port]
            host_port = fast_get_available_host_port()

            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if target[protocol]:
                    add_port_redirect_rule(self.vm.vm_index, interface, host_port, vm_port, protocol)
            self.mapped_ports[int(vm_port)] = {"host": host_port, **target}
            changed = True

        for vm_port in redirect_to_check:
            current = self.mapped_ports[vm_port]
            target = requested_ports[vm_port]
            host_port = int(current["host"])
            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if current[protocol] != target[protocol]:
                    if target[protocol]:
                        add_port_redirect_rule(self.vm.vm_index, interface, host_port, vm_port, protocol)
                    else:
                        remove_port_redirect_rule(interface, host_port, vm_port, protocol)
                    changed = True

            self.mapped_ports[int(vm_port)] = {"host": host_port, **target}

        # Persist port mappings to dedicated table if anything changed
        if changed:
            await save_port_mappings(self.vm_id, self.mapped_ports)

    async def recreate_port_redirect_rules(self) -> None:
        """Recreate nftables port redirect rules from saved mapped_ports after restart.

        This method is called during load_persistent_executions() to ensure that
        port redirect rules are properly restored after a software restart or host reboot.

        Fetches the nftables ruleset once, builds all missing rules, and submits
        them in a single batch to minimize subprocess calls.
        """
        if not self.mapped_ports:
            return

        assert self.vm, "The VM attribute has to be set before calling recreate_port_redirect_rules()"

        interface = self.vm.tap_interface
        vm_ip = str(interface.guest_ip.ip)
        port_changed = False
        ruleset = get_existing_nftables_ruleset()
        prerouting_table = get_table_for_hook("prerouting", nft_ruleset=ruleset)
        forward_table = get_table_for_hook("forward", nft_ruleset=ruleset)

        all_entities: list[dict] = []
        queued_rules: list[tuple[str, int, int]] = []

        for vm_port, mapping in list(self.mapped_ports.items()):
            host_port = int(mapping["host"])

            protocols_to_create = []
            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if not mapping.get(protocol):
                    continue

                if check_port_redirect_exists(host_port, vm_ip, vm_port, protocol, ruleset):
                    logger.debug(
                        "Port redirect rule already exists for %s:%d -> vm:%d, skipping", protocol, host_port, vm_port
                    )
                else:
                    protocols_to_create.append(protocol)

            if not protocols_to_create:
                continue

            if not is_host_port_available(host_port):
                new_host_port = fast_get_available_host_port()
                logger.warning(
                    "Port %d unavailable, reassigned to %d for vm:%d (%s)",
                    host_port,
                    new_host_port,
                    vm_port,
                    self.vm_id,
                )
                host_port = new_host_port
                mapping["host"] = new_host_port
                port_changed = True

            for protocol in protocols_to_create:
                all_entities += build_port_redirect_entities(
                    self.vm.vm_index,
                    interface,
                    host_port,
                    vm_port,
                    protocol,
                    prerouting_table,
                    forward_table,
                )
                queued_rules.append((protocol, host_port, vm_port))

        if all_entities:
            commands = add_entities_if_not_present(ruleset, all_entities)
            execute_json_nft_commands(commands)
            for protocol, host_port, vm_port in queued_rules:
                logger.info(
                    "Recreated port redirect rule: %s host:%d -> vm:%d for %s",
                    protocol,
                    host_port,
                    vm_port,
                    self.vm_id,
                )

        if port_changed:
            await save_port_mappings(self.vm_id, self.mapped_ports)

    async def removed_all_ports_redirection(self):
        if not self.vm:
            return
        interface = self.vm.tap_interface
        # copy in a list since we modify dict during iteration
        self.mapped_ports = {int(key): value for key, value in self.mapped_ports.items()}
        for vm_port, map_detail in list(self.mapped_ports.items()):
            host_port = map_detail["host"]
            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if map_detail[protocol]:
                    remove_port_redirect_rule(interface, host_port, vm_port, protocol)

            del self.mapped_ports[vm_port]

    @property
    def is_starting(self) -> bool:
        return bool(self.times.starting_at and not self.times.started_at and not self.times.stopping_at)

    @property
    def is_controller_running(self):
        return (
            self.systemd_manager.is_service_active(self.controller_service)
            if self.persistent and self.systemd_manager
            else None
        )

    @property
    def is_running(self) -> bool:
        return (
            self.systemd_manager.is_service_active(self.controller_service)
            if self.persistent and self.systemd_manager
            else bool(self.times.starting_at and not self.times.stopping_at)
        )

    @property
    def is_stopping(self) -> bool:
        return bool(self.times.stopping_at and not self.times.stopped_at)

    @property
    def vm_spec(self) -> CreateVmSpec:
        """The message-free CreateVmSpec this execution is built from."""
        return self.spec

    @property
    def is_program(self) -> bool:
        return self.spec.backend is Backend.FIRECRACKER

    @property
    def is_instance(self) -> bool:
        return self.spec.backend is Backend.QEMU

    @property
    def is_confidential(self) -> bool:
        return self.spec.tee is not None

    @property
    def is_awaiting_confidential_init(self) -> bool:
        """The confidential VM is created but waiting for its owner to upload the
        session certificates and start it via /control/machine/{ref}/confidential/initialize.

        The controller service is only started at that point, so the execution is
        neither starting nor running. It must not be treated as a dead execution:
        only the owner can start it, the orchestrator cannot."""
        return (
            self.is_confidential
            and self.persistent
            and bool(self.times.started_at and not self.times.stopping_at)
            and not self.is_running
        )

    @property
    def becomes_ready(self) -> Callable[[], Coroutine]:
        return self.ready_event.wait

    @property
    def vm_index(self) -> int | None:
        return self.vm.vm_index if self.vm else None

    @property
    def controller_service(self) -> str:
        return f"aleph-vm-controller@{self.vm_id}.service"

    @property
    def allocated_memory_mib(self) -> int:
        """Requested memory in MiB."""
        return self.spec.memory_mib

    @property
    def allocated_vcpus(self) -> int:
        """Requested vCPUs."""
        return self.spec.vcpus

    @property
    def has_resources(self) -> bool:
        assert self.vm, "The VM attribute has to be set before calling has_resources()"
        if isinstance(self.vm, AlephFirecrackerExecutable):
            return self.vm.resources_path.exists()
        else:
            return True

    def __repr__(self):
        return f"<VMExecution {type(self.vm).__name__} {self.vm_id} {self.times.started_at}>"

    def __init__(
        self,
        vm_id: VmId,
        vm_spec: CreateVmSpec,
        snapshot_manager: SnapshotManager | None = None,
        systemd_manager: SystemDManager | None = None,
        persistent: bool = False,
    ):
        self.init_task = None
        self.uuid = uuid.uuid1()  # uuid1() includes the hardware address and timestamp
        self.vm_id = vm_id
        self.spec = vm_spec
        self.times = VmExecutionTimes(defined_at=datetime.now(tz=timezone.utc))
        self.ready_event = asyncio.Event()
        self.concurrent_runs = 0
        self.runs_done_event = asyncio.Event()
        self.runs_done_event.set()  # 0 runs = all done
        self.stop_event = asyncio.Event()  # triggered when the VM is stopped
        self.preparation_pending_lock = asyncio.Lock()
        self.stop_pending_lock = asyncio.Lock()
        self.snapshot_manager = snapshot_manager
        self.systemd_manager = systemd_manager
        self.persistent = persistent
        self.mapped_ports = {}
        self.gpus = []

    @classmethod
    def from_spec(
        cls,
        spec: CreateVmSpec,
        *,
        snapshot_manager: SnapshotManager | None,
        systemd_manager: SystemDManager | None,
    ) -> "VmExecution":
        """Construct a message-free execution from a CreateVmSpec.

        The supervisor's machinery (prepare/create/start) reads only the spec.
        """
        return cls(
            vm_id=spec.vm_id,
            vm_spec=spec,
            snapshot_manager=snapshot_manager,
            systemd_manager=systemd_manager,
            persistent=spec.persistent,
        )

    def to_dict(self) -> dict:
        return {
            "is_running": self.is_running,
            **self.__dict__,
        }

    def to_json(self, indent: int | None = None) -> str:
        return dumps_for_json(self.to_dict(), indent=indent)

    async def prepare(self) -> None:
        """Build VM resources from the spec. No download (paths are resolved)."""
        async with self.preparation_pending_lock:
            if self.resources:
                # Already prepared
                return
            self.times.preparing_at = datetime.now(tz=timezone.utc)
            if self.spec.backend is Backend.FIRECRACKER:
                self.resources = SpecProgramResources.from_spec(self.spec)
            elif self.spec.tee is not None:
                self.resources = AlephQemuConfidentialResources.from_spec(self.spec, namespace=str(self.vm_id))
            else:
                self.resources = AlephQemuResources.from_spec(self.spec, namespace=str(self.vm_id))
            self.times.prepared_at = datetime.now(tz=timezone.utc)

    def uses_gpu(self, pci_host: str) -> bool:
        for gpu in self.gpus:
            if gpu.pci_host == pci_host:
                return True

        return False

    def create(
        self, vm_index: int, tap_interface: TapInterface | None = None, prepare: bool = True
    ) -> AlephVmControllerInterface:
        if not self.resources:
            msg = "Execution resources must be configured first"
            raise ValueError(msg)

        vm: AlephVmControllerInterface
        if self.spec.backend is Backend.FIRECRACKER:
            assert isinstance(self.resources, SpecProgramResources)
            self.vm = vm = SpecFirecrackerProgram(
                vm_index=vm_index,
                vm_hash=self.vm_id,
                spec=self.spec,
                resources=self.resources,
                tap_interface=tap_interface,
                prepare_jailer=prepare,
            )
            return vm
        hardware_resources = HardwareResources(vcpus=self.spec.vcpus, memory=self.spec.memory_mib)
        if self.spec.tee is not None:
            # Confidential spec launch: same controller object as the
            # plain instance path, with the SEV policy converted from the spec.
            # SAFETY-CRITICAL: never fall through to the plain AlephQemuInstance.
            assert isinstance(self.resources, AlephQemuConfidentialResources)
            self.vm = vm = AlephQemuConfidentialInstance(
                vm_index=vm_index,
                vm_hash=self.vm_id,
                resources=self.resources,
                enable_networking=self.spec.network.internet_access,
                confidential_policy=int(self.spec.tee.policy, 0),
                hardware_resources=hardware_resources,
                tap_interface=tap_interface,
            )
            return vm
        assert isinstance(self.resources, AlephQemuResources)
        self.vm = vm = AlephQemuInstance(
            vm_index=vm_index,
            vm_hash=self.vm_id,
            resources=self.resources,
            enable_networking=self.spec.network.internet_access,
            hardware_resources=hardware_resources,
            tap_interface=tap_interface,
        )
        return vm

    async def start(self, *, write_config: bool = True):
        assert self.vm, "The VM attribute has to be set before calling start()"

        self.times.starting_at = datetime.now(tz=timezone.utc)

        try:
            await self.vm.setup()
            # Avoid VM start() method because it's only for ephemeral programs,
            # for persistent and instances we will use SystemD manager
            if not self.persistent:
                await self.vm.start()

            if write_config:
                await self.vm.configure()

            await self.vm.start_guest_api()

            # Start VM and snapshots automatically
            # If the execution is a confidential instance, it is start later in the process when the session certificate
            # files are received from the client via the endpoint /control/machine/{ref}/confidential/initialize endpoint
            if self.persistent and not self.is_confidential and self.systemd_manager:
                await self.systemd_manager.enable_and_start(self.controller_service)

                if self.is_program:
                    await self.wait_for_init()
                    await self.vm.load_configuration()
                    self.times.started_at = datetime.now(tz=timezone.utc)
                elif not await self.non_blocking_wait_for_boot():
                    msg = f"{self} controller failed to start"
                    raise RuntimeError(msg)

                if self.vm and self.vm.support_snapshot and self.snapshot_manager:
                    await self.snapshot_manager.start_for(vm=self.vm)
            else:
                self.times.started_at = datetime.now(tz=timezone.utc)
            self.ready_event.set()
        except Exception:
            logger.exception("%s error during start, tearing down", self)
            if self.vm and not self.times.stopped_at:
                await self.vm.teardown()
                await self.vm.stop_guest_api()
            raise

    async def wait_for_controller_ready(self):
        """Wait until the systemd controller service is confirmed active.

        Unlike the previous ping-based check, this does not depend on
        ICMP being enabled inside the guest.  The controller service
        state is the only reliable indicator we control — if the
        controller service is active the VM is considered started.
        Guest-side issues (bad config, disabled networking) are the
        user's responsibility and visible via the logs endpoint.
        """
        if not self.persistent or not self.systemd_manager:
            msg = "wait_for_controller_ready requires a persistent VM with systemd_manager"
            raise RuntimeError(msg)

        max_attempt = 30
        for attempt in range(1, max_attempt + 1):
            state = self.systemd_manager.get_service_active_state(
                self.controller_service,
            )
            if state == "active":
                # A unit whose process dies right after start (e.g. qemu
                # refusing its arguments, with Restart=on-failure) samples
                # as "active" in the windows between crashes. Confirm the
                # unit stayed active before declaring the VM started.
                await asyncio.sleep(2)
                state = self.systemd_manager.get_service_active_state(
                    self.controller_service,
                )
                if state == "active":
                    return
                msg = f"{self} controller service went '{state}' right after starting (crash loop?)"
                raise RuntimeError(msg)
            if state == "failed":
                msg = f"{self} controller service entered 'failed' state"
                raise RuntimeError(msg)
            # "inactive" and "deactivating" are retried: the service is
            # legitimately inactive between StartUnit and systemd
            # transitioning to "activating", and "deactivating" may
            # appear if a conflicting job briefly stops the unit.
            # Both are covered by the timeout path below.

            logger.debug(
                "%s controller state=%s (attempt %d/%d)",
                self,
                state,
                attempt,
                max_attempt,
            )
            if attempt < max_attempt:
                await asyncio.sleep(2)

        msg = f"{self} controller service did not become active after {max_attempt} attempts"
        raise RuntimeError(msg)

    async def wait_for_controller_stopped(self) -> None:
        """Block until the controller unit has actually stopped.

        StopUnit only queues a job: the controller then shuts the guest
        down gracefully (ACPI powerdown, then QMP quit), which can take
        up to systemd's TimeoutStopSec (60s). Tearing down the TAP
        interface while qemu is still running makes its tap file
        descriptor go bad; qemu then aborts without flushing the disk,
        corrupting the rootfs.
        """
        if not self.systemd_manager:
            return
        # TimeoutStopSec is 60s, after which systemd SIGKILLs the
        # controller; poll a little past that before giving up.
        max_attempt = 75
        for attempt in range(1, max_attempt + 1):
            state = self.systemd_manager.get_service_active_state(self.controller_service)
            # "not-loaded" counts as stopped: systemd garbage-collects a
            # unit once it reaches a clean inactive state, so a 1s poll
            # can miss the brief "inactive" window entirely.
            if state in ("inactive", "failed", "not-loaded"):
                return
            logger.debug(
                "%s controller still '%s' while stopping (attempt %d/%d)",
                self,
                state,
                attempt,
                max_attempt,
            )
            await asyncio.sleep(1)
        logger.warning("%s controller did not stop after %ds, tearing down anyway", self, max_attempt)

    async def non_blocking_wait_for_boot(self):
        """Wait for the controller process and mark the instance as started.

        If the controller service never becomes active the instance is
        stopped and cleaned up.  Guest-level readiness (network, user
        applications) is not checked — the user can inspect logs if
        their OS fails to boot.
        """
        if not self.vm:
            msg = "non_blocking_wait_for_boot requires a VM to be set"
            raise RuntimeError(msg)
        try:
            await self.wait_for_controller_ready()
            logger.info("%s controller is running. Marking as started.", self)
            self.times.started_at = datetime.now(tz=timezone.utc)
            return True
        except Exception as e:
            logger.warning("%s controller not running, stopping: %s", self, e)
            try:
                await self.stop()
            except Exception as f:
                logger.exception("%s failed to stop: %s", self, f)
            return False

    async def wait_for_init(self):
        assert self.vm, "The VM attribute has to be set before calling wait_for_init()"
        await self.vm.wait_for_init()

    async def stop(self) -> None:
        """Stop the VM and release resources"""
        assert self.vm, "The VM attribute has to be set before calling stop()"
        logger.info("%s stopping", self)

        # Prevent concurrent calls to stop() using a Lock
        async with self.stop_pending_lock:
            if self.times.stopped_at is not None:
                logger.debug(f"VM={self.vm.vm_index} already stopped")
                return
            if self.persistent and self.systemd_manager:
                self.systemd_manager.stop_and_disable(self.controller_service)
                await self.wait_for_controller_stopped()
            self.times.stopping_at = datetime.now(tz=timezone.utc)
            await self.all_runs_complete()
            await self.record_usage()
            # First remove existing redirect rules for that VM
            await self.removed_all_ports_redirection()
            # After do the teardown
            await self.vm.teardown()

            self.times.stopped_at = datetime.now(tz=timezone.utc)

            if self.vm.support_snapshot and self.snapshot_manager:
                await self.snapshot_manager.stop_for(self.vm_id)
            self.stop_event.set()
            logger.info("%s stopped", self)

    async def all_runs_complete(self):
        """Wait for all runs to complete. Used in self.stop() to prevent interrupting a request."""
        if self.concurrent_runs == 0:
            logger.debug("Stop: clear, no run at the moment")
            return
        else:
            logger.debug("Stop: waiting for runs to complete...")
            await self.runs_done_event.wait()

    def erase_volumes(self, *, include_rootfs: bool = False, include_data_volumes: bool = True) -> int:
        """Delete this execution's on-disk volumes.

        Hypervisor mechanism behind Supervisor.delete_vm(wipe=...) and
        reinstall_vm(...). Returns the number of files deleted.
        """
        if self.resources is None:
            return 0
        deleted_count = 0
        if include_rootfs:
            rootfs = self.resources.rootfs_path
            if rootfs.exists():
                logger.info(f"Deleting rootfs {rootfs}")
                rootfs.unlink()
                deleted_count += 1
        if include_data_volumes:
            for volume in self.resources.volumes:
                if not volume.read_only:
                    logger.info(f"Deleting volume {volume.path_on_host}")
                    volume.path_on_host.unlink(missing_ok=True)
                    deleted_count += 1
        return deleted_count

    async def record_usage(self):
        # Non-persistent VMs won't restart, so clean up their port mappings
        if not self.persistent:
            await delete_port_mappings(self.vm_id)
        if settings.EXECUTION_LOG_ENABLED:
            await save_execution_data(execution_uuid=self.uuid, execution_data=self.to_json())
