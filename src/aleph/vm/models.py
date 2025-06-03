import asyncio
import json
import logging
import uuid
from asyncio import Task
from collections.abc import Callable, Coroutine
from dataclasses import dataclass
from datetime import datetime, timezone

from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ItemHash,
    ProgramContent,
)
from aleph_message.models.execution.environment import GpuProperties, HypervisorType
from pydantic.json import pydantic_encoder

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import AlephFirecrackerExecutable
from aleph.vm.controllers.firecracker.instance import AlephInstanceResources
from aleph.vm.controllers.firecracker.program import (
    AlephFirecrackerProgram,
    AlephProgramResources,
)
from aleph.vm.controllers.firecracker.snapshot_manager import SnapshotManager
from aleph.vm.controllers.interface import AlephVmControllerInterface
from aleph.vm.controllers.qemu.instance import AlephQemuInstance, AlephQemuResources
from aleph.vm.controllers.qemu_confidential.instance import (
    AlephQemuConfidentialInstance,
    AlephQemuConfidentialResources,
)
from aleph.vm.network.firewall import add_port_redirect_rule, remove_port_redirect_rule
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.network.port_availability_checker import get_available_host_port
from aleph.vm.orchestrator.metrics import (
    ExecutionRecord,
    delete_record,
    save_execution_data,
    save_record,
)
from aleph.vm.orchestrator.pubsub import PubSub
from aleph.vm.orchestrator.vm import AlephFirecrackerInstance
from aleph.vm.resources import GpuDevice, HostGPU
from aleph.vm.systemd import SystemDManager
from aleph.vm.utils import create_task_log_exceptions, dumps_for_json, is_pinging
from aleph.vm.utils.aggregate import get_user_settings

SUPPORTED_PROTOCOL_FOR_REDIRECT = ["udp", "tcp"]

logger = logging.getLogger(__name__)


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
    vm_hash: ItemHash
    original: ExecutableContent
    message: ExecutableContent
    resources: (
        AlephProgramResources | AlephInstanceResources | AlephQemuResources | AlephQemuConfidentialInstance | None
    ) = None
    vm: AlephFirecrackerExecutable | AlephQemuInstance | AlephQemuConfidentialInstance | None = None
    gpus: list[HostGPU] = []

    times: VmExecutionTimes

    ready_event: asyncio.Event
    concurrent_runs: int
    runs_done_event: asyncio.Event
    stop_pending_lock: asyncio.Lock
    stop_event: asyncio.Event
    expire_task: asyncio.Task | None = None
    update_task: asyncio.Task | None = None
    init_task: asyncio.Task | None

    snapshot_manager: SnapshotManager | None
    systemd_manager: SystemDManager | None

    persistent: bool = False
    mapped_ports: dict[int, dict]  # Port redirect to the VM
    record: ExecutionRecord | None = None

    async def fetch_port_redirect_config_and_setup(self):
        message = self.message
        try:
            port_forwarding_settings = await get_user_settings(message.address, "port-forwarding")
            ports_requests = port_forwarding_settings.get(self.vm_hash)

        except Exception:
            ports_requests = {}
            logger.exception("Could not fetch the port redirect settings for user")
        if not ports_requests:
            # FIXME DEBUG FOR NOW
            ports_requests = {22: {"tcp": True, "udp": False}}
        ports_requests = ports_requests or {}
        await self.update_port_redirects(ports_requests)

    async def update_port_redirects(self, requested_ports: dict[int, dict[str, bool]]):
        assert self.vm, "The VM attribute has to be set before calling update_port_redirects()"

        logger.info("Updating port redirect. Current %s, New %s", self.mapped_ports, requested_ports)
        redirect_to_remove = set(self.mapped_ports.keys()) - set(requested_ports.keys())
        redirect_to_add = set(requested_ports.keys()) - set(self.mapped_ports.keys())
        redirect_to_check = set(requested_ports.keys()).intersection(set(self.mapped_ports.keys()))
        interface = self.vm.tap_interface

        for vm_port in redirect_to_remove:
            current = self.mapped_ports[vm_port]
            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if current[protocol]:
                    host_port = current["host"]
                    remove_port_redirect_rule(interface, host_port, vm_port, protocol)
            del self.mapped_ports[vm_port]

        for vm_port in redirect_to_add:
            target = requested_ports[vm_port]
            host_port = get_available_host_port(start_port=25000)
            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if target[protocol]:
                    add_port_redirect_rule(interface, host_port, vm_port, protocol)
            self.mapped_ports[vm_port] = {"host": host_port, **target}

        for vm_port in redirect_to_check:
            current = self.mapped_ports[vm_port]
            target = requested_ports[vm_port]
            host_port = current["host"]
            for protocol in SUPPORTED_PROTOCOL_FOR_REDIRECT:
                if current[protocol] != target[protocol]:
                    if target[protocol]:
                        add_port_redirect_rule(interface, host_port, vm_port, protocol)
                    else:
                        remove_port_redirect_rule(interface, host_port, vm_port, protocol)
            self.mapped_ports[vm_port] = {"host": host_port, **target}

        # Save to DB
        if self.record:
            self.record.mapped_ports = self.mapped_ports
            await save_record(self.record)

    async def removed_all_ports_redirection(self):
        if not self.vm:
            return
        interface = self.vm.tap_interface
        # copy in a list since we modify dict during iteration
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
    def is_program(self) -> bool:
        return isinstance(self.message, ProgramContent)

    @property
    def is_instance(self) -> bool:
        return isinstance(self.message, InstanceContent)

    @property
    def is_confidential(self) -> bool:
        # FunctionEnvironment has no trusted_execution
        return True if getattr(self.message.environment, "trusted_execution", None) else False

    @property
    def hypervisor(self) -> HypervisorType:
        if self.is_program:
            return HypervisorType.firecracker

        # Hypervisor setting is only used for instances
        return self.message.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR

    @property
    def becomes_ready(self) -> Callable[[], Coroutine]:
        return self.ready_event.wait

    @property
    def vm_id(self) -> int | None:
        return self.vm.vm_id if self.vm else None

    @property
    def controller_service(self) -> str:
        return f"aleph-vm-controller@{self.vm_hash}.service"

    @property
    def uses_payment_stream(self) -> bool:
        return self.message.payment and self.message.payment.is_stream

    @property
    def has_resources(self) -> bool:
        assert self.vm, "The VM attribute has to be set before calling has_resources()"
        if isinstance(self.vm, AlephFirecrackerExecutable):
            assert self.hypervisor == HypervisorType.firecracker
            return self.vm.resources_path.exists()
        else:
            return True

    def __repr__(self):
        return f"<VMExecution {type(self.vm).__name__} {self.vm_hash} {self.times.started_at}>"

    def __init__(
        self,
        vm_hash: ItemHash,
        message: ExecutableContent,
        original: ExecutableContent,
        snapshot_manager: SnapshotManager | None,
        systemd_manager: SystemDManager | None,
        persistent: bool,
    ):
        self.init_task = None
        self.uuid = uuid.uuid1()  # uuid1() includes the hardware address and timestamp
        self.vm_hash = vm_hash
        self.message = message
        self.original = original
        self.times = VmExecutionTimes(defined_at=datetime.now(tz=timezone.utc))
        self.ready_event = asyncio.Event()
        self.concurrent_runs = 0
        self.runs_done_event = asyncio.Event()
        self.stop_event = asyncio.Event()  # triggered when the VM is stopped
        self.preparation_pending_lock = asyncio.Lock()
        self.stop_pending_lock = asyncio.Lock()
        self.snapshot_manager = snapshot_manager
        self.systemd_manager = systemd_manager
        self.persistent = persistent
        self.mapped_ports = {}

    def to_dict(self) -> dict:
        return {
            "is_running": self.is_running,
            **self.__dict__,
        }

    def to_json(self, indent: int | None = None) -> str:
        return dumps_for_json(self.to_dict(), indent=indent)

    async def prepare(self) -> None:
        """Download VM required files"""
        async with self.preparation_pending_lock:
            if self.resources:
                # Already prepared
                return

            self.times.preparing_at = datetime.now(tz=timezone.utc)
            resources: (
                AlephProgramResources | AlephInstanceResources | AlephQemuResources | AlephQemuConfidentialInstance
            )
            if self.is_program:
                resources = AlephProgramResources(self.message, namespace=self.vm_hash)
            elif self.is_instance:
                if self.hypervisor == HypervisorType.firecracker:
                    resources = AlephInstanceResources(self.message, namespace=self.vm_hash)
                elif self.hypervisor == HypervisorType.qemu:
                    if self.is_confidential:
                        resources = AlephQemuConfidentialResources(self.message, namespace=self.vm_hash)
                    else:
                        resources = AlephQemuResources(self.message, namespace=self.vm_hash)
                    resources.gpus = self.gpus
                else:
                    msg = f"Unknown hypervisor type {self.hypervisor}"
                    raise ValueError(msg)
            else:
                msg = "Unknown executable message type"
                raise ValueError(msg)

            if not resources:
                msg = "Unknown executable message type"
                raise ValueError(msg, repr(self.message))
            await resources.download_all()
            self.times.prepared_at = datetime.now(tz=timezone.utc)
            self.resources = resources

    def prepare_gpus(self, available_gpus: list[GpuDevice]) -> None:
        gpus: list[HostGPU] = []
        if self.message.requirements and self.message.requirements.gpu:
            for gpu in self.message.requirements.gpu:
                gpu = GpuProperties.model_validate(gpu)
                for available_gpu in available_gpus:
                    if available_gpu.device_id == gpu.device_id:
                        gpus.append(
                            HostGPU(
                                pci_host=available_gpu.pci_host,
                                supports_x_vga=available_gpu.has_x_vga_support,
                            )
                        )
                        break
        self.gpus = gpus

    def uses_gpu(self, pci_host: str) -> bool:
        for gpu in self.gpus:
            if gpu.pci_host == pci_host:
                return True

        return False

    def create(
        self, vm_id: int, tap_interface: TapInterface | None = None, prepare: bool = True
    ) -> AlephVmControllerInterface:
        if not self.resources:
            msg = "Execution resources must be configured first"
            raise ValueError(msg)

        vm: AlephVmControllerInterface
        if self.is_program:
            assert isinstance(self.resources, AlephProgramResources)
            self.vm = vm = AlephFirecrackerProgram(
                vm_id=vm_id,
                vm_hash=self.vm_hash,
                resources=self.resources,
                enable_networking=self.message.environment.internet,
                hardware_resources=self.message.resources,
                tap_interface=tap_interface,
                persistent=self.persistent,
                prepare_jailer=prepare,
            )
        elif self.is_instance:
            if self.hypervisor == HypervisorType.firecracker:
                assert isinstance(self.resources, AlephInstanceResources)
                self.vm = vm = AlephFirecrackerInstance(
                    vm_id=vm_id,
                    vm_hash=self.vm_hash,
                    resources=self.resources,
                    enable_networking=self.message.environment.internet,
                    hardware_resources=self.message.resources,
                    tap_interface=tap_interface,
                    prepare_jailer=prepare,
                )
            elif self.hypervisor == HypervisorType.qemu:
                if self.is_confidential:
                    assert isinstance(self.resources, AlephQemuConfidentialResources)
                    self.vm = vm = AlephQemuConfidentialInstance(
                        vm_id=vm_id,
                        vm_hash=self.vm_hash,
                        resources=self.resources,
                        enable_networking=self.message.environment.internet,
                        hardware_resources=self.message.resources,
                        tap_interface=tap_interface,
                    )
                else:
                    assert isinstance(self.resources, AlephQemuResources)
                    self.vm = vm = AlephQemuInstance(
                        vm_id=vm_id,
                        vm_hash=self.vm_hash,
                        resources=self.resources,
                        enable_networking=self.message.environment.internet,
                        hardware_resources=self.message.resources,
                        tap_interface=tap_interface,
                    )
            else:
                msg = "Unknown VM"
                raise Exception(msg)
        else:
            msg = "Unknown VM"
            raise Exception(msg)

        return vm

    async def start(self):
        assert self.vm, "The VM attribute has to be set before calling start()"

        self.times.starting_at = datetime.now(tz=timezone.utc)

        try:
            await self.vm.setup()
            # Avoid VM start() method because it's only for ephemeral programs,
            # for persistent and instances we will use SystemD manager
            if not self.persistent:
                await self.vm.start()
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
                else:
                    self.init_task = asyncio.create_task(self.non_blocking_wait_for_boot())

                if self.vm and self.vm.support_snapshot and self.snapshot_manager:
                    await self.snapshot_manager.start_for(vm=self.vm)
            else:
                self.times.started_at = datetime.now(tz=timezone.utc)
            self.ready_event.set()
            await self.save()
        except Exception:
            logger.exception("%s error during start, tearing down", self)
            await self.vm.teardown()
            await self.vm.stop_guest_api()
            raise

    async def wait_for_persistent_boot(self):
        """Determine if VM has booted by responding to ping and check if the process is still running"""
        assert self.vm
        assert self.vm.enable_networking and self.vm.tap_interface, f"Network not enabled for VM {self.vm.vm_id}"
        ip = self.vm.get_ip()
        if not ip:
            msg = "Host IP not available"
            raise ValueError(msg)

        ip = ip.split("/", 1)[0]
        max_attempt = 30
        timeout_seconds = 2
        attempt = 0
        while True:
            attempt += 1
            if attempt > max_attempt:
                logging.error("%s has not responded to ping after %s attempt", self, attempt)
                raise Exception("Max attempt")

            if not self.is_controller_running:
                logging.error("%s process stopped running while waiting for boot", self)
                raise Exception("Process is not running")
            if await is_pinging(ip, packets=1, timeout=timeout_seconds):
                break

    async def non_blocking_wait_for_boot(self):
        """Wait till the VM respond to ping and mark it as booted or not and clean up ressource if it fail

        Used for instances"""
        assert self.vm
        try:
            await self.wait_for_persistent_boot()
            logger.info("%s responded to ping. Marking it as started.", self)
            self.times.started_at = datetime.now(tz=timezone.utc)
            return True
            # await self.save()
        except Exception as e:
            logger.warning("%s failed to responded to ping or is not running, stopping it.: %s ", self, e)
            assert self.vm
            try:
                await self.stop()
            except Exception as f:
                logger.exception("%s failed to stop: %s", self, f)
            return False

    async def wait_for_init(self):
        assert self.vm, "The VM attribute has to be set before calling wait_for_init()"
        await self.vm.wait_for_init()

    def stop_after_timeout(self, timeout: float = 5.0) -> Task | None:
        if self.persistent:
            logger.debug("VM marked as long running. Ignoring timeout.")
            return None

        if self.expire_task:
            logger.debug("VM already has a timeout. Extending it.")
            self.expire_task.cancel()

        vm_id: str = str(self.vm.vm_id if self.vm else None)
        self.expire_task = create_task_log_exceptions(self.expire(timeout), name=f"expire {vm_id}")
        return self.expire_task

    async def expire(self, timeout: float) -> None:
        """Coroutine that will stop the VM after 'timeout' seconds."""
        await asyncio.sleep(timeout)
        assert self.times.started_at
        if self.times.stopping_at or self.times.stopped_at:
            return
        await self.stop()

    def cancel_expiration(self) -> bool:
        if self.expire_task:
            self.expire_task.cancel()
            return True
        else:
            return False

    def cancel_update(self) -> bool:
        if self.update_task:
            self.update_task.cancel()
            return True
        else:
            return False

    async def stop(self) -> None:
        """Stop the VM and release resources"""
        assert self.vm, "The VM attribute has to be set before calling stop()"
        logger.info("%s stopping", self)

        # Prevent concurrent calls to stop() using a Lock
        async with self.stop_pending_lock:
            if self.times.stopped_at is not None:
                logger.debug(f"VM={self.vm.vm_id} already stopped")
                return
            if self.persistent and self.systemd_manager:
                self.systemd_manager.stop_and_disable(self.controller_service)
            self.times.stopping_at = datetime.now(tz=timezone.utc)
            await self.all_runs_complete()
            await self.record_usage()
            await self.vm.teardown()
            await self.removed_all_ports_redirection()

            self.times.stopped_at = datetime.now(tz=timezone.utc)
            self.cancel_expiration()
            self.cancel_update()

            if self.vm.support_snapshot and self.snapshot_manager:
                await self.snapshot_manager.stop_for(self.vm_hash)
            self.stop_event.set()
            logger.info("%s stopped", self)

    def start_watching_for_updates(self, pubsub: PubSub):
        if not self.update_task:
            self.update_task = create_task_log_exceptions(self.watch_for_updates(pubsub=pubsub))

    async def watch_for_updates(self, pubsub: PubSub):
        if self.is_instance:
            await pubsub.msubscribe(
                *(volume.ref for volume in (self.original.volumes or []) if hasattr(volume, "ref")),
            )
        else:
            await pubsub.msubscribe(
                self.original.code.ref,
                self.original.runtime.ref,
                self.original.data.ref if self.original.data else None,
                *(volume.ref for volume in (self.original.volumes or []) if hasattr(volume, "ref")),
            )
        logger.debug("Update received, stopping VM...")
        await self.stop()

    async def all_runs_complete(self):
        """Wait for all runs to complete. Used in self.stop() to prevent interrupting a request."""
        if self.concurrent_runs == 0:
            logger.debug("Stop: clear, no run at the moment")
            return
        else:
            logger.debug("Stop: waiting for runs to complete...")
            await self.runs_done_event.wait()

    async def save(self):
        """Save to DB"""
        assert self.vm, "The VM attribute has to be set before calling save()"

        if not self.record:
            self.record = ExecutionRecord(
                uuid=str(self.uuid),
                vm_hash=self.vm_hash,
                vm_id=self.vm_id,
                time_defined=self.times.defined_at,
                time_prepared=self.times.prepared_at,
                time_started=self.times.started_at,
                time_stopping=self.times.stopping_at,
                cpu_time_user=None,
                cpu_time_system=None,
                io_read_count=None,
                io_write_count=None,
                io_read_bytes=None,
                io_write_bytes=None,
                vcpus=self.vm.hardware_resources.vcpus,
                memory=self.vm.hardware_resources.memory,
                message=self.message.model_dump_json(),
                original_message=self.original.model_dump_json(),
                persistent=self.persistent,
                gpus=json.dumps(self.gpus, default=pydantic_encoder),
            )
            pid_info = self.vm.to_dict() if self.vm else None
            # Handle cases when the process cannot be accessed
            if not self.persistent and pid_info and pid_info.get("process"):
                self.record.cpu_time_user = pid_info["process"]["cpu_times"].user
                self.record.cpu_time_system = pid_info["process"]["cpu_times"].system
                self.record.io_read_count = pid_info["process"]["io_counters"][0]
                self.record.io_write_count = pid_info["process"]["io_counters"][1]
                self.record.io_read_bytes = pid_info["process"]["io_counters"][2]
                self.record.io_write_bytes = pid_info["process"]["io_counters"][3]
        await save_record(self.record)

    async def record_usage(self):
        await delete_record(execution_uuid=str(self.uuid))
        if settings.EXECUTION_LOG_ENABLED:
            await save_execution_data(execution_uuid=self.uuid, execution_data=self.to_json())

    async def run_code(self, scope: dict | None = None) -> bytes:
        if not self.vm:
            msg = "The VM has not been created yet"
            raise ValueError(msg)

        if not self.is_program:
            msg = "Code can ony be run on programs"
            raise ValueError(msg)

        assert isinstance(self.vm, AlephFirecrackerProgram)

        self.concurrent_runs += 1
        self.runs_done_event.clear()
        try:
            return await self.vm.run_code(scope=scope)
        finally:
            self.concurrent_runs -= 1
            if self.concurrent_runs == 0:
                self.runs_done_event.set()
