import asyncio
import logging
import uuid
from asyncio import Task
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional, Union

from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ItemHash,
    ProgramContent,
)
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import AlephFirecrackerExecutable
from aleph.vm.controllers.firecracker.instance import AlephInstanceResources
from aleph.vm.controllers.firecracker.program import (
    AlephFirecrackerProgram,
    AlephFirecrackerResources,
    AlephProgramResources,
)
from aleph.vm.controllers.interface import AlephVmControllerInterface
from aleph.vm.controllers.qemu.instance import AlephQemuInstance, AlephQemuResources
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.orchestrator.metrics import (
    ExecutionRecord,
    delete_record,
    save_execution_data,
    save_record,
)
from aleph.vm.orchestrator.pubsub import PubSub
from aleph.vm.orchestrator.vm import AlephFirecrackerInstance
from aleph.vm.utils import create_task_log_exceptions, dumps_for_json

if TYPE_CHECKING:
    from aleph.vm.controllers.firecracker.snapshot_manager import SnapshotManager
    from aleph.vm.systemd import SystemDManager

logger = logging.getLogger(__name__)


@dataclass
class VmExecutionTimes:
    defined_at: datetime
    preparing_at: Optional[datetime] = None
    prepared_at: Optional[datetime] = None
    starting_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    stopping_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None

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
    resources: Optional[AlephFirecrackerResources] = None
    vm: Optional[Union[AlephFirecrackerExecutable, AlephQemuInstance]] = None

    times: VmExecutionTimes

    ready_event: asyncio.Event
    concurrent_runs: int
    runs_done_event: asyncio.Event
    stop_pending_lock: asyncio.Lock
    stop_event: asyncio.Event
    expire_task: Optional[asyncio.Task] = None
    update_task: Optional[asyncio.Task] = None

    persistent: bool = False

    @property
    def is_running(self):
        return (
            self.times.starting_at and not self.times.stopping_at
            if not self.persistent
            else self.systemd_manager.is_service_active(self.controller_service)
        )

    @property
    def is_program(self):
        return isinstance(self.message, ProgramContent)

    @property
    def is_instance(self):
        return isinstance(self.message, InstanceContent)

    @property
    def hypervisor(self):
        # default to firecracker for retro compat
        return self.message.environment.hypervisor or HypervisorType.firecracker

    @property
    def becomes_ready(self):
        return self.ready_event.wait

    @property
    def vm_id(self) -> Optional[int]:
        return self.vm.vm_id if self.vm else None

    @property
    def controller_service(self) -> str:
        return f"aleph-vm-controller@{self.vm_hash}.service"

    def __init__(
        self,
        vm_hash: ItemHash,
        message: ExecutableContent,
        original: ExecutableContent,
        snapshot_manager: "SnapshotManager",
        systemd_manager: "SystemDManager",
        persistent: bool,
    ):
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

    def to_dict(self) -> dict:
        return {
            "is_running": self.is_running,
            **self.__dict__,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return dumps_for_json(self.to_dict(), indent=indent)

    async def prepare(self, download: bool = True):
        """Download VM required files"""
        async with self.preparation_pending_lock:
            if self.resources:
                # Already prepared
                return

            self.times.preparing_at = datetime.now(tz=timezone.utc)
            resources = None
            if self.is_program:
                resources = AlephProgramResources(self.message, namespace=self.vm_hash)
            elif self.is_instance:
                if self.hypervisor == HypervisorType.firecracker:
                    resources = AlephInstanceResources(self.message, namespace=self.vm_hash)
                elif self.hypervisor == HypervisorType.qemu:
                    resources = AlephQemuResources(self.message, namespace=self.vm_hash)

            if not resources:
                msg = "Unknown executable message type"
                raise ValueError(msg, repr(self.message))
            if download:
                await resources.download_all()
            self.times.prepared_at = datetime.now(tz=timezone.utc)
            self.resources = resources

    def create(
        self, vm_id: int, tap_interface: Optional[TapInterface] = None, prepare: bool = True
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
                raise Exception("Unknown VM")
        else:
            raise Exception("Unknown VM")

        return vm

    async def start(self):
        self.times.starting_at = datetime.now(tz=timezone.utc)

        try:
            await self.vm.setup()
            # Avoid VM start() method because it's only for ephemeral programs,
            # for persistent and instances we will use SystemD manager
            if not self.persistent:
                await self.vm.start()
            await self.vm.configure()
            await self.vm.start_guest_api()
            self.times.started_at = datetime.now(tz=timezone.utc)
            self.ready_event.set()
            await self.save()
        except Exception:
            await self.vm.teardown()
            raise

    async def wait_for_init(self):
        await self.vm.wait_for_init()

    def stop_after_timeout(self, timeout: float = 5.0) -> Optional[Task]:
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

    async def stop(self):
        """Stop the VM and release resources"""

        # Prevent concurrent calls to stop() using a Lock
        async with self.stop_pending_lock:
            if self.times.stopped_at is not None:
                logger.debug(f"VM={self.vm.vm_id} already stopped")
                return
            await self.all_runs_complete()
            self.times.stopping_at = datetime.now(tz=timezone.utc)
            await self.record_usage()
            await self.vm.teardown()
            self.times.stopped_at = datetime.now(tz=timezone.utc)
            self.cancel_expiration()
            self.cancel_update()

            if self.vm.support_snapshot:
                await self.snapshot_manager.stop_for(self.vm_hash)
            self.stop_event.set()

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
        pid_info = self.vm.to_dict()
        # Handle cases when the process cannot be accessed
        if not self.persistent and pid_info and pid_info.get("process"):
            await save_record(
                ExecutionRecord(
                    uuid=str(self.uuid),
                    vm_hash=self.vm_hash,
                    vm_id=self.vm_id,
                    time_defined=self.times.defined_at,
                    time_prepared=self.times.prepared_at,
                    time_started=self.times.started_at,
                    time_stopping=self.times.stopping_at,
                    cpu_time_user=pid_info["process"]["cpu_times"].user,
                    cpu_time_system=pid_info["process"]["cpu_times"].system,
                    io_read_count=pid_info["process"]["io_counters"][0],
                    io_write_count=pid_info["process"]["io_counters"][1],
                    io_read_bytes=pid_info["process"]["io_counters"][2],
                    io_write_bytes=pid_info["process"]["io_counters"][3],
                    vcpus=self.vm.hardware_resources.vcpus,
                    memory=self.vm.hardware_resources.memory,
                    network_tap=self.vm.tap_interface.device_name if self.vm.tap_interface else "",
                    message=self.message,
                    original_message=self.original,
                    persistent=self.persistent,
                )
            )
        else:
            # The process cannot be accessed, or it's a persistent VM.
            await save_record(
                ExecutionRecord(
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
                    message=self.message.json(),
                    original_message=self.original.json(),
                    persistent=self.persistent,
                )
            )

    async def record_usage(self):
        await delete_record(execution_uuid=str(self.uuid))
        if settings.EXECUTION_LOG_ENABLED:
            await save_execution_data(execution_uuid=self.uuid, execution_data=self.to_json())

    async def run_code(self, scope: Optional[dict] = None) -> bytes:
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
