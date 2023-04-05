import asyncio
import logging
import sys
import uuid
from asyncio import Task
from dataclasses import dataclass
from datetime import datetime
from typing import NewType, Optional, Dict

from aleph_message.models import ExecutableContent
from aleph_message.models.executable import MachineType

from .conf import settings
from .metrics import save_record, save_execution_data, ExecutionRecord
from .pubsub import PubSub
from .utils import dumps_for_json, create_task_log_exceptions
from .vm import AlephFirecrackerVM
from .vm.firecracker_microvm import AlephFirecrackerResources

logger = logging.getLogger(__name__)

VmHash = NewType("VmHash", str)

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
    vm_hash: VmHash
    original: ExecutableContent
    program: ExecutableContent
    resources: Optional[AlephFirecrackerResources] = None
    vm: Optional[AlephFirecrackerVM] = None

    times: VmExecutionTimes

    ready_event: asyncio.Event
    concurrent_runs: int
    runs_done_event: asyncio.Event
    expire_task: Optional[asyncio.Task] = None
    update_task: Optional[asyncio.Task] = None

    persistent: bool = False
    is_instance: bool = False

    @property
    def is_running(self):
        return self.times.starting_at and not self.times.stopping_at

    @property
    def becomes_ready(self):
        return self.ready_event.wait

    @property
    def vm_id(self) -> Optional[int]:
        return self.vm.vm_id if self.vm else None

    def __init__(
        self, vm_hash: VmHash, program: ExecutableContent, original: ExecutableContent
    ):
        self.uuid = uuid.uuid1()  # uuid1() includes the hardware address and timestamp
        self.vm_hash = vm_hash
        self.program = program
        self.original = original
        self.times = VmExecutionTimes(defined_at=datetime.now())
        self.ready_event = asyncio.Event()
        self.concurrent_runs = 0
        self.runs_done_event = asyncio.Event()
        self.is_instance = self.program.type == MachineType.vm_instance

    def to_dict(self) -> Dict:
        return {
            "is_running": self.is_running,
            **self.__dict__,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        return dumps_for_json(self.to_dict(), indent=indent)

    async def prepare(self):
        """Download VM required files"""
        self.times.preparing_at = datetime.now()
        resources = AlephFirecrackerResources(self.program, namespace=self.vm_hash)
        await resources.download_all()
        self.times.prepared_at = datetime.now()
        self.resources = resources

    async def create(self, vm_id: int) -> AlephFirecrackerVM:
        if not self.resources:
            raise ValueError("Execution resources must be configured first")
        self.times.starting_at = datetime.now()
        self.vm = vm = AlephFirecrackerVM(
            vm_id=vm_id,
            vm_hash=self.vm_hash,
            resources=self.resources,
            enable_networking=self.program.environment.internet,
            hardware_resources=self.program.resources,
            is_instance=self.is_instance,
        )
        try:
            await vm.setup()
            await vm.start()
            await vm.configure()
            await vm.start_guest_api()
            self.times.started_at = datetime.now()
            self.ready_event.set()
            return vm
        except Exception:
            await vm.teardown()
            raise

    def stop_after_timeout(self, timeout: float = 5.0) -> Optional[Task]:
        if self.persistent:
            logger.debug("VM marked as long running. Ignoring timeout.")
            return

        if self.expire_task:
            logger.debug("VM already has a timeout. Extending it.")
            self.expire_task.cancel()

        if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
            # Task can be named
            vm_id: str = str(self.vm.vm_id if self.vm else None)
            self.expire_task = create_task_log_exceptions(
                self.expire(timeout), name=f"expire {vm_id}"
            )
        else:
            self.expire_task = create_task_log_exceptions(self.expire(timeout))
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
        if self.times.stopped_at is not None:
            logger.debug(f"VM={self.vm.vm_id} already stopped")
            return
        await self.all_runs_complete()
        self.times.stopping_at = datetime.now()
        await self.record_usage()
        await self.vm.teardown()
        self.times.stopped_at = datetime.now()
        self.cancel_expiration()
        self.cancel_update()

    def start_watching_for_updates(self, pubsub: PubSub):
        if not self.update_task:
            self.update_task = create_task_log_exceptions(
                self.watch_for_updates(pubsub=pubsub)
            )

    async def watch_for_updates(self, pubsub: PubSub):
        if self.is_instance:
            await pubsub.msubscribe(
                self.original.rootfs.ref,
                self.original.data.ref if self.original.data else None,
                *(
                    volume.ref
                    for volume in (self.original.volumes or [])
                    if hasattr(volume, "ref")
                ),
            )
        else:
            await pubsub.msubscribe(
                self.original.code.ref,
                self.original.runtime.ref,
                self.original.data.ref if self.original.data else None,
                *(
                    volume.ref
                    for volume in (self.original.volumes or [])
                    if hasattr(volume, "ref")
                ),
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

    async def record_usage(self):
        if settings.EXECUTION_LOG_ENABLED:
            await save_execution_data(
                execution_uuid=self.uuid, execution_data=self.to_json()
            )
        pid_info = self.vm.to_dict()
        # Handle cases when the process cannot be accessed
        if pid_info and pid_info.get("process"):
            await save_record(
                ExecutionRecord(
                    uuid=str(self.uuid),
                    vm_hash=self.vm_hash,
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
                    network_tap=self.vm.fvm.network_tap,
                )
            )
        else:
            # The process cannot be accessed. It has probably already exited
            # and its metrics are not available anymore.
            await save_record(
                ExecutionRecord(
                    uuid=str(self.uuid),
                    vm_hash=self.vm_hash,
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
                    network_tap=self.vm.fvm.network_tap,
                )
            )

    async def run_code(self, scope: dict = None) -> bytes:
        if not self.vm:
            raise ValueError("The VM has not been created yet")
        self.concurrent_runs += 1
        self.runs_done_event.clear()
        try:
            return await self.vm.run_code(scope=scope)
        finally:
            self.concurrent_runs -= 1
            if self.concurrent_runs == 0:
                self.runs_done_event.set()
