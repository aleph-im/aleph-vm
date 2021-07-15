import asyncio
import logging
import sys
from asyncio import Task
from dataclasses import dataclass
from datetime import datetime
from typing import NewType, Optional, Dict

from aleph_message.models import ProgramContent
from .pubsub import PubSub
from .vm import AlephFirecrackerVM
from .vm.firecracker_microvm import AlephFirecrackerResources

logger = logging.getLogger(__name__)

VmHash = NewType("VmHash", str)


@dataclass
class VmExecutionTimes:
    defined_at: datetime = None
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

    vm_hash: VmHash
    original: ProgramContent
    program: ProgramContent
    resources: Optional[AlephFirecrackerResources]
    vm: AlephFirecrackerVM = None

    times: VmExecutionTimes

    ready_event: asyncio.Event = None
    concurrent_runs: int = None
    runs_done_event: asyncio.Event = None
    expire_task: Optional[asyncio.Task] = None

    @property
    def is_running(self):
        return self.times.starting_at and not (self.times.stopping_at)

    @property
    def becomes_ready(self):
        return self.ready_event.wait

    def __init__(self, vm_hash: VmHash, program: ProgramContent, original: ProgramContent):
        self.vm_hash = vm_hash
        self.program = program
        self.original = original
        self.times = VmExecutionTimes(defined_at=datetime.now())
        self.ready_event = asyncio.Event()
        self.concurrent_runs = 0
        self.runs_done_event = asyncio.Event()

    def to_dict(self) -> Dict:
        return {
            'is_running': self.is_running,
            **self.__dict__,
        }

    async def prepare(self):
        """Download VM required files"""
        self.times.preparing_at = datetime.now()
        resources = AlephFirecrackerResources(self.program, namespace=self.vm_hash)
        await resources.download_all()
        self.times.prepared_at = datetime.now()
        self.resources = resources

    async def create(self, address: int) -> AlephFirecrackerVM:
        self.times.starting_at = datetime.now()
        self.vm = vm = AlephFirecrackerVM(
            vm_id=address,
            vm_hash=self.vm_hash,
            resources=self.resources,
            enable_networking=self.program.environment.internet,
            hardware_resources=self.program.resources,
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

    def stop_after_timeout(self, timeout: float = 5.0) -> Task:
        if self.expire_task:
            logger.debug("VM already has a timeout. Extending it.")
            self.expire_task.cancel()

        loop = asyncio.get_event_loop()
        if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
            # Task can be named
            self.expire_task = loop.create_task(self.expire(timeout),
                                                name=f"expire {self.vm.vm_id}")
        else:
            self.expire_task = loop.create_task(self.expire(timeout))
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

    async def stop(self):
        await self.all_runs_complete()
        self.times.stopping_at = datetime.now()
        await self.vm.teardown()
        self.times.stopped_at = datetime.now()

    def start_watching_for_updates(self, pubsub: PubSub):
        pool = asyncio.get_running_loop()
        pool.create_task(self.watch_for_updates(pubsub=pubsub))

    async def watch_for_updates(self, pubsub: PubSub):
        await pubsub.msubscibe(
            self.original.code.ref,
            self.original.runtime.ref,
            self.original.data.ref if self.original.data else None,
            *(
                volume.ref
                for volume in (self.original.volumes or [])
                if hasattr(volume, 'ref')
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

    async def run_code(self, scope: dict = None):
        self.concurrent_runs += 1
        self.runs_done_event.clear()
        try:
            return await self.vm.run_code(scope=scope)
        finally:
            self.concurrent_runs -= 1
            if self.concurrent_runs == 0:
                self.runs_done_event.set()
