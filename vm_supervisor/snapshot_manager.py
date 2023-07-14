import asyncio
import logging
import threading
from time import sleep
from typing import Dict, Optional

from aleph_message.models import ItemHash
from schedule import Job, Scheduler

from .conf import settings
from .models import VmExecution
from .snapshots import CompressedDiskVolumeSnapshot

logger = logging.getLogger(__name__)


def wrap_async_snapshot(execution):
    asyncio.run(do_execution_snapshot(execution))


def run_threaded_snapshot(execution):
    job_thread = threading.Thread(target=wrap_async_snapshot, args=(execution,))
    job_thread.start()


async def do_execution_snapshot(execution: VmExecution) -> CompressedDiskVolumeSnapshot:
    try:
        logger.debug(f"Starting new snapshot for VM {execution.vm_hash}")
        assert execution.vm, "VM execution not set"

        snapshot = await execution.vm.create_snapshot()
        await snapshot.upload(execution.vm_hash)

        logger.debug(
            f"New snapshots for VM {execution.vm_hash} created in {snapshot.path}"
        )
        return snapshot
    except ValueError:
        raise ValueError("Something failed taking an snapshot")


def infinite_run_scheduler_jobs(scheduler: Scheduler) -> None:
    while True:
        scheduler.run_pending()
        sleep(1)


class SnapshotExecution:
    vm_hash: ItemHash
    execution: VmExecution
    frequency: int
    _scheduler: Scheduler
    _job: Job

    def __init__(
        self,
        scheduler: Scheduler,
        vm_hash: ItemHash,
        execution: VmExecution,
        frequency: int,
    ):
        self.vm_hash = vm_hash
        self.execution = execution
        self.frequency = frequency
        self._scheduler = scheduler

    async def start(self) -> None:
        logger.debug(
            f"Starting snapshots for VM {self.vm_hash} every {self.frequency} minutes"
        )
        job = self._scheduler.every(self.frequency).minutes.do(
            run_threaded_snapshot, self.execution
        )
        self._job = job

    async def stop(self) -> None:
        logger.debug(f"Stopping snapshots for VM {self.vm_hash}")
        self._scheduler.cancel_job(self._job)


class SnapshotManager:
    """
    Manage VM snapshots.
    """

    executions: Dict[ItemHash, SnapshotExecution]
    _scheduler: Scheduler

    def __init__(self):
        self.executions = {}
        self._scheduler = Scheduler()

    def run_snapshots(self) -> None:
        job_thread = threading.Thread(
            target=infinite_run_scheduler_jobs,
            args=[self._scheduler],
            daemon=True,
            name="SnapshotManager",
        )
        job_thread.start()

    async def start_for(
        self, execution: VmExecution, frequency: Optional[int] = None
    ) -> None:
        if not execution.is_instance:
            raise TypeError("VM execution should be an Instance only")

        if not frequency:
            frequency = settings.SNAPSHOT_FREQUENCY

        vm_hash = execution.vm_hash
        snapshot_execution = SnapshotExecution(
            scheduler=self._scheduler,
            vm_hash=vm_hash,
            execution=execution,
            frequency=frequency,
        )
        self.executions[vm_hash] = snapshot_execution
        await snapshot_execution.start()

    async def stop_for(self, vm_hash: ItemHash) -> None:
        if not self.executions[vm_hash]:
            raise ValueError(f"Snapshot execution not running for VM {vm_hash}")

        await self.executions[vm_hash].stop()

    async def stop_all(self) -> None:
        await asyncio.gather(
            *(self.stop_for(vm_hash) for vm_hash, execution in self.executions)
        )
