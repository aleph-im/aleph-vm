import asyncio
import logging
import threading
from time import sleep
from typing import Optional

from aleph_message.models import ItemHash
from schedule import Job, Scheduler

from aleph.vm.conf import settings

from .executable import AlephFirecrackerExecutable
from .snapshots import CompressedDiskVolumeSnapshot

logger = logging.getLogger(__name__)


def wrap_async_snapshot(vm):
    asyncio.run(do_vm_snapshot(vm))


def run_threaded_snapshot(vm):
    job_thread = threading.Thread(target=wrap_async_snapshot, args=(vm,))
    job_thread.start()


async def do_vm_snapshot(vm: AlephFirecrackerExecutable) -> CompressedDiskVolumeSnapshot:
    try:
        logger.debug(f"Starting new snapshot for VM {vm.vm_hash}")
        assert vm, "VM execution not set"

        snapshot = await vm.create_snapshot()
        await snapshot.upload()

        logger.debug(f"New snapshots for VM {vm.vm_hash} created in {snapshot.path}")
        return snapshot
    except ValueError as error:
        msg = "Something failed taking an snapshot"
        raise ValueError(msg) from error


def infinite_run_scheduler_jobs(scheduler: Scheduler) -> None:
    while True:
        scheduler.run_pending()
        sleep(1)


class SnapshotExecution:
    vm_hash: ItemHash
    execution: AlephFirecrackerExecutable
    frequency: int
    _scheduler: Scheduler
    _job: Job

    def __init__(
        self,
        scheduler: Scheduler,
        vm_hash: ItemHash,
        execution: AlephFirecrackerExecutable,
        frequency: int,
    ):
        self.vm_hash = vm_hash
        self.execution = execution
        self.frequency = frequency
        self._scheduler = scheduler

    async def start(self) -> None:
        logger.debug(f"Starting snapshots for VM {self.vm_hash} every {self.frequency} minutes")
        job = self._scheduler.every(self.frequency).minutes.do(run_threaded_snapshot, self.execution)
        self._job = job

    async def stop(self) -> None:
        logger.debug(f"Stopping snapshots for VM {self.vm_hash}")
        self._scheduler.cancel_job(self._job)


class SnapshotManager:
    """
    Manage VM snapshots.
    """

    executions: dict[ItemHash, SnapshotExecution]
    _scheduler: Scheduler

    def __init__(self):
        self.executions = {}
        self._scheduler = Scheduler()

    def run_in_thread(self) -> None:
        job_thread = threading.Thread(
            target=infinite_run_scheduler_jobs,
            args=[self._scheduler],
            daemon=True,
            name="SnapshotManager",
        )
        job_thread.start()

    async def start_for(self, vm: AlephFirecrackerExecutable, frequency: Optional[int] = None) -> None:
        if not vm.support_snapshot:
            msg = "Snapshots are not implemented for programs."
            raise NotImplementedError(msg)

        default_frequency = frequency or settings.SNAPSHOT_FREQUENCY

        vm_hash = vm.vm_hash
        snapshot_execution = SnapshotExecution(
            scheduler=self._scheduler,
            vm_hash=vm_hash,
            execution=vm,
            frequency=default_frequency,
        )
        self.executions[vm_hash] = snapshot_execution
        await snapshot_execution.start()

    async def stop_for(self, vm_hash: ItemHash) -> None:
        try:
            snapshot_execution = self.executions.pop(vm_hash)
        except KeyError:
            logger.warning("Could not find snapshot task for instance %s", vm_hash)
            return

        await snapshot_execution.stop()

    async def stop_all(self) -> None:
        await asyncio.gather(*(self.stop_for(vm_hash) for vm_hash, execution in self.executions))
