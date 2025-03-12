import asyncio
import logging
import threading
from time import sleep

from aleph_message.models import ItemHash
from schedule import Job, Scheduler

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.snapshots import CompressedDiskVolumeSnapshot

logger = logging.getLogger(__name__)


def wrap_async_snapshot(vm):
    asyncio.run(do_vm_snapshot(vm))


def run_threaded_snapshot(vm):
    job_thread = threading.Thread(target=wrap_async_snapshot, args=(vm,))
    job_thread.start()


async def do_vm_snapshot(vm) -> CompressedDiskVolumeSnapshot:
    try:
        logger.debug(f"Starting new snapshot for QEMU VM {vm.vm_hash}")
        assert vm, "VM execution not set"

        snapshot = await vm.create_snapshot()
        logger.debug(f"New snapshot for QEMU VM {vm.vm_hash} created successfully")
        return snapshot
    except ValueError as error:
        msg = "Failed to create QEMU VM snapshot"
        raise ValueError(msg) from error


def infinite_run_scheduler_jobs(scheduler: Scheduler) -> None:
    while True:
        scheduler.run_pending()
        sleep(1)


class QemuSnapshotExecution:
    vm_hash: ItemHash
    execution: any  # AlephQemuInstance
    frequency: int
    _scheduler: Scheduler
    _job: Job

    def __init__(
        self,
        scheduler: Scheduler,
        vm_hash: ItemHash,
        execution,
        frequency: int,
    ):
        self.vm_hash = vm_hash
        self.execution = execution
        self.frequency = frequency
        self._scheduler = scheduler

    async def start(self) -> None:
        logger.debug(f"Starting QEMU snapshots for VM {self.vm_hash} every {self.frequency} minutes")
        job = self._scheduler.every(self.frequency).minutes.do(run_threaded_snapshot, self.execution)
        self._job = job

    async def stop(self) -> None:
        logger.debug(f"Stopping QEMU snapshots for VM {self.vm_hash}")
        self._scheduler.cancel_job(self._job)


class QemuSnapshotManager:
    """
    Manage QEMU VM snapshots.
    """

    executions: dict[ItemHash, QemuSnapshotExecution]
    _scheduler: Scheduler

    def __init__(self):
        self.executions = {}
        self._scheduler = Scheduler()

    def run_in_thread(self) -> None:
        job_thread = threading.Thread(
            target=infinite_run_scheduler_jobs,
            args=[self._scheduler],
            daemon=True,
            name="QemuSnapshotManager",
        )
        job_thread.start()

    async def start_for(self, vm, frequency: int | None = None) -> None:
        if not vm.support_snapshot:
            msg = "Snapshots are not supported for this VM type."
            raise NotImplementedError(msg)

        # Default to 10 minutes if not specified and settings value is 0
        default_frequency = frequency or settings.SNAPSHOT_FREQUENCY or 10

        vm_hash = vm.vm_hash
        snapshot_execution = QemuSnapshotExecution(
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
            logger.warning("Could not find snapshot task for QEMU instance %s", vm_hash)
            return

        await snapshot_execution.stop()

    async def stop_all(self) -> None:
        await asyncio.gather(*(self.stop_for(vm_hash) for vm_hash in list(self.executions.keys())))