import logging
from pathlib import Path
from typing import Dict, Optional

from aleph_message.models import ItemHash
from schedule import Job, Scheduler

from .conf import SnapshotCompressionAlgorithm, settings
from .models import VmExecution
from .storage import compress_volume_snapshot, create_volume_snapshot

logger = logging.getLogger(__name__)


class DiskVolumeFile:
    path: Path
    size_mib: int

    def __init__(self, path: Path):
        self.path = path
        self.size_mib = int(path.stat().st_size / 2**20)


class CompressedDiskVolumeSnapshot(DiskVolumeFile):
    algorithm: SnapshotCompressionAlgorithm

    def __init__(self, path: Path, algorithm: SnapshotCompressionAlgorithm):
        super().__init__(path=path)
        self.algorithm = algorithm


class DiskVolumeSnapshot(DiskVolumeFile):
    async def compress(
        self, algorithm: SnapshotCompressionAlgorithm
    ) -> CompressedDiskVolumeSnapshot:
        compressed_snapshot = await compress_volume_snapshot(self.path, algorithm)
        return CompressedDiskVolumeSnapshot(
            path=compressed_snapshot, algorithm=algorithm
        )


class DiskVolume(DiskVolumeFile):
    async def take_snapshot(self) -> DiskVolumeSnapshot:
        snapshot = await create_volume_snapshot(self.path)
        return DiskVolumeSnapshot(snapshot)


class SnapshotExecution:
    vm_hash: ItemHash
    execution: VmExecution
    frequency: int
    _scheduler: Scheduler
    _job: Job

    def __init__(self, vm_hash: ItemHash, execution: VmExecution, frequency: int):
        self.vm_hash = vm_hash
        self.execution = execution
        self.frequency = frequency
        self._scheduler = Scheduler()

    async def start(self) -> None:
        logger.debug(f"Starting snapshots for VM {self.vm_hash}")
        job = self._scheduler.every(self.frequency).minutes.do(self._do_snapshot)
        self._job = job

    async def stop(self) -> None:
        logger.debug(f"Stopping snapshots for VM {self.vm_hash}")
        self._scheduler.cancel_job(self._job)

    async def _do_snapshot(self) -> CompressedDiskVolumeSnapshot:
        try:
            logger.debug(f"Starting new snapshot for VM {self.vm_hash}")
            assert self.execution.vm, "VM execution not set"

            snapshot = await self.execution.vm.create_snapshot()
            # TODO: Publish snapshot to IPFS and Aleph network
            logger.debug(f"New snapshots for VM {self.vm_hash} created in {snapshot}")
            return snapshot
        except ValueError:
            raise ValueError("Something failed taking an snapshot")


class SnapshotManager:
    """
    Manage VM snapshots.
    """

    executions: Dict[ItemHash, SnapshotExecution]

    def __init__(self):
        self.executions = {}

    def start_for(
        self, execution: VmExecution, frequency: Optional[int] = None
    ) -> None:
        if not execution.is_instance():
            raise TypeError("VM execution should be an Instance only")

        if not frequency:
            frequency = settings.SNAPSHOT_FREQUENCY

        vm_hash = execution.vm_hash
        snapshot_execution = SnapshotExecution(
            vm_hash=vm_hash, execution=execution, frequency=frequency
        )
        self.executions[vm_hash] = snapshot_execution

    async def stop_for(self, vm_hash: ItemHash) -> None:
        if not self.executions[vm_hash]:
            raise ValueError(f"Snapshot execution not running for VM {vm_hash}")

        await self.executions[vm_hash].stop()
