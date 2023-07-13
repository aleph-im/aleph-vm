import logging
from schedule import Scheduler, Job
from pathlib import Path
from typing import Dict, Optional

from aleph_message.models import (
    ItemHash,
)

from .models import VmExecution

logger = logging.getLogger(__name__)


class SnapshotExecution:
    vm_hash: ItemHash
    execution: VmExecution
    frequency: int
    _scheduler: Scheduler
    _job: Job

    def __init__(
            self, vm_hash: ItemHash, execution: VmExecution, frequency: int
    ):
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

    async def _do_snapshot(self) -> Path:
        logger.debug(f"Starting new snapshot for VM {self.vm_hash}")
        snapshot = await self.execution.vm.create_snapshot()
        # TODO: Publish snapshot to IPFS and Aleph network
        logger.debug(f"New snapshots for VM {self.vm_hash} created in {snapshot}")
        return snapshot


class SnapshotManager:
    """
    Manage VM snapshots.
    """
    executions: Dict[ItemHash, SnapshotExecution]
    # Assumed a default snapshot frequency of 5 minutes
    default_snapshot_frequency: int = 5

    def __init__(self):
        self.executions = {}

    def start_for(self, execution: VmExecution, frequency: Optional[int] = None) -> None:
        if not execution.is_instance():
            raise

        if not frequency:
            frequency = self.default_snapshot_frequency

        vm_hash = execution.vm_hash
        snapshot_execution = SnapshotExecution(vm_hash=vm_hash, execution=execution, frequency=frequency)
        self.executions[vm_hash] = snapshot_execution

    def stop_for(self, vm_hash: ItemHash) -> None:
        if not self.executions[vm_hash]:
            raise ValueError(f"Snapshot execution not running for VM {vm_hash}")

        self.executions[vm_hash].stop()


