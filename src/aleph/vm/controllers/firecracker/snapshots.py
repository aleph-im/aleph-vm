import logging
from pathlib import Path
from typing import Optional

from aleph_message.models import ItemHash

from aleph.vm.conf import SnapshotCompressionAlgorithm
from aleph.vm.storage import compress_volume_snapshot, create_volume_snapshot

logger = logging.getLogger(__name__)


class DiskVolumeFile:
    path: Path
    size: int

    def __init__(self, path: Path):
        self.path = path
        self.size = path.stat().st_size


class CompressedDiskVolumeSnapshot(DiskVolumeFile):
    algorithm: SnapshotCompressionAlgorithm

    def __init__(self, path: Path, algorithm: SnapshotCompressionAlgorithm):
        super().__init__(path=path)
        self.algorithm = algorithm

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)

    async def upload(self) -> ItemHash:
        # TODO: Upload snapshots to Aleph Network
        pass


class DiskVolumeSnapshot(DiskVolumeFile):
    compressed: Optional[CompressedDiskVolumeSnapshot]

    def delete(self) -> None:
        if self.compressed:
            self.compressed.delete()

        self.path.unlink(missing_ok=True)

    async def compress(self, algorithm: SnapshotCompressionAlgorithm) -> CompressedDiskVolumeSnapshot:
        compressed_snapshot = await compress_volume_snapshot(self.path, algorithm)
        compressed = CompressedDiskVolumeSnapshot(path=compressed_snapshot, algorithm=algorithm)
        self.compressed = compressed
        return compressed


class DiskVolume(DiskVolumeFile):
    async def take_snapshot(self) -> DiskVolumeSnapshot:
        snapshot = await create_volume_snapshot(self.path)
        return DiskVolumeSnapshot(snapshot)
