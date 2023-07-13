import logging
from pathlib import Path

from .conf import SnapshotCompressionAlgorithm
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
