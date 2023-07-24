import logging
from pathlib import Path
from typing import Optional

from aleph_message.models import ItemHash

from .conf import SnapshotCompressionAlgorithm
from .ipfs import (
    ipfs_remove_file,
    ipfs_upload_file,
    send_forget_ipfs_message,
    send_store_ipfs_message,
)
from .storage import compress_volume_snapshot, create_volume_snapshot

logger = logging.getLogger(__name__)


class DiskVolumeFile:
    path: Path
    size: int

    def __init__(self, path: Path):
        self.path = path
        self.size = path.stat().st_size


class CompressedDiskVolumeSnapshot(DiskVolumeFile):
    algorithm: SnapshotCompressionAlgorithm
    uploaded_item_hash: Optional[ItemHash]
    uploaded_ipfs_hash: Optional[str]

    def __init__(
        self,
        path: Path,
        algorithm: SnapshotCompressionAlgorithm,
        uploaded_item_hash: Optional[ItemHash] = None,
        uploaded_ipfs_hash: Optional[ItemHash] = None,
    ):
        super().__init__(path=path)
        self.algorithm = algorithm
        self.uploaded_item_hash = uploaded_item_hash
        self.uploaded_ipfs_hash = uploaded_ipfs_hash

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)

    async def upload(self, vm_hash: ItemHash) -> ItemHash:
        ref = f"snapshot_{vm_hash}"
        snapshot_hash = await ipfs_upload_file(self.path)
        self.uploaded_ipfs_hash = snapshot_hash
        snapshot_item_hash = await send_store_ipfs_message(snapshot_hash, ref)
        logger.debug(
            f"Uploaded snapshot to Aleph with message item_hash {snapshot_item_hash}"
        )
        self.uploaded_item_hash = snapshot_item_hash
        return snapshot_item_hash

    async def forget(self, reason: Optional[str] = "") -> None:
        assert (
            self.uploaded_item_hash and self.uploaded_ipfs_hash
        ), "CompressedDiskVolumeSnapshot item_hash or IPFS hash not available"

        logger.debug(
            f"Forgetting snapshot in Aleph with message item_hash {self.uploaded_item_hash}"
        )
        await send_forget_ipfs_message(item_hash=self.uploaded_item_hash, reason=reason)
        await ipfs_remove_file(self.path.name, self.uploaded_ipfs_hash)


class DiskVolumeSnapshot(DiskVolumeFile):
    compressed: Optional[CompressedDiskVolumeSnapshot]

    def delete(self) -> None:
        if self.compressed:
            self.compressed.delete()

        self.path.unlink(missing_ok=True)

    async def compress(
        self, algorithm: SnapshotCompressionAlgorithm
    ) -> CompressedDiskVolumeSnapshot:
        compressed_snapshot = await compress_volume_snapshot(self.path, algorithm)
        compressed = CompressedDiskVolumeSnapshot(
            path=compressed_snapshot, algorithm=algorithm
        )
        self.compressed = compressed
        return compressed


class DiskVolume(DiskVolumeFile):
    async def take_snapshot(self) -> DiskVolumeSnapshot:
        snapshot = await create_volume_snapshot(self.path)
        return DiskVolumeSnapshot(snapshot)
