import logging
from pathlib import Path
from typing import Optional

from aleph.sdk.chains.common import get_fallback_account
from aleph.sdk.client import AuthenticatedAlephClient
from aleph.sdk.types import StorageEnum
from aleph_message.models import ItemHash, StoreMessage
from aleph_message.status import MessageStatus

from .conf import SnapshotCompressionAlgorithm
from .storage import (
    compress_volume_snapshot,
    create_volume_snapshot,
    decompress_volume_snapshot,
)

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

    def __init__(
        self,
        path: Path,
        algorithm: SnapshotCompressionAlgorithm,
        uploaded_item_hash: Optional[ItemHash] = None,
    ):
        super().__init__(path=path)
        self.algorithm = algorithm
        self.uploaded_item_hash = uploaded_item_hash

    def delete(self) -> None:
        self.path.unlink(missing_ok=True)

    async def decompress(self, algorithm: SnapshotCompressionAlgorithm):
        decompressed_snapshot = await decompress_volume_snapshot(self.path, algorithm)
        decompressed = DiskVolumeSnapshot(path=decompressed_snapshot)
        return decompressed

    async def upload(self, vm_hash: ItemHash) -> ItemHash:
        account = get_fallback_account()
        async with AuthenticatedAlephClient(
            account=account, api_server="https://official.aleph.cloud"
        ) as client:
            message, status = await client.create_store(
                file_path=self.path,
                storage_engine=StorageEnum.ipfs,
                sync=True,
                ref=f"snapshot_{vm_hash}",
            )
            assert status == MessageStatus.PROCESSED
            self.uploaded_item_hash = message.item_hash
            return self.uploaded_item_hash

    async def forget(self) -> None:
        assert (
            self.uploaded_item_hash
        ), "CompressedDiskVolumeSnapshot item_hash not available"

        account = get_fallback_account()
        async with AuthenticatedAlephClient(
            account=account, api_server="https://official.aleph.cloud"
        ) as client:
            message, status = await client.forget(hashes=[self.uploaded_item_hash])
            assert status == MessageStatus.PROCESSED


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
