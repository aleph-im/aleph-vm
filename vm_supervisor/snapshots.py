import logging
from pathlib import Path
from typing import Optional

from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephClient
from aleph.sdk.types import StorageEnum
from aleph_message.models import ItemHash, StoreMessage
from aleph_message.status import MessageStatus

from .conf import SnapshotCompressionAlgorithm
from .messages import try_get_store_messages_sdk
from .storage import (
    get_data_path,
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
        pkey = get_fallback_private_key()
        account = ETHAccount(private_key=pkey)
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

        pkey = get_fallback_private_key()
        account = ETHAccount(private_key=pkey)
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


async def get_last_snapshot_by_ref(ref: str) -> Optional[DiskVolumeSnapshot]:
    messages = await try_get_store_messages_sdk(ref)
    if len(messages) == 0:
        return None

    message = messages.pop()
    compressed_snapshot_path = await get_data_path(message.item_hash)
    compressed_snapshot = CompressedDiskVolumeSnapshot(
        compressed_snapshot_path, SnapshotCompressionAlgorithm.gz
    )
    snapshot = await compressed_snapshot.decompress(
        SnapshotCompressionAlgorithm.gz
    )
    return snapshot

