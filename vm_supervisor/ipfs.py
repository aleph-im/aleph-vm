import logging
from pathlib import Path
from typing import Optional

import aioipfs
from aleph.sdk.chains.common import get_fallback_private_key
from aleph.sdk.chains.ethereum import ETHAccount
from aleph.sdk.client import AuthenticatedAlephClient
from aleph.sdk.types import StorageEnum
from aleph_message.models import ItemHash
from aleph_message.status import MessageStatus

logger = logging.getLogger(__name__)


async def ipfs_upload_file(path: Path) -> str:
    """Push a file to the IPFS service."""
    # Use local ipfs node by default. TODO: Add a general setting to allow to customize it
    client = aioipfs.AsyncIPFS(host="localhost", port=5001)
    ipfs_hash = None
    async for added_file in client.add(str(path), recursive=True):
        ipfs_hash = added_file["Hash"]
        logger.debug(f"Pushed {path} file to IPFS with hash {ipfs_hash}")

    await client.close()
    assert ipfs_hash, "File not pinned on IPFS"

    return ipfs_hash


async def ipfs_remove_file(name: str, ipfs_hash: str) -> None:
    """Remove a file to the IPFS service."""
    # Use local ipfs node by default. TODO: Add a general setting to allow to customize it
    client = aioipfs.AsyncIPFS(host="localhost", port=5001)
    logger.debug(f"Removed {name} file to IPFS with hash {ipfs_hash}")
    await client.files.rm(name, recursive=True)
    await client.pin.rm(ipfs_hash, recursive=True)
    await client.close()


async def send_store_ipfs_message(file_hash: str, ref: str) -> ItemHash:
    pkey = get_fallback_private_key()
    account = ETHAccount(private_key=pkey)
    async with AuthenticatedAlephClient(
        account=account, api_server="https://official.aleph.cloud"
    ) as client:
        message, status = await client.create_store(
            file_hash=file_hash,
            storage_engine=StorageEnum.ipfs,
            ref=ref,
        )
        assert status != MessageStatus.REJECTED
        return message.item_hash


async def send_forget_ipfs_message(
    item_hash: ItemHash, reason: Optional[str] = ""
) -> None:
    pkey = get_fallback_private_key()
    account = ETHAccount(private_key=pkey)
    async with AuthenticatedAlephClient(
        account=account, api_server="https://official.aleph.cloud"
    ) as client:
        message, status = await client.forget(hashes=[item_hash], reason=reason)
        logger.debug(f"Forgetting status: {status}")
        assert status != MessageStatus.REJECTED
