import asyncio
import copy
from typing import Tuple, List

from aiohttp import ClientConnectorError, ClientResponseError
from aiohttp.web_exceptions import HTTPNotFound, HTTPServiceUnavailable
from aleph.sdk.client import AlephClient
from aleph_message.models import StoreMessage, ExecutableMessage, ItemHash, MessageType

from .storage import get_latest_amend, get_message


async def try_get_message(ref: str) -> ExecutableMessage:
    """Get the message or raise an aiohttp HTTP error"""
    try:
        return await get_message(ref)
    except ClientConnectorError:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable")
    except ClientResponseError as error:
        if error.status == 404:
            raise HTTPNotFound(reason="Hash not found", text=f"Hash not found: {ref}")
        else:
            raise


async def get_latest_ref(item_hash: str) -> str:
    try:
        return await get_latest_amend(item_hash)
    except ClientConnectorError:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable")
    except ClientResponseError as error:
        if error.status == 404:
            raise HTTPNotFound(
                reason="Hash not found", text=f"Hash not found: {item_hash}"
            )
        else:
            raise


async def update_with_latest_ref(obj):
    """
    Update the reference `ref` inplace if a newer version is available.

    Useful to update references in parallel with asyncio.gather.
    """
    if hasattr(obj, "use_latest") and obj.use_latest:
        obj.ref = await get_latest_ref(obj.ref)
    else:
        return obj


async def update_message(message: ExecutableMessage):
    if message.type == MessageType.program:
        # Load amends
        await asyncio.gather(
            update_with_latest_ref(message.content.runtime),
            update_with_latest_ref(message.content.code),
            update_with_latest_ref(message.content.data),
            *(
                update_with_latest_ref(volume)
                for volume in (message.content.volumes or [])
            ),
        )
    else:
        assert message.type == MessageType.instance
        await asyncio.gather(
            update_with_latest_ref(message.content.rootfs.parent),
            *(
                update_with_latest_ref(volume)
                for volume in (message.content.volumes or [])
            ),
        )


async def load_updated_message(
    ref: ItemHash,
) -> Tuple[ExecutableMessage, ExecutableMessage]:
    original_message = await try_get_message(ref)
    message = copy.deepcopy(original_message)
    await update_message(message)
    return message, original_message


async def try_get_store_messages_sdk(ref: str) -> List[StoreMessage]:
    async with AlephClient(api_server="https://official.aleph.cloud") as client:
        response = await client.get_messages(
            message_type=MessageType.store,
            refs=ref,
        )
        return response.messages

