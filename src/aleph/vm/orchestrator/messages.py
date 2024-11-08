import asyncio
import copy

from aiohttp import ClientConnectorError, ClientResponseError, ClientSession
from aiohttp.web_exceptions import HTTPNotFound, HTTPServiceUnavailable
from aleph_message.models import ExecutableMessage, ItemHash, MessageType
from aleph_message.status import MessageStatus

from aleph.vm.conf import settings
from aleph.vm.storage import get_latest_amend, get_message


async def try_get_message(ref: str) -> ExecutableMessage:
    """Get the message or raise an aiohttp HTTP error"""
    try:
        return await get_message(ref)
    except ClientConnectorError as error:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable") from error
    except ClientResponseError as error:
        if error.status == HTTPNotFound.status_code:
            raise HTTPNotFound(reason="Hash not found", text=f"Hash not found: {ref}") from error
        else:
            raise


async def get_latest_ref(item_hash: str) -> str:
    try:
        return await get_latest_amend(item_hash)
    except ClientConnectorError as error:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable") from error
    except ClientResponseError as error:
        if error.status == HTTPNotFound.status_code:
            raise HTTPNotFound(reason="Hash not found", text=f"Hash not found: {item_hash}") from error
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
            *(update_with_latest_ref(volume) for volume in (message.content.volumes or [])),
        )
    else:
        assert message.type == MessageType.instance
        await asyncio.gather(
            update_with_latest_ref(message.content.rootfs.parent),
            *(update_with_latest_ref(volume) for volume in (message.content.volumes or [])),
        )


async def load_updated_message(
    ref: ItemHash,
) -> tuple[ExecutableMessage, ExecutableMessage]:
    original_message = await try_get_message(ref)
    message = copy.deepcopy(original_message)
    await update_message(message)
    return message, original_message


async def get_message_status(item_hash: ItemHash) -> MessageStatus:
    """
    Fetch the status of an execution from the reference API server.
    We use a normal API call to the CCN instead to use the connector because we want to get the updated status of the
    message and bypass the messages cache.
    """
    async with ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/messages/{item_hash}"
        resp = await session.get(url)
        # Raise an error if the request failed
        resp.raise_for_status()

        resp_data = await resp.json()
        return resp_data["status"]
