import asyncio
import json
import logging
import math
import time
from typing import AsyncIterable

import aiohttp
import pydantic
from aiohttp import web
from yarl import URL

from aleph_message import Message
from aleph_message.models import BaseMessage
from .conf import settings
from .pubsub import PubSub

logger = logging.getLogger(__name__)


async def subscribe_via_ws(url) -> AsyncIterable[BaseMessage]:
    logger.debug("subscribe_via_ws()")
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url) as ws:
            logger.debug(f"Websocket connected on {url}")
            async for msg in ws:
                logger.debug(f"Websocket received data...")
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    # Patch data format to match HTTP GET format
                    data["_id"] = {"$oid": data["_id"]}
                    try:
                        yield Message(**data)
                    except pydantic.error_wrappers.ValidationError as error:
                        print(error.json())
                        print(error.raw_errors)
                        raise
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break


async def watch_for_messages(dispatcher: PubSub):
    """Watch for new Aleph messages"""
    logger.debug("watch_for_messages()")
    url = URL(f"{settings.API_SERVER}/api/ws0/messages").with_query(
        {"startDate": math.floor(time.time())}
    )

    async for message in subscribe_via_ws(url):
        logger.info(f"Websocket received message: {message.item_hash}")
        ref = (
            message.content.ref
            if hasattr(message.content, "ref")
            else message.item_hash
        )
        await dispatcher.publish(key=ref, value=message)


async def start_watch_for_messages_task(app: web.Application):
    logger.debug("start_watch_for_messages_task()")
    pubsub = PubSub()
    app["pubsub"] = pubsub
    app["messages_listener"] = asyncio.create_task(watch_for_messages(pubsub))


async def stop_watch_for_messages_task(app: web.Application):
    app["messages_listener"].cancel()
    await app["messages_listener"]
