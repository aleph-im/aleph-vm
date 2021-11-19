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
from aleph_message.models import BaseMessage, ProgramMessage
from .conf import settings
from .messages import load_updated_message
from .pubsub import PubSub
from .reactor import Reactor

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


async def watch_for_messages(dispatcher: PubSub, reactor: Reactor):
    """Watch for new Aleph messages"""
    logger.debug("watch_for_messages()")
    url = URL(f"{settings.API_SERVER}/api/ws0/messages").with_query(
        {"startDate": math.floor(time.time())}
    )

    async for message in subscribe_via_ws(url):
        logger.info(f"Websocket received message: {message.item_hash}")

        # Dispatch update to running VMs
        ref = (
            message.content.ref
            if hasattr(message.content, "ref")
            else message.item_hash
        )
        await dispatcher.publish(key=ref, value=message)

        # Register new VM to run on future messages:
        if isinstance(message, ProgramMessage):
            if message.content.on.message:
                reactor.register(message)
        await reactor.trigger(message=message)


async def start_watch_for_messages_task(app: web.Application):
    logger.debug("start_watch_for_messages_task()")
    pubsub = PubSub()
    reactor = Reactor(pubsub)

    # Register an hardcoded initial program
    # TODO: Register all programs with subscriptions
    sample_message, _ = await load_updated_message(
        ref="cad11970efe9b7478300fd04d7cc91c646ca0a792b9cc718650f86e1ccfac73e")
    assert sample_message.content.on.message, sample_message
    reactor.register(sample_message)

    app["pubsub"] = pubsub
    app["reactor"] = reactor
    app["messages_listener"] = asyncio.create_task(watch_for_messages(pubsub, reactor))


async def stop_watch_for_messages_task(app: web.Application):
    app["messages_listener"].cancel()
    try:
        await app["messages_listener"]
    except asyncio.CancelledError:
        logger.debug("Task messages_listener is cancelled now")
