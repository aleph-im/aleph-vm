import asyncio
import json
import logging
import math
import time
from typing import AsyncIterable, TypeVar

import aiohttp
import pydantic
from aiohttp import web
from yarl import URL

from aleph_message import Message
from aleph_message.models import BaseMessage, ProgramMessage
from .conf import settings
from .messages import load_updated_message
from .models import VmHash
from .pubsub import PubSub
from .reactor import Reactor

logger = logging.getLogger(__name__)

Value = TypeVar("Value")


async def retry_generator(
    generator: AsyncIterable[Value], max_seconds: int = 8
) -> AsyncIterable[Value]:
    retry_delay = 0.1
    while True:
        async for value in generator:
            yield value

        await asyncio.sleep(retry_delay)
        retry_delay = max(retry_delay * 2, max_seconds)


async def subscribe_via_ws(url) -> AsyncIterable[BaseMessage]:
    logger.debug("subscribe_via_ws()")
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url) as ws:
            logger.debug(f"Websocket connected on {url}")
            async for msg in ws:
                logger.debug(f"Websocket received data...")
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        # Patch data format to match HTTP GET format
                        data["_id"] = {"$oid": data["_id"]}
                    except json.JSONDecodeError:
                        logger.error(
                            f"Invalid JSON from websocket subscription {msg.data}",
                            exc_info=True,
                        )
                    try:
                        yield Message(**data)
                    except pydantic.error_wrappers.ValidationError as error:
                        logger.error(
                            f"Invalid Aleph message: \n  {error.json()}\n  {error.raw_errors}",
                            exc_info=True,
                        )
                        continue
                    except KeyError:
                        logger.exception(
                            f"Invalid Aleph message could not be parsed '{data}'",
                            exc_info=True,
                        )
                        continue
                    except Exception:
                        logger.exception(
                            f"Unknown error when parsing Aleph message {data}",
                            exc_info=True,
                        )
                        continue
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break


async def watch_for_messages(dispatcher: PubSub, reactor: Reactor):
    """Watch for new Aleph messages"""
    logger.debug("watch_for_messages()")
    url = URL(f"{settings.API_SERVER}/api/ws0/messages").with_query(
        {"startDate": math.floor(time.time())}
    )

    async for message in retry_generator(subscribe_via_ws(url)):
        logger.info(f"Websocket received message: {message.item_hash}")

        # Dispatch update to running VMs
        if hasattr(message.content, "ref") and message.content.ref:
            ref = message.content.ref
        else:
            ref = message.item_hash
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
        ref=VmHash("cad11970efe9b7478300fd04d7cc91c646ca0a792b9cc718650f86e1ccfac73e")
    )
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
