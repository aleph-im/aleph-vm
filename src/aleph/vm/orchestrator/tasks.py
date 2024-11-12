import asyncio
import json
import logging
import math
import time
from collections.abc import AsyncIterable
from typing import TypeVar

import aiohttp
import pydantic
from pydantic import ValidationError
from aiohttp import web
from aleph_message.models import (
    AlephMessage,
    PaymentType,
    ProgramMessage,
    parse_message,
)
from aleph_message.status import MessageStatus
from yarl import URL

from aleph.vm.conf import settings
from aleph.vm.pool import VmPool
from aleph.vm.utils import create_task_log_exceptions

from .messages import get_message_status
from .payment import (
    compute_required_balance,
    compute_required_flow,
    fetch_balance_of_address,
    get_stream,
)
from .pubsub import PubSub
from .reactor import Reactor

logger = logging.getLogger(__name__)

Value = TypeVar("Value")


async def retry_generator(generator: AsyncIterable[Value], max_seconds: int = 8) -> AsyncIterable[Value]:
    retry_delay = 0.1
    while True:
        async for value in generator:
            yield value

        await asyncio.sleep(retry_delay)
        retry_delay = max(retry_delay * 2, max_seconds)


async def subscribe_via_ws(url) -> AsyncIterable[AlephMessage]:
    logger.debug("subscribe_via_ws()")
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url) as ws:
            logger.debug(f"Websocket connected on {url}")
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                    except json.JSONDecodeError:
                        logger.error(
                            f"Invalid JSON from websocket subscription {msg.data}",
                            exc_info=True,
                        )

                    # Chain confirmation messages are published in the WS subscription
                    # but do not contain the fields "item_type" or "content, hence they
                    # are not valid Messages.
                    if "item_type" not in data:
                        assert "content" not in data
                        assert "confirmation" in data
                        logger.info(f"Ignoring confirmation message '{data['item_hash']}'")
                        continue

                    try:
                        yield parse_message(data)
                    except pydantic.ValidationError as error:
                        item_hash = data.get("item_hash", "ITEM_HASH_NOT_FOUND")
                        logger.warning(
                            f"Invalid Aleph message: {item_hash} \n  {error.errors}",
                            exc_info=False,
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
    url = URL(f"{settings.API_SERVER}/api/ws0/messages").with_query({"startDate": math.floor(time.time())})

    async for message in retry_generator(subscribe_via_ws(url)):
        # Dispatch update to running VMs
        await dispatcher.publish(key=message.item_hash, value=message)
        if hasattr(message.content, "ref") and message.content.ref:
            await dispatcher.publish(key=message.content.ref, value=message)

        # Register new VM to run on future messages:
        if isinstance(message, ProgramMessage):
            if message.content.on.message:
                reactor.register(message)
        await reactor.trigger(message=message)


async def start_watch_for_messages_task(app: web.Application):
    logger.debug("start_watch_for_messages_task()")
    pubsub = PubSub()
    pool: VmPool = app["vm_pool"]
    reactor = Reactor(pubsub, pool)

    # Register an hardcoded initial program
    # TODO: Register all programs with subscriptions
    # sample_message, _ = await load_updated_message(
    #     ref=ItemHash("cad11970efe9b7478300fd04d7cc91c646ca0a792b9cc718650f86e1ccfac73e")
    # )
    # if isinstance(sample_message, ProgramMessage):
    #     assert sample_message.content.on.message, sample_message
    #     reactor.register(sample_message)

    app["pubsub"] = pubsub
    app["reactor"] = reactor
    app["messages_listener"] = create_task_log_exceptions(watch_for_messages(pubsub, reactor))


async def stop_watch_for_messages_task(app: web.Application):
    app["messages_listener"].cancel()
    try:
        await app["messages_listener"]
    except asyncio.CancelledError:
        logger.debug("Task messages_listener is cancelled now")


async def monitor_payments(app: web.Application):
    logger.debug("Monitoring balances")
    pool: VmPool = app["vm_pool"]
    while True:
        await asyncio.sleep(settings.PAYMENT_MONITOR_INTERVAL)

        # Check if the executions continues existing or are forgotten before checking the payment
        for vm_hash in list(pool.executions.keys()):
            message_status = await get_message_status(vm_hash)
            if message_status != MessageStatus.PROCESSED:
                logger.debug(f"Stopping {vm_hash} execution due to {message_status} message status")
                await pool.stop_vm(vm_hash)
                pool.forget_vm(vm_hash)

        # Check if the balance held in the wallet is sufficient holder tier resources (Not do it yet)
        for sender, chains in pool.get_executions_by_sender(payment_type=PaymentType.hold).items():
            for chain, executions in chains.items():
                executions = [execution for execution in executions if execution.is_confidential]
                balance = await fetch_balance_of_address(sender)

                # Stop executions until the required balance is reached
                required_balance = await compute_required_balance(executions)
                logger.debug(f"Required balance for Sender {sender} executions: {required_balance}")
                # Stop executions until the required balance is reached
                while executions and balance < (required_balance + settings.PAYMENT_BUFFER):
                    last_execution = executions.pop(-1)
                    logger.debug(f"Stopping {last_execution} due to insufficient balance")
                    await pool.stop_vm(last_execution.vm_hash)
                    required_balance = await compute_required_balance(executions)

        # Check if the balance held in the wallet is sufficient stream tier resources
        for sender, chains in pool.get_executions_by_sender(payment_type=PaymentType.superfluid).items():
            for chain, executions in chains.items():
                stream = await get_stream(sender=sender, receiver=settings.PAYMENT_RECEIVER_ADDRESS, chain=chain)
                logger.debug(
                    f"Get stream flow from Sender {sender} to Receiver {settings.PAYMENT_RECEIVER_ADDRESS} of {stream}"
                )

                required_stream = await compute_required_flow(executions)
                logger.debug(f"Required stream for Sender {sender} executions: {required_stream}")
                # Stop executions until the required stream is reached
                while (stream + settings.PAYMENT_BUFFER) < required_stream:
                    try:
                        last_execution = executions.pop(-1)
                    except IndexError:  # Empty list
                        logger.debug("No execution can be maintained due to insufficient stream")
                        break
                    logger.debug(f"Stopping {last_execution} due to insufficient stream")
                    await pool.stop_vm(last_execution.vm_hash)
                    required_stream = await compute_required_flow(executions)


async def start_payment_monitoring_task(app: web.Application):
    app["payments_monitor"] = create_task_log_exceptions(monitor_payments(app))


async def stop_balances_monitoring_task(app: web.Application):
    app["payments_monitor"].cancel()
    try:
        await app["payments_monitor"]
    except asyncio.CancelledError:
        logger.debug("Task payments_monitor is cancelled now")
