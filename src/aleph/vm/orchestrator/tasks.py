import asyncio
import json
import logging
import math
import time
from collections.abc import AsyncIterable
from decimal import Decimal
from typing import TypeVar

import aiohttp
import pydantic
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
from aleph.vm.orchestrator.utils import (
    format_cost,
    get_community_wallet_address,
    is_after_community_wallet_start,
)
from aleph.vm.pool import VmPool
from aleph.vm.utils import create_task_log_exceptions

# Terminal statuses that confirm a message is no longer valid.
# Only these should trigger VM shutdown — never an unexpected or missing value.
_TERMINAL_STATUSES: frozenset[MessageStatus] = frozenset({
    MessageStatus.REJECTED,
    MessageStatus.FORGOTTEN,
    MessageStatus.REMOVED,
})

# Track consecutive terminal-status confirmations per VM before stopping.
# Prevents a single bad API response from killing a running instance.
STOP_AFTER_CONFIRMATIONS = 3
_terminal_strike_count: dict[str, int] = {}

from .messages import get_message_status
from .payment import (
    compute_required_balance,
    compute_required_credit_balance,
    compute_required_flow,
    fetch_balance_of_address,
    fetch_credit_balance_of_address,
    get_stream,
)
from .pubsub import PubSub
from .reactor import Reactor

logger = logging.getLogger(__name__)

Value = TypeVar("Value")
COMMUNITY_STREAM_RATIO = Decimal(0.2)


async def retry_generator(generator: AsyncIterable[Value], max_seconds: int = 8) -> AsyncIterable[Value]:
    retry_delay = 0.1
    while True:
        async for value in generator:
            yield value

        await asyncio.sleep(retry_delay)
        retry_delay = max(retry_delay * 2, max_seconds)


async def subscribe_via_ws(url) -> AsyncIterable[AlephMessage]:
    logger.debug("subscribe_via_ws()")
    from aleph.vm.orchestrator.http import get_session

    session = get_session()
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
                    continue

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
    """Periodically checks and stops VMs if payment conditions are unmet, such as insufficient
    wallet balance or payment stream coverage. Handles forgotten VMs, balance checks for the
    "hold" tier, and stream flow validation for the "superfluid" tier to ensure compliance.
    """
    pool: VmPool = app["vm_pool"]
    while True:
        await asyncio.sleep(settings.PAYMENT_MONITOR_INTERVAL)
        # noinspection PyBroadException
        try:
            logger.debug("Monitoring balances task running")
            await check_payment(pool)
            logger.debug("Monitoring balances task ended")
        except Exception as e:
            # Catch all exceptions as to never stop the task.
            logger.warning(f"check_payment failed {e}", exc_info=True)


async def check_payment(pool: VmPool):
    """Ensures VMs are stopped if payment conditions are unmet, such as insufficient
    funds in the wallet or inadequate payment stream coverage. Handles forgotten VMs
    balance checks for the "hold" tier, and stream flow validation for the "superfluid" tier
    stopping executions as needed to maintain compliance.
    """
    # Check if the executions continues existing or are forgotten before checking the payment
    # this is actually the main workflow for properly stopping PAYG instances, a user agent would stop the payment stream
    # and forget the instance message. Compared to just stopping or decreasing the payment stream as the CRN don't know
    # which VM it affects.
    for vm_hash in list(pool.executions.keys()):
        if vm_hash == settings.FAKE_INSTANCE_ID:
            continue
        try:
            message_status = await get_message_status(vm_hash)
        except Exception:
            logger.warning("Failed to fetch status for %s, skipping", vm_hash)
            continue

        if message_status in _TERMINAL_STATUSES:
            key = str(vm_hash)
            _terminal_strike_count[key] = _terminal_strike_count.get(key, 0) + 1
            strikes = _terminal_strike_count[key]
            if strikes < STOP_AFTER_CONFIRMATIONS:
                logger.info(
                    "VM %s has terminal status %s (%d/%d confirmations)",
                    vm_hash, message_status, strikes, STOP_AFTER_CONFIRMATIONS,
                )
                continue
            logger.info(
                "Stopping %s after %d consecutive %s confirmations",
                vm_hash, strikes, message_status,
            )
            del _terminal_strike_count[key]
            await pool.stop_vm(vm_hash)
            pool.forget_vm(vm_hash)
        else:
            # Status is healthy — reset any previous strikes
            _terminal_strike_count.pop(str(vm_hash), None)

    # Check if the balance held in the wallet is sufficient holder tier resources (Not do it yet)
    for execution_address, chains in pool.get_executions_by_address(payment_type=PaymentType.hold).items():
        for chain, executions in chains.items():
            executions = [execution for execution in executions if execution.is_confidential]
            if not executions:
                continue
            balance = await fetch_balance_of_address(execution_address)

            # Stop executions until the required balance is reached
            required_balance = await compute_required_balance(executions)
            logger.debug(
                f"Required balance for Sender {execution_address} executions: {required_balance}, {executions}"
            )
            # Stop executions until the required balance is reached
            while executions and balance < (required_balance + settings.PAYMENT_BUFFER):
                last_execution = executions.pop(-1)
                logger.debug(f"Stopping {last_execution} due to insufficient balance")
                await pool.stop_vm(last_execution.vm_hash)
                required_balance = await compute_required_balance(executions)

    community_wallet = await get_community_wallet_address()
    if not community_wallet:
        logger.error("Monitor payment ERROR: No community wallet set. Cannot check community payment")

    # Check if the credit balance held in the wallet is sufficient credit tier resources (Not do it yet)
    for execution_address, chains in pool.get_executions_by_address(payment_type=PaymentType.credit).items():
        for chain, executions in chains.items():
            executions = [execution for execution in executions]
            if not executions:
                continue
            balance = await fetch_credit_balance_of_address(execution_address)

            # Stop executions until the required credits are reached
            required_credits = await compute_required_credit_balance(executions)
            logger.debug(
                f"Required credit balance for Address {execution_address} executions: {required_credits}, {executions}"
            )
            # Stop executions until the required credits are reached
            while executions and balance < (required_credits + settings.PAYMENT_BUFFER):
                last_execution = executions.pop(-1)
                logger.debug(f"Stopping {last_execution} due to insufficient credit balance")
                await pool.stop_vm(last_execution.vm_hash)
                required_credits = await compute_required_credit_balance(executions)

    # Check if the balance held in the wallet is sufficient stream tier resources
    for execution_address, chains in pool.get_executions_by_address(payment_type=PaymentType.superfluid).items():
        for chain, executions in chains.items():
            try:
                stream = await get_stream(
                    sender=execution_address, receiver=settings.PAYMENT_RECEIVER_ADDRESS, chain=chain
                )

                logger.debug(
                    f"Stream flow from {execution_address} to {settings.PAYMENT_RECEIVER_ADDRESS} = {stream} {chain.value}"
                )
            except ValueError as error:
                logger.error(f"Error found getting stream for chain {chain} and sender {execution_address}: {error}")
                continue
            try:
                community_stream = await get_stream(sender=execution_address, receiver=community_wallet, chain=chain)
                logger.debug(
                    f"Stream flow from {execution_address} to {community_wallet} (community) : {stream} {chain}"
                )

            except ValueError as error:
                logger.error(f"Error found getting stream for chain {chain} and sender {execution_address}: {error}")
                continue

            while executions:
                executions_with_community = [
                    execution
                    for execution in executions
                    if await is_after_community_wallet_start(execution.times.started_at)
                ]

                required_stream = await compute_required_flow(executions_with_community)
                executions_without_community = [
                    execution
                    for execution in executions
                    if not await is_after_community_wallet_start(execution.times.started_at)
                ]
                logger.info("flow community %s", executions_with_community)
                logger.info("flow without community %s", executions_without_community)
                required_stream_without_community = await compute_required_flow(executions_without_community)
                # TODO, rounding should be done per executions to not have the extra  accumulate before rounding
                required_crn_stream = format_cost(
                    required_stream * (1 - COMMUNITY_STREAM_RATIO) + required_stream_without_community
                )
                required_community_stream = format_cost(required_stream * COMMUNITY_STREAM_RATIO)
                logger.debug(
                    f"Stream for senders {execution_address} {len(executions)} executions.  CRN : {stream} /  {required_crn_stream}."
                    f"Community: {community_stream} / {required_community_stream}"
                )
                # Can pay all executions
                if (stream + settings.PAYMENT_BUFFER) > required_crn_stream and (
                    community_stream + settings.PAYMENT_BUFFER
                ) > required_community_stream:
                    break
                # Stop executions until the required stream is reached
                last_execution = executions.pop(-1)
                logger.info(f"Stopping {last_execution} of {execution_address} due to insufficient stream")
                await pool.stop_vm(last_execution.vm_hash)


async def start_payment_monitoring_task(app: web.Application):
    app["payments_monitor"] = create_task_log_exceptions(monitor_payments(app), name="payment_monitor")


async def stop_balances_monitoring_task(app: web.Application):
    app["payments_monitor"].cancel()
    try:
        await app["payments_monitor"]
    except asyncio.CancelledError:
        logger.debug("Task payments_monitor is cancelled now")
