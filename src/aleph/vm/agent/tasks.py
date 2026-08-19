import asyncio
import json
import logging
import math
import random
import time
from collections.abc import AsyncIterable, Callable
from typing import TypeVar

import aiohttp
import pydantic
from aiohttp import web
from aleph_message.models import (
    AggregateMessage,
    AlephMessage,
    InstanceContent,
    ProgramMessage,
    parse_message,
)
from yarl import URL

from aleph.vm.agent.haproxy_sync import sync_domain_mappings
from aleph.vm.agent.run import reconcile_port_forwards
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import Backend, VmId, VmStatus
from aleph.vm.utils import create_task_log_exceptions

from .pubsub import PubSub
from .reactor import Reactor

# Terminal statuses that confirm a message is no longer valid.
# Only these should trigger VM shutdown — never an unexpected or missing value.


logger = logging.getLogger(__name__)

Value = TypeVar("Value")


async def retry_generator(
    factory: Callable[[], AsyncIterable[Value]],
    max_seconds: float = 8.0,
) -> AsyncIterable[Value]:
    """Repeatedly create and consume an async generator, reconnecting on failure.

    ``factory`` is called on every (re)connection to produce a fresh async
    generator. A single generator instance is exhausted once its underlying
    connection drops, so reusing the same object would loop over nothing.
    """
    retry_delay = 0.1
    while True:
        try:
            async for value in factory():
                retry_delay = 0.1
                yield value
        except RuntimeError as e:
            if "Event loop is closed" in str(e):
                logger.debug("retry_generator exiting: event loop closed")
                return
            raise
        except Exception:
            logger.exception("WebSocket generator error, reconnecting")

        logger.warning("WebSocket disconnected, reconnecting in %.1fs", retry_delay)
        await asyncio.sleep(retry_delay)
        retry_delay = min(retry_delay * 2, max_seconds)


async def subscribe_via_ws(url) -> AsyncIterable[AlephMessage]:
    logger.debug("subscribe_via_ws()")
    from aleph.vm.utils.http import get_session

    session = get_session()
    async with session.ws_connect(
        url,
        heartbeat=30,
        timeout=aiohttp.ClientWSTimeout(ws_close=10),
    ) as ws:
        logger.info("WebSocket connected on %s", url)
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
                # but do not contain the fields "item_type" or "content", hence they
                # are not valid Messages.
                if "item_type" not in data:
                    if "confirmation" in data:
                        logger.debug("Ignoring confirmation message '%s'", data.get("item_hash"))
                    else:
                        logger.warning("Unexpected message without item_type: %s", data)
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
                logger.error("WebSocket error: %s", ws.exception() or "unknown")
                break
            elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSING, aiohttp.WSMsgType.CLOSED):
                logger.warning("WebSocket closed by server")
                break


async def watch_for_messages(dispatcher: PubSub, reactor: Reactor, supervisor: Supervisor, registry: AgentVmRegistry):
    """Watch for new Aleph messages"""
    logger.debug("watch_for_messages()")
    url = URL(f"{settings.API_SERVER}/api/ws0/messages").with_query({"startDate": math.floor(time.time())})

    async for message in retry_generator(lambda: subscribe_via_ws(url)):
        # Dispatch update to running VMs
        await dispatcher.publish(key=message.item_hash, value=message)
        if hasattr(message.content, "ref") and message.content.ref:
            await dispatcher.publish(key=message.content.ref, value=message)

        # Register new VM to run on future messages:
        if isinstance(message, ProgramMessage):
            if message.content.on.message:
                reactor.register(message)
        await reactor.trigger(message=message)

        # Handle aggregate updates in real-time
        if isinstance(message, AggregateMessage):
            key = message.content.key
            if isinstance(key, str):
                if key == "port-forwarding":
                    await _handle_port_forwarding_aggregate(message, supervisor, registry)
                elif key == "domains":
                    await _handle_domains_aggregate(message, supervisor, registry)


async def _handle_port_forwarding_aggregate(
    message: AggregateMessage, supervisor: Supervisor, registry: AgentVmRegistry
):
    """Reconcile port forwards for VMs affected by a port-forwarding aggregate change."""
    # Use content.address (the target account), not message.sender,
    # because a sender can publish aggregates on behalf of another address.
    address = message.content.address
    affected = [
        (vm_hash, record)
        for vm_hash, record in registry.items()
        if isinstance(record.message, InstanceContent) and record.message.address == address
    ]
    if not affected:
        return
    logger.info("Port-forwarding aggregate for %s, updating %d VM(s)", address, len(affected))
    for vm_hash, record in affected:
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            continue
        if info.status is not VmStatus.RUNNING:
            continue
        try:
            await reconcile_port_forwards(supervisor, vm_id, record.message)
        except Exception:
            logger.exception("Failed to update port redirects for %s", vm_hash)


async def _handle_domains_aggregate(message: AggregateMessage, supervisor: Supervisor, registry: AgentVmRegistry):
    """Update HAProxy domain mapping when a domains aggregate changes.

    The aggregate content maps domain names to instance configs:
    {"testd.example.com": {"message_id": "<item_hash>", "type": "instance"}}

    Only trigger if the address owns an instance present on this node. The owner
    address comes from the agent registry, not the hypervisor object: spec-built
    and restored executions carry no message. Enumerating through the registry
    and ``supervisor.get_vm`` (instead of the in-process pool's executions) keeps
    this working in split mode, where the daemon owns the pool. This covers both
    additions (new domain pointing to a local instance) and deletions (domain
    removed, the map must be rebuilt).
    """
    address = message.content.address

    has_local_instance = False
    for vm_hash, record in registry.items():
        if record.message.address != address:
            continue
        try:
            info = await supervisor.get_vm(VmId(str(vm_hash)))
        except VmNotFoundError:
            continue
        # QEMU is the instance backend (the old execution.is_instance check).
        if info.backend is Backend.QEMU:
            has_local_instance = True
            break
    if not has_local_instance:
        return

    logger.info("Domains aggregate for %s, updating HAProxy domain mapping", address)
    try:
        await sync_domain_mappings(supervisor)
    except Exception:
        logger.exception("Failed to update domain mapping for %s", address)


async def start_watch_for_messages_task(app: web.Application):
    logger.debug("start_watch_for_messages_task()")
    pubsub = PubSub()
    supervisor = app["supervisor"]
    registry = app["vm_registry"]
    reactor = Reactor(
        pubsub, supervisor, app["expiry"], app["update_watcher"], registry, app["capacity"], app["program_client"]
    )

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
    app["messages_listener"] = create_task_log_exceptions(watch_for_messages(pubsub, reactor, supervisor, registry))


async def stop_watch_for_messages_task(app: web.Application):
    app["messages_listener"].cancel()
    try:
        await app["messages_listener"]
    except asyncio.CancelledError:
        logger.debug("Task messages_listener is cancelled now")


async def periodic_domain_resync(app: web.Application):
    """Re-sync HAProxy domain mappings on a jittered interval.

    Belt-and-braces for the WS-event-driven path in
    `_handle_domains_aggregate`: a missed frame or upstream indexing lag
    on DOMAIN_SERVICE_URL would otherwise leave the map stale until the
    next aggregate update or supervisor restart.

    Jitter prevents thundering-herd against DOMAIN_SERVICE_URL when many
    CRNs restart together (rolling deploys, common upstream events).
    First sleep picks a random phase across the full interval;
    subsequent sleeps stay decorrelated with ±15% jitter.
    """
    supervisor = app["supervisor"]
    interval = settings.DOMAIN_RESYNC_INTERVAL

    # Seed the map once at startup (force), replacing the pool's old load-time
    # sync. Restored/running VMs may already serve domains before the first
    # jittered resync fires.
    try:
        await sync_domain_mappings(supervisor, force_update=True)
    except Exception as e:
        if isinstance(e, RuntimeError) and "Event loop is closed" in str(e):
            logger.debug("periodic_domain_resync exiting: event loop closed")
            return
        logger.warning("initial domain sync failed: %s", e, exc_info=True)

    await asyncio.sleep(random.uniform(0, interval))
    while True:
        try:
            await sync_domain_mappings(supervisor)
        except Exception as e:
            if isinstance(e, RuntimeError) and "Event loop is closed" in str(e):
                logger.debug("periodic_domain_resync exiting: event loop closed")
                return
            logger.warning("periodic_domain_resync failed: %s", e, exc_info=True)
        await asyncio.sleep(interval * random.uniform(0.85, 1.15))


async def start_domain_resync_task(app: web.Application):
    app["domain_resync"] = create_task_log_exceptions(periodic_domain_resync(app), name="domain_resync")


async def stop_domain_resync_task(app: web.Application):
    app["domain_resync"].cancel()
    try:
        await app["domain_resync"]
    except asyncio.CancelledError:
        logger.debug("Task domain_resync is cancelled now")
