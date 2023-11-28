import asyncio
import logging
from datetime import timedelta

import aiohttp.web_exceptions
from aiohttp import web
from aiohttp.web_urldispatcher import UrlMappingMatchInfo
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash
from aleph_message.models.execution import BaseExecutableContent

from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.run import create_vm_execution
from aleph.vm.orchestrator.views import authenticate_api_request
from aleph.vm.orchestrator.views.authentication import (
    authenticate_websocket_message,
    require_jwk_authentication,
)
from aleph.vm.pool import VmPool

logger = logging.getLogger(__name__)


def get_itemhash_or_400(match_info: UrlMappingMatchInfo) -> ItemHash:
    try:
        ref = match_info["ref"]
    except KeyError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body="Missing field: 'ref'") from error
    try:
        return ItemHash(ref)
    except UnknownHashError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body=f"Invalid ref: '{ref}'") from error


def get_execution_or_404(ref: ItemHash, pool: VmPool) -> VmExecution:
    """Return the execution corresponding to the ref or raise an HTTP 404 error."""
    # TODO: Check if this should be execution.message.address or execution.message.content.address?
    execution = pool.executions.get(ref)
    if execution:
        return execution
    else:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {ref}")


def is_sender_authorized(authenticated_sender: str, message: BaseExecutableContent) -> bool:
    if authenticated_sender.lower() == message.address.lower():
        return True
    else:
        logger.debug(f"Unauthorized sender {authenticated_sender} is not {message.address}")
        return False


async def stream_logs(request: web.Request) -> web.StreamResponse:
    """Stream the logs of a VM.

    The authentication method is slightly different because browsers do not
    allow Javascript to set headers in WebSocket requests.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if execution.vm is None:
        raise web.HTTPBadRequest(body=f"VM {vm_hash} is not running")
    queue = None
    try:
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        try:
            await authenticate_for_vm_or_403(execution, request, vm_hash, ws)
            await ws.send_json({"status": "connected"})

            queue = await execution.vm.get_log_queue()

            while True:
                log_type, message = await queue.get()
                assert log_type in ("stdout", "stderr")

                await ws.send_json({"type": log_type, "message": message.decode()})
        finally:
            await ws.close()
    finally:
        if queue:
            await execution.vm.unregister_queue(queue)


async def authenticate_for_vm_or_403(execution, request, vm_hash, ws):
    """Allow authentication via HEADER or via websocket"""
    if authenticate_api_request(request):
        logger.debug(f"Accepted request to access logs via the allocatioan api key on {vm_hash}")
        return True

    first_message = await ws.receive_json()
    credentials = first_message["auth"]
    authenticated_sender = await authenticate_websocket_message(credentials)
    if is_sender_authorized(authenticated_sender, execution.message):
        logger.debug(f"Accepted request to access logs by {authenticated_sender} on {vm_hash}")
        return True

    logger.debug(f"Denied request to access logs by {authenticated_sender} on {vm_hash}")
    await ws.send_json({"status": "failed", "reason": "unauthorized sender"})
    raise web.HTTPForbidden(body="Unauthorized sender")


@require_jwk_authentication
async def operate_expire(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible.

    A timeout may be specified to delay the action."""
    vm_hash = get_itemhash_or_400(request.match_info)
    try:
        timeout = float(ItemHash(request.match_info["timeout"]))
    except (KeyError, ValueError) as error:
        raise web.HTTPBadRequest(body="Invalid timeout duration") from error
    if not 0 < timeout < timedelta(days=10).total_seconds():
        return web.HTTPBadRequest(body="Invalid timeout duration")

    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
    await execution.expire(timeout=timeout)
    execution.persistent = False

    return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


@require_jwk_authentication
async def operate_stop(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible."""
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)

    pool: VmPool = request.app["vm_pool"]
    logger.debug(f"Iterating through running executions... {pool.executions}")
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    if execution.is_running:
        logger.info(f"Stopping {execution.vm_hash}")
        await execution.stop()
        execution.persistent = False
        return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
    else:
        return web.Response(status=200, body="Already stopped, nothing to do")


@require_jwk_authentication
async def operate_reboot(request: web.Request, authenticated_sender: str) -> web.Response:
    """
    Reboots the virtual machine, smoothly if possible.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    if execution.is_running:
        logger.info(f"Rebooting {execution.vm_hash}")
        await pool.stop_vm(vm_hash)

        await create_vm_execution(vm_hash=vm_hash, pool=pool)
        return web.Response(status=200, body=f"Rebooted VM with ref {vm_hash}")
    else:
        return web.Response(status=200, body="Starting VM (was not running) with ref {vm_hash}")


@require_jwk_authentication
async def operate_erase(request: web.Request, authenticated_sender: str) -> web.Response:
    """Delete all data stored by a virtual machine.
    Stop the virtual machine first if needed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    logger.info(f"Erasing {execution.vm_hash}")

    # Stop the VM
    await execution.stop()
    execution.persistent = False

    # Delete all data
    if execution.resources is not None:
        for volume in execution.resources.volumes:
            if not volume.read_only:
                logger.info(f"Deleting volume {volume.path_on_host}")
                volume.path_on_host.unlink()

    return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")
