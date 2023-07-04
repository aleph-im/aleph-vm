import asyncio
import logging
from datetime import timedelta

import aiohttp.web_exceptions
from aiohttp import web
from aiohttp.web_urldispatcher import UrlMappingMatchInfo
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash

from ..models import VmExecution
from ..run import pool

logger = logging.getLogger(__name__)


def get_itemhash_or_400(match_info: UrlMappingMatchInfo) -> ItemHash:
    try:
        ref = match_info["ref"]
    except KeyError:
        raise aiohttp.web_exceptions.HTTPBadRequest(body="Missing field: 'ref'")
    try:
        return ItemHash(ref)
    except UnknownHashError:
        raise aiohttp.web_exceptions.HTTPBadRequest(body=f"Invalid ref: '{ref}'")


def get_execution_or_404(ref: ItemHash) -> VmExecution:
    """Return the execution corresponding to the ref or raise an HTTP 404 error.
    """
    execution = pool.executions.get(ref)
    if execution:
        return execution
    else:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {ref}")


async def stream_logs(request: web.Request):
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)
    execution = get_execution_or_404(vm_hash)

    queue = asyncio.Queue()
    try:
        ws = web.WebSocketResponse()
        try:
            await ws.prepare(request)

            execution.vm.fvm.log_queues.append(queue)

            while True:
                log_type, message = await queue.get()
                assert log_type in ('stdout', 'stderr')

                await ws.send_json({
                    "type": log_type,
                    "message": message.decode()
                })
        finally:
            await ws.close()
    finally:
        execution.vm.fvm.log_queues.remove(queue)
        queue.empty()


async def operate_expire(request: web.Request):
    """Stop the virtual machine, smoothly if possible.
    """
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)
    timeout = float(ItemHash(request.match_info["timeout"]))
    if not 0 < timeout < timedelta(days=10).total_seconds():
        return web.HTTPBadRequest(body="Invalid timeout duration")

    execution = get_execution_or_404(vm_hash)

    logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
    await execution.expire(timeout=timeout)
    execution.persistent = False

    return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


async def operate_stop(request: web.Request):
    """Stop the virtual machine, smoothly if possible.
    """
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)

    logger.debug(f"Iterating through running executions... {pool.executions}")
    execution = get_execution_or_404(vm_hash)

    if execution.is_running:
        logger.info(f"Stopping {execution.vm_hash}")
        await execution.stop()
        execution.persistent = False
        return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
    else:
        return web.Response(status=200, body=f"Already stopped, nothing to do")


async def operate_erase(request: web.Request):
    """Delete all data stored by a virtual machine.
    Stop the virtual machine first if needed.
    """
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)
    execution = get_execution_or_404(vm_hash)

    logger.info(f"Erasing {execution.vm_hash}")

    # Stop the VM
    await execution.stop()
    execution.persistent = False

    # Delete all data
    for volume in execution.resources.volumes:
        if not volume.read_only:
            logger.info(f"Deleting volume {volume.path_on_host}")
            volume.path_on_host.unlink()

    return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")
