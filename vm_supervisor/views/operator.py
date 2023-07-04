import asyncio
import logging
from datetime import timedelta

from aiohttp import web
from aleph_message.models import ItemHash

from ..models import VmExecution
from ..run import pool

logger = logging.getLogger(__name__)


def get_execution_or_404(ref: ItemHash) -> VmExecution:
    """Return the execution corresponding to the ref or raise an HTTP 404 error.
    """
    for execution in pool.get_instance_executions():
        if execution.vm_hash == ref:
            return execution
    else:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {ref}")


async def stream_logs(request: web.Request):
    # TODO: Add user authentication
    vm_hash = ItemHash(request.match_info["ref"])
    execution = get_execution_or_404(vm_hash)

    queue = asyncio.Queue()
    try:
        ws = web.WebSocketResponse()
        try:
            await ws.prepare(request)

            execution.vm.fvm.log_queues.append(queue)

            while True:
                log_type, message = queue.get()
                assert log_type in ('stdout', 'stderr')

                await ws.send_json({
                    "type": log_type,
                    "message": message
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
    vm_hash = ItemHash(request.match_info["ref"])
    timeout = float(ItemHash(request.match_info["timeout"]))
    if not 0 < timeout < timedelta(days=10).total_seconds():
        return web.HTTPBadRequest(body="Invalid timeout duration")

    for execution in pool.get_instance_executions():
        if execution.vm_hash == vm_hash:
            logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
            await execution.expire(timeout=timeout)
            execution.persistent = False
            break
    else:
        return web.HTTPNotFound(body=f"No running VM with ref {vm_hash}")

    return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


async def operate_stop(request: web.Request):
    """Stop the virtual machine, smoothly if possible.
    """
    # TODO: Add user authentication
    vm_hash = ItemHash(request.match_info["ref"])

    for execution in pool.get_instance_executions():
        if execution.vm_hash == vm_hash:
            logger.info(f"Stopping {execution.vm_hash}")
            await execution.stop()
            execution.persistent = False
            break
    else:
        return web.HTTPNotFound(body=f"No running VM with ref {vm_hash}")

    return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")


async def operate_erase(request: web.Request):
    """Delete all data stored by a virtual machine.
    Stop the virtual machine first if needed.
    """
    # TODO: Add user authentication
    vm_hash = ItemHash(request.match_info["ref"])
    for execution in pool.get_instance_executions():
        if execution.vm_hash == vm_hash:
            logger.info(f"Erasing {execution.vm_hash}")

            # Stop the VM
            await execution.stop()
            execution.persistent = False

            # Delete all data
            for volume in execution.resources.volumes:
                if not volume.read_only:
                    logger.info(f"Deleting volume {volume.path_on_host}")
                    volume.path_on_host.unlink()

            break
    else:
        return web.HTTPNotFound(body=f"No running VM with ref {vm_hash}")

    return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")
