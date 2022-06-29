import asyncio
import logging
from typing import Dict, Any, Optional

import msgpack
from aiohttp import web
from aiohttp.web_exceptions import HTTPBadRequest, HTTPInternalServerError
from msgpack import UnpackValueError

from firecracker.microvm import MicroVMFailedInit
from .conf import settings
from .messages import load_updated_message
from .models import VmHash, VmExecution
from .pool import VmPool
from .pubsub import PubSub
from .vm.firecracker_microvm import (
    ResourceDownloadError,
    VmSetupError,
    FileTooLargeError,
)

logger = logging.getLogger(__name__)

pool = VmPool()


async def build_asgi_scope(path: str, request: web.Request) -> Dict[str, Any]:
    # ASGI mandates lowercase header names
    headers = tuple((name.lower(), value) for name, value in request.raw_headers)
    return {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": headers,
        "body": await request.read(),
    }


async def build_event_scope(event) -> Dict[str, Any]:
    return {
        "type": "aleph.message",
        "body": event,
    }


async def create_vm_execution(vm_hash: VmHash) -> VmExecution:
    message, original_message = await load_updated_message(vm_hash)
    pool.message_cache[vm_hash] = message

    try:
        execution = await pool.create_a_vm(
            vm_hash=vm_hash,
            program=message.content,
            original=original_message.content,
        )
    except ResourceDownloadError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPBadRequest(reason="Code, runtime or data not available")
    except FileTooLargeError as error:
        raise HTTPInternalServerError(reason=error.args[0])
    except VmSetupError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during program initialisation")
    except MicroVMFailedInit as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during runtime initialisation")

    if not execution.vm:
        raise ValueError("The VM has not been created")

    return execution


async def run_code_on_request(
    vm_hash: VmHash, path: str, request: web.Request
) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """

    execution: Optional[VmExecution] = await pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        execution = await create_vm_execution(vm_hash=vm_hash)

    logger.debug(f"Using vm={execution.vm.vm_id}")

    scope: Dict = await build_asgi_scope(path, request)

    try:
        await execution.becomes_ready()
        result_raw: bytes = await execution.run_code(scope=scope)

        if result_raw == b'':
            # Missing result from the init process of the virtual machine, not even an error message.
            # It may have completely crashed.

            # Stop the virtual machine due to failing init.
            # It will be restarted on a future request.
            await execution.stop()

            return web.Response(status=502, reason="No response from VM",
                                text="VM did not respond and was shut down")

    except asyncio.TimeoutError:
        logger.warning(
            f"VM{execution.vm.vm_id} did not respond within `resource.seconds`"
        )
        return web.HTTPGatewayTimeout(
            body="Program did not respond within `resource.seconds`"
        )
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            logger.warning(result["traceback"])
            return web.Response(
                status=500,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        headers = {
            key.decode(): value.decode() for key, value in result["headers"]["headers"]
        }
        if "content-length" not in headers:
            headers["Content-Length".lower()] = str(len(result["body"]["body"]))
        for header in ["Content-Encoding", "Transfer-Encoding", "Vary"]:
            if header in headers:
                del headers[header]

        headers.update(
            {
                "Aleph-Program-ItemHash": execution.vm_hash,
                "Aleph-Program-Code-Ref": execution.program.code.ref,
                # "Aleph-Compute-Vm-Id": str(execution.vm.vm_id),
            }
        )

        return web.Response(
            status=result["headers"]["status"],
            body=result["body"]["body"],
            headers=headers,
        )
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                execution.start_watching_for_updates(pubsub=request.app["pubsub"])
            execution.stop_after_timeout(timeout=settings.REUSE_TIMEOUT)
        else:
            await execution.stop()


async def run_code_on_event(vm_hash: VmHash, event, pubsub: PubSub):
    """
    Execute code in response to an event.
    """

    execution: Optional[VmExecution] = await pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        execution = await create_vm_execution(vm_hash=vm_hash)

    logger.debug(f"Using vm={execution.vm.vm_id}")

    scope: Dict = await build_event_scope(event)

    try:
        await execution.becomes_ready()
        result_raw: bytes = await execution.run_code(scope=scope)
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            logger.warning(result["traceback"])
            return web.Response(
                status=500,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        logger.info(f"Result: {result['body']}")
        return result["body"]

    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                execution.start_watching_for_updates(pubsub=pubsub)
            execution.stop_after_timeout(timeout=settings.REUSE_TIMEOUT)
        else:
            await execution.stop()


async def start_long_running(vm_hash: VmHash, pubsub: PubSub) -> VmExecution:
    execution: Optional[VmExecution] = await pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        execution = await create_vm_execution(vm_hash=vm_hash)\

    execution.marked_as_long_running = True
    execution.cancel_expiration()

    await execution.becomes_ready()

    # if settings.WATCH_FOR_UPDATES:
    #     # FIXME: Is this added for every request ?
    #     execution.start_watching_for_updates(pubsub=request.app["pubsub"])

    return execution


async def stop_long_running(vm_hash: VmHash) -> Optional[VmExecution]:
    execution = await pool.get_running_vm(vm_hash)
    if execution:
        await execution.stop()
    return execution
