import asyncio
import json
import logging
from typing import Any

import msgpack
from aiohttp import ClientResponseError, web
from aiohttp.web_exceptions import (
    HTTPBadGateway,
    HTTPBadRequest,
    HTTPInternalServerError,
)
from aleph_message.models import ItemHash
from msgpack import UnpackValueError
from multidict import CIMultiDict

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.program import (
    FileTooLargeError,
    ResourceDownloadError,
    VmSetupError,
)
from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError
from aleph.vm.models import VmExecution
from aleph.vm.pool import VmPool
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.utils import HostNotFoundError

from .messages import load_updated_message
from .pubsub import PubSub

logger = logging.getLogger(__name__)


async def build_asgi_scope(path: str, request: web.Request) -> dict[str, Any]:
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


async def build_event_scope(event) -> dict[str, Any]:
    """Build an ASGI scope for an event."""
    return {
        "type": "aleph.message",
        "body": event,
    }


async def create_vm_execution(vm_hash: ItemHash, pool: VmPool, persistent: bool = False) -> VmExecution:
    message, original_message = await load_updated_message(vm_hash)
    pool.message_cache[vm_hash] = message

    logger.debug(f"Message: {json.dumps(message.model_dump(exclude_none=True), indent=4, sort_keys=True, default=str)}")

    execution = await pool.create_a_vm(
        vm_hash=vm_hash,
        message=message.content,
        original=original_message.content,
        persistent=persistent,
    )

    return execution


async def create_vm_execution_or_raise_http_error(vm_hash: ItemHash, pool: VmPool) -> VmExecution:
    try:
        return await create_vm_execution(vm_hash=vm_hash, pool=pool)
    except ResourceDownloadError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPBadRequest(reason="Code, runtime or data not available") from error
    except InsufficientResourcesError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPBadRequest(reason=str(error)) from error
    except FileTooLargeError as error:
        raise HTTPInternalServerError(reason=error.args[0]) from error
    except VmSetupError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during vm initialisation") from error
    except MicroVMFailedInitError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during runtime initialisation") from error
    except HostNotFoundError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Host did not respond to ping") from error
    except ClientResponseError as error:
        logger.exception(error)
        if error.status == 404:
            raise HTTPInternalServerError(reason=f"Item hash {vm_hash} not found") from error
        else:
            raise HTTPInternalServerError(reason=f"Error downloading {vm_hash}") from error
    except Exception as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Unhandled error during initialisation") from error


async def run_code_on_request(vm_hash: ItemHash, path: str, pool: VmPool, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """

    execution: VmExecution | None = pool.get_running_vm(vm_hash=vm_hash)

    # Prevent execution issues if the execution resources are empty
    # TODO: Improve expiration process to avoid that kind of issues.
    if execution and not execution.has_resources:
        pool.forget_vm(execution.vm_hash)
        execution = None

    if not execution:
        execution = await create_vm_execution_or_raise_http_error(vm_hash=vm_hash, pool=pool)

    logger.debug(f"Using vm={execution.vm_id}")

    scope: dict = await build_asgi_scope(path, request)

    try:
        await execution.becomes_ready()
        result_raw: bytes = await execution.run_code(scope=scope)

        if result_raw == b"":
            # Missing result from the init process of the virtual machine, not even an error message.
            # It may have completely crashed.

            # Stop the virtual machine due to failing init.
            # It will be restarted on a future request.
            await execution.stop()

            return web.Response(
                status=HTTPBadGateway.status_code,
                reason="No response from VM",
                text="VM did not respond and was shut down",
            )

    except asyncio.TimeoutError:
        logger.warning(f"VM{execution.vm_id} did not respond within `resource.seconds`")
        return web.HTTPGatewayTimeout(body="Program did not respond within `resource.seconds`")
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            # An error took place, the stacktrace of the error will be returned.
            # TODO: Add an option for VM developers to prevent stacktraces from being exposed.

            # The Diagnostics VM checks for the proper handling of exceptions.
            # This fills the logs with noisy stack traces, so we ignore this specific error.
            ignored_errors = ['raise CustomError("Whoops")', "main.CustomError: Whoops"]

            if settings.IGNORE_TRACEBACK_FROM_DIAGNOSTICS and any(
                ignored_error in result["traceback"] for ignored_error in ignored_errors
            ):
                logger.debug('Ignored traceback from CustomError("Whoops")')
            else:
                logger.warning(result["traceback"])

            return web.Response(
                status=HTTPInternalServerError.status_code,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        # HTTP Headers require specific data structure
        headers = CIMultiDict([(key.decode().lower(), value.decode()) for key, value in result["headers"]["headers"]])
        if "content-length" not in headers:
            headers["Content-Length".lower()] = str(len(result["body"]["body"]))
        for header in ["Content-Encoding", "Transfer-Encoding", "Vary"]:
            if header in headers:
                del headers[header]

        headers.update(
            {
                "Aleph-Program-ItemHash": execution.vm_hash,
                "Aleph-Program-Code-Ref": execution.message.code.ref,
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
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                execution.start_watching_for_updates(pubsub=request.app["pubsub"])
            _ = execution.stop_after_timeout(timeout=settings.REUSE_TIMEOUT)
        else:
            await execution.stop()
            pool.forget_vm(execution.vm_hash)


async def run_code_on_event(vm_hash: ItemHash, event, pubsub: PubSub, pool: VmPool):
    """
    Execute code in response to an event.
    """

    execution: VmExecution | None = pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        execution = await create_vm_execution_or_raise_http_error(vm_hash=vm_hash, pool=pool)

    logger.debug(f"Using vm={execution.vm_id}")

    scope: dict = await build_event_scope(event)

    try:
        await execution.becomes_ready()
        result_raw: bytes = await execution.run_code(scope=scope)
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            logger.warning(result["traceback"])
            return web.Response(
                status=HTTPInternalServerError.status_code,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        logger.info(f"Result: {result['body']}")
        return result["body"]

    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                execution.start_watching_for_updates(pubsub=pubsub)
            _ = execution.stop_after_timeout(timeout=settings.REUSE_TIMEOUT)
        else:
            await execution.stop()


async def start_persistent_vm(vm_hash: ItemHash, pubsub: PubSub | None, pool: VmPool) -> VmExecution:
    execution: VmExecution | None = pool.executions.get(vm_hash)
    if execution:
        if execution.is_running:
            logger.info(f"{vm_hash} is already running")
        elif execution.is_starting:
            logger.info(f"{vm_hash} is already starting")
        elif execution.is_stopping:
            logger.info(f"{vm_hash} is stopping, waiting for complete stop before restarting")
            await execution.stop_event.wait()
            execution = None
        else:
            logger.info(f"{vm_hash} unknown execution state, stopping the vm")
            await execution.stop()
            execution = None

    if not execution:
        logger.info(f"Starting persistent virtual machine with id: {vm_hash}")
        execution = await create_vm_execution(vm_hash=vm_hash, pool=pool, persistent=True)

    await execution.becomes_ready()

    # If the VM was already running in lambda mode, it should not expire
    # as long as it is also scheduled as long-running
    execution.cancel_expiration()

    if pubsub and settings.WATCH_FOR_UPDATES:
        execution.start_watching_for_updates(pubsub=pubsub)

    return execution
