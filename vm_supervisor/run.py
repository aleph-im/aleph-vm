import logging
from typing import Dict, Any

import msgpack
from aiohttp import web
from aiohttp.web_exceptions import HTTPBadRequest, HTTPInternalServerError
from msgpack import UnpackValueError

from firecracker.microvm import MicroVMFailedInit
from .conf import settings
from .messages import load_updated_message
from .models import VmHash, VmExecution
from .pool import VmPool
from .vm.firecracker_microvm import ResourceDownloadError, VmSetupError

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


async def run_code_on_request(vm_hash: VmHash, path: str, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """

    execution: VmExecution = await pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
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
        except VmSetupError as error:
            logger.exception(error)
            pool.forget_vm(vm_hash=vm_hash)
            raise HTTPInternalServerError(reason="Error during program initialisation")
        except MicroVMFailedInit as error:
            logger.exception(error)
            pool.forget_vm(vm_hash=vm_hash)
            raise HTTPInternalServerError(reason="Error during runtime initialisation")

    logger.debug(f"Using vm={execution.vm.vm_id}")

    scope: Dict = await build_asgi_scope(path, request)

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

        headers = {
            key.decode(): value.decode() for key, value in result["headers"]["headers"]
        }

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
