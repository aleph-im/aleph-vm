"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""
import logging
from typing import Awaitable, Dict, Any

import msgpack
from aiohttp import web, ClientResponseError, ClientConnectorError
from aiohttp.web_exceptions import HTTPNotFound, HTTPServiceUnavailable, HTTPBadRequest
from msgpack import UnpackValueError

from .conf import settings
from .models import FilePath, FunctionMessage
from .pool import VmPool
from .storage import get_message
from .vm.firecracker_microvm import ResourceDownloadError

logger = logging.getLogger(__name__)
pool = VmPool()


async def index(request: web.Request):
    assert request.method == "GET"
    return web.Response(text="Server: Aleph VM Supervisor")


async def try_get_message(ref: str) -> FunctionMessage:
    # Get the message or raise an aiohttp HTTP error
    try:
        return await get_message(ref)
    except ClientConnectorError:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable")
    except ClientResponseError as error:
        if error.status == 404:
            raise HTTPNotFound(reason="Hash not found")
        else:
            raise


def build_asgi_scope(path: str, request: web.Request) -> Dict[str, Any]:
    return {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": request.raw_headers,
    }


def load_file_content(path: FilePath) -> bytes:
    if path:
        with open(path, "rb") as fd:
            return fd.read()
    else:
        return b""


async def run_code(message_ref: str, path: str, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """

    message = await try_get_message(message_ref)

    try:
        vm = await pool.get_a_vm(message)
    except ResourceDownloadError as error:
        logger.exception(error)
        raise HTTPBadRequest(reason="Code, runtime or data not available")

    logger.debug(f"Using vm={vm.vm_id}")

    scope: Dict = build_asgi_scope(path, request)

    code: bytes = load_file_content(vm.resources.code_path)
    input_data: bytes = load_file_content(vm.resources.data_path)

    try:
        result_raw: bytes = await vm.run_code(
            code=code,
            entrypoint=message.content.code.entrypoint,
            input_data=input_data,
            encoding=message.content.code.encoding,
            scope=scope,
        )

    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)
        # TODO: Handle other content-types

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            logger.warning(result["traceback"])
            return web.Response(
                status=500,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        headers = {key.decode(): value.decode()
                   for key, value in result['headers']['headers']}

        return web.Response(
            status=result['headers']['status'],
            body=result["body"]["body"],
            headers=headers,
        )
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=502, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            pool.keep_in_cache(vm, message, timeout=settings.REUSE_TIMEOUT)
        else:
            await vm.teardown()


def run_code_from_path(request: web.Request) -> Awaitable[web.Response]:
    """Allow running an Aleph VM function from a URL path

    The path is expected to follow the scheme defined in `app.add_routes` below,
    where the identifier of the message is named `ref`.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref: str = request.match_info["ref"]
    return run_code(message_ref, path, request)


async def run_code_from_hostname(request: web.Request) -> web.Response:
    """Allow running an Aleph VM function from a hostname

    The first component of the hostname is used as identifier of the message defining the
    Aleph VM function.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref = request.host.split(".")[0]
    return await run_code(message_ref, path, request)


app = web.Application()

app.add_routes([web.route("*", "/vm/function/{ref}{suffix:.*}", run_code_from_path)])
app.add_routes([web.route("*", "/{suffix:.*}", run_code_from_hostname)])


def run():
    """Run the VM Supervisor."""
    settings.check()
    web.run_app(app)
