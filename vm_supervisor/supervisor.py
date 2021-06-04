"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""
import binascii
import logging
from base64 import b32decode, b16encode
from typing import Awaitable, Dict, Any

import msgpack
from aiohttp import web, ClientResponseError, ClientConnectorError
from aiohttp.web_exceptions import HTTPNotFound, HTTPServiceUnavailable, HTTPBadRequest, \
    HTTPInternalServerError
from msgpack import UnpackValueError

from aleph_message.models import ProgramMessage, ProgramContent
from .conf import settings
from .pool import VmPool
from .storage import get_message
from .vm.firecracker_microvm import ResourceDownloadError, VmSetupError

logger = logging.getLogger(__name__)
pool = VmPool()


async def index(request: web.Request):
    assert request.method == "GET"
    return web.Response(text="Server: Aleph VM Supervisor")


async def try_get_message(ref: str) -> ProgramMessage:
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


async def build_asgi_scope(path: str, request: web.Request) -> Dict[str, Any]:
    return {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": request.raw_headers,
        "body": await request.text()
    }


async def run_code(message_ref: str, path: str, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """

    message: ProgramMessage = await try_get_message(message_ref)
    message_content: ProgramContent = message.content

    try:
        vm = await pool.get_a_vm(message_content)
    except ResourceDownloadError as error:
        logger.exception(error)
        raise HTTPBadRequest(reason="Code, runtime or data not available")
    except VmSetupError as error:
        logger.exception(error)
        raise HTTPInternalServerError(reason="Error during program initialisation")

    logger.debug(f"Using vm={vm.vm_id}")

    scope: Dict = await build_asgi_scope(path, request)

    try:
        result_raw: bytes = await vm.run_code(scope=scope)
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
            pool.keep_in_cache(vm, message_content, timeout=settings.REUSE_TIMEOUT)
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


def b32_to_b16(hash: str) -> bytes:
    """Convert base32 encoded bytes to base16 encoded bytes."""
    # Add padding
    hash_b32: str = hash.upper() + "=" * (56 - len(hash))
    hash_bytes: bytes = b32decode(hash_b32.encode())
    return b16encode(hash_bytes).lower()


async def run_code_from_hostname(request: web.Request) -> web.Response:
    """Allow running an Aleph VM function from a hostname

    The first component of the hostname is used as identifier of the message defining the
    Aleph VM function.

    Since hostname labels are limited to 63 characters and hex(sha256(...)) has a length of 64,
    we expect the hash to be encoded in base32 instead of hexadecimal. Padding is added
    automatically.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref_base32 = request.host.split(".")[0]
    if settings.FAKE_DATA:
        message_ref = "test"
    else:
        try:
            message_ref = b32_to_b16(message_ref_base32).decode()
        except binascii.Error:
            raise HTTPNotFound(reason="Invalid message reference")

    return await run_code(message_ref, path, request)


app = web.Application()

app.add_routes([web.route("*", "/vm/{ref}{suffix:.*}", run_code_from_path)])
app.add_routes([web.route("*", "/{suffix:.*}", run_code_from_hostname)])


def run():
    """Run the VM Supervisor."""
    settings.check()
    web.run_app(app)
