"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""
import asyncio
import logging
import os.path
from multiprocessing import Process, set_start_method
from os import system
from typing import Optional, Tuple

import msgpack
from aiohttp import web, ClientResponseError, ClientConnectorError
from aiohttp.web_exceptions import HTTPNotFound, HTTPBadRequest, HTTPServiceUnavailable

from guest_api.__main__ import run_guest_api
from .conf import settings
from .models import FilePath, FunctionMessage
from .pool import VmPool
from .storage import get_code_path, get_runtime_path, get_message, get_data_path
from .vm.firecracker_microvm import AlephFirecrackerResources

logger = logging.getLogger(__name__)
pool = VmPool()

set_start_method('spawn')


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


def build_asgi_scope(request: web.Request):
    path = request.match_info["suffix"]
    if not path.startswith("/"):
        path = "/" + path

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
        return b''


async def run_code(request: web.Request):
    """
    Execute the code corresponding to the 'code id' in the path.
    """
    message_ref: str = request.match_info["ref"]
    message = await try_get_message(message_ref)

    # vm_resources = AlephFirecrackerResources(message)
    #
    # try:
    #     await vm_resources.download_all()
    # except ClientResponseError as error:
    #     if error.status == 404:
    #         raise HTTPBadRequest(reason="Code, runtime or data not found")
    #     else:
    #         raise

    vm = await pool.get_a_vm(message)
    await vm.start_guest_api()
    logger.debug(f"Using vm={vm.vm_id}")

    scope = build_asgi_scope(request)

    code: bytes = load_file_content(vm.resources.code_path)
    input_data: bytes = load_file_content(vm.resources.data_path)

    result_raw: bytes = await vm.run_code(
        code=code,
        entrypoint=message.content.code.entrypoint,
        input_data=input_data,
        encoding=message.content.code.encoding,
        scope=scope,
    )

    result = msgpack.loads(result_raw, raw=False)

    await vm.teardown()

    # TODO: Handle other content-types
    return web.Response(body=result['body']['body'],
                        content_type="application/json")


app = web.Application()

app.add_routes([web.get("/", index)])
app.add_routes([web.route("*", "/vm/function/{ref}{suffix:.*}", run_code)])


def run():
    """Run the VM Supervisor."""
    settings.check()
    web.run_app(app)
