"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""

import logging
import os.path
from os import system

from aiohttp import web, ClientResponseError, ClientConnectorError
from aiohttp.web_exceptions import HTTPNotFound, HTTPBadRequest, HTTPServiceUnavailable

from .conf import settings
from .models import FilePath
from .pool import VmPool
from .storage import get_code, get_runtime, get_message

logger = logging.getLogger(__name__)
pool = VmPool()


async def index(request: web.Request):
    assert request
    return web.Response(text="Server: Aleph VM Supervisor")


async def run_code(request: web.Request):
    """
    Execute the code corresponding to the 'code id' in the path.
    """
    msg_ref: str = request.match_info["ref"]

    try:
        msg = await get_message(msg_ref)
    except ClientConnectorError:
        raise HTTPServiceUnavailable(reason="Aleph Connector unavailable")
    except ClientResponseError as error:
        if error.status == 404:
            raise HTTPNotFound(reason="Hash not found")
        else:
            raise

    code_ref: str = msg.content.code.ref
    runtime_ref: str = msg.content.runtime.ref
    # data_ref: str = msg.content['data']['ref']

    try:
        code_path: FilePath = await get_code(code_ref)
        rootfs_path: FilePath = await get_runtime(runtime_ref)
        # data_path: FilePath = await get_data(data_ref)
    except ClientResponseError as error:
        if error.status == 404:
            raise HTTPBadRequest(reason="Code or runtime not found")
        else:
            raise

    logger.debug("Got files")

    kernel_image_path = settings.LINUX_PATH

    vm = await pool.get_a_vm(
        kernel_image_path=kernel_image_path, rootfs_path=rootfs_path
    )

    path = request.match_info["suffix"]
    if not path.startswith("/"):
        path = "/" + path

    logger.debug(f"Using vm={vm.vm_id}")
    scope = {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": request.raw_headers,
    }
    with open(code_path, "rb") as code_file:
        result = await vm.run_code(
            code_file.read(),
            entrypoint=msg.content.code.entrypoint,
            encoding=msg.content.code.encoding,
            scope=scope,
        )
    await vm.stop()
    system(f"rm -fr {vm.jailer_path}")
    # TODO: Handle other content-types
    return web.Response(body=result, content_type="application/json")


app = web.Application()

app.add_routes([web.get("/", index)])
app.add_routes([web.route("*", "/vm/function/{ref}{suffix:.*}", run_code)])


def run():
    """Run the VM Supervisor."""

    # runtime = 'aleph-alpine-3.13-python'
    kernel_image_path = os.path.abspath("./kernels/vmlinux.bin")
    # rootfs_path = os.path.abspath(f"./runtimes/{runtime}/rootfs.ext4")

    for path in (settings.FIRECRACKER_PATH, settings.JAILER_PATH, kernel_image_path):
        if not os.path.isfile(path):
            raise FileNotFoundError(path)

    web.run_app(app)
