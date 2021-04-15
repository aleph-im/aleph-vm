"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""

import asyncio
import logging
import os.path
from os import system

from aiohttp import web

from .conf import settings
from .pool import VmPool
from .storage import get_code

logger = logging.getLogger(__name__)
pool = VmPool()


async def index(request: web.Request):
    return web.Response(text="Hello, world")


async def run_code(request: web.Request):
    """
    Execute the code corresponding to the 'code id' in the path.
    """
    code_id = request.match_info['code_id']
    code, entrypoint, encoding = get_code(code_id)

    runtime = 'aleph-alpine-3.13-python'
    kernel_image_path = os.path.abspath('./kernels/vmlinux.bin')
    rootfs_path = os.path.abspath(f"./runtimes/{runtime}/rootfs.ext4")

    vm = await pool.get_a_vm(
        kernel_image_path=kernel_image_path,
        rootfs_path=rootfs_path)

    path = request.match_info['suffix']
    if not path.startswith('/'):
        path = '/' + path

    logger.debug(f"Using vm={vm.vm_id}")
    scope = {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": request.raw_headers,
    }
    result = {
        'output': (await vm.run_code(code, entrypoint=entrypoint,
                                     encoding=encoding, scope=scope)).decode()
    }
    await vm.stop()
    system(f"rm -fr {vm.jailer_path}")
    return web.json_response(result)


app = web.Application()

app.add_routes([web.get('/', index)])
app.add_routes([web.route('*', '/run/{code_id}{suffix:.*}', run_code)])

def run():
    """Run the VM Supervisor."""

    runtime = 'aleph-alpine-3.13-python'
    kernel_image_path = os.path.abspath('./kernels/vmlinux.bin')
    rootfs_path = os.path.abspath(f"./runtimes/{runtime}/rootfs.ext4")

    for path in (settings.FIRECRACKER_PATH,
                 settings.JAILER_PATH,
                 kernel_image_path,
                 rootfs_path):
        if not os.path.isfile(path):
            raise FileNotFoundError(path)

    loop = asyncio.get_event_loop()
    for i in range(settings.PREALLOC_VM_COUNT):
        loop.create_task(pool.provision(kernel_image_path=kernel_image_path,
                                        rootfs_path=rootfs_path))
    web.run_app(app)
