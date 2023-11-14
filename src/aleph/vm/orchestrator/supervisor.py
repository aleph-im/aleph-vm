"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""
import logging
from collections.abc import Awaitable
from pathlib import Path
from secrets import token_urlsafe
from typing import Callable

from aiohttp import web

from aleph.vm.version import __version__

from ..conf import settings
from ..pool import VmPool
from .metrics import create_tables, setup_engine
from .resources import about_system_usage
from .tasks import start_watch_for_messages_task, stop_watch_for_messages_task
from .views import (
    about_config,
    about_execution_records,
    about_executions,
    about_login,
    run_code_from_hostname,
    run_code_from_path,
    status_check_fastapi,
    status_check_version,
    status_public_config,
    update_allocations,
)
from .views.operator import operate_erase, operate_expire, operate_stop, stream_logs

logger = logging.getLogger(__name__)


@web.middleware
async def server_version_middleware(
    request: web.Request,
    handler: Callable[[web.Request], Awaitable[web.StreamResponse]],
) -> web.StreamResponse:
    """Add the version of Aleph-VM in the HTTP headers of the responses."""
    resp: web.StreamResponse = await handler(request)
    resp.headers.update(
        {"Server": f"aleph-vm/{__version__}"},
    )
    return resp


app = web.Application(middlewares=[server_version_middleware])

app.add_routes(
    [
        web.get("/about/login", about_login),
        web.get("/about/executions", about_executions),
        web.get("/about/executions/records", about_execution_records),
        web.get("/about/usage/system", about_system_usage),
        web.get("/about/config", about_config),
        web.post("/control/allocations", update_allocations),
        web.get("/control/machine/{ref}/logs", stream_logs),
        web.post("/control/machine/{ref}/expire", operate_expire),
        web.post("/control/machine/{ref}/stop", operate_stop),
        web.post("/control/machine/{ref}/erase", operate_erase),
        web.get("/status/check/fastapi", status_check_fastapi),
        web.get("/status/check/version", status_check_version),
        web.get("/status/config", status_public_config),
        web.static("/static", Path(__file__).parent / "views/static"),
        web.route("*", "/vm/{ref}{suffix:.*}", run_code_from_path),
        web.route("*", "/{suffix:.*}", run_code_from_hostname),
    ]
)


async def stop_all_vms(app: web.Application):
    pool: VmPool = app["vm_pool"]
    await pool.stop()


def run():
    """Run the VM Supervisor."""
    settings.check()
    pool = VmPool()
    pool.setup()

    hostname = settings.DOMAIN_NAME
    protocol = "http" if hostname == "localhost" else "https"

    # Require a random token to access /about APIs
    secret_token = token_urlsafe(nbytes=32)
    # Store app singletons. Note that app["pubsub"] will also be created.
    app["secret_token"] = secret_token
    app["vm_pool"] = pool

    print(f"Login to /about pages {protocol}://{hostname}/about/login?token={secret_token}")

    engine = setup_engine()
    create_tables(engine)

    try:
        if settings.WATCH_FOR_MESSAGES:
            app.on_startup.append(start_watch_for_messages_task)
            app.on_cleanup.append(stop_watch_for_messages_task)
            app.on_cleanup.append(stop_all_vms)

        web.run_app(app, host=settings.SUPERVISOR_HOST, port=settings.SUPERVISOR_PORT)
    except OSError as e:
        if e.errno == 98:
            logger.error(
                f"Port {settings.SUPERVISOR_PORT} already in use. "
                f"Please check that no other instance of Aleph-VM is running."
            )
        else:
            raise
    finally:
        if settings.ALLOW_VM_NETWORKING:
            pool.teardown()
