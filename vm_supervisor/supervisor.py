"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""
import logging
from secrets import token_urlsafe
from typing import Awaitable, Callable

from aiohttp import web

from . import __version__
from . import metrics
from .conf import settings
from .resources import about_system_usage
from .run import pool
from .tasks import start_watch_for_messages_task, stop_watch_for_messages_task
from .views import (
    run_code_from_path,
    run_code_from_hostname,
    about_login,
    about_executions,
    about_config,
    status_check_fastapi,
    about_execution_records, status_check_version,
)

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
        web.get("/status/check/fastapi", status_check_fastapi),
        web.get("/status/check/version", status_check_version),
        web.route("*", "/vm/{ref}{suffix:.*}", run_code_from_path),
        web.route("*", "/{suffix:.*}", run_code_from_hostname),
    ]
)


async def stop_all_vms(app: web.Application):
    await pool.stop()


def run():
    """Run the VM Supervisor."""
    settings.check()

    hostname = settings.DOMAIN_NAME
    protocol = "http" if hostname == "localhost" else "https"

    # Require a random token to access /about APIs
    secret_token = token_urlsafe(nbytes=32)
    app["secret_token"] = secret_token
    print(
        f"Login to /about pages {protocol}://{hostname}/about/login?token={secret_token}"
    )

    engine = metrics.setup_engine()
    metrics.create_tables(engine)

    if settings.WATCH_FOR_MESSAGES:
        app.on_startup.append(start_watch_for_messages_task)
        app.on_cleanup.append(stop_watch_for_messages_task)
        app.on_cleanup.append(stop_all_vms)

    web.run_app(app, host=settings.SUPERVISOR_HOST, port=settings.SUPERVISOR_PORT)
