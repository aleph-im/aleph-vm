"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""

import asyncio
import logging
from collections.abc import Awaitable
from pathlib import Path
from secrets import token_urlsafe
from typing import Callable

from aiohttp import web
from aiohttp_cors import ResourceOptions, setup

from aleph.vm.conf import settings
from aleph.vm.pool import VmPool
from aleph.vm.sevclient import SevClient
from aleph.vm.version import __version__

from .metrics import create_tables, setup_engine
from .resources import about_certificates, about_system_usage
from .tasks import (
    start_payment_monitoring_task,
    start_watch_for_messages_task,
    stop_balances_monitoring_task,
    stop_watch_for_messages_task,
)
from .views import (
    about_config,
    about_execution_records,
    about_executions,
    about_login,
    list_executions,
    notify_allocation,
    run_code_from_hostname,
    run_code_from_path,
    status_check_fastapi,
    status_check_fastapi_legacy,
    status_check_host,
    status_check_ipv6,
    status_check_version,
    status_public_config,
    update_allocations,
)
from .views.operator import (
    operate_confidential_initialize,
    operate_confidential_inject_secret,
    operate_confidential_measurement,
    operate_erase,
    operate_expire,
    operate_logs,
    operate_reboot,
    operate_stop,
    stream_logs,
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


async def http_not_found(request: web.Request):
    """Return a 404 error for unknown URLs."""
    return web.HTTPNotFound()


def setup_webapp():
    app = web.Application(middlewares=[server_version_middleware])
    cors = setup(
        app,
        defaults={
            "*": ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
            )
        },
    )

    # Routes that need CORS enabled
    cors_routes = [
        # /about APIs return information about the VM Orchestrator
        web.get("/about/login", about_login),
        web.get("/about/executions/list", list_executions),
        web.get("/about/executions/details", about_executions),
        web.get("/about/executions/records", about_execution_records),
        web.get("/about/usage/system", about_system_usage),
        web.get("/about/certificates", about_certificates),
        web.get("/about/config", about_config),
        # /control APIs are used to control the VMs and access their logs
        web.post("/control/allocation/notify", notify_allocation),
        web.get("/control/machine/{ref}/stream_logs", stream_logs),
        web.get("/control/machine/{ref}/logs", operate_logs),
        web.post("/control/machine/{ref}/expire", operate_expire),
        web.post("/control/machine/{ref}/stop", operate_stop),
        web.post("/control/machine/{ref}/erase", operate_erase),
        web.post("/control/machine/{ref}/reboot", operate_reboot),
        web.post("/control/machine/{ref}/confidential/initialize", operate_confidential_initialize),
        web.get("/control/machine/{ref}/confidential/measurement", operate_confidential_measurement),
        web.post("/control/machine/{ref}/confidential/inject_secret", operate_confidential_inject_secret),
        # /status APIs are used to check that the VM Orchestrator is running properly
        web.get("/status/check/fastapi", status_check_fastapi),
        web.get("/status/check/fastapi/legacy", status_check_fastapi_legacy),
        web.get("/status/check/host", status_check_host),
        web.get("/status/check/version", status_check_version),
        web.get("/status/check/ipv6", status_check_ipv6),
        web.get("/status/config", status_public_config),
    ]
    routes = app.add_routes(cors_routes)
    for route in routes:
        cors.add(route)

    # Routes that don't need CORS enabled
    other_routes = [
        # /control APIs are used to control the VMs and access their logs
        web.post("/control/allocations", update_allocations),
        # Raise an HTTP Error 404 if attempting to access an unknown URL within these paths.
        web.get("/about/{suffix:.*}", http_not_found),
        web.get("/control/{suffix:.*}", http_not_found),
        web.get("/status/{suffix:.*}", http_not_found),
        # /static is used to serve static files
        web.static("/static", Path(__file__).parent / "views/static"),
        # /vm is used to launch VMs on-demand
        web.route("*", "/vm/{ref}{suffix:.*}", run_code_from_path),
        web.route("*", "/{suffix:.*}", run_code_from_hostname),
    ]
    app.add_routes(other_routes)
    return app


async def stop_all_vms(app: web.Application):
    pool: VmPool = app["vm_pool"]
    await pool.stop()


def run():
    """Run the VM Supervisor."""
    settings.check()

    engine = setup_engine()
    asyncio.run(create_tables(engine))

    loop = asyncio.new_event_loop()
    pool = VmPool(loop)
    pool.setup()

    hostname = settings.DOMAIN_NAME
    protocol = "http" if hostname == "localhost" else "https"

    # Require a random token to access /about APIs
    secret_token = token_urlsafe(nbytes=32)
    app = setup_webapp()
    # Store app singletons. Note that app["pubsub"] will also be created.
    app["secret_token"] = secret_token
    app["vm_pool"] = pool

    # Store sevctl app singleton only if confidential feature is enabled
    if settings.ENABLE_CONFIDENTIAL_COMPUTING:
        sev_client = SevClient(settings.CONFIDENTIAL_DIRECTORY, settings.SEV_CTL_PATH)
        app["sev_client"] = sev_client
        # TODO: Review and check sevctl first initialization steps, like (sevctl generate and sevctl provision)

    logger.info(f"Login to /about pages {protocol}://{hostname}/about/login?token={secret_token}")

    try:
        if settings.WATCH_FOR_MESSAGES:
            app.on_startup.append(start_watch_for_messages_task)
            app.on_startup.append(start_payment_monitoring_task)
            app.on_cleanup.append(stop_watch_for_messages_task)
            app.on_cleanup.append(stop_balances_monitoring_task)
            app.on_cleanup.append(stop_all_vms)

        logger.info("Loading existing executions ...")
        asyncio.run(pool.load_persistent_executions())

        logger.info(f"Starting the web server on http://{settings.SUPERVISOR_HOST}:{settings.SUPERVISOR_PORT}")
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
