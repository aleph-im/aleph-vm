"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
an API to launch these operations.

At its core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""

import asyncio
import logging
from pathlib import Path
from secrets import token_urlsafe

from aiohttp import hdrs, web
from aiohttp.web_exceptions import HTTPException
from aiohttp_cors import ResourceOptions, setup

from aleph.vm.conf import settings
from aleph.vm.pool import VmPool
from aleph.vm.sevclient import SevClient
from aleph.vm.version import __version__

from .resources import about_capability, about_certificates, about_system_usage
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
    debug_haproxy,
    list_executions,
    list_executions_v2,
    notify_allocation,
    operate_reserve_resources,
    operate_update,
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
    operate_logs_json,
    operate_reboot,
    operate_stop,
    stream_logs,
)

logger = logging.getLogger(__name__)


@web.middleware
async def error_middleware(request, handler) -> web.Response:
    "Ensure we always return a JSON response for errors."
    try:
        response = await handler(request)
        if response.status == 404:
            message = response.text
            status = response.status
            return web.json_response({"error": message}, status=status)
        if isinstance(response, HTTPException):
            if response.headers[hdrs.CONTENT_TYPE] != "application/json":
                message = response.text or response.reason
                status = response.status
                return web.json_response(
                    {"error": message},
                    status=status,
                )
        return response
    except web.HTTPException as exc:
        message = exc.text or exc.reason
        status = exc.status
        return web.json_response({"error": message}, status=status)
    except Exception as exc:
        logger.exception("Unhandled exception for %s", request.path)
        message = str(exc)
        status = 500
        return web.json_response({"error": message, "error_type": str(type(exc))}, status=status)
    assert False, "unreachable"


async def on_prepare_server_version(request: web.Request, response: web.Response) -> None:
    """Add the version of Aleph-VM in the HTTP headers of the responses."""
    response.headers["Server"] = f"aleph-vm/{__version__}"


async def http_not_found(request: web.Request):  # noqa: ARG001
    """Return a 404 error for unknown URLs."""
    return web.HTTPNotFound()


def setup_webapp(pool: VmPool | None):
    """Create the webapp and set the VmPool

    Only case where VmPool is None is in some tests that won't use it.
    """
    app = web.Application(middlewares=[error_middleware])
    app.on_response_prepare.append(on_prepare_server_version)
    app["vm_pool"] = pool
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
        web.get("/v2/about/executions/list", list_executions_v2),
        web.get("/about/executions/details", about_executions),
        web.get("/about/executions/records", about_execution_records),
        web.get("/about/usage/system", about_system_usage),
        web.get("/about/certificates", about_certificates),
        web.get("/about/capability", about_capability),
        web.get("/about/config", about_config),
        # /control APIs are used to control the VMs and access their logs
        web.post("/control/allocation/notify", notify_allocation),
        web.post("/control/reserve_resources", operate_reserve_resources),
        web.post("/control/machine/{ref}/update", operate_update),
        web.get("/control/machine/{ref}/stream_logs", stream_logs),
        web.get("/control/machine/{ref}/logs", operate_logs_json),
        web.post("/control/machine/{ref}/expire", operate_expire),
        web.post("/control/machine/{ref}/stop", operate_stop),
        web.post("/control/machine/{ref}/erase", operate_erase),
        web.post("/control/machine/{ref}/reboot", operate_reboot),
        web.post("/control/machine/{ref}/confidential/initialize", operate_confidential_initialize),
        web.get("/control/machine/{ref}/confidential/measurement", operate_confidential_measurement),
        web.post("/control/machine/{ref}/confidential/inject_secret", operate_confidential_inject_secret),
        web.get("/debug/haproxy", debug_haproxy),
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

    loop = asyncio.new_event_loop()
    pool = VmPool()
    asyncio.run(pool.setup())

    hostname = settings.DOMAIN_NAME
    protocol = "http" if hostname == "localhost" else "https"

    # Require a random token to access /about APIs
    secret_token = token_urlsafe(nbytes=32)
    (settings.EXECUTION_ROOT / "login_token").write_text(secret_token)
    (settings.EXECUTION_ROOT / "login_token").chmod(0o400)
    app = setup_webapp(pool=pool)
    # Store app singletons. Note that app["pubsub"] will also be created.
    app["secret_token"] = secret_token

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
