"""
The VM Supervisor is in charge of executing code, starting and stopping VMs and provides
and API to launch these operations.

At it's core, it is currently an asynchronous HTTP server using aiohttp, but this may
evolve in the future.
"""
import logging
from secrets import token_urlsafe

from aiohttp import web

from .conf import settings
from .tasks import start_watch_for_messages_task, stop_watch_for_messages_task
from .views import (
    run_code_from_path,
    run_code_from_hostname,
    about_login,
    about_executions,
    about_config,
    status_check_fastapi,
)

logger = logging.getLogger(__name__)

app = web.Application()

app.add_routes(
    [
        web.get("/about/login", about_login),
        web.get("/about/executions", about_executions),
        web.get("/about/config", about_config),
        web.get("/status/check/fastapi", status_check_fastapi),
        web.route("*", "/vm/{ref}{suffix:.*}", run_code_from_path),
        web.route("*", "/{suffix:.*}", run_code_from_hostname),
    ]
)


def run():
    """Run the VM Supervisor."""
    settings.check()

    # Require a random token to access /about APIs
    secret_token = token_urlsafe(nbytes=32)
    app["secret_token"] = secret_token
    print(f"Login to /about pages /about/login?token={secret_token}")

    if settings.WATCH_FOR_MESSAGES:
        app.on_startup.append(start_watch_for_messages_task)
        app.on_cleanup.append(stop_watch_for_messages_task)

    web.run_app(app, host=settings.SUPERVISOR_HOST,
                port=settings.SUPERVISOR_PORT)
