import binascii
import logging
import os.path
from string import Template
from typing import Awaitable, Optional

import aiodns
import aiohttp
from aiohttp import web
from aiohttp.web_exceptions import HTTPNotFound
from packaging.version import Version, InvalidVersion
from pydantic import ValidationError

from . import status, __version__
from .conf import settings
from .metrics import get_execution_records
from .models import VmHash
from .resources import Allocation
from .run import run_code_on_request, pool, start_long_running
from .utils import b32_to_b16, get_ref_from_dns, dumps_for_json

logger = logging.getLogger(__name__)


def run_code_from_path(request: web.Request) -> Awaitable[web.Response]:
    """Allow running an Aleph VM function from a URL path

    The path is expected to follow the scheme defined in `app.add_routes` below,
    where the identifier of the message is named `ref`.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref = VmHash(request.match_info["ref"])
    return run_code_on_request(message_ref, path, request)


async def run_code_from_hostname(request: web.Request) -> web.Response:
    """Allow running an Aleph VM function from a hostname

    The first component of the hostname is used as identifier of the message defining the
    Aleph VM function.

    Since hostname labels are limited to 63 characters and hex(sha256(...)) has a length of 64,
    we expect the hash to be encoded in base32 instead of hexadecimal. Padding is added
    automatically.
    """
    if (
        request.host.split(":")[0] == settings.DOMAIN_NAME
        and request.method == "GET"
        and request.path == "/"
    ):
        # Serve the index page
        return await index(request=request)

    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref_base32 = request.host.split(".")[0]
    if settings.FAKE_DATA_PROGRAM:
        message_ref = VmHash("fake-hash")
    else:
        try:
            message_ref = VmHash(b32_to_b16(message_ref_base32).decode())
            logger.debug(
                f"Using base32 message id from hostname to obtain '{message_ref}"
            )
        except binascii.Error:
            try:
                message_ref = VmHash(
                    await get_ref_from_dns(domain=f"_aleph-id.{request.host}")
                )
                logger.debug(f"Using DNS TXT record to obtain '{message_ref}'")
            except aiodns.error.DNSError:
                raise HTTPNotFound(reason="Invalid message reference")

    return await run_code_on_request(message_ref, path, request)


def authenticate_request(request: web.Request) -> web.Response:
    """Check that the token in the cookies matches the app's secret token."""
    if request.cookies.get("token") != request.app["secret_token"]:
        raise web.HTTPUnauthorized(reason="Invalid token", text="401 Invalid token")


async def about_login(request: web.Request) -> web.Response:
    token = request.query.get("token")
    if token == request.app["secret_token"]:
        response = web.HTTPFound("/about/config")
        response.cookies["token"] = token
        return response
    else:
        return web.json_response({"success": False}, status=401)


async def about_executions(request: web.Request) -> web.Response:
    authenticate_request(request)
    return web.json_response(
        [{key: value for key, value in pool.executions.items()}],
        dumps=dumps_for_json,
    )


async def about_config(request: web.Request) -> web.Response:
    authenticate_request(request)
    return web.json_response(
        settings,
        dumps=dumps_for_json,
    )


async def about_execution_records(request: web.Request):
    records = await get_execution_records()
    return web.json_response(
        records,
        dumps=dumps_for_json,
    )


async def index(request: web.Request):
    assert request.method == "GET"
    path = os.path.join(os.path.dirname(__file__), "templates/index.html")
    with open(path, "r") as template:
        body = template.read()
        s = Template(body)
        body = s.substitute(
            public_url=f"https://{settings.DOMAIN_NAME}/",
            multiaddr_dns4=f"/dns4/{settings.DOMAIN_NAME}/tcp/443/https",
            multiaddr_dns6=f"/dns6/{settings.DOMAIN_NAME}/tcp/443/https",
            check_fastapi_vm_id=settings.CHECK_FASTAPI_VM_ID,
            version=__version__,
        )
    return web.Response(content_type="text/html", body=body)


async def status_check_fastapi(request: web.Request):
    async with aiohttp.ClientSession() as session:
        result = {
            "index": await status.check_index(session),
            "environ": await status.check_environ(session),
            "messages": await status.check_messages(session),
            "internet": await status.check_internet(session),
            "cache": await status.check_cache(session),
            "persistent_storage": await status.check_persistent_storage(session),
            "error_handling": await status.check_error_raised(session),
        }
        return web.json_response(result, status=200 if all(result.values()) else 503)


async def status_check_version(request: web.Request):
    """Check if the software is running a version equal or newer than the given one"""
    reference_str: Optional[str] = request.query.get("reference")
    if not reference_str:
        raise web.HTTPBadRequest(text="Query field '?reference=` must be specified")
    try:
        reference = Version(reference_str)
    except InvalidVersion as error:
        raise web.HTTPBadRequest(text=error.args[0])

    try:
        current = Version(__version__)
    except InvalidVersion as error:
        raise web.HTTPServiceUnavailable(text=error.args[0])

    if current >= reference:
        return web.Response(
            status=200, text=f"Up-to-date: version {current} >= {reference}"
        )
    else:
        return web.HTTPForbidden(text=f"Outdated: version {current} < {reference}")


async def update_allocations(request: web.Request):
    # TODO: Add some form of authentication
    try:
        data = await request.json()
        allocation = Allocation(**data)
    except ValidationError as error:
        return web.json_response(
            data=error.json(), status=web.HTTPBadRequest.status_code
        )

    pubsub = request.app["pubsub"]

    for vm_hash in allocation.long_running_vms:
        vm_hash = VmHash(vm_hash)
        logger.info(f"Starting long running VM {vm_hash}")
        await start_long_running(vm_hash, pubsub)

    for execution in pool.get_long_running_executions():
        if execution.vm_hash not in allocation.long_running_vms:
            logger.info(f"Stopping long running VM {execution.vm_hash}")
            await execution.stop()
            execution.marked_as_long_running = False

    if allocation.on_demand_vms:
        logger.info("Not supported yet: 'allocation.on_demand_vms'")
    if allocation.jobs:
        logger.info("Not supported yet: 'allocation.on_demand_vms'")

    return web.json_response(data={"success": True})
