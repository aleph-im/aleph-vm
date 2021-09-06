import binascii
import logging
from typing import Awaitable

import aiodns
from aiohttp import web
from aiohttp.web_exceptions import HTTPNotFound

from .conf import settings
from .models import VmHash
from .run import run_code_on_request, pool
from .utils import b32_to_b16, get_ref_from_dns, dumps_for_json

logger = logging.getLogger(__name__)


def run_code_from_path(request: web.Request) -> Awaitable[web.Response]:
    """Allow running an Aleph VM function from a URL path

    The path is expected to follow the scheme defined in `app.add_routes` below,
    where the identifier of the message is named `ref`.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref: VmHash = request.match_info["ref"]
    return run_code_on_request(message_ref, path, request)


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
        message_ref = "TEST_HASH"
    else:
        try:
            message_ref = b32_to_b16(message_ref_base32).decode()
            logger.debug(
                f"Using base32 message id from hostname to obtain '{message_ref}"
            )
        except binascii.Error:
            try:
                message_ref = await get_ref_from_dns(domain=f"_aleph-id.{request.host}")
                logger.debug(f"Using DNS TXT record to obtain '{message_ref}'")
            except aiodns.error.DNSError:
                raise HTTPNotFound(reason="Invalid message reference")

    return await run_code_on_request(message_ref, path, request)


def authenticate_request(request: web.Request):
    """Check that the token in the cookies matches the app's secret token."""
    if request.cookies.get("token") != request.app["secret_token"]:
        raise web.HTTPUnauthorized(reason="Invalid token")


async def about_login(request: web.Request):
    token = request.query.get("token")
    if token == request.app["secret_token"]:
        response = web.HTTPFound("/about/config")
        response.cookies["token"] = token
        return response
    else:
        return web.json_response({"success": False}, status=401)


async def about_executions(request: web.Request):
    authenticate_request(request)
    return web.json_response(
        [{key: value for key, value in pool.executions.items()}],
        dumps=dumps_for_json,
    )


async def about_config(request: web.Request):
    authenticate_request(request)
    return web.json_response(
        settings,
        dumps=dumps_for_json,
    )


async def index(request: web.Request):
    assert request.method == "GET"
    return web.Response(text="Server: Aleph VM Supervisor")
