import binascii
import logging
from collections.abc import Awaitable
from hashlib import sha256
from pathlib import Path
from string import Template
from typing import Optional

import aiodns
import aiohttp
from aiohttp import web
from aiohttp.web_exceptions import HTTPNotFound
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash
from pydantic import ValidationError

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import (
    ResourceDownloadError,
    VmSetupError,
)
from aleph.vm.controllers.firecracker.program import FileTooLargeError
from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError
from aleph.vm.orchestrator import status
from aleph.vm.orchestrator.metrics import get_execution_records
from aleph.vm.orchestrator.pubsub import PubSub
from aleph.vm.orchestrator.resources import Allocation, VMNotification
from aleph.vm.orchestrator.run import run_code_on_request, start_persistent_vm
from aleph.vm.orchestrator.views.host_status import (
    check_dns_ipv4,
    check_dns_ipv6,
    check_domain_resolution_ipv4,
    check_domain_resolution_ipv6,
    check_host_egress_ipv4,
    check_host_egress_ipv6,
)
from aleph.vm.pool import VmPool
from aleph.vm.utils import (
    HostNotFoundError,
    b32_to_b16,
    dumps_for_json,
    get_ref_from_dns,
)
from aleph.vm.version import __version__
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)


def run_code_from_path(request: web.Request) -> Awaitable[web.Response]:
    """Allow running an Aleph VM function from a URL path

    The path is expected to follow the scheme defined in `app.add_routes` below,
    where the identifier of the message is named `ref`.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref = ItemHash(request.match_info["ref"])
    pool: VmPool = request.app["vm_pool"]
    return run_code_on_request(message_ref, path, pool, request)


async def run_code_from_hostname(request: web.Request) -> web.Response:
    """Allow running an Aleph VM function from a hostname

    The first component of the hostname is used as identifier of the message defining the
    Aleph VM function.

    Since hostname labels are limited to 63 characters and hex(sha256(...)) has a length of 64,
    we expect the hash to be encoded in base32 instead of hexadecimal. Padding is added
    automatically.
    """
    if request.host.split(":")[0] == settings.DOMAIN_NAME and request.method == "GET" and request.path == "/":
        # Serve the index page
        return await index(request=request)

    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref_base32 = request.host.split(".")[0]
    if settings.FAKE_DATA_PROGRAM:
        message_ref = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    else:
        try:
            message_ref = ItemHash(b32_to_b16(message_ref_base32).decode())
            logger.debug(f"Using base32 message id from hostname to obtain '{message_ref}")
        except binascii.Error:
            try:
                message_ref = ItemHash(await get_ref_from_dns(domain=f"_aleph-id.{request.host}"))
                logger.debug(f"Using DNS TXT record to obtain '{message_ref}'")
            except aiodns.error.DNSError as error:
                raise HTTPNotFound(reason="Invalid message reference") from error

    pool = request.app["vm_pool"]
    return await run_code_on_request(message_ref, path, pool, request)


def authenticate_request(request: web.Request) -> None:
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
    pool: VmPool = request.app["vm_pool"]
    return web.json_response(
        [dict(pool.executions.items())],
        dumps=dumps_for_json,
    )


async def about_config(request: web.Request) -> web.Response:
    authenticate_request(request)
    return web.json_response(
        settings,
        dumps=dumps_for_json,
    )


async def about_execution_records(_: web.Request):
    records = await get_execution_records()
    return web.json_response(
        records,
        dumps=dumps_for_json,
    )


async def index(request: web.Request):
    assert request.method == "GET"
    body = (Path(__file__).parent.absolute() / "templates/index.html").read_text()
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
    retro_compatibility: bool = request.rel_url.query.get("retro-compatibility", "false") == "true"

    async with aiohttp.ClientSession() as session:
        result = {
            "index": await status.check_index(session),
            "environ": await status.check_environ(session),
            "messages": await status.check_messages(session),
            "dns": await status.check_dns(session),
            "ipv4": await status.check_ipv4(session),
            "internet": await status.check_internet(session),
            "cache": await status.check_cache(session),
            "persistent_storage": await status.check_persistent_storage(session),
            "error_handling": await status.check_error_raised(session),
        }
        if not retro_compatibility:
            # These fields were added in the runtime running Debian 12.
            result = result | {
                "lifespan": await status.check_lifespan(session),
                # IPv6 requires extra work from node operators and is not required yet.
                # "ipv6": await status.check_ipv6(session),
            }

        return web.json_response(result, status=200 if all(result.values()) else 503)


async def status_check_host(request: web.Request):
    """Check that the platform is supported and configured correctly"""

    result = {
        "ipv4": {
            "egress": await check_host_egress_ipv4(),
            "dns": await check_dns_ipv4(),
            "domain": await check_domain_resolution_ipv4(),
        },
        "ipv6": {
            "egress": await check_host_egress_ipv6(),
            "dns": await check_dns_ipv6(),
            "domain": await check_domain_resolution_ipv6(),
        },
    }
    result_status = 200 if all(result["ipv4"].values()) and all(result["ipv6"].values()) else 503
    return web.json_response(result, status=result_status)


async def status_check_version(request: web.Request):
    """Check if the software is running a version equal or newer than the given one"""
    reference_str: Optional[str] = request.query.get("reference")
    if not reference_str:
        raise web.HTTPBadRequest(text="Query field '?reference=` must be specified")
    try:
        reference = Version(reference_str)
    except InvalidVersion as error:
        raise web.HTTPBadRequest(text=error.args[0]) from error

    try:
        current = Version(__version__)
    except InvalidVersion as error:
        raise web.HTTPServiceUnavailable(text=error.args[0]) from error

    if current >= reference:
        return web.Response(status=200, text=f"Up-to-date: version {current} >= {reference}")
    else:
        return web.HTTPForbidden(text=f"Outdated: version {current} < {reference}")


async def status_public_config(request: web.Request):
    """Expose the public fields from the configuration"""
    return web.json_response(
        {
            "DOMAIN_NAME": settings.DOMAIN_NAME,
            "version": __version__,
            "references": {
                "API_SERVER": settings.API_SERVER,
                "CHECK_FASTAPI_VM_ID": settings.CHECK_FASTAPI_VM_ID,
                "CONNECTOR_URL": settings.CONNECTOR_URL,
            },
            "security": {
                "USE_JAILER": settings.USE_JAILER,
                "PRINT_SYSTEM_LOGS": settings.PRINT_SYSTEM_LOGS,
                "WATCH_FOR_UPDATES": settings.WATCH_FOR_UPDATES,
                "ALLOW_VM_NETWORKING": settings.ALLOW_VM_NETWORKING,
                "USE_DEVELOPER_SSH_KEYS": bool(settings.USE_DEVELOPER_SSH_KEYS),
            },
            "networking": {
                "IPV6_ADDRESS_POOL": settings.IPV6_ADDRESS_POOL,
                "IPV6_ALLOCATION_POLICY": str(settings.IPV6_ALLOCATION_POLICY),
                "IPV6_SUBNET_PREFIX": settings.IPV6_SUBNET_PREFIX,
                "IPV6_FORWARDING_ENABLED": settings.IPV6_FORWARDING_ENABLED,
                "USE_NDP_PROXY": settings.USE_NDP_PROXY,
            },
            "debug": {
                "SENTRY_DSN_CONFIGURED": bool(settings.SENTRY_DSN),
                "DEBUG_ASYNCIO": settings.DEBUG_ASYNCIO,
                "EXECUTION_LOG_ENABLED": settings.EXECUTION_LOG_ENABLED,
            },
        },
        dumps=dumps_for_json,
    )


def authenticate_api_request(request: web.Request) -> bool:
    """Authenticate an API request to update the VM allocations."""
    signature: bytes = request.headers.get("X-Auth-Signature", "").encode()

    if not signature:
        raise web.HTTPUnauthorized(text="Authentication token is missing")

    # Use a simple authentication method: the hash of the signature should match the value in the settings
    return sha256(signature).hexdigest() == settings.ALLOCATION_TOKEN_HASH


async def update_allocations(request: web.Request):
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    try:
        data = await request.json()
        allocation = Allocation.parse_obj(data)
    except ValidationError as error:
        return web.json_response(data=error.json(), status=web.HTTPBadRequest.status_code)

    pubsub: PubSub = request.app["pubsub"]
    pool: VmPool = request.app["vm_pool"]

    # First free resources from persistent programs and instances that are not scheduled anymore.
    allocations = allocation.persistent_vms | allocation.instances
    # Make a copy since the pool is modified
    for execution in list(pool.get_persistent_executions()):
        if execution.vm_hash not in allocations and execution.is_running and not execution.uses_payment_stream:
            vm_type = "instance" if execution.is_instance else "persistent program"
            logger.info("Stopping %s %s", vm_type, execution.vm_hash)
            await pool.stop_vm(execution.vm_hash)
            pool.forget_vm(execution.vm_hash)

    # Second start persistent VMs and instances sequentially to limit resource usage.

    # Exceptions that can be raised when starting a VM:
    vm_creation_exceptions = (
        UnknownHashError,
        ResourceDownloadError,
        FileTooLargeError,
        VmSetupError,
        MicroVMFailedInitError,
        HostNotFoundError,
    )

    scheduling_errors: dict[ItemHash, Exception] = {}

    # Schedule the start of persistent VMs:
    for vm_hash in allocation.persistent_vms:
        try:
            logger.info(f"Starting long running VM '{vm_hash}'")
            vm_hash = ItemHash(vm_hash)
            await start_persistent_vm(vm_hash, pubsub, pool)
        except vm_creation_exceptions as error:
            logger.exception(error)
            scheduling_errors[vm_hash] = error

    # Schedule the start of instances:
    for instance_hash in allocation.instances:
        logger.info(f"Starting instance '{instance_hash}'")
        instance_item_hash = ItemHash(instance_hash)
        try:
            await start_persistent_vm(instance_item_hash, pubsub, pool)
        except vm_creation_exceptions as error:
            logger.exception(error)
            scheduling_errors[instance_item_hash] = error

    # Log unsupported features
    if allocation.on_demand_vms:
        logger.warning("Not supported yet: 'allocation.on_demand_vms'")
    if allocation.jobs:
        logger.warning("Not supported yet: 'allocation.on_demand_vms'")

    failing = set(scheduling_errors.keys())
    successful = allocations - failing

    status_code: int
    if not failing:
        status_code = 200  # OK
    elif not successful:
        status_code = 503  # Service Unavailable
    else:
        status_code = 207  # Multi-Status

    return web.json_response(
        data={
            "success": not failing,
            "successful": list(successful),
            "failing": list(failing),
            "errors": {vm_hash: repr(error) for vm_hash, error in scheduling_errors.items()},
        },
        status=status_code,
    )


async def notify_allocation(request: web.Request):
    """Notify instance allocation, only used for Pay as you Go feature"""
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    try:
        data = await request.json()
        vm_notification = VMNotification.parse_obj(data)
    except ValidationError as error:
        return web.json_response(data=error.json(), status=web.HTTPBadRequest.status_code)

    pubsub: PubSub = request.app["pubsub"]
    pool: VmPool = request.app["vm_pool"]

    instance = vm_notification.instance

    # Exceptions that can be raised when starting a VM:
    vm_creation_exceptions = (
        UnknownHashError,
        ResourceDownloadError,
        FileTooLargeError,
        VmSetupError,
        MicroVMFailedInitError,
        HostNotFoundError,
    )

    scheduling_errors: dict[ItemHash, Exception] = {}

    instance_item_hash = ItemHash(instance)
    try:
        await start_persistent_vm(instance_item_hash, pubsub, pool)
        successful = True
    except vm_creation_exceptions as error:
        logger.exception(error)
        scheduling_errors[instance_item_hash] = error
        successful = False

    failing = set(scheduling_errors.keys())

    status_code: int
    if not failing:
        status_code = 200  # OK
    elif not successful:
        status_code = 503  # Service Unavailable
    else:
        status_code = 207  # Multi-Status

    return web.json_response(
        data={
            "success": not failing,
            "successful": successful,
            "failing": list(failing),
            "errors": {vm_hash: repr(error) for vm_hash, error in scheduling_errors.items()},
        },
        status=status_code,
    )
