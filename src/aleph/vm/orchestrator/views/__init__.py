import binascii
import logging
from collections.abc import Awaitable
from decimal import Decimal
from hashlib import sha256
from json import JSONDecodeError
from pathlib import Path
from secrets import compare_digest
from string import Template
from typing import Optional

import aiodns
import aiohttp
from aiohttp import web
from aiohttp.web_exceptions import HTTPNotFound
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash, MessageType
from pydantic import ValidationError

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import (
    ResourceDownloadError,
    VmSetupError,
)
from aleph.vm.controllers.firecracker.program import FileTooLargeError
from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError
from aleph.vm.orchestrator import status
from aleph.vm.orchestrator.messages import try_get_message
from aleph.vm.orchestrator.metrics import get_execution_records
from aleph.vm.orchestrator.payment import (
    InvalidAddressError,
    fetch_execution_flow_price,
    get_stream,
)
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
    cors_allow_all,
    dumps_for_json,
    get_ref_from_dns,
)
from aleph.vm.version import __version__
from packaging.version import InvalidVersion, Version

logger = logging.getLogger(__name__)


async def run_code_from_path(request: web.Request) -> web.Response:
    """Allow running an Aleph VM function from a URL path

    The path is expected to follow the scheme defined in `app.add_routes` below,
    where the identifier of the message is named `ref`.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    message_ref = ItemHash(request.match_info["ref"])
    pool: VmPool = request.app["vm_pool"]
    return await run_code_on_request(message_ref, path, pool, request)


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


@cors_allow_all
async def about_login(request: web.Request) -> web.Response:
    secret_token = request.app["secret_token"]
    request_token = request.query.get("token")

    if request_token and secret_token and compare_digest(request_token, secret_token):
        response = web.HTTPFound("/about/config")
        response.cookies["token"] = request_token
        return response
    else:
        return web.json_response({"success": False}, status=401)


@cors_allow_all
async def about_executions(request: web.Request) -> web.Response:
    authenticate_request(request)
    pool: VmPool = request.app["vm_pool"]
    return web.json_response(
        [dict(pool.executions.items())],
        dumps=dumps_for_json,
    )


@cors_allow_all
async def list_executions(request: web.Request) -> web.Response:
    pool: VmPool = request.app["vm_pool"]
    return web.json_response(
        {
            item_hash: {
                "networking": {
                    "ipv4": execution.vm.tap_interface.ip_network,
                    "ipv6": execution.vm.tap_interface.ipv6_network,
                },
            }
            for item_hash, execution in pool.executions.items()
            if execution.is_running
        },
        dumps=dumps_for_json,
    )


@cors_allow_all
async def about_config(request: web.Request) -> web.Response:
    authenticate_request(request)
    return web.json_response(
        settings,
        dumps=dumps_for_json,
    )


@cors_allow_all
async def about_execution_records(_: web.Request):
    records = await get_execution_records()
    return web.json_response(records, dumps=dumps_for_json)


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


@cors_allow_all
async def status_check_fastapi(request: web.Request, vm_id: Optional[ItemHash] = None):
    """Check that the FastAPI diagnostic VM runs correctly"""

    # Retro-compatibility mode ignores some of the newer checks. It is used to check the status of legacy VMs.
    retro_compatibility: bool = (
        vm_id == settings.LEGACY_CHECK_FASTAPI_VM_ID
        or request.rel_url.query.get("retro-compatibility", "false") == "true"
    )
    # Default to the value in the settings.
    fastapi_vm_id: ItemHash = vm_id or ItemHash(settings.CHECK_FASTAPI_VM_ID)

    try:
        async with aiohttp.ClientSession() as session:
            result = {
                "index": await status.check_index(session, fastapi_vm_id),
                "environ": await status.check_environ(session, fastapi_vm_id),
                "messages": await status.check_messages(session, fastapi_vm_id),
                "dns": await status.check_dns(session, fastapi_vm_id),
                "ipv4": await status.check_ipv4(session, fastapi_vm_id),
                "internet": await status.check_internet(session, fastapi_vm_id),
                "cache": await status.check_cache(session, fastapi_vm_id),
                "persistent_storage": await status.check_persistent_storage(session, fastapi_vm_id),
                "error_handling": await status.check_error_raised(session, fastapi_vm_id),
            }
            if not retro_compatibility:
                # These fields were added in the runtime running Debian 12.
                result = result | {
                    "lifespan": await status.check_lifespan(session, fastapi_vm_id),
                    # IPv6 requires extra work from node operators and is not required yet.
                    # "ipv6": await status.check_ipv6(session),
                }

            return web.json_response(
                result, status=200 if all(result.values()) else 503, headers={"Access-Control-Allow-Origin": "*"}
            )
    except aiohttp.ServerDisconnectedError as error:
        return web.json_response(
            {"error": f"Server disconnected: {error}"}, status=503, headers={"Access-Control-Allow-Origin": "*"}
        )


@cors_allow_all
async def status_check_fastapi_legacy(request: web.Request):
    """Check that the legacy FastAPI VM runs correctly"""
    return await status_check_fastapi(request, vm_id=ItemHash(settings.LEGACY_CHECK_FASTAPI_VM_ID))


@cors_allow_all
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
    return web.json_response(result, status=result_status, headers={"Access-Control-Allow-Origin": "*"})


@cors_allow_all
async def status_check_ipv6(request: web.Request):
    """Check that the platform has IPv6 egress connectivity"""
    timeout = aiohttp.ClientTimeout(total=2)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        try:
            vm_ipv6 = await status.check_ipv6(session, vm_id=ItemHash(settings.CHECK_FASTAPI_VM_ID))
        except TimeoutError:
            vm_ipv6 = False

    result = {"host": await check_host_egress_ipv6(), "vm": vm_ipv6}
    return web.json_response(result, headers={"Access-Control-Allow-Origin": "*"})


@cors_allow_all
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
        return web.Response(
            status=200,
            text=f"Up-to-date: version {current} >= {reference}",
            headers={"Access-Control-Allow-Origin": "*"},
        )
    else:
        return web.HTTPForbidden(text=f"Outdated: version {current} < {reference}")


@cors_allow_all
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
            "payment": {
                "PAYMENT_RECEIVER_ADDRESS": settings.PAYMENT_RECEIVER_ADDRESS,
                "PAYMENT_SUPER_TOKEN": settings.PAYMENT_SUPER_TOKEN,
                "PAYMENT_CHAIN_ID": settings.PAYMENT_CHAIN_ID,
            },
        },
        dumps=dumps_for_json,
        headers={"Access-Control-Allow-Origin": "*"},
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


@cors_allow_all
async def notify_allocation(request: web.Request):
    """Notify instance allocation, only used for Pay as you Go feature"""
    try:
        data = await request.json()
        vm_notification = VMNotification.parse_obj(data)
    except JSONDecodeError as error:
        raise web.HTTPBadRequest(reason="Body is not valid JSON") from error
    except ValidationError as error:
        raise web.json_response(
            data=error.json(), status=web.HTTPBadRequest.status_code, headers={"Access-Control-Allow-Origin": "*"}
        ) from error

    pubsub: PubSub = request.app["pubsub"]
    pool: VmPool = request.app["vm_pool"]

    item_hash: ItemHash = vm_notification.instance
    message = await try_get_message(item_hash)
    if message.type != MessageType.instance:
        raise web.HTTPBadRequest(reason="Message is not an instance")

    if not message.content.payment:
        raise web.HTTPBadRequest(reason="Message does not have payment information")

    if message.content.payment.receiver != settings.PAYMENT_RECEIVER_ADDRESS:
        raise web.HTTPBadRequest(reason="Message is not for this instance")

    # Check that there is a payment stream for this instance
    try:
        active_flow: Decimal = await get_stream(
            sender=message.sender, receiver=message.content.payment.receiver, chain=message.content.payment.chain
        )
    except InvalidAddressError as error:
        logger.warning(f"Invalid address {error}", exc_info=True)
        raise web.HTTPBadRequest(reason=f"Invalid address {error}") from error

    if not active_flow:
        raise web.HTTPPaymentRequired(reason="Empty payment stream for this instance")

    required_flow: Decimal = await fetch_execution_flow_price(item_hash)

    if active_flow < required_flow:
        active_flow_per_month = active_flow * 60 * 60 * 24 * (Decimal("30.41666666666923904761904784"))
        required_flow_per_month = required_flow * 60 * 60 * 24 * Decimal("30.41666666666923904761904784")
        raise web.HTTPPaymentRequired(
            reason="Insufficient payment stream",
            text="Insufficient payment stream for this instance\n\n"
            f"Required: {required_flow_per_month} / month (flow = {required_flow})\n"
            f"Present: {active_flow_per_month} / month (flow = {active_flow})",
        )

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
    try:
        await start_persistent_vm(item_hash, pubsub, pool)
        successful = True
    except vm_creation_exceptions as error:
        logger.exception(error)
        scheduling_errors[item_hash] = error
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
