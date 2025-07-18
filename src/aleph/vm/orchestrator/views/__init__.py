import asyncio
import binascii
import http
import logging
from decimal import Decimal
from hashlib import sha256
from json import JSONDecodeError
from packaging.version import InvalidVersion, Version
from pathlib import Path
from secrets import compare_digest
from string import Template

import aiodns
import aiohttp
from aiohttp import web
from aiohttp.web_exceptions import HTTPBadRequest, HTTPNotFound
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import InstanceContent, ItemHash, MessageType, PaymentType
from pydantic import ValidationError

from aleph.vm import haproxy
from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import (
    ResourceDownloadError,
    VmSetupError,
)
from aleph.vm.controllers.firecracker.program import FileTooLargeError
from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator import payment, status
from aleph.vm.orchestrator.chain import STREAM_CHAINS
from aleph.vm.orchestrator.custom_logs import set_vm_for_logging
from aleph.vm.orchestrator.messages import try_get_message
from aleph.vm.orchestrator.metrics import get_execution_records
from aleph.vm.orchestrator.payment import (
    InvalidAddressError,
    InvalidChainError,
    fetch_execution_flow_price,
    get_stream,
)
from aleph.vm.orchestrator.pubsub import PubSub
from aleph.vm.orchestrator.resources import Allocation, VMNotification
from aleph.vm.orchestrator.run import run_code_on_request, start_persistent_vm
from aleph.vm.orchestrator.tasks import COMMUNITY_STREAM_RATIO
from aleph.vm.orchestrator.utils import (
    format_cost,
    get_community_wallet_address,
    is_after_community_wallet_start,
    update_aggregate_settings,
)
from aleph.vm.orchestrator.views.authentication import require_jwk_authentication
from aleph.vm.orchestrator.views.host_status import (
    check_dns_ipv4,
    check_dns_ipv6,
    check_domain_resolution_ipv4,
    check_domain_resolution_ipv6,
    check_host_egress_ipv4,
    check_host_egress_ipv6,
)
from aleph.vm.orchestrator.views.operator import get_itemhash_or_400
from aleph.vm.pool import VmPool
from aleph.vm.utils import (
    HostNotFoundError,
    b32_to_b16,
    cors_allow_all,
    dumps_for_json,
    get_ref_from_dns,
)
from aleph.vm.version import __version__

logger = logging.getLogger(__name__)


async def run_code_from_path(request: web.Request) -> web.Response:
    """Allow running an Aleph VM function from a URL path

    The path is expected to follow the scheme defined in `app.add_routes` below,
    where the identifier of the message is named `ref`.
    """
    path = request.match_info["suffix"]
    path = path if path.startswith("/") else f"/{path}"

    try:
        message_ref = ItemHash(request.match_info["ref"])
    except UnknownHashError as e:
        raise HTTPBadRequest(
            reason="Invalid message reference", text=f"Invalid message reference: {request.match_info['ref']}"
        ) from e

    pool: VmPool = request.app["vm_pool"]
    with set_vm_for_logging(vm_hash=message_ref):
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
            except aiodns.error.DNSError:
                return HTTPNotFound(reason="Invalid message reference")
            except UnknownHashError:
                return HTTPNotFound(reason="Invalid message reference")

    pool = request.app["vm_pool"]
    with set_vm_for_logging(vm_hash=message_ref):
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


async def debug_haproxy(request: web.Request) -> web.Response:
    """ "Debug endpoint to check the status of HAProxy and the domains mapped to it.

    This is a debug endpoint and should not be used in production. The interface is subject to change.
    """
    socket = settings.HAPROXY_SOCKET
    import pathlib

    if not pathlib.Path(socket).exists():
        logger.info("HAProxy not running? socket not found, skip domain mapping update")
        return web.json_response({"status": "no socket"}, status=http.HTTPStatus)
    r: dict = {"status": "ok", "backends": {}}
    for backend in haproxy.HAPROXY_BACKENDS:
        r["backends"][str(backend["name"])] = haproxy.get_current_backends(socket, backend["name"])
    return web.json_response(
        r,
        dumps=dumps_for_json,
    )


@cors_allow_all
async def about_executions(request: web.Request) -> web.Response:
    "/about/executions/details Debugging endpoint with full execution details."
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
async def list_executions_v2(request: web.Request) -> web.Response:
    """List all executions. Returning their status and ip"""
    pool: VmPool = request.app["vm_pool"]

    return web.json_response(
        {
            item_hash: {
                "networking": {
                    "ipv4_network": execution.vm.tap_interface.ip_network,
                    "host_ipv4": pool.network.host_ipv4,
                    "ipv6_network": execution.vm.tap_interface.ipv6_network,
                    "ipv6_ip": execution.vm.tap_interface.guest_ipv6.ip,
                    "ipv4_ip": execution.vm.tap_interface.guest_ip.ip,
                    "mapped_ports": execution.mapped_ports,
                }
                if execution.vm and execution.vm.tap_interface
                else {},
                "status": execution.times,
                "running": execution.is_running,
            }
            for item_hash, execution in pool.executions.items()
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
async def status_check_fastapi(request: web.Request, vm_id: ItemHash | None = None):
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
                # Using the remote account currently causes issues
                # "post_a_message": await status.check_post_a_message(session, fastapi_vm_id),
                # "sign_a_message": await status.check_sign_a_message(session, fastapi_vm_id),
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
                    "get_a_message": await status.check_get_a_message(session, fastapi_vm_id),
                    "lifespan": await status.check_lifespan(session, fastapi_vm_id),
                    # IPv6 requires extra work from node operators and is not required yet.
                    # "ipv6": await status.check_ipv6(session),
                }

            return web.json_response(result, status=200 if all(result.values()) else 503)
    except aiohttp.ServerDisconnectedError as error:
        return web.json_response({"error": f"Server disconnected: {error}"}, status=503)


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
    return web.json_response(result, status=result_status)


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
    return web.json_response(result)


@cors_allow_all
async def status_check_version(request: web.Request):
    """Check if the software is running a version equal or newer than the given one"""
    reference_str: str | None = request.query.get("reference")
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
        )
    else:
        return web.HTTPForbidden(text=f"Outdated: version {current} < {reference}")


@cors_allow_all
async def status_public_config(request: web.Request):
    """Expose the public fields from the configuration"""

    available_payments = {
        str(chain_name): chain_info for chain_name, chain_info in STREAM_CHAINS.items() if chain_info.active
    }

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
                "AVAILABLE_PAYMENTS": available_payments,
                "PAYMENT_MONITOR_INTERVAL": settings.PAYMENT_MONITOR_INTERVAL,
            },
            "computing": {
                "ENABLE_QEMU_SUPPORT": settings.ENABLE_QEMU_SUPPORT,
                "INSTANCE_DEFAULT_HYPERVISOR": settings.INSTANCE_DEFAULT_HYPERVISOR,
                "ENABLE_CONFIDENTIAL_COMPUTING": settings.ENABLE_CONFIDENTIAL_COMPUTING,
                "ENABLE_GPU_SUPPORT": settings.ENABLE_GPU_SUPPORT,
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


allocation_lock = None


async def update_allocations(request: web.Request):
    """Main entry for the start of persistence VM and instance, called by the Scheduler,


    auth via the SETTINGS.ALLOCATION_TOKEN_HASH  sent in header X-Auth-Signature.
    Receive a list of vm and instance that should be present and then match that state by stopping and launching VMs
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    global allocation_lock
    if allocation_lock is None:
        allocation_lock = asyncio.Lock()
    try:
        data = await request.json()
        allocation = Allocation.model_validate(data)
    except ValidationError as error:
        return web.json_response(text=error.json(), status=web.HTTPBadRequest.status_code)

    pubsub: PubSub = request.app["pubsub"]
    pool: VmPool = request.app["vm_pool"]

    async with allocation_lock:
        # First, free resources from persistent programs and instances that are not scheduled anymore.
        allocations = allocation.persistent_vms | allocation.instances
        # Make a copy since the pool is modified
        for execution in list(pool.get_persistent_executions()):
            if (
                execution.vm_hash not in allocations
                and execution.is_running
                and not execution.uses_payment_stream
                and not execution.gpus
                and not execution.is_confidential
            ):
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
            HTTPNotFound,
        )

        scheduling_errors: dict[ItemHash, Exception] = {}

        # Schedule the start of persistent VMs:
        for vm_hash in allocation.persistent_vms:
            try:
                logger.info(f"Starting long running VM '{vm_hash}'")
                vm_hash = ItemHash(vm_hash)
                await start_persistent_vm(vm_hash, pubsub, pool)
            except vm_creation_exceptions as error:
                logger.exception("Error while starting VM '%s': %s", vm_hash, error)
                scheduling_errors[vm_hash] = error
            except Exception as error:
                # Handle unknown exception separately, to avoid leaking data
                logger.exception("Unhandled Error while starting VM '%s': %s", vm_hash, error)
                scheduling_errors[vm_hash] = Exception("Unhandled Error")

        # Schedule the start of instances:
        for instance_hash in allocation.instances:
            logger.info(f"Starting instance '{instance_hash}'")
            instance_item_hash = ItemHash(instance_hash)
            try:
                await start_persistent_vm(instance_item_hash, pubsub, pool)
            except vm_creation_exceptions as error:
                logger.exception("Error while starting VM '%s': %s", instance_hash, error)
                scheduling_errors[instance_item_hash] = error
            except Exception as error:
                # Handle unknown exception separately, to avoid leaking data
                logger.exception("Unhandled Error while starting VM '%s': %s", instance_hash, error)
                scheduling_errors[instance_hash] = Exception("Unhandled Error")

        # Log unsupported features
        if allocation.on_demand_vms:
            logger.warning("Not supported yet: 'allocation.on_demand_vms'")
        if allocation.jobs:
            logger.warning("Not supported yet: 'allocation.jobs'")

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
    await update_aggregate_settings()
    try:
        data = await request.json()
        vm_notification = VMNotification.model_validate(data)
    except JSONDecodeError:
        return web.HTTPBadRequest(text="Body is not valid JSON")
    except ValidationError as error:
        return web.json_response(data=error.json(), status=web.HTTPBadRequest.status_code)

    pubsub: PubSub = request.app["pubsub"]
    pool: VmPool = request.app["vm_pool"]

    item_hash: ItemHash = vm_notification.instance
    message = await try_get_message(item_hash)
    if message.type != MessageType.instance:
        return web.HTTPBadRequest(reason="Message is not an instance")

    payment_type = message.content.payment and message.content.payment.type or PaymentType.hold

    is_confidential = message.content.environment.trusted_execution is not None
    have_gpu = message.content.requirements and message.content.requirements.gpu is not None

    if payment_type == PaymentType.hold and (is_confidential or have_gpu):
        # Log confidential and instances with GPU support
        if is_confidential:
            logger.debug(f"Confidential instance {item_hash} not using PAYG")
        if have_gpu:
            logger.debug(f"GPU Instance {item_hash} not using PAYG")
        user_balance = await payment.fetch_balance_of_address(message.sender)
        hold_price = await payment.fetch_execution_hold_price(item_hash)
        logger.debug(f"Address {message.sender} Balance: {user_balance}, Price: {hold_price}")
        if hold_price > user_balance:
            return web.HTTPPaymentRequired(
                reason="Insufficient balance",
                text="Insufficient balance for this instance\n\n"
                f"Required: {hold_price} token \n"
                f"Current user balance: {user_balance}",
            )
    elif payment_type == PaymentType.superfluid:
        # Payment via PAYG
        if message.content.payment.receiver != settings.PAYMENT_RECEIVER_ADDRESS:
            return web.HTTPBadRequest(reason="Message is not for this instance")

        # Check that there is a payment stream for this instance
        try:
            active_flow: Decimal = await get_stream(
                sender=message.sender, receiver=message.content.payment.receiver, chain=message.content.payment.chain
            )
        except InvalidAddressError as error:
            logger.warning(f"Invalid address {error}", exc_info=True)
            return web.HTTPBadRequest(reason=f"Invalid address {error}")
        except InvalidChainError as error:
            logger.warning(f"Invalid chain {error}", exc_info=True)
            return web.HTTPBadRequest(reason=f"Invalid Chain {error}")

        if not active_flow:
            raise web.HTTPPaymentRequired(reason="Empty payment stream for this instance")

        required_flow: Decimal = await fetch_execution_flow_price(item_hash)
        community_wallet = await get_community_wallet_address()
        required_crn_stream: Decimal
        required_community_stream: Decimal
        if await is_after_community_wallet_start() and community_wallet:
            required_crn_stream = format_cost(required_flow * (1 - COMMUNITY_STREAM_RATIO))
            required_community_stream = format_cost(required_flow * COMMUNITY_STREAM_RATIO)
        else:  # No community wallet payment
            required_crn_stream = format_cost(required_flow)
            required_community_stream = Decimal(0)

        if active_flow < (required_crn_stream - settings.PAYMENT_BUFFER):
            active_flow_per_month = active_flow * 60 * 60 * 24 * (Decimal("30.41666666666923904761904784"))
            required_flow_per_month = required_crn_stream * 60 * 60 * 24 * Decimal("30.41666666666923904761904784")
            return web.HTTPPaymentRequired(
                reason="Insufficient payment stream",
                text="Insufficient payment stream for this instance\n\n"
                f"Required: {required_flow_per_month} / month (flow = {required_crn_stream})\n"
                f"Present: {active_flow_per_month} / month (flow = {active_flow})",
            )

        if community_wallet and required_community_stream:
            community_flow: Decimal = await get_stream(
                sender=message.sender,
                receiver=community_wallet,
                chain=message.content.payment.chain,
            )
            if community_flow < (required_community_stream - settings.PAYMENT_BUFFER):
                active_flow_per_month = community_flow * 60 * 60 * 24 * (Decimal("30.41666666666923904761904784"))
                required_flow_per_month = (
                    required_community_stream * 60 * 60 * 24 * Decimal("30.41666666666923904761904784")
                )
                return web.HTTPPaymentRequired(
                    reason="Insufficient payment stream to community",
                    text="Insufficient payment stream for community \n\n"
                    f"Required: {required_flow_per_month} / month (flow = {required_community_stream})\n"
                    f"Present: {active_flow_per_month} / month (flow = {community_flow})\n"
                    f"Address: {community_wallet}",
                )
    else:
        return web.HTTPBadRequest(reason="Invalid payment method")

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
        logger.info(f"Starting persistent vm {item_hash} from notify_allocation")
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


@cors_allow_all
@require_jwk_authentication
async def operate_reserve_resources(request: web.Request, authenticated_sender: str) -> web.Response:
    """Reserve a GPU"""
    pool: VmPool = request.app["vm_pool"]
    try:
        data = await request.json()
        message = InstanceContent.model_validate(data)
    except JSONDecodeError:
        return web.HTTPBadRequest(text="Body is not valid JSON")
    except ValidationError as error:
        return web.json_response(data=error.json(), status=web.HTTPBadRequest.status_code)

    # TODO When creating a new VM check if all reservation are for user
    try:
        expiration_date = await pool.reserve_resources(message, authenticated_sender)
    except Exception as error:
        return web.json_response(
            {"status": "error", "error": "Failed to reserves all resources", "reason": str(error)},
            status=http.HTTPStatus.BAD_REQUEST,
        )
    return web.json_response(
        {
            "status": "reserved",
            "expires": expiration_date,
        },
        dumps=dumps_for_json,
    )


@cors_allow_all
async def operate_update(request: web.Request) -> web.Response:
    """Notify that the instance configuration has changed

    For now used to notify the CRN that port-forwarding config has changed
    and that it should be fetched and the setup upgraded"""
    vm_hash = get_itemhash_or_400(request.match_info)

    pool: VmPool = request.app["vm_pool"]
    execution: VmExecution = pool.executions.get(vm_hash)
    if not execution:
        raise HTTPNotFound(reason="VM not found")
    if not execution.vm:
        # Configuration will be fetched when the VM start so no need to return an error
        return web.json_response({"status": "ok", "msg": "VM not starting yet"}, dumps=dumps_for_json, status=200)
    await execution.fetch_port_redirect_config_and_setup()
    await pool.update_domain_mapping()
    return web.json_response({}, dumps=dumps_for_json, status=200)
