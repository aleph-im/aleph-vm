import asyncio
import binascii
import http
import logging
from datetime import datetime, timezone
from decimal import Decimal
from json import JSONDecodeError
from packaging.version import InvalidVersion, Version
from pathlib import Path
from secrets import compare_digest
from string import Template
from typing import cast

import aiodns
import aiohttp
from aiohttp import web
from aiohttp.web_exceptions import HTTPBadRequest, HTTPNotFound
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import InstanceContent, ItemHash, MessageType, PaymentType
from pydantic import ValidationError

from aleph.vm import haproxy
from aleph.vm.agent import payment, status
from aleph.vm.agent.chain import STREAM_CHAINS
from aleph.vm.agent.custom_logs import set_vm_for_logging
from aleph.vm.agent.haproxy_sync import sync_domain_mappings
from aleph.vm.agent.messages import try_get_message
from aleph.vm.agent.metrics import get_execution_records
from aleph.vm.agent.node_identity import NodeIdentity
from aleph.vm.agent.payment import (
    InvalidAddressError,
    InvalidChainError,
    fetch_credit_balance_of_address,
    fetch_execution_price,
    get_stream,
)
from aleph.vm.agent.pubsub import PubSub
from aleph.vm.agent.resources import Allocation, VMNotification
from aleph.vm.agent.run import (
    reconcile_port_forwards,
    run_code_on_request,
    start_persistent_vm,
)
from aleph.vm.agent.tasks import COMMUNITY_STREAM_RATIO
from aleph.vm.agent.translate import build_reservation_request
from aleph.vm.agent.utils import (
    format_cost,
    get_community_wallet_address,
    is_after_community_wallet_start,
    update_aggregate_settings,
)
from aleph.vm.agent.views.allocation_auth import authenticate_api_request
from aleph.vm.agent.views.authentication import require_jwk_authentication
from aleph.vm.agent.views.host_status import (
    check_dns_ipv4,
    check_dns_ipv6,
    check_domain_resolution_ipv4,
    check_domain_resolution_ipv6,
    check_host_egress_ipv4,
    check_host_egress_ipv6,
    check_host_http_ipv4,
    check_host_http_ipv6,
)
from aleph.vm.agent.views.operator import get_itemhash_or_400
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import (
    InsufficientResourcesError as BoundaryInsufficientResourcesError,
)
from aleph.vm.supervisor_interface.errors import (
    InternalSupervisorError,
    SupervisorError,
    VmNotFoundError,
)
from aleph.vm.supervisor_interface.types import (
    ConfidentialMode,
    PortForwardInfo,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.utils import (
    HostNotFoundError,
    b32_to_b16,
    cors_allow_all,
    dumps_for_json,
    get_ref_from_dns,
)
from aleph.vm.version import __version__
from aleph.vm.vm_type import VmType

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

    with set_vm_for_logging(vm_hash=message_ref):
        return await run_code_on_request(message_ref, path, request)


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

    with set_vm_for_logging(vm_hash=message_ref):
        return await run_code_on_request(message_ref, path, request)


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
        return web.json_response({"status": "no socket"}, status=404)
    r: dict = {"status": "ok", "mappings": {}}
    for backend in haproxy.HAPROXY_BACKENDS:
        r["mappings"][backend["name"]] = haproxy.get_current_mappings(socket, backend["map_file"])
    return web.json_response(
        r,
        dumps=dumps_for_json,
    )


def _vm_type_name(record: AgentVmRecord | None, info: VmInfo) -> str:
    """vm_type label: from the agent's message when known; otherwise a
    best-effort guess from the guest channel (registry-miss fallback for
    spec-created / reattached VMs).

    The instance/program distinction is agent vocabulary the wire no longer
    carries. Every VM the agent runs as a microvm has a guest channel and
    instances have none, so the channel's presence recovers the label for VMs
    we lost the record of. (Backend alone cannot: an instance running under
    Firecracker reports Backend.FIRECRACKER yet is still an instance.)"""
    if record is not None:
        return VmType.from_message_content(record.message).name
    return VmType.microvm.name if info.guest_channel_path else VmType.instance.name


def _datetime_from_ns(ns: int) -> datetime | None:
    """Inverse of the supervisor's ns composition; lossless at µs precision."""
    if not ns:
        return None
    return datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc).replace(
        microsecond=(ns % 1_000_000_000) // 1_000
    )


def _times_dict(info: VmInfo) -> dict[str, datetime | None]:
    """The VmExecutionTimes-shaped dict the v2 endpoint has always served."""
    return {
        "defined_at": _datetime_from_ns(info.defined_at_ns),
        "preparing_at": _datetime_from_ns(info.preparing_at_ns),
        "prepared_at": _datetime_from_ns(info.prepared_at_ns),
        "starting_at": _datetime_from_ns(info.starting_at_ns),
        "started_at": _datetime_from_ns(info.started_at_ns),
        "stopping_at": _datetime_from_ns(info.stopping_at_ns),
        "stopped_at": _datetime_from_ns(info.stopped_at_ns),
    }


def _group_port_forwards(forwards: list[PortForwardInfo]) -> dict[str, dict[int, dict]]:
    """{vm_id: {vm_port: {"host", "tcp", "udp"}}} — the legacy mapped_ports
    shape, rebuilt from the supervisor's flat port-forward list.

    Deliberate divergence from the old pool dump: a "ghost" mapping with no
    enabled protocol yields no PortForwardInfo and is therefore not listed.
    """
    grouped: dict[str, dict[int, dict]] = {}
    for fwd in forwards:
        entry = grouped.setdefault(str(fwd.vm_id), {}).setdefault(
            int(fwd.vm_port), {"host": int(fwd.host_port), "tcp": False, "udp": False}
        )
        entry[fwd.protocol.value] = True
    return grouped


def _is_listable_awaiting_confidential_init(info: VmInfo) -> bool:
    """Whether a confidential VM waiting for its owner belongs in the v1 list.

    The scheduler re-allocates any planned VM absent from the list, so a waiting
    confidential VM must be listed or it gets re-allocated forever. The v1 schema
    requires the networking fields, so only list it once its tap network exists.
    """
    return info.awaiting_confidential_init and bool(info.ipv4.network_cidr)


@cors_allow_all
async def list_executions(request: web.Request) -> web.Response:
    # ASSUMPTION (single-tenant supervisor): list_vms() is hypervisor-global —
    # it returns every VM the supervisor manages, and we report all of them as
    # ours. That is correct only while the agent is the supervisor's sole
    # client, so every VmId is one of our item hashes and registry.get either
    # hits or cleanly misses on our own set. The moment the supervisor gains
    # another tenant (a node operator's own VMs, a second agent with a
    # different VmId scheme), a foreign VmId misses the registry and falls
    # through _vm_type_name to backend inference — i.e. we would list and label
    # a VM we do not own. Fix then by scoping ownership at the boundary
    # (list_vms(owner=...) / an auth-scoped supervisor) so foreign VmInfos never
    # arrive, or, failing that, filter here to `registry.get(info.vm_id) is not
    # None`. Until then these /list endpoints mean "agent-owned"; a node-wide
    # debug view belongs on the operator surface.
    supervisor: Supervisor = request.app["supervisor"]
    registry: AgentVmRegistry = request.app["vm_registry"]
    infos = await supervisor.list_vms()
    return web.json_response(
        {
            info.vm_id: {
                "networking": {
                    "ipv4": info.ipv4.network_cidr,
                    "ipv6": info.ipv6.network_cidr,
                },
                # cast: info.vm_id is a VmId (opaque str at the boundary); the
                # agent knows its own VMs are keyed by item hash. See the
                # ownership note at the top of list_executions.
                "vm_type": _vm_type_name(registry.get(cast(ItemHash, info.vm_id)), info),
                # Confidential VMs awaiting owner initialization are listed but
                # not running, so the scheduler can tell them apart from dead VMs.
                "awaiting_confidential_init": info.awaiting_confidential_init,
            }
            for info in infos
            if info.status is VmStatus.RUNNING or _is_listable_awaiting_confidential_init(info)
        },
        dumps=dumps_for_json,
    )


@cors_allow_all
async def list_executions_v2(request: web.Request) -> web.Response:
    """List all executions. Returning their status and ip"""
    # Same single-tenant assumption as list_executions: list_vms() is
    # hypervisor-global, so under a multi-tenant supervisor this would report
    # VMs the agent does not own. See the note there.
    supervisor: Supervisor = request.app["supervisor"]
    registry: AgentVmRegistry = request.app["vm_registry"]
    infos = await supervisor.list_vms()
    host_info = await supervisor.get_host_info()
    mapped_ports = _group_port_forwards(await supervisor.list_port_forwards())
    return web.json_response(
        {
            info.vm_id: {
                "networking": (
                    {
                        "ipv4_network": info.ipv4.network_cidr,
                        "host_ipv4": host_info.host_ipv4,
                        "ipv6_network": info.ipv6.network_cidr,
                        "ipv6_ip": info.ipv6.address,
                        "ipv4_ip": info.ipv4.address,
                        "mapped_ports": mapped_ports.get(info.vm_id, {}),
                    }
                    if info.ipv4.network_cidr
                    else {}
                ),
                "status": _times_dict(info),
                "running": info.status is VmStatus.RUNNING,
                # Confidential VMs are only started once their owner uploads the
                # session certificates: not running, but not dead either.
                "awaiting_confidential_init": info.awaiting_confidential_init,
                # cast: info.vm_id is a VmId (opaque str at the boundary); the
                # agent knows its own VMs are keyed by item hash. See the
                # ownership note at the top of list_executions.
                "vm_type": _vm_type_name(registry.get(cast(ItemHash, info.vm_id)), info),
            }
            for info in infos
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

            required_keys = {"index", "environ", "ipv4", "internet", "dns", "error_handling", "lifespan"}
            required_ok = all(result[k] for k in required_keys if k in result)
            return web.json_response(result, status=200 if required_ok else 503)
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
            "http": await check_host_http_ipv4(),
        },
        "ipv6": {
            "egress": await check_host_egress_ipv6(),
            "dns": await check_dns_ipv6(),
            "domain": await check_domain_resolution_ipv6(),
            "http": await check_host_http_ipv6(),
        },
    }
    # "http" is advisory — transient failures in third-party probe endpoints
    # should not make the CRN appear offline to monitoring systems.
    required_keys = {"egress", "dns", "domain"}
    result_status = (
        200 if all(result["ipv4"][k] for k in required_keys) and all(result["ipv6"][k] for k in required_keys) else 503
    )
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

    node_identity: NodeIdentity | None = request.app.get("node_identity")
    node_hash = node_identity.get_node_hash() if node_identity else None

    available_payments = {
        str(chain_name): chain_info for chain_name, chain_info in STREAM_CHAINS.items() if chain_info.active
    }

    return web.json_response(
        {
            "DOMAIN_NAME": settings.DOMAIN_NAME,
            "node_hash": node_hash,
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


allocation_lock = None
network_recreation_lock = None
proxy_regeneration_lock = None


async def update_allocations(request: web.Request):
    """Main entry for the start of persistence VM and instance, called by the Scheduler,
    POST /control/allocations

    Auth via either:
    - `Authorization: Aleph-EIP191-V1 sig=...,payload=...` (recommended)
    - `X-Auth-Signature` matching `settings.ALLOCATION_TOKEN_HASH` (DEPRECATED)

    See :mod:`aleph.vm.agent.views.allocation_auth` for the dispatcher.
    Receive a list of vm and instance that should be present and then match
    that state by stopping and launching VMs.
    """
    if not await authenticate_api_request(request):
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
    supervisor = request.app["supervisor"]
    registry = request.app["vm_registry"]
    expiry = request.app["expiry"]
    update_watcher = request.app["update_watcher"]

    async with allocation_lock:
        logger.debug("Got allocation_lock, updating allocations")

        # Snapshot systemd's ActiveState for every persistent controller
        # in one batched D-Bus ListUnits() call off the event loop. The
        # per-VM path (execution.is_running -> is_service_active) would
        # otherwise issue O(N) synchronous D-Bus round-trips inside this
        # loop; on CRNs with dozens of persistent VMs that stalls the
        # loop long enough for the aleph-admin HTTP client to time out.
        persistent_services = [
            execution.controller_service for execution in pool.executions.values() if execution.persistent
        ]
        # None (not {}) when no batch was performed, so get_persistent_executions
        # falls back to its per-VM is_running path instead of treating every
        # service as not-running.
        running_states: dict[str, bool] | None = None
        if persistent_services and pool.systemd_manager:
            running_states = await asyncio.to_thread(
                pool.systemd_manager.get_services_active_states,
                persistent_services,
            )

        # First, free resources from persistent programs and instances that are not scheduled anymore.
        allocations = allocation.persistent_vms | allocation.instances
        stopped_vms = []
        # Status comes from the supervisor (VmInfo); persistence, payment tier
        # and owner come from the agent registry. A VM with no registry record is
        # not scheduler-managed and is skipped here; this is safe because every
        # agent-created VM has a record (persisted on create, rehydrated on
        # restart) post-#972, so a record-less running VM should not occur.
        for info in await supervisor.list_vms():
            vm_hash = ItemHash(info.vm_id)
            record = registry.get(vm_hash)
            if (
                record is not None
                and record.persistent
                and vm_hash not in allocations
                and info.status is VmStatus.RUNNING
                and not record.uses_payment_stream
                and not record.uses_payment_credit
                and not info.gpus
                and info.confidential_mode is ConfidentialMode.NONE
            ):
                vm_type = VmType.from_message_content(record.message).name
                logger.info("Stopping %s %s", vm_type, vm_hash)
                try:
                    await supervisor.delete_vm(VmId(str(vm_hash)))
                except VmNotFoundError:
                    pass
                registry.forget(vm_hash)
                stopped_vms.append(vm_hash)

        # Second start persistent VMs and instances sequentially to limit resource usage.

        # Exceptions that can be raised when starting a VM. The create path now
        # raises a single vocabulary: the agent download phase and the
        # supervisor boundary both surface contract SupervisorError subclasses
        # (ResourceDownloadError, FileTooLargeError, VmSetupError,
        # MicroVMInitError, InsufficientResourcesError); SupervisorError catches
        # them all. The remaining entries are agent-side foundation/HTTP errors.
        vm_creation_exceptions = (
            UnknownHashError,
            SupervisorError,
            HostNotFoundError,
            HTTPNotFound,
            InsufficientResourcesError,
        )

        scheduling_errors: dict[ItemHash, Exception] = {}

        # Schedule the start of persistent VMs:
        for vm_hash in allocation.persistent_vms:
            try:
                # start_persistent_vm logs at INFO when it actually starts
                # a VM; firing an unconditional log here just adds noise
                # when the scheduler re-pushes the full allocation list.
                vm_hash = ItemHash(vm_hash)
                await start_persistent_vm(
                    vm_hash,
                    pubsub,
                    supervisor=supervisor,
                    registry=registry,
                    expiry=expiry,
                    update_watcher=update_watcher,
                )
            except vm_creation_exceptions as error:
                logger.exception("Error while starting VM '%s': %s", vm_hash, error)
                scheduling_errors[vm_hash] = error
            except Exception as error:
                # Handle unknown exception separately, to avoid leaking data
                logger.exception("Unhandled Error while starting VM '%s': %s", vm_hash, error)
                scheduling_errors[vm_hash] = Exception("Unhandled Error")

        # Schedule the start of instances:
        for instance_hash in allocation.instances:
            instance_item_hash = ItemHash(instance_hash)
            try:
                await start_persistent_vm(
                    instance_item_hash,
                    pubsub,
                    supervisor=supervisor,
                    registry=registry,
                    expiry=expiry,
                    update_watcher=update_watcher,
                )
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
                "stopped": list(stopped_vms),
                "errors": {vm_hash: repr(error) for vm_hash, error in scheduling_errors.items()},
            },
            status=status_code,
        )


async def recreate_network(request: web.Request):
    """Recreate network settings for the CRN and all running VMs.

    This endpoint performs a complete network reconfiguration by:
    1. Querying the nftables ruleset to find all aleph-related chains
    2. Removing ALL chains created by aleph software (both tracked and untracked)
       including VM-specific chains and supervisor chains
    3. Re-initializing the base network setup with nftables (creating fresh
       supervisor chains: aleph-supervisor-nat, aleph-supervisor-filter,
       aleph-supervisor-prerouting)
    4. Recreating VM-specific chains and rules for each currently running VM
    5. Restoring port forwarding rules for all running instances

    This method is designed to handle cases where:
    - Network rules have become duplicated or inconsistent
    - Chains exist on the host that are no longer tracked by the software
    - The firewall state needs to be reset to match the current VM pool

    The operation is atomic and uses a lock to prevent concurrent modifications.

    Returns:
        JSON response with:
        - success: Boolean indicating if all VMs were successfully recreated
        - removed_chains_count: Number of chains that were removed
        - removed_chains: List of chain names that were removed
        - recreated_count: Number of VMs that were successfully recreated
        - failed_count: Number of VMs that failed to recreate
        - recreated_vms: List of VM hashes that were recreated
        - failed_vms: List of VM hashes and errors for failed recreations
    """
    if not await authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    global network_recreation_lock
    if network_recreation_lock is None:
        network_recreation_lock = asyncio.Lock()

    async with network_recreation_lock:
        try:
            result = await request.app["supervisor"].recreate_network()
        except InternalSupervisorError as error:
            logger.error(f"Network recreation failed: {error}")
            return web.json_response({"success": False, "error": str(error)}, status=500)

        return web.json_response(result, status=200 if result["success"] else 207)


async def regenerate_proxy(request: web.Request):
    """Regenerate HAProxy configuration for all running VMs.

    This endpoint forces a refresh of the HAProxy domain mappings and backend
    configurations for all currently running VMs. It's useful when:
    - HAProxy rules have become stale or inconsistent
    - Domain mappings need to be synchronized with the current VM pool state
    - After manual changes to HAProxy configuration

    The operation uses a lock to prevent concurrent modifications.

    Returns:
        JSON response with:
        - success: Boolean indicating if the operation completed successfully
        - message: Description of the operation result
    """
    if not await authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    global proxy_regeneration_lock
    if proxy_regeneration_lock is None:
        proxy_regeneration_lock = asyncio.Lock()

    async with proxy_regeneration_lock:
        logger.info("Starting HAProxy configuration regeneration")

        try:
            await sync_domain_mappings(request.app["supervisor"], force_update=True)
            logger.info("HAProxy configuration regeneration complete")
            return web.json_response(
                {
                    "success": True,
                    "message": "HAProxy configuration regenerated successfully",
                },
                status=200,
            )
        except Exception as e:
            logger.error(f"Error regenerating HAProxy configuration: {e}")
            return web.json_response(
                {"success": False, "error": f"Failed to regenerate HAProxy configuration: {e!s}"},
                status=500,
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

    item_hash: ItemHash = vm_notification.instance
    message = await try_get_message(item_hash)
    if message.type != MessageType.instance:
        return web.HTTPBadRequest(reason="Message is not an instance")

    # Validate node hash if the allocation targets a specific node
    required_node_hash = (
        message.content.requirements
        and message.content.requirements.node
        and message.content.requirements.node.node_hash
    )
    if required_node_hash:
        node_identity: NodeIdentity | None = request.app.get("node_identity")
        node_hash = node_identity.get_node_hash() if node_identity else None
        if not node_hash:
            return web.HTTPServiceUnavailable(reason="Node hash not yet discovered, cannot accept targeted allocations")
        if str(required_node_hash) != node_hash:
            return web.HTTPBadRequest(reason="Instance is allocated to a different node")

    pubsub: PubSub = request.app["pubsub"]
    supervisor = request.app["supervisor"]
    registry = request.app["vm_registry"]
    expiry = request.app["expiry"]
    update_watcher = request.app["update_watcher"]

    # Capacity admission is no longer checked here: the engine enforces it
    # atomically inside the create path (pool.check_spec_admission, on the
    # shared pool.check_capacity core), raising the typed
    # InsufficientResourcesError. The vm_creation_exceptions / 503 path below
    # surfaces that error to the caller.

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
        hold_price = await payment.fetch_execution_price(item_hash, [PaymentType.hold], False)
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

        required_flow: Decimal = await fetch_execution_price(item_hash, [PaymentType.superfluid])
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
    elif payment_type == PaymentType.credit:
        if is_confidential:
            logger.debug(f"Confidential instance {item_hash} using Credits")
        if have_gpu:
            logger.debug(f"GPU Instance {item_hash} using Credits")

        credit_balance = await fetch_credit_balance_of_address(message.content.address)

        credits_price_x_second = await fetch_execution_price(item_hash, [PaymentType.credit])
        required_credits = Decimal(credits_price_x_second) * Decimal(60) * Decimal(60)
        logger.debug(
            f"Required credit balance for Address {message.content.address} executions: {required_credits}, {item_hash}"
        )

        if required_credits > credit_balance:
            return web.HTTPPaymentRequired(
                reason="Insufficient balance",
                text="Insufficient credits for this instance\n\n"
                f"Required: {required_credits} credits \n"
                f"Current user credits: {credit_balance}",
            )

    else:
        return web.HTTPBadRequest(reason="Invalid payment method")

    # Exceptions that can be raised when starting a VM. SupervisorError covers
    # the full create-failure contract vocabulary (download, setup, init,
    # capacity); see the matching tuple in update_allocations above.
    vm_creation_exceptions = (
        UnknownHashError,
        SupervisorError,
        HostNotFoundError,
        InsufficientResourcesError,
    )

    scheduling_errors: dict[ItemHash, Exception] = {}
    try:
        logger.info(f"Starting persistent vm {item_hash} from notify_allocation")
        await start_persistent_vm(
            item_hash,
            pubsub,
            supervisor=supervisor,
            registry=registry,
            expiry=expiry,
            update_watcher=update_watcher,
        )
        successful = True
        await sync_domain_mappings(request.app["supervisor"])
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
    supervisor: Supervisor = request.app["supervisor"]
    try:
        data = await request.json()
        message = InstanceContent.model_validate(data)
    except JSONDecodeError:
        return web.HTTPBadRequest(text="Body is not valid JSON")
    except ValidationError as error:
        return web.json_response(data=error.json(), status=web.HTTPBadRequest.status_code)

    # The agent translates the message into a message-free resources DTO; the
    # supervisor runs capacity admission (keeping the dry-run honest) then holds
    # the requested resources, returning the reservation expiry. No Aleph message
    # crosses the supervisor boundary.
    reservation_request = build_reservation_request(message, authenticated_sender)
    try:
        expiration_date = await supervisor.reserve_resources(reservation_request)
    except BoundaryInsufficientResourcesError as error:
        logger.warning("Refusing resource reservation: %s", error)
        return web.HTTPServiceUnavailable(
            reason="Insufficient capacity",
            text="This CRN cannot reserve the requested resources at this time.",
        )
    except SupervisorError as error:
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

    registry = request.app["vm_registry"]
    record = registry.get(vm_hash)
    if record is None:
        raise HTTPNotFound(reason="VM not found")

    supervisor = request.app["supervisor"]
    vm_id = VmId(str(vm_hash))
    try:
        info = await supervisor.get_vm(vm_id)
    except VmNotFoundError:
        raise HTTPNotFound(reason="VM not found") from None
    if info.status is not VmStatus.RUNNING:
        # Configuration will be fetched when the VM starts; not an error.
        return web.json_response({"status": "ok", "msg": "VM not starting yet"}, dumps=dumps_for_json, status=200)

    await reconcile_port_forwards(supervisor, vm_id, record.message)
    await sync_domain_mappings(request.app["supervisor"])
    return web.json_response({}, dumps=dumps_for_json, status=200)
