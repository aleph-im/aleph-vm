import asyncio
import hashlib
import hmac
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from pathlib import Path

import aiohttp
import aiohttp.web_exceptions
import pydantic
from aiohttp import web
from aiohttp.web_urldispatcher import UrlMappingMatchInfo
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash, MessageType
from aleph_message.models.execution import BaseExecutableContent
from pydantic import BaseModel

from aleph.vm.conf import settings
from aleph.vm.controllers.qemu.backup import (
    download_volume_by_ref,
    get_backup_directory,
)
from aleph.vm.orchestrator import metrics
from aleph.vm.orchestrator.cache import AsyncTTLCache
from aleph.vm.orchestrator.custom_logs import set_vm_for_logging
from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.orchestrator.http import get_session
from aleph.vm.orchestrator.run import create_vm_execution_or_raise_http_error
from aleph.vm.orchestrator.views.authentication import (
    authenticate_websocket_message,
    require_jwk_authentication,
)
from aleph.vm.orchestrator.vm_registry import AgentVmRecord
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import (
    BackupNotFoundError,
    InsufficientResourcesError,
    InvalidBackendError,
    VmNotFoundError,
)
from aleph.vm.supervisor.types import (
    BackupId,
    BackupInfo,
    BackupStatus,
    ConfidentialMode,
    VmId,
    VmStatus,
)
from aleph.vm.utils import (
    cors_allow_all,
    dumps_for_json,
    get_message_executable_content,
)

logger = logging.getLogger(__name__)


_security_aggregate_cache = AsyncTTLCache(ttl_seconds=settings.CACHE_TTL_SECURITY_AGGREGATE)


def _validate_backup_id(
    backup_id: str,
    vm_hash: ItemHash,
) -> str:
    """Sanitize backup_id and verify it belongs to the given VM.

    Raises HTTPBadRequest on path traversal attempts and HTTPForbidden
    when the backup does not belong to the VM.
    """
    if not backup_id or "/" in backup_id or "\\" in backup_id or ".." in backup_id:
        raise web.HTTPBadRequest(body="Invalid backup_id")
    if not backup_id.startswith(str(vm_hash)):
        raise web.HTTPForbidden(body="Backup does not belong to this VM")
    return backup_id


_BACKUP_SIGNATURE_TTL = 24 * 3600  # 24 hours


def _sign_backup_url(
    secret: str,
    backup_id: str,
    vm_hash: str,
    expires: int,
) -> str:
    """Generate an HMAC-SHA256 signature for a backup download URL."""
    msg = f"{backup_id}:{vm_hash}:{expires}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def _build_signed_download_url(
    request: web.Request,
    vm_hash: str,
    backup_id: str,
) -> str:
    """Build a presigned download URL valid for 24 hours."""
    secret = request.app["secret_token"]
    expires = int(time.time()) + _BACKUP_SIGNATURE_TTL
    signature = _sign_backup_url(secret, backup_id, vm_hash, expires)
    path = f"/control/machine/{vm_hash}/backup/{backup_id}"
    domain = settings.DOMAIN_NAME
    return f"https://{domain}{path}?signature={signature}&expires={expires}"


def _verify_backup_download(request: web.Request, vm_hash: str, backup_id: str) -> None:
    """Verify a presigned backup download URL.

    Raises HTTPForbidden if the signature is missing/invalid/expired.
    """
    signature = request.query.get("signature", "")
    expires_str = request.query.get("expires", "")
    if not signature or not expires_str:
        raise web.HTTPForbidden(body="Missing signature or expires parameter")
    try:
        expires = int(expires_str)
    except ValueError:
        raise web.HTTPBadRequest(body="Invalid expires parameter") from None
    if time.time() > expires:
        raise web.HTTPForbidden(body="Download link has expired")
    secret = request.app["secret_token"]
    expected = _sign_backup_url(secret, backup_id, str(vm_hash), expires)
    if not hmac.compare_digest(signature, expected):
        raise web.HTTPForbidden(body="Invalid signature")


def get_itemhash_or_400(match_info: UrlMappingMatchInfo) -> ItemHash:
    try:
        ref = match_info["ref"]
    except KeyError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body="Missing field: 'ref'") from error
    try:
        return ItemHash(ref)
    except UnknownHashError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body=f"Invalid ref: '{ref}'") from error


def get_agent_record_or_404(request: web.Request, vm_hash: ItemHash) -> AgentVmRecord:
    """Owner identity now comes from the agent registry, not the execution."""
    record = request.app["vm_registry"].get(vm_hash)
    if record is None:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}")
    return record


# A confidential instance is created through the allocation path, where
# create_vm (build config + start to the awaiting state) can take ~20s, but the
# scheduler exposes placement earlier. The agent now records the owner identity
# at the *start* of create (see create_vm_execution), so owner-auth resolves
# immediately via get_agent_record_or_404. The VM itself, however, only reaches
# awaiting_confidential_init when create_vm completes (the controller config is
# written and start() sets starting_at). The owner's one-shot init-session call
# can still land in that window, so wait for the VM to become awaiting-ready
# before initializing it. Happy path returns in one poll; the cap only bounds a
# create that never reaches the awaiting state.
_CONFIDENTIAL_AWAITING_WAIT_SECONDS = 120
_CONFIDENTIAL_AWAITING_POLL_INTERVAL = 2.0


async def wait_for_awaiting_confidential_init(supervisor: Supervisor, vm_id: VmId) -> bool:
    """Poll until the VM reaches awaiting_confidential_init. Return True once it
    does, or False if the bounded deadline passes first.

    initialize_confidential writes the session files and starts the controller;
    it fails if called before the VM is awaiting-ready. The owner's single
    init-session call may arrive while create_vm is still building the config,
    so poll get_vm rather than racing it. The caller maps a False return to the
    appropriate HTTP response.
    """
    deadline = asyncio.get_running_loop().time() + _CONFIDENTIAL_AWAITING_WAIT_SECONDS
    while True:
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            info = None
        if info is not None and info.awaiting_confidential_init:
            return True
        if asyncio.get_running_loop().time() >= deadline:
            return False
        await asyncio.sleep(_CONFIDENTIAL_AWAITING_POLL_INTERVAL)


async def check_owner_permissions(authenticated_sender: str, message: BaseExecutableContent) -> bool:
    """Check if the authenticated sender has delegation permissions from the message owner.

    Fetches the security aggregate for the message address (cached) and checks
    if the authenticated_sender is listed in the delegations.
    """
    cache_key = message.address.lower()
    security_data = _security_aggregate_cache.get(cache_key)

    if security_data is None:
        try:
            session = get_session()
            url = f"{settings.API_SERVER}/api/v0/aggregates/{message.address}.json?keys=security"
            logger.debug(f"Fetching security aggregate from {url}")
            resp = await session.get(url)
            resp.raise_for_status()

            resp_data = await resp.json()
            security_data = resp_data.get("data", {}).get("security", {})
            _security_aggregate_cache.set(cache_key, security_data)
        except Exception:
            logger.warning("Failed to fetch security aggregate", exc_info=True)
            return False

    delegations = security_data.get("authorizations", [])
    for delegation in delegations:
        if not isinstance(delegation, dict):
            continue

        delegated_message_types = delegation.get("types", [])
        if len(delegated_message_types) > 0 and MessageType.instance not in delegated_message_types:
            continue

        authorized_address = delegation.get("address", "")
        if authorized_address.lower() == authenticated_sender.lower():
            logger.debug(f"Found delegation for {authenticated_sender} from {message.address}")
            return True

    logger.debug(f"No delegation found for {authenticated_sender} from {message.address}")
    return False


async def is_sender_authorized(authenticated_sender: str, message: BaseExecutableContent) -> bool:
    """
    Check if the authenticated sender is authorized to access the message resources.

    Authorization is granted if:
    1. The authenticated sender matches the message owner address, OR
    2. The authenticated sender has delegation permissions from the owner

    Args:
        authenticated_sender: The address of the authenticated user
        message: The message containing the owner address

    Returns:
        True if authorized, False otherwise
    """
    # Check if sender is the owner
    if authenticated_sender.lower() == message.address.lower():
        return True

    # Check if sender has delegation permissions
    if await check_owner_permissions(authenticated_sender, message):
        return True

    logger.debug(f"Unauthorized sender {authenticated_sender} is not {message.address}")
    return False


async def _logs_auth_message(request: web.Request, vm_hash: ItemHash):
    """Message for owner-auth on the logs endpoints: registry first, then the
    agent DB (past executions keep their record until record_usage deletes it)."""
    record = request.app["vm_registry"].get(vm_hash)
    if record is not None:
        return record.message
    db_record = await metrics.get_last_record_for_vm(vm_hash=vm_hash)
    if not db_record:
        return None
    return get_message_executable_content(json.loads(db_record.message))


@cors_allow_all
async def stream_logs(request: web.Request) -> web.StreamResponse:
    """Stream the logs of a VM.

    The authentication method is slightly different because browsers do not
    allow Javascript to set headers in WebSocket requests.

    When the VM is stopped, past logs are sent from journald and the
    connection is closed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        message = await _logs_auth_message(request, vm_hash)
        if message is None:
            raise web.HTTPNotFound(body=f"No execution found for VM {vm_hash}")

        ws = web.WebSocketResponse()
        logger.info(f"starting websocket: {request.path}")
        await ws.prepare(request)

        try:
            first_message = await ws.receive_json()
        except (TypeError, ValueError) as error:
            logger.exception(error)
            await ws.send_json({"status": "failed", "reason": str(error)})
            await ws.close()
            return ws

        credentials = first_message.get("auth")
        if not credentials:
            await ws.send_json({"status": "failed", "reason": "missing 'auth' key in message"})
            await ws.close()
            return ws

        try:
            authenticated_sender = await authenticate_websocket_message(credentials)
            if not await is_sender_authorized(authenticated_sender, message):
                await ws.send_json({"status": "failed", "reason": "unauthorized sender"})
                await ws.close()
                return ws
        except Exception as error:
            await ws.send_json({"status": "failed", "reason": str(error)})
            await ws.close()
            return ws

        await ws.send_json({"status": "connected"})

        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            info = None

        if info and info.status is VmStatus.RUNNING:
            try:
                async for chunk in supervisor.stream_logs(vm_id):
                    await ws.send_json({"type": chunk.source.value, "message": chunk.line})
            finally:
                await ws.close()
                logger.info(f"connection {ws} closed")
        elif info and info.status is VmStatus.BOOTING:
            await ws.send_json({"type": "system", "message": "VM is starting, try again shortly"})
            await ws.close()
        else:
            for chunk in await supervisor.get_logs(vm_id):
                await ws.send_json({"type": chunk.source.value, "message": chunk.line})
            await ws.send_json({"type": "system", "message": "VM is not running, past logs sent"})
            await ws.close()
            logger.info(f"connection {ws} closed (past logs for stopped VM)")

        return ws


@cors_allow_all
@require_jwk_authentication
async def operate_logs_json(request: web.Request, authenticated_sender: str) -> web.StreamResponse:
    """Logs of a VM (not streaming) as json"""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        message = await _logs_auth_message(request, vm_hash)
        if message is None:
            raise aiohttp.web_exceptions.HTTPNotFound(body="No execution found for this VM")
        if not await is_sender_authorized(authenticated_sender, message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        chunks = await supervisor.get_logs(VmId(str(vm_hash)))

        response = web.StreamResponse()
        response.headers["Transfer-encoding"] = "chunked"
        response.headers["Content-Type"] = "application/json"
        await response.prepare(request)
        await response.write(b"[")
        first = True
        for chunk in chunks:
            if not first:
                await response.write(b",\n")
            first = False
            identifier = f"vm-{vm_hash}-{chunk.source.value}"
            msg = {
                "SYSLOG_IDENTIFIER": identifier,
                "MESSAGE": chunk.line,
                "file": chunk.source.value,
                "__REALTIME_TIMESTAMP": datetime.fromtimestamp(chunk.timestamp_ns / 1e9, tz=timezone.utc),
            }
            await response.write(dumps_for_json(msg).encode())
        await response.write(b"]")
        await response.write_eof()
        return response


@cors_allow_all
@require_jwk_authentication
async def operate_expire(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible.

    A timeout may be specified to delay the action."""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        try:
            timeout = float(ItemHash(request.match_info["timeout"]))
        except (KeyError, ValueError) as error:
            raise web.HTTPBadRequest(body="Invalid timeout duration") from error
        if not 0 < timeout < timedelta(days=10).total_seconds():
            return web.HTTPBadRequest(body="Invalid timeout duration")

        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Expiring in {timeout} seconds: {vm_hash}")
        expiry: ExpiryManager = request.app["expiry"]
        expiry.schedule(VmId(str(vm_hash)), timeout)
        # Deliberately leave the update watcher armed: the VM keeps running until
        # the timer fires, so an update during the window should still redeploy it.

        return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


@cors_allow_all
@require_jwk_authentication
async def operate_confidential_initialize(request: web.Request, authenticated_sender: str) -> web.Response:
    """Start the confidential virtual machine if possible."""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        # Owner identity is recorded at the start of create (create_vm_execution),
        # so this resolves immediately even while create_vm is still in flight;
        # no long poll for the record. Readiness (the VM reaching the
        # awaiting-init state) is handled separately, below.
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            # create_vm may not have registered the VM with the supervisor yet;
            # the awaiting-init wait below tolerates that, so don't 404 here.
            info = None

        # A confidential VM awaiting its owner's session reports BOOTING on the
        # spec create path (start() sets starting_at without launching the
        # controller), but it is precisely what this endpoint initializes — so
        # only reject a VM that is actually running, not one awaiting init.
        if (
            info is not None
            and info.status in (VmStatus.RUNNING, VmStatus.BOOTING)
            and not info.awaiting_confidential_init
        ):
            return web.json_response(
                {"code": "vm_running", "description": "Operation not allowed, instance already running"},
                status=HTTPStatus.BAD_REQUEST,
            )
        if info is not None and info.confidential_mode is ConfidentialMode.NONE:
            return web.json_response(
                {"code": "not_confidential", "description": "Instance is not a confidential instance"},
                status=HTTPStatus.BAD_REQUEST,
            )

        # The owner's init-session call can land before create_vm has finished
        # building the controller config and started the VM into the awaiting
        # state. initialize_confidential fails if the VM is not awaiting-ready,
        # so wait for that state (bounded) before uploading the session files. A
        # VM that never reaches it (timeout, or one the supervisor never
        # registers) is reported as not found.
        if info is None or not info.awaiting_confidential_init:
            if not await wait_for_awaiting_confidential_init(supervisor, vm_id):
                raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}")

        post = await request.post()

        session_file_content = post.get("session")
        if not session_file_content:
            return web.json_response(
                {"code": "field_missing", "description": "Session field is missing"},
                status=HTTPStatus.BAD_REQUEST,
            )

        godh_file_content = post.get("godh")
        if not godh_file_content:
            return web.json_response(
                {"code": "field_missing", "description": "godh field is missing. Please provide a GODH file"},
                status=HTTPStatus.BAD_REQUEST,
            )

        await supervisor.initialize_confidential(
            vm_id,
            session_file_content.file.read(),
            godh_file_content.file.read(),
        )

        return web.Response(status=200, body=f"Started VM with ref {vm_hash}")


@cors_allow_all
@require_jwk_authentication
async def operate_stop(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible."""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
            if info.status in (VmStatus.RUNNING, VmStatus.BOOTING):
                logger.info(f"Stopping {vm_hash}")
                # Stop means stop: the VM stays defined and listed (STOPPED),
                # and start brings it back in place. Deleting it is a separate
                # action, triggered by forgetting the instance message
                # (operate_erase). Ephemeral VMs have no stop state, so for
                # them the stop cycle is delete + recreate.
                if record.persistent:
                    await supervisor.stop_vm(vm_id)
                else:
                    await supervisor.delete_vm(vm_id)
                request.app["expiry"].cancel(vm_id)
                request.app["update_watcher"].cancel(vm_id)
                return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        return web.Response(status=200, body="Already stopped, nothing to do")


@cors_allow_all
@require_jwk_authentication
async def operate_reboot(request: web.Request, authenticated_sender: str) -> web.Response:
    """
    Reboots the virtual machine, smoothly if possible.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
            if info.status in (VmStatus.RUNNING, VmStatus.BOOTING):
                logger.info(f"Rebooting {vm_hash}")
                if record.persistent:
                    await supervisor.reboot_vm(vm_id)
                else:
                    await supervisor.delete_vm(vm_id)
                    request.app["expiry"].cancel(vm_id)
                    request.app["update_watcher"].cancel(vm_id)
                    await create_vm_execution_or_raise_http_error(
                        vm_hash=vm_hash,
                        supervisor=supervisor,
                        registry=request.app["vm_registry"],
                    )
                return web.Response(status=200, body=f"Rebooted VM with ref {vm_hash}")
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        return web.Response(status=200, body=f"Starting VM (was not running) with ref {vm_hash}")


@cors_allow_all
@require_jwk_authentication
async def operate_confidential_measurement(request: web.Request, authenticated_sender) -> web.Response:
    """
    Fetch the sev measurement for the VM
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        measurement = await supervisor.get_measurement(VmId(str(vm_hash)))
        sev_info = measurement.sev_info

        return web.json_response(
            data={
                "sev_info": {
                    "enabled": sev_info.enabled,
                    "api_major": sev_info.api_major,
                    "api_minor": sev_info.api_minor,
                    "build_id": sev_info.build_id,
                    "policy": sev_info.policy,
                    "state": sev_info.state,
                    "handle": sev_info.handle,
                },
                "launch_measure": measurement.launch_measure,
            },
            status=200,
            dumps=dumps_for_json,
        )


class InjectSecretParams(BaseModel):
    """
    packet_header: as base64 string
    secret : encrypted secret table as base64 string
    """

    packet_header: str
    secret: str


@cors_allow_all
@require_jwk_authentication
async def operate_confidential_inject_secret(request: web.Request, authenticated_sender) -> web.Response:
    """
    Send secret to the VM and start it
    """
    try:
        data = await request.json()
        params = InjectSecretParams.model_validate(data)
    except json.JSONDecodeError:
        return web.HTTPBadRequest(text="Body is not valid JSON")
    except pydantic.ValidationError as error:
        return web.json_response(data=error.json(), status=web.HTTPBadRequest.status_code)

    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        await supervisor.inject_secret(
            vm_id,
            params.packet_header.encode(),
            params.secret.encode(),
        )

        # The confidential VM only boots now (post-secret). At create time it was
        # awaiting init, so the normal create-completion port setup
        # (run.finish_instance_create) was skipped; establish its host port
        # forwards (SSH/22 + the owner's aggregate) now that it is running, like
        # a normal instance gets at create. Without this the VM has no mapped
        # port 22 and is unreachable.
        from aleph.vm.orchestrator.run import reconcile_port_forwards

        await reconcile_port_forwards(supervisor, vm_id, record.message)

        # inject_secret only returns on the success path (a QMP failure raises),
        # so the VM has resumed and is running. The void supervisor method cannot
        # carry the post-injection QMP status back, so we reproduce the running
        # query-status body the pre-Phase-1 endpoint returned here instead of
        # round-tripping query-status only to discard everything but this fact.
        return web.json_response(
            data={"status": {"status": "running", "running": True, "singlestep": False}},
            status=200,
            dumps=dumps_for_json,
        )


@cors_allow_all
@require_jwk_authentication
async def operate_erase(request: web.Request, authenticated_sender: str) -> web.Response:
    """Delete all data stored by a virtual machine.
    Stop the virtual machine first if needed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Erasing {vm_hash}")
        supervisor: Supervisor = request.app["supervisor"]
        try:
            await supervisor.delete_vm(VmId(str(vm_hash)), wipe=True)
            request.app["expiry"].cancel(VmId(str(vm_hash)))
            request.app["update_watcher"].cancel(VmId(str(vm_hash)))
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        request.app["vm_registry"].forget(vm_hash)
        return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")


@cors_allow_all
@require_jwk_authentication
async def operate_reinstall(request: web.Request, authenticated_sender: str) -> web.Response:
    """Reinstall a virtual machine to its initial state.

    Stops the VM, erases volumes, and starts it fresh.

    Query Parameters:
        erase_volumes: Set to 'false' to only reset the rootfs
            while preserving persistent data volumes.
            Defaults to 'true' (erase everything).
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    rootfs_only = request.query.get("erase_volumes", "true") == "false"

    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Reinstalling (reset to initial state) {vm_hash}")
        supervisor: Supervisor = request.app["supervisor"]
        try:
            await supervisor.reinstall_vm(VmId(str(vm_hash)), wipe_volumes=not rootfs_only)
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        if not record.persistent:
            await create_vm_execution_or_raise_http_error(
                vm_hash=vm_hash,
                supervisor=supervisor,
                registry=request.app["vm_registry"],
            )
        return web.Response(status=200, body=f"Reinstalled VM with ref {vm_hash}")


def _backup_metadata_response(info: BackupInfo, request: web.Request, vm_hash_str: str) -> dict:
    """Build the JSON metadata body for a completed backup.

    Sourced entirely from the BackupInfo the supervisor returns plus the
    presigned download URL the agent signs (an HTTP-only concern).
    """
    expires_at = datetime.fromtimestamp(
        info.created_at_unix_secs + _BACKUP_SIGNATURE_TTL,
        tz=timezone.utc,
    ).isoformat()
    meta: dict = {
        "backup_id": str(info.backup_id),
        "size": info.size_bytes,
        "volumes": list(info.volumes),
        "expires_at": expires_at,
        "download_url": _build_signed_download_url(request, vm_hash_str, str(info.backup_id)),
    }
    if info.checksum:
        meta["checksum"] = info.checksum
    if info.source_sizes:
        meta["source_sizes"] = dict(info.source_sizes)
    return meta


@cors_allow_all
@require_jwk_authentication
async def operate_backup(request: web.Request, authenticated_sender: str) -> web.Response:
    """Create a QEMU VM disk backup and return metadata.

    By default backs up only the rootfs.  Add ``?include_volumes=true``
    to also include non-read-only persistent volumes in the archive.

    The supervisor freezes the guest filesystems during the copy (unless
    ``?skip_fsfreeze=true``), verifies the archive, and tracks progress: a
    backup still running returns 202; a completed one returns its metadata.

    Query Parameters:
        include_volumes: Set to 'true' to include persistent volumes.
        skip_fsfreeze: Set to 'true' to skip filesystem freeze.

    Returns:
        JSON with backup_id, size, checksum, volumes, expires_at, download_url.
        202 while a backup is in progress.

    Raises:
        400: VM not running or not a QEMU VM (invalid backend).
        403: Unauthorized sender.
        507: Insufficient disk space.
        500: Backup creation failed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    vm_hash_str = str(vm_hash)

    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        include_volumes = request.query.get("include_volumes") == "true"
        quiesce_guest = request.query.get("skip_fsfreeze") != "true"
        try:
            info = await supervisor.start_backup(
                VmId(vm_hash_str),
                quiesce_guest=quiesce_guest,
                include_volumes=include_volumes,
            )
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        except InvalidBackendError as error:
            return web.HTTPBadRequest(body=str(error) or "Backup only supported for QEMU VMs")
        except InsufficientResourcesError as error:
            return web.Response(status=507, body=str(error))

        if info.status is BackupStatus.RUNNING:
            return web.json_response({"status": "in_progress"}, status=202, dumps=dumps_for_json)
        if info.status is BackupStatus.FAILED:
            return web.Response(status=500, body=f"Backup failed: {info.error_message}")
        return web.json_response(
            _backup_metadata_response(info, request, vm_hash_str),
            dumps=dumps_for_json,
        )


@cors_allow_all
@require_jwk_authentication
async def operate_backup_status(request: web.Request, authenticated_sender: str) -> web.Response:
    """Report the latest backup for a VM: 202 while one is running, the
    metadata (with a presigned URL) for a completed one, 404 when none."""
    vm_hash = get_itemhash_or_400(request.match_info)
    vm_hash_str = str(vm_hash)

    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        backups = await supervisor.list_backups(VmId(vm_hash_str))

        if any(b.status is BackupStatus.RUNNING for b in backups):
            return web.json_response({"status": "in_progress"}, status=202, dumps=dumps_for_json)

        completed = [b for b in backups if b.status is BackupStatus.COMPLETE]
        if not completed:
            raise web.HTTPNotFound(body="No backup found for this VM")

        # The freshest completed archive.
        latest = max(completed, key=lambda b: b.created_at_unix_secs)
        return web.json_response(
            _backup_metadata_response(latest, request, vm_hash_str),
            dumps=dumps_for_json,
        )


@cors_allow_all
async def operate_backup_download(request: web.Request) -> web.StreamResponse:
    """Download a previously created backup archive via presigned URL.

    Requires ``?signature=...&expires=...`` query parameters generated
    by the backup creation endpoint.  No JWK authentication needed.

    The archive bytes stream from the supervisor; the sidecar headers
    (Content-Length, X-Backup-Checksum, X-Source-Size) come from the backup
    metadata the supervisor reports.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    backup_id = _validate_backup_id(request.match_info.get("backup_id", ""), vm_hash)
    _verify_backup_download(request, str(vm_hash), backup_id)

    with set_vm_for_logging(vm_hash=vm_hash):
        supervisor: Supervisor = request.app["supervisor"]
        try:
            info = await supervisor.get_backup_status(VmId(str(vm_hash)), BackupId(backup_id))
        except BackupNotFoundError:
            raise web.HTTPNotFound(body=f"Backup {backup_id} not found") from None

        response = web.StreamResponse()
        response.headers["Content-Type"] = "application/x-tar"
        response.headers["Content-Disposition"] = f'attachment; filename="{backup_id}.tar"'
        response.headers["Content-Length"] = str(info.size_bytes)
        if info.checksum:
            response.headers["X-Backup-Checksum"] = info.checksum
        total_source_size = sum(info.source_sizes.values())
        if total_source_size:
            response.headers["X-Source-Size"] = str(total_source_size)

        await response.prepare(request)
        async for chunk in supervisor.download_backup(VmId(str(vm_hash)), BackupId(backup_id)):
            await response.write(chunk.data)
        await response.write_eof()
        return response


@cors_allow_all
@require_jwk_authentication
async def operate_backup_delete(
    request: web.Request,
    authenticated_sender: str,
) -> web.Response:
    """Delete a backup archive and its sidecars."""
    vm_hash = get_itemhash_or_400(request.match_info)
    backup_id = _validate_backup_id(request.match_info.get("backup_id", ""), vm_hash)

    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        try:
            await supervisor.delete_backup(VmId(str(vm_hash)), BackupId(backup_id))
        except BackupNotFoundError:
            raise web.HTTPNotFound(body=f"Backup {backup_id} not found") from None

        logger.info("Deleted backup %s for %s", backup_id, vm_hash)
        return web.Response(status=200, body=f"Deleted backup {backup_id}")


async def _stage_restore_upload(
    request: web.Request,
    staging_dir: Path,
    vm_hash: str,
    max_bytes: int,
) -> Path:
    """Stream a multipart rootfs upload to a host path the engine can read."""
    limit = max_bytes or settings.MAX_RESTORE_UPLOAD_BYTES
    reader = await request.multipart()
    field = await reader.next()
    while field is not None:
        if field.name == "rootfs":
            break
        field = await reader.next()
    if field is None:
        raise web.HTTPBadRequest(body="Missing 'rootfs' field in multipart upload")
    upload_path = staging_dir / f"restore-{vm_hash}.qcow2"
    bytes_written = 0
    with open(upload_path, "wb") as f:
        while True:
            chunk = await field.read_chunk(65536)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > limit:
                upload_path.unlink(missing_ok=True)
                raise web.HTTPRequestEntityTooLarge(max_size=limit, actual_size=bytes_written)
            f.write(chunk)
    return upload_path


async def _stage_restore_volume_ref(request: web.Request, staging_dir: Path) -> Path:
    """Download a volume by item hash from a JSON request body to a host path."""
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(body="Expected multipart upload or JSON with volume_ref") from None
    volume_ref = data.get("volume_ref", "")
    if not volume_ref:
        raise web.HTTPBadRequest(body="Missing volume_ref in JSON body")
    if not all(c in "0123456789abcdef" for c in volume_ref):
        raise web.HTTPBadRequest(body="Invalid volume_ref format")
    return await download_volume_by_ref(volume_ref, staging_dir)


@cors_allow_all
@require_jwk_authentication
async def operate_restore(
    request: web.Request,
    authenticated_sender: str,
) -> web.Response:
    """Restore a VM's rootfs from an uploaded QCOW2 or a volume item hash.

    Accepts either:
    - Multipart upload with a ``rootfs`` file field (QCOW2).
    - JSON body with ``{"volume_ref": "<item_hash>"}``.

    The agent stages the bytes to a host path and hands the disk/VM work
    (validate, size-check, swap rootfs, restart) to the supervisor.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    temp_file: Path | None = None
    restore_succeeded = False

    with set_vm_for_logging(vm_hash=vm_hash):
        try:
            record = get_agent_record_or_404(request, vm_hash)
            if not await is_sender_authorized(authenticated_sender, record.message):
                return web.Response(status=403, body="Unauthorized sender")

            supervisor: Supervisor = request.app["supervisor"]
            staging_dir = get_backup_directory()

            max_upload = record.message.rootfs.size_mib * 1024 * 1024
            if request.content_length and request.content_length > max_upload:
                return web.HTTPRequestEntityTooLarge(
                    max_size=max_upload,
                    actual_size=request.content_length,
                )

            content_type = request.content_type or ""
            if content_type.startswith("multipart/"):
                temp_file = await _stage_restore_upload(request, staging_dir, str(vm_hash), max_upload)
            else:
                temp_file = await _stage_restore_volume_ref(request, staging_dir)

            try:
                await supervisor.restore_from_image(
                    VmId(str(vm_hash)),
                    temp_file,
                    max_virtual_size_bytes=max_upload,
                )
            except VmNotFoundError:
                raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
            except InvalidBackendError as error:
                # qemu-img rejecting the image, an oversized disk, or a
                # non-QEMU VM are all client errors.
                logger.info("Rejected restore for VM %s: %s", vm_hash, error)
                return web.HTTPBadRequest(body=str(error) or "Invalid restore image")
            restore_succeeded = True

            return web.json_response(
                {"status": "restored", "vm_hash": str(vm_hash)},
                dumps=dumps_for_json,
            )

        except web.HTTPException:
            raise
        except Exception:
            logger.exception("Failed to restore VM %s", vm_hash)
            raise web.HTTPInternalServerError(body="Restore failed") from None
        finally:
            # Only delete the staged file after a successful restore. On
            # failure, keep it so the user doesn't have to re-upload.
            if restore_succeeded and temp_file and temp_file.exists():
                temp_file.unlink(missing_ok=True)
