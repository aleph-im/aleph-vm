import asyncio
import hashlib
import hmac
import json
import logging
import time
from dataclasses import dataclass
from datetime import timedelta
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
    InsufficientDiskSpaceError,
    backup_metadata,
    check_disk_space_for_multiple,
    cleanup_expired_backups,
    create_backup_archive,
    create_qemu_disk_backup,
    download_volume_by_ref,
    find_existing_backup,
    get_backup_directory,
    get_qemu_disk_virtual_size,
    restore_rootfs,
    verify_qemu_disk,
)
from aleph.vm.controllers.qemu.client import QemuVmClient
from aleph.vm.controllers.qemu.instance import AlephQemuInstance
from aleph.vm.controllers.qemu_confidential.instance import (
    AlephQemuConfidentialInstance,
)
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator import metrics
from aleph.vm.orchestrator.cache import AsyncTTLCache
from aleph.vm.orchestrator.custom_logs import set_vm_for_logging
from aleph.vm.orchestrator.http import get_session
from aleph.vm.orchestrator.run import create_vm_execution_or_raise_http_error
from aleph.vm.orchestrator.views.authentication import (
    authenticate_websocket_message,
    require_jwk_authentication,
)
from aleph.vm.pool import VmPool
from aleph.vm.utils import (
    cors_allow_all,
    dumps_for_json,
    get_message_executable_content,
)
from aleph.vm.utils.logs import get_past_vm_logs

logger = logging.getLogger(__name__)

_BACKUP_RESULT_TTL = 3600  # Keep results for 1 hour max


class BackupState:
    """Per-app container for backup-related mutable state.

    Stored on ``app["backup_state"]`` so lifecycle is tied to the app
    and tests get a fresh instance automatically.
    """

    def __init__(self) -> None:
        self.locks: dict[str, asyncio.Lock] = {}
        self.tasks: dict[str, asyncio.Task] = {}
        self.results: dict[str, tuple[float, dict | Exception]] = {}

    def evict_stale_results(self) -> None:
        """Remove results older than the TTL."""
        now = time.time()
        stale = [k for k, (ts, _) in self.results.items() if now - ts > _BACKUP_RESULT_TTL]
        for k in stale:
            self.results.pop(k, None)


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


def _erase_execution_volumes(
    execution: VmExecution,
    *,
    include_rootfs: bool = False,
    include_data_volumes: bool = True,
) -> int:
    """Delete volumes from an execution.

    Args:
        execution: The VM execution whose volumes to delete.
        include_rootfs: Delete the rootfs disk image.
        include_data_volumes: Delete non-read-only data volumes.

    Returns the number of volumes deleted.
    """
    if execution.resources is None:
        return 0

    deleted_count = 0

    if include_rootfs:
        rootfs = execution.resources.rootfs_path
        if rootfs.exists():
            logger.info(f"Deleting rootfs {rootfs}")
            rootfs.unlink()
            deleted_count += 1

    if include_data_volumes:
        for volume in execution.resources.volumes:
            if not volume.read_only:
                logger.info(f"Deleting volume {volume.path_on_host}")
                volume.path_on_host.unlink(missing_ok=True)
                deleted_count += 1

    return deleted_count


async def _restart_persistent_vm(
    pool: VmPool,
    execution: VmExecution,
) -> None:
    """Re-register a stopped persistent VM and restart it via systemd."""
    if pool.network and execution.vm:
        await pool.network.create_tap(
            execution.vm.vm_id,
            execution.vm.tap_interface,
        )
    # stop_vm fires stop_event which triggers a background task that
    # removes the execution from the pool.  Reset execution state so
    # it is tracked again after the systemd restart.
    execution.times.stopping_at = None
    execution.times.stopped_at = None
    execution.stop_event = asyncio.Event()
    pool.executions[execution.vm_hash] = execution
    pool._schedule_forget_on_stop(execution)
    pool.systemd_manager.restart(execution.controller_service)
    # Re-save so load_persistent_executions() finds it on restart.
    execution.record = None
    await execution.save()


def get_itemhash_or_400(match_info: UrlMappingMatchInfo) -> ItemHash:
    try:
        ref = match_info["ref"]
    except KeyError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body="Missing field: 'ref'") from error
    try:
        return ItemHash(ref)
    except UnknownHashError as error:
        raise aiohttp.web_exceptions.HTTPBadRequest(body=f"Invalid ref: '{ref}'") from error


def get_execution_or_404(ref: ItemHash, pool: VmPool) -> VmExecution:
    """Return the execution corresponding to the ref or raise an HTTP 404 error."""
    # TODO: Check if this should be execution.message.address or execution.message.content.address?
    execution = pool.executions.get(ref)
    if execution:
        return execution
    else:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {ref}")


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


@cors_allow_all
async def stream_logs(request: web.Request) -> web.StreamResponse:
    """Stream the logs of a VM.

    The authentication method is slightly different because browsers do not
    allow Javascript to set headers in WebSocket requests.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if execution.vm is None:
            raise web.HTTPBadRequest(body=f"VM {vm_hash} is not running")
        queue = None
        try:
            ws = web.WebSocketResponse()
            logger.info(f"starting websocket: {request.path}")
            await ws.prepare(request)
            try:
                await authenticate_websocket_for_vm_or_403(execution, vm_hash, ws)
                await ws.send_json({"status": "connected"})

                queue = execution.vm.get_log_queue()

                while True:
                    log_type, message = await queue.get()
                    assert log_type in ("stdout", "stderr")
                    logger.debug(message)

                    await ws.send_json({"type": log_type, "message": message})
                    queue.task_done()

            finally:
                await ws.close()
                logger.info(f"connection  {ws} closed")

        finally:
            if queue:
                execution.vm.unregister_queue(queue)


@cors_allow_all
@require_jwk_authentication
async def operate_logs_json(request: web.Request, authenticated_sender: str) -> web.StreamResponse:
    """Logs of a VM (not streaming) as json"""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        # This endpoint allow logs for past executions, so we look into the database if any execution by that hash
        # occurred, which we can then use to look for rights. We still check in the pool first, it is faster
        pool: VmPool = request.app["vm_pool"]
        execution = pool.executions.get(vm_hash)
        if execution:
            message = execution.message
        else:
            record = await metrics.get_last_record_for_vm(vm_hash=vm_hash)
            if not record:
                raise aiohttp.web_exceptions.HTTPNotFound(body="No execution found for this VM")
            message = get_message_executable_content(json.loads(record.message))
        if not await is_sender_authorized(authenticated_sender, message):
            return web.Response(status=403, body="Unauthorized sender")

        _journal_stdout_name = f"vm-{vm_hash}-stdout"
        _journal_stderr_name = f"vm-{vm_hash}-stderr"

        response = web.StreamResponse()
        response.headers["Transfer-encoding"] = "chunked"
        response.headers["Content-Type"] = "application/json"
        await response.prepare(request)
        await response.write(b"[")

        first = True
        for entry in get_past_vm_logs(_journal_stdout_name, _journal_stderr_name):
            if not first:
                await response.write(b",\n")
            first = False
            log_type = "stdout" if entry["SYSLOG_IDENTIFIER"] == _journal_stdout_name else "stderr"
            msg = {
                "SYSLOG_IDENTIFIER": entry["SYSLOG_IDENTIFIER"],
                "MESSAGE": entry["MESSAGE"],
                "file": log_type,
                "__REALTIME_TIMESTAMP": entry["__REALTIME_TIMESTAMP"],
            }
            await response.write(dumps_for_json(msg).encode())
        await response.write(b"]")

        await response.write_eof()
        return response


async def authenticate_websocket_for_vm_or_403(execution: VmExecution, vm_hash: ItemHash, ws: web.WebSocketResponse):
    """Authenticate a websocket connection.

    Web browsers do not allow setting headers in WebSocket requests, so the authentication
    relies on the first message sent by the client.
    """
    try:
        first_message = await ws.receive_json()
    except TypeError as error:
        logging.exception(error)
        await ws.send_json({"status": "failed", "reason": str(error)})
        raise web.HTTPForbidden(body="Invalid auth package")
    credentials = first_message["auth"]

    try:
        authenticated_sender = await authenticate_websocket_message(credentials)

        if await is_sender_authorized(authenticated_sender, execution.message):
            logger.debug(f"Accepted request to access logs by {authenticated_sender} on {vm_hash}")
            return True
    except Exception as error:
        # Error occurred (invalid auth packet or other
        await ws.send_json({"status": "failed", "reason": str(error)})
        raise web.HTTPForbidden(body="Unauthorized sender")

    # Auth was valid but not the correct user
    logger.debug(f"Denied request to access logs by {authenticated_sender} on {vm_hash}")
    await ws.send_json({"status": "failed", "reason": "unauthorized sender"})
    raise web.HTTPForbidden(body="Unauthorized sender")


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

        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
        await execution.expire(timeout=timeout)
        execution.persistent = False

        return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


@cors_allow_all
@require_jwk_authentication
async def operate_confidential_initialize(request: web.Request, authenticated_sender: str) -> web.Response:
    """Start the confidential virtual machine if possible."""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        logger.debug(f"Iterating through running executions... {pool.executions}")
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        if execution.is_running:
            return web.json_response(
                {"code": "vm_running", "description": "Operation not allowed, instance already running"},
                status=HTTPStatus.BAD_REQUEST,
            )
        if not execution.is_confidential:
            return web.json_response(
                {"code": "not_confidential", "description": "Instance is not a confidential instance"},
                status=HTTPStatus.BAD_REQUEST,
            )

        post = await request.post()

        vm_session_path = settings.CONFIDENTIAL_SESSION_DIRECTORY / vm_hash
        vm_session_path.mkdir(exist_ok=True)

        session_file_content = post.get("session")
        if not session_file_content:
            return web.json_response(
                {"code": "field_missing", "description": "Session field is missing"},
                status=HTTPStatus.BAD_REQUEST,
            )

        session_file_path = vm_session_path / "vm_session.b64"
        session_file_path.write_bytes(session_file_content.file.read())

        godh_file_content = post.get("godh")
        if not godh_file_content:
            return web.json_response(
                {"code": "field_missing", "description": "godh field is missing. Please provide a GODH file"},
                status=HTTPStatus.BAD_REQUEST,
            )

        godh_file_path = vm_session_path / "vm_godh.b64"
        godh_file_path.write_bytes(godh_file_content.file.read())

        await pool.systemd_manager.enable_and_start(execution.controller_service)

        return web.Response(status=200, body=f"Started VM with ref {vm_hash}")


@cors_allow_all
@require_jwk_authentication
async def operate_stop(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible."""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        logger.debug(f"Iterating through running executions... {pool.executions}")
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        if execution.is_running:
            logger.info(f"Stopping {execution.vm_hash}")
            await pool.stop_vm(execution.vm_hash)
            return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
        else:
            return web.Response(status=200, body="Already stopped, nothing to do")


@cors_allow_all
@require_jwk_authentication
async def operate_reboot(request: web.Request, authenticated_sender: str) -> web.Response:
    """
    Reboots the virtual machine, smoothly if possible.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        if execution.is_running:
            logger.info(f"Rebooting {execution.vm_hash}")
            if execution.persistent:
                pool.systemd_manager.restart(execution.controller_service)
            else:
                await pool.stop_vm(vm_hash)
                pool.forget_vm(vm_hash)

                await create_vm_execution_or_raise_http_error(vm_hash=vm_hash, pool=pool)
            return web.Response(status=200, body=f"Rebooted VM with ref {vm_hash}")
        else:
            return web.Response(status=200, body=f"Starting VM (was not running) with ref {vm_hash}")


@cors_allow_all
@require_jwk_authentication
async def operate_confidential_measurement(request: web.Request, authenticated_sender) -> web.Response:
    """
    Fetch the sev measurement for the VM
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        if not execution.is_running:
            raise web.HTTPForbidden(body="Operation not running")
        vm_client = QemuVmClient(execution.vm)
        vm_sev_info = vm_client.query_sev_info()
        launch_measure = vm_client.query_launch_measure()

        return web.json_response(
            data={"sev_info": vm_sev_info, "launch_measure": launch_measure},
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
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)
        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        # if not execution.is_running:
        #     raise web.HTTPForbidden(body="Operation not running")
        vm_client = QemuVmClient(execution.vm)
        vm_client.inject_secret(params.packet_header, params.secret)
        vm_client.continue_execution()

        status = vm_client.query_status()
        logger.debug("VM status after secret injection: %s", status)

        return web.json_response(
            data={"status": status},
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
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Erasing {execution.vm_hash}")

        # Stop the VM
        await pool.stop_vm(execution.vm_hash)
        if execution.vm_hash in pool.executions:
            logger.warning(f"VM {execution.vm_hash} was not stopped properly, forgetting it anyway")
            pool.forget_vm(execution.vm_hash)

        # Delete all data
        _erase_execution_volumes(execution)

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
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Reinstalling (reset to initial state) {execution.vm_hash}")

        if execution.persistent:
            await pool.stop_vm(execution.vm_hash)
            _erase_execution_volumes(
                execution,
                include_rootfs=True,
                include_data_volumes=not rootfs_only,
            )
            execution.resources = None
            await execution.prepare()
            await _restart_persistent_vm(pool, execution)
        else:
            await pool.stop_vm(execution.vm_hash)
            if execution.vm_hash in pool.executions:
                pool.forget_vm(execution.vm_hash)
            _erase_execution_volumes(
                execution,
                include_rootfs=True,
                include_data_volumes=not rootfs_only,
            )
            await create_vm_execution_or_raise_http_error(
                vm_hash=vm_hash,
                pool=pool,
            )

        return web.Response(status=200, body=f"Reinstalled VM with ref {vm_hash}")


@dataclass(frozen=True, slots=True)
class _BackupParams:
    vm_hash: str
    execution: VmExecution
    disk_paths: dict[str, Path]
    destination_dir: Path
    skip_fsfreeze: bool
    secret_token: str
    domain: str
    state: BackupState


async def _run_backup_work(params: _BackupParams) -> dict:
    """Execute the backup work and return metadata dict.

    Called both synchronously (inline) and as a background task.
    """
    vm_hash = params.vm_hash
    execution = params.execution
    disk_paths = params.disk_paths
    state = params.state
    qemu_client: QemuVmClient | None = None
    fs_frozen = False
    individual_backups: list[Path] = []
    lock = state.locks.setdefault(vm_hash, asyncio.Lock())

    await lock.acquire()
    try:
        # Re-check for existing backup inside the lock to avoid
        # two requests both passing the pre-lock check and creating
        # duplicate backups.
        existing = find_existing_backup(params.destination_dir, vm_hash)
        if existing:
            meta = backup_metadata(existing)
            expires = int(time.time()) + _BACKUP_SIGNATURE_TTL
            signature = _sign_backup_url(
                params.secret_token,
                meta["backup_id"],
                vm_hash,
                expires,
            )
            path = f"/control/machine/{vm_hash}/backup/{meta['backup_id']}"
            meta["download_url"] = f"https://{params.domain}{path}?signature={signature}&expires={expires}"
            return meta

        qemu_client = QemuVmClient(execution.vm)

        if not params.skip_fsfreeze:
            try:
                frozen = await asyncio.wait_for(
                    qemu_client.guest_fsfreeze_freeze(),
                    timeout=30,
                )
                fs_frozen = True
                logger.info("Froze %d filesystem(s) for %s", frozen, vm_hash)
            except Exception as exc:
                logger.warning(
                    "fsfreeze unavailable for %s, proceeding without: %s",
                    vm_hash,
                    exc,
                )

        backup_files: dict[str, Path] = {}
        try:
            for member_name, src in disk_paths.items():
                bak = await create_qemu_disk_backup(
                    vm_hash=vm_hash,
                    source_disk_path=src,
                    destination_dir=params.destination_dir,
                )
                individual_backups.append(bak)
                backup_files[member_name] = bak
        finally:
            if fs_frozen and qemu_client:
                try:
                    thawed = await qemu_client.guest_fsfreeze_thaw()
                    logger.info("Thawed %d filesystem(s) for %s", thawed, vm_hash)
                    fs_frozen = False
                except Exception as exc:
                    logger.error(
                        "Failed to thaw filesystems for %s: %s",
                        vm_hash,
                        exc,
                    )

        for bak_path in individual_backups:
            await verify_qemu_disk(bak_path)

        source_sizes = {name: src.stat().st_size for name, src in disk_paths.items()}

        tar_path = await create_backup_archive(
            vm_hash=vm_hash,
            backup_files=backup_files,
            destination_dir=params.destination_dir,
            source_sizes=source_sizes,
        )

        for bak_path in individual_backups:
            bak_path.unlink(missing_ok=True)
        individual_backups.clear()

        meta = backup_metadata(tar_path)
        expires = int(time.time()) + _BACKUP_SIGNATURE_TTL
        signature = _sign_backup_url(
            params.secret_token,
            meta["backup_id"],
            vm_hash,
            expires,
        )
        path = f"/control/machine/{vm_hash}/backup/{meta['backup_id']}"
        meta["download_url"] = f"https://{params.domain}{path}?signature={signature}&expires={expires}"
        return meta

    finally:
        lock.release()
        state.locks.pop(vm_hash, None)
        if fs_frozen and qemu_client:
            try:
                await qemu_client.guest_fsfreeze_thaw()
                logger.info("Thawed filesystems for %s (cleanup)", vm_hash)
            except Exception as exc:
                logger.error(
                    "Failed to thaw filesystems for %s (cleanup): %s",
                    vm_hash,
                    exc,
                )
        if qemu_client:
            try:
                qemu_client.close()
            except Exception:
                logger.debug("Failed to close QMP client for %s", vm_hash)
        for bak_path in individual_backups:
            bak_path.unlink(missing_ok=True)


async def _background_backup_wrapper(params: _BackupParams) -> None:
    """Wrapper that stores result or exception in backup state."""
    state = params.state
    try:
        meta = await _run_backup_work(params)
        state.results[params.vm_hash] = (time.time(), meta)
    except Exception as exc:
        logger.exception("Background backup failed for %s", params.vm_hash)
        state.results[params.vm_hash] = (time.time(), exc)
    finally:
        state.tasks.pop(params.vm_hash, None)


@cors_allow_all
@require_jwk_authentication
async def operate_backup(request: web.Request, authenticated_sender: str) -> web.Response:
    """Create a QEMU VM disk backup and return metadata.

    By default backs up only the rootfs.  Add ``?include_volumes=true``
    to also include non-read-only persistent volumes in the archive.

    Uses the QEMU guest agent to freeze filesystems during the copy,
    then thaws immediately before running integrity verification.

    If a non-expired backup already exists for the VM it is returned
    without re-freezing.

    Backups always run asynchronously. Returns 202 immediately; poll
    ``GET /control/machine/{ref}/backup`` for progress or result.

    Query Parameters:
        include_volumes: Set to 'true' to include persistent volumes.
        skip_fsfreeze: Set to 'true' to skip filesystem freeze.

    Returns:
        JSON with backup_id, size, checksum, volumes, expires_at.
        202 when backup is in progress.

    Raises:
        400: VM not running or not a QEMU VM.
        403: Unauthorized sender.
        409: Concurrent backup in progress.
        507: Insufficient disk space.
        500: Backup creation failed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    vm_hash_str = str(vm_hash)

    with set_vm_for_logging(vm_hash=vm_hash):
        try:
            pool: VmPool = request.app["vm_pool"]
            execution = get_execution_or_404(vm_hash, pool=pool)

            if not await is_sender_authorized(authenticated_sender, execution.message):
                return web.Response(status=403, body="Unauthorized sender")

            if not execution.is_running:
                return web.HTTPBadRequest(body="VM must be running to create backup")

            if not isinstance(execution.vm, AlephQemuInstance | AlephQemuConfidentialInstance):
                return web.HTTPBadRequest(body="Backup only supported for QEMU VMs")

            if not execution.vm.resources or not execution.vm.resources.rootfs_path:
                return web.HTTPBadRequest(body="VM has no disk image")

            destination_dir = get_backup_directory()
            cleanup_expired_backups(destination_dir)

            state: BackupState = request.app["backup_state"]
            state.evict_stale_results()

            # Check for completed background backup result
            if vm_hash_str in state.results:
                _, result = state.results.pop(vm_hash_str)
                if isinstance(result, Exception):
                    return web.Response(
                        status=500,
                        body=f"Backup failed: {result}",
                    )
                return web.json_response(result, dumps=dumps_for_json)

            # Check for in-progress background task
            if vm_hash_str in state.tasks:
                return web.json_response(
                    {"status": "in_progress"},
                    status=202,
                    dumps=dumps_for_json,
                )

            lock = state.locks.setdefault(vm_hash_str, asyncio.Lock())
            if lock.locked():
                return web.json_response(
                    {"status": "in_progress"},
                    status=202,
                    dumps=dumps_for_json,
                )

            # Check for existing backup
            existing = find_existing_backup(destination_dir, vm_hash_str)
            if existing:
                meta = backup_metadata(existing)
                meta["download_url"] = _build_signed_download_url(
                    request,
                    vm_hash_str,
                    meta["backup_id"],
                )
                return web.json_response(meta, dumps=dumps_for_json)

            disk_paths: dict[str, Path] = {
                "rootfs.qcow2": Path(execution.vm.resources.rootfs_path),
            }
            include_volumes = request.query.get("include_volumes") == "true"
            if include_volumes and execution.resources and execution.resources.volumes:
                for vol in execution.resources.volumes:
                    if not vol.read_only:
                        vol_path = Path(vol.path_on_host)
                        name = vol_path.stem + ".qcow2"
                        disk_paths[name] = vol_path

            try:
                await check_disk_space_for_multiple(
                    list(disk_paths.values()),
                    destination_dir,
                )
            except InsufficientDiskSpaceError as exc:
                return web.Response(status=507, body=str(exc))

            params = _BackupParams(
                vm_hash=vm_hash_str,
                execution=execution,
                disk_paths=disk_paths,
                destination_dir=destination_dir,
                skip_fsfreeze=request.query.get("skip_fsfreeze") == "true",
                secret_token=request.app["secret_token"],
                domain=settings.DOMAIN_NAME,
                state=state,
            )

            task = asyncio.create_task(
                _background_backup_wrapper(params),
            )
            state.tasks[vm_hash_str] = task
            return web.json_response(
                {"status": "in_progress"},
                status=202,
                dumps=dumps_for_json,
            )

        except web.HTTPException:
            raise
        except Exception:
            logger.exception("Failed to create backup for %s", vm_hash)
            raise web.HTTPInternalServerError(
                body="Backup creation failed",
            ) from None


@cors_allow_all
@require_jwk_authentication
async def operate_backup_status(request: web.Request, authenticated_sender: str) -> web.Response:
    """Check whether a non-expired backup exists for a VM."""
    vm_hash = get_itemhash_or_400(request.match_info)

    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        vm_hash_str = str(vm_hash)
        state: BackupState = request.app["backup_state"]

        # Check for in-progress background task or lock
        if vm_hash_str in state.tasks:
            return web.json_response(
                {"status": "in_progress"},
                status=202,
                dumps=dumps_for_json,
            )
        lock = state.locks.get(vm_hash_str)
        if lock and lock.locked():
            return web.json_response(
                {"status": "in_progress"},
                status=202,
                dumps=dumps_for_json,
            )

        # Check for completed background result
        if vm_hash_str in state.results:
            _, result = state.results.pop(vm_hash_str)
            if isinstance(result, Exception):
                return web.Response(status=500, body=f"Backup failed: {result}")
            return web.json_response(result, dumps=dumps_for_json)

        destination_dir = get_backup_directory()
        cleanup_expired_backups(destination_dir)

        existing = find_existing_backup(destination_dir, vm_hash_str)
        if not existing:
            raise web.HTTPNotFound(body="No backup found for this VM")

        meta = backup_metadata(existing)
        meta["download_url"] = _build_signed_download_url(
            request,
            str(vm_hash),
            meta["backup_id"],
        )
        return web.json_response(meta, dumps=dumps_for_json)


@cors_allow_all
async def operate_backup_download(request: web.Request) -> web.StreamResponse:
    """Download a previously created backup archive via presigned URL.

    Requires ``?signature=...&expires=...`` query parameters generated
    by the backup creation endpoint.  No JWK authentication needed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    backup_id = _validate_backup_id(request.match_info.get("backup_id", ""), vm_hash)
    _verify_backup_download(request, str(vm_hash), backup_id)

    with set_vm_for_logging(vm_hash=vm_hash):
        destination_dir = get_backup_directory()
        cleanup_expired_backups(destination_dir)

        tar_path = destination_dir / f"{backup_id}.tar"
        if not tar_path.exists():
            raise web.HTTPNotFound(body=f"Backup {backup_id} not found")

        sidecar = tar_path.with_suffix(".tar.sha256")
        checksum = ""
        if sidecar.exists():
            checksum = sidecar.read_text().split()[0]

        meta_file = tar_path.with_suffix(".tar.meta.json")
        total_source_size = 0
        if meta_file.exists():
            stored = json.loads(meta_file.read_text())
            total_source_size = sum(stored.get("source_sizes", {}).values())

        response = web.StreamResponse()
        response.headers["Content-Type"] = "application/x-tar"
        response.headers["Content-Disposition"] = f'attachment; filename="{backup_id}.tar"'
        response.headers["Content-Length"] = str(tar_path.stat().st_size)
        if checksum:
            response.headers["X-Backup-Checksum"] = f"sha256:{checksum}"
        if total_source_size:
            response.headers["X-Source-Size"] = str(total_source_size)

        await response.prepare(request)

        chunk_size = 65536

        def _read_chunk(fh, size):
            return fh.read(size)

        with open(tar_path, "rb") as f:
            while True:
                chunk = await asyncio.to_thread(_read_chunk, f, chunk_size)
                if not chunk:
                    break
                await response.write(chunk)

        await response.write_eof()
        return response


@cors_allow_all
@require_jwk_authentication
async def operate_backup_delete(
    request: web.Request,
    authenticated_sender: str,
) -> web.Response:
    """Delete a backup archive and its checksum sidecar."""
    vm_hash = get_itemhash_or_400(request.match_info)
    backup_id = _validate_backup_id(request.match_info.get("backup_id", ""), vm_hash)

    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        destination_dir = get_backup_directory()
        tar_path = destination_dir / f"{backup_id}.tar"

        if not tar_path.exists():
            raise web.HTTPNotFound(body=f"Backup {backup_id} not found")

        tar_path.unlink()
        tar_path.with_suffix(".tar.sha256").unlink(missing_ok=True)
        tar_path.with_suffix(".tar.meta.json").unlink(missing_ok=True)

        logger.info("Deleted backup %s for %s", backup_id, vm_hash)
        return web.Response(status=200, body=f"Deleted backup {backup_id}")


async def _parse_restore_upload(
    request: web.Request,
    backup_dir: Path,
    vm_hash: str,
    max_bytes: int = 0,
) -> Path:
    """Stream a multipart rootfs upload to disk."""
    limit = max_bytes or settings.MAX_RESTORE_UPLOAD_BYTES
    reader = await request.multipart()
    field = await reader.next()
    while field is not None:
        if field.name == "rootfs":
            break
        field = await reader.next()
    if field is None:
        raise web.HTTPBadRequest(body="Missing 'rootfs' field in multipart upload")
    upload_path = backup_dir / f"restore-{vm_hash}.qcow2"
    bytes_written = 0
    with open(upload_path, "wb") as f:
        while True:
            chunk = await field.read_chunk(65536)
            if not chunk:
                break
            bytes_written += len(chunk)
            if bytes_written > limit:
                upload_path.unlink(missing_ok=True)
                raise web.HTTPRequestEntityTooLarge(
                    max_size=limit,
                    actual_size=bytes_written,
                )
            f.write(chunk)
    return upload_path


async def _parse_restore_json(
    request: web.Request,
    backup_dir: Path,
) -> Path:
    """Download a volume by item hash from a JSON request body."""
    try:
        data = await request.json()
    except json.JSONDecodeError:
        raise web.HTTPBadRequest(body="Expected multipart upload or JSON with volume_ref") from None
    volume_ref = data.get("volume_ref", "")
    if not volume_ref:
        raise web.HTTPBadRequest(body="Missing volume_ref in JSON body")
    if not all(c in "0123456789abcdef" for c in volume_ref):
        raise web.HTTPBadRequest(body="Invalid volume_ref format")
    return await download_volume_by_ref(volume_ref, backup_dir)


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

    Stops the VM, validates the new image, replaces rootfs, restarts.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    temp_file: Path | None = None
    restore_succeeded = False

    with set_vm_for_logging(vm_hash=vm_hash):
        try:
            pool: VmPool = request.app["vm_pool"]
            execution = get_execution_or_404(vm_hash, pool=pool)

            if not await is_sender_authorized(authenticated_sender, execution.message):
                return web.Response(status=403, body="Unauthorized sender")

            if not isinstance(execution.vm, AlephQemuInstance | AlephQemuConfidentialInstance):
                return web.HTTPBadRequest(body="Restore only supported for QEMU VMs")

            if not execution.vm.resources or not execution.vm.resources.rootfs_path:
                return web.HTTPBadRequest(body="VM has no rootfs")

            current_rootfs = Path(execution.vm.resources.rootfs_path)
            backup_dir = get_backup_directory()

            max_upload = execution.message.rootfs.size_mib * 1024 * 1024
            if request.content_length and request.content_length > max_upload:
                return web.HTTPRequestEntityTooLarge(
                    max_size=max_upload,
                    actual_size=request.content_length,
                )

            content_type = request.content_type or ""
            if content_type.startswith("multipart/"):
                temp_file = await _parse_restore_upload(
                    request,
                    backup_dir,
                    str(vm_hash),
                    max_upload,
                )
            else:
                temp_file = await _parse_restore_json(request, backup_dir)

            await verify_qemu_disk(temp_file)

            new_size = await get_qemu_disk_virtual_size(temp_file)
            max_size = execution.message.rootfs.size_mib * 1024 * 1024
            if new_size > max_size:
                return web.HTTPBadRequest(
                    body=f"New rootfs virtual size ({new_size} bytes) exceeds "
                    f"declared rootfs size ({max_size} bytes). "
                    f"Restore cannot increase disk size.",
                )

            if execution.is_running:
                logger.info("Stopping VM %s for restore", vm_hash)
                await pool.stop_vm(execution.vm_hash)

            await restore_rootfs(temp_file, current_rootfs)
            restore_succeeded = True

            logger.info("Restarting VM %s after restore", vm_hash)
            if execution.persistent:
                await _restart_persistent_vm(pool, execution)
            else:
                if execution.vm_hash in pool.executions:
                    pool.forget_vm(execution.vm_hash)
                await create_vm_execution_or_raise_http_error(
                    vm_hash=vm_hash,
                    pool=pool,
                )

            return web.json_response(
                {
                    "status": "restored",
                    "vm_hash": str(vm_hash),
                },
                dumps=dumps_for_json,
            )

        except web.HTTPException:
            raise
        except Exception:
            logger.exception("Failed to restore VM %s", vm_hash)
            raise web.HTTPInternalServerError(body="Restore failed") from None
        finally:
            # Only delete the uploaded temp file after a successful restore.
            # On failure, keep it so the user doesn't have to re-upload.
            if restore_succeeded and temp_file and temp_file.exists():
                temp_file.unlink(missing_ok=True)
