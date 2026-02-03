import json
import logging
from datetime import timedelta
from http import HTTPStatus

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
from aleph.vm.controllers.qemu.client import QemuVmClient
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator import metrics
from aleph.vm.orchestrator.custom_logs import set_vm_for_logging
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


def _erase_execution_volumes(execution: VmExecution) -> int:
    """Delete all non-readonly volumes from an execution.

    Returns the number of volumes deleted.
    """
    deleted_count = 0
    if execution.resources is not None:
        for volume in execution.resources.volumes:
            if not volume.read_only:
                logger.info(f"Deleting volume {volume.path_on_host}")
                volume.path_on_host.unlink()
                deleted_count += 1
    return deleted_count


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
    """
    Check if the authenticated sender has delegation permissions from the message owner.

    Fetches the security aggregate for the message address and checks if the authenticated_sender
    is listed in the delegations.

    Args:
        authenticated_sender: The address of the authenticated user
        message: The message containing the owner address

    Returns:
        True if the authenticated_sender has delegation permissions, False otherwise
    """
    try:
        async with aiohttp.ClientSession() as session:
            url = f"{settings.API_SERVER}/api/v0/aggregates/{message.address}.json?keys=security"
            logger.debug(f"Fetching security aggregate from {url}")
            resp = await session.get(url)

            # Raise an error if the request failed
            resp.raise_for_status()

            resp_data = await resp.json()
            security_data = resp_data.get("data", {}).get("security", {})

            # Check if authenticated_sender is in the delegations list
            delegations = security_data.get("authorizations", [])

            # Check if the authenticated_sender is authorized
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

    except Exception as error:
        logger.warning(f"Failed to check owner permissions: {error}")
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
        print(status["status"] != "running")

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
async def operate_restart(request: web.Request, authenticated_sender: str) -> web.Response:
    """Reset a virtual machine to its initial state.

    Stops the VM, deletes all non-readonly volumes (user data), and starts it fresh.
    The VM will boot as if it was first created.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        pool: VmPool = request.app["vm_pool"]
        execution = get_execution_or_404(vm_hash, pool=pool)

        if not await is_sender_authorized(authenticated_sender, execution.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Restarting (reset to initial state) {execution.vm_hash}")

        # Stop the VM
        await pool.stop_vm(execution.vm_hash)
        if execution.vm_hash in pool.executions:
            pool.forget_vm(execution.vm_hash)

        # Delete all data
        _erase_execution_volumes(execution)

        # Start the VM again from scratch
        await create_vm_execution_or_raise_http_error(vm_hash=vm_hash, pool=pool)

        return web.Response(status=200, body=f"Restarted VM with ref {vm_hash}")
