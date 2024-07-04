import json
import logging
from datetime import timedelta

import aiohttp.web_exceptions
import pydantic
from aiohttp import web
from aiohttp.web_urldispatcher import UrlMappingMatchInfo
from aleph_message.exceptions import UnknownHashError
from aleph_message.models import ItemHash
from aleph_message.models.execution import BaseExecutableContent
from pydantic import BaseModel

from aleph.vm.conf import settings
from aleph.vm.controllers.qemu.client import QemuVmClient
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.run import create_vm_execution_or_raise_http_error
from aleph.vm.orchestrator.views.authentication import (
    authenticate_websocket_message,
    require_jwk_authentication,
)
from aleph.vm.pool import VmPool
from aleph.vm.utils import cors_allow_all, dumps_for_json

logger = logging.getLogger(__name__)


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


def is_sender_authorized(authenticated_sender: str, message: BaseExecutableContent) -> bool:
    if authenticated_sender.lower() == message.address.lower():
        return True
    else:
        logger.debug(f"Unauthorized sender {authenticated_sender} is not {message.address}")
        return False


@cors_allow_all
async def stream_logs(request: web.Request) -> web.StreamResponse:
    """Stream the logs of a VM.

    The authentication method is slightly different because browsers do not
    allow Javascript to set headers in WebSocket requests.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
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

        finally:
            await ws.close()
            logger.info(f"connection  {ws} closed")

    finally:
        if queue:
            execution.vm.unregister_queue(queue)


@cors_allow_all
@require_jwk_authentication
async def operate_logs(request: web.Request, authenticated_sender: str) -> web.StreamResponse:
    """Logs of a VM (not streaming)"""
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)
    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    response = web.StreamResponse()
    response.headers["Content-Type"] = "text/plain"
    await response.prepare(request)

    for entry in execution.vm.past_logs():
        msg = f'{entry["__REALTIME_TIMESTAMP"].isoformat()}> {entry["MESSAGE"]}'
        await response.write(msg.encode())
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
        raise web.HTTPForbidden(body="Invalid auth package")
    credentials = first_message["auth"]
    authenticated_sender = await authenticate_websocket_message(credentials)

    if is_sender_authorized(authenticated_sender, execution.message):
        logger.debug(f"Accepted request to access logs by {authenticated_sender} on {vm_hash}")
        return True

    logger.debug(f"Denied request to access logs by {authenticated_sender} on {vm_hash}")
    await ws.send_json({"status": "failed", "reason": "unauthorized sender"})
    raise web.HTTPForbidden(body="Unauthorized sender")


@cors_allow_all
@require_jwk_authentication
async def operate_expire(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible.

    A timeout may be specified to delay the action."""
    vm_hash = get_itemhash_or_400(request.match_info)
    try:
        timeout = float(ItemHash(request.match_info["timeout"]))
    except (KeyError, ValueError) as error:
        raise web.HTTPBadRequest(body="Invalid timeout duration") from error
    if not 0 < timeout < timedelta(days=10).total_seconds():
        return web.HTTPBadRequest(body="Invalid timeout duration")

    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
    await execution.expire(timeout=timeout)
    execution.persistent = False

    return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")


@cors_allow_all
@require_jwk_authentication
async def operate_confidential_initialize(request: web.Request, authenticated_sender: str) -> web.Response:
    """Start the confidential virtual machine if possible."""
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)

    pool: VmPool = request.app["vm_pool"]
    logger.debug(f"Iterating through running executions... {pool.executions}")
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    if execution.is_running:
        return web.Response(status=403, body=f"VM with ref {vm_hash} already running")

    if not execution.is_confidential:
        return web.Response(status=403, body=f"Operation not allowed for VM {vm_hash} because it isn't confidential")

    post = await request.post()

    vm_session_path = settings.CONFIDENTIAL_SESSION_DIRECTORY / vm_hash
    vm_session_path.mkdir(exist_ok=True)

    session_file_content = post.get("session")
    if not session_file_content:
        return web.Response(status=403, body=f"Session file required for VM with ref {vm_hash}")

    session_file_path = vm_session_path / "vm_session.b64"
    session_file_path.write_bytes(session_file_content.file.read())

    godh_file_content = post.get("godh")
    if not godh_file_content:
        return web.Response(status=403, body=f"GODH file required for VM with ref {vm_hash}")

    godh_file_path = vm_session_path / "vm_godh.b64"
    godh_file_path.write_bytes(godh_file_content.file.read())

    pool.systemd_manager.enable_and_start(execution.controller_service)

    return web.Response(status=200, body=f"Started VM with ref {vm_hash}")


@cors_allow_all
@require_jwk_authentication
async def operate_stop(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible."""
    # TODO: Add user authentication
    vm_hash = get_itemhash_or_400(request.match_info)

    pool: VmPool = request.app["vm_pool"]
    logger.debug(f"Iterating through running executions... {pool.executions}")
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    if not is_sender_authorized(authenticated_sender, execution.message):
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
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
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
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
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
        params = InjectSecretParams.parse_obj(data)
    except json.JSONDecodeError:
        return web.HTTPBadRequest(reason="Body is not valid JSON")
    except pydantic.ValidationError as error:
        return web.json_response(data=error.json(), status=web.HTTPBadRequest.status_code)

    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)
    if not is_sender_authorized(authenticated_sender, execution.message):
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
    pool: VmPool = request.app["vm_pool"]
    execution = get_execution_or_404(vm_hash, pool=pool)

    if not is_sender_authorized(authenticated_sender, execution.message):
        return web.Response(status=403, body="Unauthorized sender")

    logger.info(f"Erasing {execution.vm_hash}")

    # Stop the VM
    await pool.stop_vm(execution.vm_hash)
    if execution.vm_hash in pool.executions:
        logger.warning(f"VM {execution.vm_hash} was not stopped properly, forgetting it anyway")
        pool.forget_vm(execution.vm_hash)

    # Delete all data
    if execution.resources is not None:
        for volume in execution.resources.volumes:
            if not volume.read_only:
                logger.info(f"Deleting volume {volume.path_on_host}")
                volume.path_on_host.unlink()

    return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")
