import asyncio
import json
import logging
from typing import Any

import msgpack
from aiohttp import ClientResponseError, web
from aiohttp.web_exceptions import (
    HTTPBadGateway,
    HTTPBadRequest,
    HTTPInternalServerError,
    HTTPServiceUnavailable,
)
from aleph_message.models import InstanceContent, ItemHash
from aleph_message.models.execution.environment import HypervisorType
from msgpack import UnpackValueError
from multidict import CIMultiDict

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.program import (
    FileTooLargeError,
    ResourceDownloadError,
    VmSetupError,
)
from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError
from aleph.vm.models import MessageSpec, VmExecution
from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.orchestrator.update_watcher import UpdateWatcher
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.pool import VmPool
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.translate import build_create_vm_spec
from aleph.vm.supervisor.types import (
    GuestPort,
    HostPort,
    PortForwardSpec,
    Protocol,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.utils import HostNotFoundError
from aleph.vm.utils.aggregate import get_user_settings

from .messages import load_updated_message
from .pubsub import PubSub

logger = logging.getLogger(__name__)

# Readiness poll for the spec create path (replaces execution.becomes_ready()).
_START_POLL_TIMEOUT_SECONDS = 120.0
_START_POLL_INTERVAL_SECONDS = 0.5


async def build_asgi_scope(path: str, request: web.Request) -> dict[str, Any]:
    # ASGI mandates lowercase header names
    headers = tuple((name.lower(), value) for name, value in request.raw_headers)
    return {
        "type": "http",
        "path": path,
        "method": request.method,
        "query_string": request.query_string,
        "headers": headers,
        "body": await request.read(),
    }


async def build_event_scope(event) -> dict[str, Any]:
    """Build an ASGI scope for an event."""
    return {
        "type": "aleph.message",
        "body": event,
    }


def _is_spec_eligible(content) -> bool:
    """True when the supervisor's message-free create path can handle this message.

    Gates which messages reach build_create_vm_spec, mirroring its validation:
    a non-confidential QEMU instance. The GPU exclusion below is an extra
    conservatism of this gate — build_create_vm_spec itself accepts GPUs (via
    its ``gpus`` argument), so GPU instances are filtered here, not there. Keep
    the two in sync. Everything else keeps the legacy path.
    """
    if not isinstance(content, InstanceContent):
        return False
    hypervisor = content.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR
    if hypervisor != HypervisorType.qemu:
        return False
    if getattr(content.environment, "trusted_execution", None) is not None:
        return False
    if content.requirements and content.requirements.gpu:
        return False
    return True


async def resolve_port_forwards(vm_id: VmId, content) -> list[PortForwardSpec]:
    """Agent-side policy: translate the user's port-forwarding aggregate settings
    into the set of forwards the hypervisor should apply.

    This is the agent half of the old VmExecution.fetch_port_redirect_config_and_setup.
    Nothing here touches nftables; the caller applies each spec through
    supervisor.add_port_forward. host_port is left 0; the hypervisor assigns it.
    """
    ports_requests: dict[int, dict[str, bool]] = {}
    try:
        settings_for_user = await get_user_settings(content.address, "port-forwarding")
        vm_port_forwarding = settings_for_user.get(str(vm_id), {}) or {}
        fetched = vm_port_forwarding.get("ports", {})
        ports_requests = {int(port): flags for port, flags in fetched.items()}
    except Exception:
        logger.info("Could not fetch port redirect settings for %s", content.address, exc_info=True)

    # Always forward SSH.
    ports_requests.setdefault(22, {"tcp": True, "udp": False})

    forwards: list[PortForwardSpec] = []
    for vm_port, flags in ports_requests.items():
        for protocol in (Protocol.TCP, Protocol.UDP):
            if flags.get(protocol.value):
                forwards.append(
                    PortForwardSpec(
                        vm_id=vm_id,
                        host_port=HostPort(0),
                        vm_port=GuestPort(int(vm_port)),
                        protocol=protocol,
                    )
                )
    return forwards


async def reconcile_port_forwards(supervisor: Supervisor, vm_id: VmId, content) -> None:
    """Drive the hypervisor's forwards to match the aggregate settings.

    Agent policy half of the old fetch_port_redirect_config_and_setup: compute
    the desired set, diff against what the hypervisor reports, and issue
    add/remove calls. The hypervisor owns application and persistence.
    """
    desired = {(int(spec.vm_port), spec.protocol): spec for spec in await resolve_port_forwards(vm_id, content)}
    current = {(int(info.vm_port), info.protocol): info for info in await supervisor.list_port_forwards(vm_id)}
    for key, info in current.items():
        if key not in desired:
            await supervisor.remove_port_forward(vm_id, info.host_port, info.protocol)
    for key, spec in desired.items():
        if key not in current:
            await supervisor.add_port_forward(spec)


async def _wait_until_running(
    supervisor: Supervisor,
    vm_id: VmId,
    *,
    timeout: float | None = None,
    interval: float | None = None,
) -> VmInfo:
    """Poll get_vm until the VM reports RUNNING.

    In-process the first poll already reports RUNNING (create_vm blocked until
    boot); across a future gRPC boundary this does real work. Raises on a
    terminal status or after `timeout` seconds.

    `timeout`/`interval` default to the module constants, resolved at call time
    so tests (and operators) can override them by patching the constants.
    """
    if timeout is None:
        timeout = _START_POLL_TIMEOUT_SECONDS
    if interval is None:
        interval = _START_POLL_INTERVAL_SECONDS
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        info = await supervisor.get_vm(vm_id)
        if info.status is VmStatus.RUNNING:
            return info
        if info.status in (VmStatus.STOPPED, VmStatus.FAILED):
            msg = f"VM {vm_id} entered status {info.status.value} while waiting to start"
            raise RuntimeError(msg)
        if asyncio.get_running_loop().time() >= deadline:
            msg = f"VM {vm_id} did not reach RUNNING within {timeout}s"
            raise asyncio.TimeoutError(msg)
        await asyncio.sleep(interval)


async def create_vm_execution(
    vm_hash: ItemHash,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    persistent: bool = False,
) -> VmExecution:
    message, original_message = await load_updated_message(vm_hash)

    logger.debug(f"Message: {json.dumps(message.model_dump(exclude_none=True), indent=4, sort_keys=True, default=str)}")

    content = message.content
    if _is_spec_eligible(content):
        spec = await build_create_vm_spec(vm_hash, content)
        info = await supervisor.create_vm(spec)
        # Agent territory: record the message in the agent's own cache. This is
        # what the message-free agent will read once owner-auth and billing move
        # off the VmExecution (design doc section 5). The supervisor machinery
        # that created the VM never reads it.
        registry.record(vm_hash, message=content, original=original_message.content, persistent=True)
        try:
            await _wait_until_running(supervisor, info.vm_id)
            for forward in await resolve_port_forwards(info.vm_id, content):
                await supervisor.add_port_forward(forward)
        except Exception:
            # Readiness or port-forward setup failed: tear the half-started VM
            # down, but never let a teardown error mask the original failure.
            registry.forget(vm_hash)
            try:
                await supervisor.delete_vm(info.vm_id)
            except Exception:
                logger.exception("Teardown of half-started VM %s failed", vm_hash)
            raise
        # TEMPORARY (PR 1 boundary, design doc sections 5/8): the operator
        # endpoints, billing and update-watching still read owner identity and
        # the message off the VmExecution, and start_persistent_vm drives it for
        # the pre-existing check and expiry-cancel. Re-source the message-free
        # execution as message-driven and hand it back unchanged. This goes away
        # when those consumers read the registry instead.
        execution = pool.executions[vm_hash]
        execution.spec = MessageSpec(message=content, original=original_message.content)
        # The spec create path skipped save() (no MessageSpec at start time).
        # Persist the record now: registry rehydration and past-logs owner
        # auth read the message back from the agent DB.
        await execution.save()
        return execution

    execution = await pool.create_a_vm(
        vm_hash=vm_hash,
        message=content,
        original=original_message.content,
        persistent=persistent,
    )
    registry.record(vm_hash, message=content, original=original_message.content, persistent=persistent)
    return execution


async def create_vm_execution_or_raise_http_error(
    vm_hash: ItemHash,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
) -> VmExecution:
    try:
        return await create_vm_execution(vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry)
    except ResourceDownloadError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPBadRequest(reason="Code, runtime or data not available") from error
    except InsufficientResourcesError as error:
        logger.warning("Refusing %s: %s", vm_hash, error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPServiceUnavailable(
            reason="Insufficient capacity",
            text="This CRN cannot host the requested workload at this time.",
        ) from error
    except FileTooLargeError as error:
        raise HTTPInternalServerError(reason=error.args[0]) from error
    except VmSetupError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during vm initialisation") from error
    except MicroVMFailedInitError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Error during runtime initialisation") from error
    except HostNotFoundError as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Host did not respond to ping") from error
    except ClientResponseError as error:
        logger.exception(error)
        if error.status == 404:
            raise HTTPInternalServerError(reason=f"Item hash {vm_hash} not found") from error
        else:
            raise HTTPInternalServerError(reason=f"Error downloading {vm_hash}") from error
    except Exception as error:
        logger.exception(error)
        pool.forget_vm(vm_hash=vm_hash)
        raise HTTPInternalServerError(reason="Unhandled error during initialisation") from error


async def run_code_on_request(vm_hash: ItemHash, path: str, pool: VmPool, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """
    supervisor: Supervisor = request.app["supervisor"]
    expiry: ExpiryManager = request.app["expiry"]
    update_watcher: UpdateWatcher = request.app["update_watcher"]
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve

    execution: VmExecution | None = pool.get_running_vm(vm_hash=vm_hash)

    # Prevent execution issues if the execution resources are empty
    if execution and not execution.has_resources:
        logger.warning("VM %s has no resources, stopping and removing", vm_hash)
        await pool.stop_vm(execution.vm_hash)
        pool.forget_vm(execution.vm_hash)
        execution = None

    if not execution:
        # Programs always take the legacy create path (they are never spec-eligible),
        # which ignores the supervisor. Use the app-wide registry so the agent's
        # update-watcher (which reads app["vm_registry"]) sees the record it creates.
        registry = request.app["vm_registry"]
        execution = await create_vm_execution_or_raise_http_error(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
        )

    logger.debug(f"Using vm={execution.vm_id}")

    scope: dict = await build_asgi_scope(path, request)

    try:
        await execution.becomes_ready()
        result_raw: bytes = await execution.run_code(scope=scope)

        if result_raw == b"":
            # Missing result from the init process of the virtual machine, not even an error message.
            # It may have completely crashed.

            # Stop the virtual machine due to failing init.
            # It will be restarted on a future request.
            await execution.stop()

            return web.Response(
                status=HTTPBadGateway.status_code,
                reason="No response from VM",
                text="VM did not respond and was shut down",
            )

    except asyncio.TimeoutError:
        logger.warning(f"VM{execution.vm_id} did not respond within `resource.seconds`")
        return web.HTTPGatewayTimeout(body="Program did not respond within `resource.seconds`")
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            # An error took place, the stacktrace of the error will be returned.
            # TODO: Add an option for VM developers to prevent stacktraces from being exposed.

            # The Diagnostics VM checks for the proper handling of exceptions.
            # This fills the logs with noisy stack traces, so we ignore this specific error.
            ignored_errors = ['raise CustomError("Whoops")', "main.CustomError: Whoops"]

            if settings.IGNORE_TRACEBACK_FROM_DIAGNOSTICS and any(
                ignored_error in result["traceback"] for ignored_error in ignored_errors
            ):
                logger.debug('Ignored traceback from CustomError("Whoops")')
            else:
                logger.warning(result["traceback"])

            return web.Response(
                status=HTTPInternalServerError.status_code,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        # HTTP Headers require specific data structure
        headers = CIMultiDict([(key.decode().lower(), value.decode()) for key, value in result["headers"]["headers"]])
        if "content-length" not in headers:
            headers["Content-Length".lower()] = str(len(result["body"]["body"]))
        for header in ["Content-Encoding", "Transfer-Encoding", "Vary"]:
            if header in headers:
                del headers[header]

        headers.update(
            {
                "Aleph-Program-ItemHash": execution.vm_hash,
                "Aleph-Program-Code-Ref": execution.message.code.ref,
                # "Aleph-Compute-Vm-Id": str(execution.vm.vm_id),
            }
        )

        return web.Response(
            status=result["headers"]["status"],
            body=result["body"]["body"],
            headers=headers,
        )
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                update_watcher.watch(vm_id, vm_hash, request.app["pubsub"])
            # Persistent executions are long-running by design: never idle-reap them.
            if not execution.persistent:
                expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        else:
            update_watcher.cancel(vm_id)
            await supervisor.delete_vm(vm_id)


async def run_code_on_event(
    vm_hash: ItemHash,
    event,
    pubsub: PubSub,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
    registry: AgentVmRegistry,
):
    """
    Execute code in response to an event.
    """
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve

    execution: VmExecution | None = pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        # programs use the legacy create path; the registry is the agent's
        # shared known-VM store (so the watcher reads the same record).
        execution = await create_vm_execution_or_raise_http_error(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
        )

    logger.debug(f"Using vm={execution.vm_id}")

    scope: dict = await build_event_scope(event)

    try:
        await execution.becomes_ready()
        result_raw: bytes = await execution.run_code(scope=scope)
    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")

    try:
        result = msgpack.loads(result_raw, raw=False)

        logger.debug(f"Result from VM: <<<\n\n{str(result)[:1000]}\n\n>>>")

        if "traceback" in result:
            logger.warning(result["traceback"])
            return web.Response(
                status=HTTPInternalServerError.status_code,
                reason="Error in VM execution",
                body=result["traceback"],
                content_type="text/plain",
            )

        logger.info(f"Result: {result['body']}")
        return result["body"]

    except UnpackValueError as error:
        logger.exception(error)
        return web.Response(status=HTTPBadGateway.status_code, reason="Invalid response from VM")
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                update_watcher.watch(vm_id, vm_hash, pubsub)
            # Persistent executions are long-running by design: never idle-reap them.
            if not execution.persistent:
                expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        else:
            update_watcher.cancel(vm_id)
            await supervisor.delete_vm(vm_id)


async def start_persistent_vm(
    vm_hash: ItemHash,
    pubsub: PubSub | None,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    expiry: ExpiryManager,
) -> VmExecution:
    execution: VmExecution | None = pool.executions.get(vm_hash)
    if execution:
        if execution.is_running:
            logger.info(f"{vm_hash} is already running")
        elif execution.is_starting:
            logger.info(f"{vm_hash} is already starting")
        elif execution.is_stopping:
            logger.info(f"{vm_hash} is stopping, waiting for complete stop before restarting")
            await execution.stop_event.wait()
            execution = None
        else:
            logger.info(f"{vm_hash} unknown execution state, stopping the vm")
            if execution.vm:
                await execution.stop()
            else:
                if execution._forget_task:
                    execution._forget_task.cancel()
                pool.forget_vm(vm_hash)
            execution = None

    if not execution:
        logger.info(f"Starting persistent virtual machine with id: {vm_hash}")
        execution = await create_vm_execution(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry, persistent=True
        )

    await execution.becomes_ready()

    # If the VM was already running in lambda mode, it should not expire
    # as long as it is also scheduled as long-running
    expiry.cancel(VmId(str(vm_hash)))

    if pubsub and settings.WATCH_FOR_UPDATES:
        execution.start_watching_for_updates(pubsub=pubsub)

    return execution
