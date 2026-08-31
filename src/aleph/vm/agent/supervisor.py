"""
The agent web server: the public HTTP API of the CRN (aiohttp). It executes
code and starts/stops VMs by driving the supervisor daemon, which owns the
VmPool, over gRPC (the `Supervisor` contract); the agent itself never builds
a pool.
"""

import asyncio
import logging
import sys
from pathlib import Path
from secrets import token_urlsafe

from aiohttp import hdrs, web
from aiohttp.web_exceptions import HTTPException
from aiohttp_cors import ResourceOptions, setup

from aleph.vm.agent.capacity import CapacityManager
from aleph.vm.agent.expiry import ExpiryManager
from aleph.vm.agent.migration.reaper import reap_orphan_migration_files
from aleph.vm.agent.update_watcher import UpdateWatcher
from aleph.vm.agent.vcpu_probe import get_snp_launch_capability
from aleph.vm.agent.vm.backup import BackupManager
from aleph.vm.agent.vm.program_client import ProgramGuestClient
from aleph.vm.agent.vm_registry import AgentVmRegistry, rehydrate_registry
from aleph.vm.conf import settings
from aleph.vm.sevclient import SevClient
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.client import GrpcSupervisor
from aleph.vm.utils import check_amd_sev_snp_supported, create_task_log_exceptions
from aleph.vm.version import __version__

from .node_identity import (
    NodeIdentity,
    start_node_hash_discovery,
    stop_node_hash_discovery,
)
from .resources import about_capability, about_certificates, about_system_usage
from .tasks import (
    start_domain_resync_task,
    start_payment_monitoring_task,
    start_watch_for_messages_task,
    stop_balances_monitoring_task,
    stop_domain_resync_task,
    stop_watch_for_messages_task,
)
from .views import (
    about_config,
    about_execution_records,
    about_login,
    debug_haproxy,
    list_executions,
    list_executions_v2,
    notify_allocation,
    operate_reserve_resources,
    operate_update,
    recreate_network,
    regenerate_proxy,
    run_code_from_hostname,
    run_code_from_path,
    status_check_fastapi,
    status_check_fastapi_legacy,
    status_check_host,
    status_check_ipv6,
    status_check_version,
    status_public_config,
    update_allocations,
)
from .views.migration import (
    migration_cleanup,
    migration_disk_download,
    migration_export,
    migration_export_status,
    migration_import,
    migration_import_status,
)
from .views.operator import (
    operate_backup,
    operate_backup_delete,
    operate_backup_download,
    operate_backup_status,
    operate_confidential_initialize,
    operate_confidential_inject_secret,
    operate_confidential_measurement,
    operate_erase,
    operate_expire,
    operate_logs_json,
    operate_reboot,
    operate_reinstall,
    operate_restore,
    operate_stop,
    stream_logs,
)

logger = logging.getLogger(__name__)


@web.middleware
async def drain_middleware(request, handler) -> web.Response:
    """Reject new VM execution requests while the agent is draining.

    Only blocks the paths that trigger on-demand VM creation
    (/vm/* and hostname-based routing). Status, control, and about
    endpoints remain accessible for monitoring and operations.

    The draining flag is agent-owned (``app["draining"]``): the agent fronts
    every request while the supervisor daemon owns the VMs.
    """
    if request.app.get("draining"):
        path = request.path
        is_vm_request = path.startswith("/vm/") or (
            not path.startswith(("/about/", "/control/", "/status/", "/static/", "/debug/"))
            and request.host.split(":")[0] != settings.DOMAIN_NAME.split(":")[0]
        )
        if is_vm_request:
            return web.json_response(
                {"error": "Server is draining, try another node"},
                status=503,
            )
    return await handler(request)


@web.middleware
async def error_middleware(request, handler) -> web.Response:
    "Ensure we always return a JSON response for errors."
    try:
        response = await handler(request)
        if response.status == 404:
            message = response.text
            status = response.status
            return web.json_response({"error": message}, status=status)
        if isinstance(response, HTTPException):
            if response.headers[hdrs.CONTENT_TYPE] != "application/json":
                message = response.text or response.reason
                status = response.status
                return web.json_response(
                    {"error": message},
                    status=status,
                )
        return response
    except web.HTTPException as exc:
        message = exc.text or exc.reason
        status = exc.status
        return web.json_response({"error": message}, status=status)
    except RuntimeError as exc:
        if "Event loop is closed" in str(exc):
            logger.debug("Request failed (event loop closed): %s", request.path)
            return web.json_response({"error": "Server is shutting down"}, status=503)
        raise
    except Exception as exc:
        logger.exception("Unhandled exception for %s", request.path)
        message = str(exc)
        status = 500
        return web.json_response({"error": message, "error_type": str(type(exc))}, status=status)
    assert False, "unreachable"


async def on_prepare_server_version(request: web.Request, response: web.Response) -> None:
    """Add the version of Aleph-VM in the HTTP headers of the responses."""
    response.headers["Server"] = f"aleph-vm/{__version__}"


async def http_not_found(request: web.Request):  # noqa: ARG001
    """Return a 404 error for unknown URLs."""
    return web.HTTPNotFound()


RECONNECT_DELAY = 5


async def _drop_vm_state(app: web.Application, vm_id) -> None:
    """Drop the agent's per-VM state after the VM went down (idempotent)."""
    app["expiry"].cancel(vm_id)
    app["update_watcher"].cancel(vm_id)
    await app["program_client"].forget(vm_id)


async def _reconcile_after_event_gap(app: web.Application) -> None:
    """Compensate for VM-down events missed while the event stream was down.

    The stream is the agent's only push channel, so a VM that went down during
    the gap never got its state drop. Re-list the VMs and apply the same drop
    a missed event would have triggered to every tracked VM that is now
    STOPPED, FAILED, or gone entirely.
    """
    from aleph.vm.supervisor_interface.types import VmStatus

    status_by_vm = {info.vm_id: info.status for info in await app["supervisor"].list_vms()}
    tracked = app["expiry"].tracked() | app["update_watcher"].tracked() | app["program_client"].tracked()
    for vm_id in tracked:
        status = status_by_vm.get(vm_id)
        if status is None or status in (VmStatus.STOPPED, VmStatus.FAILED):
            logger.info("Reconcile after event-stream gap: dropping agent state for %s (status: %s)", vm_id, status)
            await _drop_vm_state(app, vm_id)


async def watch_supervisor_events(app: web.Application) -> None:
    """Consume the supervisor's WatchEvents stream and drop agent-side per-VM
    state when a VM goes down.

    A VM leaving RUNNING (stop, reboot's down-phase, delete, reinstall) must
    drop the agent's guest-side program state (guest API process, configured
    mark) and cancel pending idle-teardown timers; the supervisor's event
    stream is the agent's only way to learn about it without polling.
    Reconnects on stream failure and reconciles first (events lost during the
    gap are compensated by re-listing the VMs; only the instant between the
    re-list and the re-subscribe remains uncovered, versus the whole outage).
    Exits if the supervisor does not implement WatchEvents.
    """
    from aleph.vm.supervisor_interface.errors import NotImplementedSupervisorError
    from aleph.vm.supervisor_interface.types import VmStatus

    supervisor = app["supervisor"]
    stream_interrupted = False
    while True:
        try:
            if stream_interrupted:
                await _reconcile_after_event_gap(app)
                stream_interrupted = False
            async for event in supervisor.watch_events():
                if event.new_status in (VmStatus.STOPPED, VmStatus.FAILED):
                    await _drop_vm_state(app, event.vm_id)
        except NotImplementedSupervisorError:
            logger.info("Supervisor does not implement WatchEvents; agent state relies on its own reaps only")
            return
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.warning("Supervisor event stream interrupted; reconnecting in %ss", RECONNECT_DELAY, exc_info=True)
            stream_interrupted = True
        await asyncio.sleep(RECONNECT_DELAY)


def build_supervisor(settings) -> GrpcSupervisor:
    """Build the agent's handle on the supervisor daemon.

    gRPC is the only supervisor mode: the Rust daemon (`aleph-vm-supervisor`,
    rust/crates/supervisor-daemon) owns the VM pool and serves the `Supervisor` contract
    on `settings.SUPERVISOR_GRPC_SOCKET`. The setting is always set: it
    defaults to `EXECUTION_ROOT/supervisor.sock`, the same path the packaged
    supervisor.env pins.
    """
    logger.info("Supervisor over gRPC at %s", settings.SUPERVISOR_GRPC_SOCKET)
    return GrpcSupervisor(settings.SUPERVISOR_GRPC_SOCKET)


def setup_webapp(supervisor: Supervisor):
    """Create the agent webapp around a `Supervisor`.

    Production passes `build_supervisor(settings)`'s `GrpcSupervisor`; tests
    may inject the daemon's engine (`LocalSupervisor(pool)`) to drive the
    views in-process as a harness. Request handlers never touch a VmPool:
    every VM operation (backups, restore, confidential, migration, network
    recreation, GPU reservation, persistent programs) goes through the
    `Supervisor` interface.
    """
    app = web.Application(middlewares=[drain_middleware, error_middleware])
    app.on_response_prepare.append(on_prepare_server_version)
    # Agent-owned drain flag: drain_middleware rejects new VM requests when set;
    # flipped by drain_in_flight_requests.
    app["draining"] = False
    app["supervisor"] = supervisor
    app["expiry"] = ExpiryManager(app["supervisor"])
    app["vm_registry"] = AgentVmRegistry()
    # Admission policy and the GPU reservation ledger are agent-side, owned
    # alongside the registry: the reserve endpoint and the create paths share
    # this instance.
    app["capacity"] = CapacityManager(app["supervisor"], app["vm_registry"])
    app["update_watcher"] = UpdateWatcher(app["supervisor"], app["vm_registry"])
    app["program_client"] = ProgramGuestClient()
    # Backups are agent work (the agent created the disks it copies); the
    # supervisor only freezes and thaws the guest around the copy.
    app["backups"] = BackupManager(app["supervisor"])

    # When a reaper tears a VM down: each idle-teardown facility cancels the
    # other's timer (an expired or updated VM never leaks the sibling's pending
    # task), and the agent's guest-side program state (guest API process,
    # configured mark) is dropped.
    def _drop_program_guest_state(vm_id) -> None:
        create_task_log_exceptions(app["program_client"].forget(vm_id), name=f"forget {vm_id}")

    def _on_expiry_reaped(vm_id) -> None:
        app["update_watcher"].cancel(vm_id)
        _drop_program_guest_state(vm_id)

    def _on_update_reaped(vm_id) -> None:
        app["expiry"].cancel(vm_id)
        _drop_program_guest_state(vm_id)

    app["expiry"].on_reaped = _on_expiry_reaped
    app["update_watcher"].on_reaped = _on_update_reaped

    # The supervisor daemon owns the VMs, so its event stream is the only way
    # for the agent to learn that a VM went down without polling; feed the
    # reap hooks above from it.
    async def _start_event_watcher(app: web.Application) -> None:
        app["_event_watcher"] = asyncio.get_running_loop().create_task(watch_supervisor_events(app))

    async def _stop_event_watcher(app: web.Application) -> None:
        task = app.get("_event_watcher")
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    # type-ignores: aiohttp's Signal stubs reject perfectly valid
    # `async (Application) -> None` handlers here.
    app.on_startup.append(_start_event_watcher)  # type: ignore[arg-type]
    app.on_cleanup.append(_stop_event_watcher)  # type: ignore[arg-type]

    cors = setup(
        app,
        defaults={
            "*": ResourceOptions(
                allow_credentials=True,
                expose_headers="*",
                allow_headers="*",
            )
        },
    )

    # Routes that need CORS enabled
    cors_routes = [
        # /about APIs return information about the VM Orchestrator
        web.get("/about/login", about_login),
        web.get("/about/executions/list", list_executions),
        web.get("/v2/about/executions/list", list_executions_v2),
        web.get("/about/executions/records", about_execution_records),
        web.get("/about/usage/system", about_system_usage),
        web.get("/about/certificates", about_certificates),
        web.get("/about/capability", about_capability),
        web.get("/about/config", about_config),
        # /control APIs are used to control the VMs and access their logs
        web.post("/control/allocation/notify", notify_allocation),
        web.post("/control/reserve_resources", operate_reserve_resources),
        web.post("/control/machine/{ref}/update", operate_update),
        web.get("/control/machine/{ref}/stream_logs", stream_logs),
        web.get("/control/machine/{ref}/logs", operate_logs_json),
        web.post("/control/machine/{ref}/expire", operate_expire),
        web.post("/control/machine/{ref}/stop", operate_stop),
        web.post("/control/machine/{ref}/erase", operate_erase),
        web.post("/control/machine/{ref}/reboot", operate_reboot),
        web.post("/control/machine/{ref}/reinstall", operate_reinstall),
        web.post("/control/machine/{ref}/backup", operate_backup),
        web.get("/control/machine/{ref}/backup", operate_backup_status),
        web.get("/control/machine/{ref}/backup/{backup_id}", operate_backup_download),
        web.delete("/control/machine/{ref}/backup/{backup_id}", operate_backup_delete),
        web.post("/control/machine/{ref}/restore", operate_restore),
        web.post("/control/machine/{ref}/confidential/initialize", operate_confidential_initialize),
        web.get("/control/machine/{ref}/confidential/measurement", operate_confidential_measurement),
        web.post("/control/machine/{ref}/confidential/inject_secret", operate_confidential_inject_secret),
        web.get("/debug/haproxy", debug_haproxy),
        # /status APIs are used to check that the VM Orchestrator is running properly
        web.get("/status/check/fastapi", status_check_fastapi),
        web.get("/status/check/fastapi/legacy", status_check_fastapi_legacy),
        web.get("/status/check/host", status_check_host),
        web.get("/status/check/version", status_check_version),
        web.get("/status/check/ipv6", status_check_ipv6),
        web.get("/status/config", status_public_config),
    ]
    routes = app.add_routes(cors_routes)
    for route in routes:
        cors.add(route)

    # Routes that don't need CORS enabled
    other_routes = [
        # /control APIs are used to control the VMs and access their logs
        web.post("/control/allocations", update_allocations),
        web.post("/control/network/recreate", recreate_network),
        web.post("/control/proxy/regenerate", regenerate_proxy),
        # Migration endpoints (scheduler-only, uses Aleph-EIP191-V1 auth)
        web.post("/control/machine/{ref}/migration/export", migration_export),
        web.get("/control/machine/{ref}/migration/export/status", migration_export_status),
        web.get("/control/machine/{ref}/migration/disk/{filename}", migration_disk_download),
        web.post("/control/migrate", migration_import),
        web.get("/control/migrate/{ref}/status", migration_import_status),
        web.post("/control/machine/{ref}/migration/cleanup", migration_cleanup),
        # Raise an HTTP Error 404 if attempting to access an unknown URL within these paths.
        web.get("/about/{suffix:.*}", http_not_found),
        web.get("/control/{suffix:.*}", http_not_found),
        web.get("/status/{suffix:.*}", http_not_found),
        # /static is used to serve static files
        web.static("/static", Path(__file__).parent / "views/static"),
        # /vm is used to launch VMs on-demand
        web.route("*", "/vm/{ref}{suffix:.*}", run_code_from_path),
        web.route("*", "/{suffix:.*}", run_code_from_hostname),
    ]
    app.add_routes(other_routes)
    return app


async def drain_in_flight_requests(app: web.Application):
    """Stop accepting new VM requests.

    Setting the agent-owned draining flag makes drain_middleware reject new VM
    requests. The daemon owns the pool and keeps VMs running across the agent's
    restart, so the agent only flips the flag and lets aiohttp finish its
    in-flight handlers.
    """
    app["draining"] = True


async def stop_expiry_manager(app: web.Application) -> None:
    """on_cleanup hook: cancel any pending idle-teardown timers."""
    expiry = app.get("expiry")
    if expiry is not None:
        await expiry.cancel_all()


async def stop_update_watcher(app: web.Application) -> None:
    """on_cleanup hook: cancel any pending update-watch subscriptions."""
    update_watcher = app.get("update_watcher")
    if update_watcher is not None:
        await update_watcher.cancel_all()


async def stop_program_client(app: web.Application) -> None:
    """on_cleanup hook: stop the agent-owned guest API processes."""
    program_client = app.get("program_client")
    if program_client is not None:
        await program_client.forget_all()


async def _run_migration_reaper(app: web.Application) -> None:
    """on_startup hook: clean up orphan migration files from a prior agent run.

    Cold migration staging is agent-owned, so this runs agent-side. The live-VM
    set comes from the supervisor over the ABC; it only guards against deleting
    a running VM's volume directory.
    """
    supervisor = app["supervisor"]
    known_vm_ids = {str(info.vm_id) for info in await supervisor.list_vms()}
    await reap_orphan_migration_files(known_vm_ids)


async def _rehydrate_vm_registry(app: web.Application) -> None:
    """on_startup hook: refill the agent's message registry from its DB."""
    count = await rehydrate_registry(app["vm_registry"])
    logger.info("Rehydrated %d VM record(s) into the agent registry", count)


async def log_snp_launch_capability(_app) -> None:
    """on_startup hook: tell the operator, once and loudly, when SNP silicon
    is enabled but this host still cannot launch confidential guests (field
    report F2: a capable EPYC host silently advertised nothing, and later a
    QEMU too old to launch). Never fails startup."""
    try:
        if not check_amd_sev_snp_supported():
            return
        capability = await get_snp_launch_capability()
        if capability.supported_vcpu_types:
            logger.info(
                "SEV-SNP confidential launches available; advertising guest CPU models: %s",
                ", ".join(capability.supported_vcpu_types),
            )
        else:
            logger.warning(
                "SEV-SNP silicon is enabled on this host but confidential launches are "
                "DISABLED, so the node will not advertise SNP capability: %s",
                capability.unavailable_reason,
            )
    except Exception:
        logger.exception("Could not determine SNP launch capability at startup")


def run():
    """Run the agent web server."""
    settings.check()
    from aleph.vm.agent.views.allocation_auth import log_allocation_auth_config

    log_allocation_auth_config()

    hostname = settings.DOMAIN_NAME
    protocol = "http" if hostname == "localhost" else "https"

    # Require a random token to access /about APIs
    secret_token = token_urlsafe(nbytes=32)
    (settings.EXECUTION_ROOT / "login_token").write_text(secret_token)
    (settings.EXECUTION_ROOT / "login_token").chmod(0o400)
    # The Rust supervisor daemon owns the VM pool; the agent only holds the
    # gRPC client handle.
    app = setup_webapp(supervisor=build_supervisor(settings))
    # Store app singletons. Note that app["pubsub"] will also be created.
    app["secret_token"] = secret_token

    app["node_identity"] = NodeIdentity(
        node_hash=settings.NODE_HASH,
        owner_address=settings.OWNER_ADDRESS,
        domain_name=settings.DOMAIN_NAME,
        cache_dir=settings.EXECUTION_ROOT,
    )
    app.on_startup.append(_run_migration_reaper)
    app.on_startup.append(_rehydrate_vm_registry)
    app.on_startup.append(log_snp_launch_capability)
    app.on_startup.append(start_node_hash_discovery)
    app.on_cleanup.append(stop_node_hash_discovery)

    # Store sevctl app singleton only if confidential feature is enabled
    if settings.ENABLE_CONFIDENTIAL_COMPUTING:
        sev_client = SevClient(settings.CONFIDENTIAL_DIRECTORY, settings.SEV_CTL_PATH)
        app["sev_client"] = sev_client
        # TODO: Review and check sevctl first initialization steps, like (sevctl generate and sevctl provision)

    logger.info(f"Login to /about pages {protocol}://{hostname}/about/login?token={secret_token}")

    try:
        # on_shutdown fires while the server still accepts keep-alive requests,
        # so the drain middleware can reject new ones with 503.
        # on_cleanup fires after the server is already closed — too late.
        app.on_shutdown.append(drain_in_flight_requests)

        if settings.WATCH_FOR_MESSAGES:
            app.on_startup.append(start_watch_for_messages_task)
            app.on_startup.append(start_payment_monitoring_task)
            app.on_startup.append(start_domain_resync_task)
            app.on_cleanup.append(stop_watch_for_messages_task)
            app.on_cleanup.append(stop_balances_monitoring_task)
            app.on_cleanup.append(stop_domain_resync_task)

        app.on_cleanup.append(stop_expiry_manager)
        app.on_cleanup.append(stop_update_watcher)
        app.on_cleanup.append(stop_program_client)

        from aleph.vm.utils.http import close_session, reset_session

        app.on_cleanup.append(close_session)

        # Each asyncio.run() creates and destroys its own event loop.
        # Discard any HTTP session created during setup so it doesn't hold
        # a reference to a dead loop.
        reset_session()

        logger.info(f"Starting the web server on http://{settings.SUPERVISOR_HOST}:{settings.SUPERVISOR_PORT}")
        web.run_app(app, host=settings.SUPERVISOR_HOST, port=settings.SUPERVISOR_PORT)
    except OSError as e:
        if e.errno == 98:
            logger.error(
                f"Port {settings.SUPERVISOR_PORT} already in use. "
                f"Please check that no other instance of Aleph-VM is running."
            )
            sys.exit(1)
        else:
            raise
