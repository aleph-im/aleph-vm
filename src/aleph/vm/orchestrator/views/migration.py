"""
Migration endpoints for live VM migration between CRN hosts.

These endpoints are called by the scheduler to coordinate VM migration:
1. POST /control/migrate - Prepare destination to receive migration
2. POST /control/machine/{ref}/migration/start - Start migration from source
"""

import asyncio
import logging
import time
from datetime import datetime, timezone
from http import HTTPStatus

import pydantic
from aiohttp import web
from aleph_message.models import ItemHash, MessageType
from aleph_message.models.execution.environment import HypervisorType
from pydantic import BaseModel

from aleph.vm.conf import settings
from aleph.vm.controllers.qemu.client import QemuVmClient, VmRunStatus
from aleph.vm.models import MigrationState, VmExecution
from aleph.vm.orchestrator.messages import load_updated_message
from aleph.vm.pool import VmPool
from aleph.vm.utils import cors_allow_all, create_task_log_exceptions, dumps_for_json

from . import authenticate_api_request
from .operator import get_execution_or_404, get_itemhash_or_400

logger = logging.getLogger(__name__)

# Lock to prevent concurrent migration operations
migration_lock: asyncio.Lock | None = None

# Track background migration finalization tasks
_migration_finalization_tasks: dict[ItemHash, asyncio.Task] = {}


class AllocateMigrationRequest(BaseModel):
    """Request body for POST /control/migrate."""

    vm_hash: str
    migration_port: int


class MigrationStartRequest(BaseModel):
    """Request body for POST /control/machine/{ref}/migration/start."""

    destination_host: str
    destination_port: int
    bandwidth_limit_mbps: int | None = None


@cors_allow_all
async def allocate_migration(request: web.Request) -> web.Response:
    """
    POST /control/migrate

    Prepare destination host to receive migrating VM.
    Called by the scheduler before initiating migration from source.

    Auth: X-Auth-Signature header (scheduler token, same as /control/allocations)

    Body: {"vm_hash": "abc123...", "migration_port": 4444}

    This endpoint:
    - Validates scheduler authentication (ALLOCATION_TOKEN_HASH)
    - Fetches VM message from Aleph network
    - Validates this is a QEMU instance
    - Creates destination disk image (sparse QCOW2)
    - Sets up network (TAP interface, firewall rules)
    - Prepares QEMU configuration with -incoming tcp:0.0.0.0:PORT flag

    Returns: {"status": "ready", "migration_host": "...", "migration_port": 4444, "vm_hash": "..."}
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    global migration_lock
    if migration_lock is None:
        migration_lock = asyncio.Lock()

    try:
        data = await request.json()
        params = AllocateMigrationRequest.model_validate(data)
    except pydantic.ValidationError as error:
        return web.json_response(data=error.json(), status=HTTPStatus.BAD_REQUEST)

    pool: VmPool = request.app["vm_pool"]
    vm_hash = ItemHash(params.vm_hash)

    async with migration_lock:
        # Check if VM already exists on this host
        existing = pool.executions.get(vm_hash)
        if existing and existing.is_running:
            return web.json_response(
                {"status": "error", "error": "VM already running on this host", "vm_hash": str(vm_hash)},
                status=HTTPStatus.CONFLICT,
            )

        try:
            # Fetch VM message from Aleph network
            message, original_message = await load_updated_message(vm_hash)

            # Validate it's an instance
            if message.type != MessageType.instance:
                return web.json_response(
                    {"status": "error", "error": "Message is not an instance", "vm_hash": str(vm_hash)},
                    status=HTTPStatus.BAD_REQUEST,
                )

            # Validate it's a QEMU instance
            hypervisor = message.content.environment.hypervisor or HypervisorType.firecracker
            if hypervisor != HypervisorType.qemu:
                return web.json_response(
                    {
                        "status": "error",
                        "error": "Live migration only supported for QEMU instances",
                        "vm_hash": str(vm_hash),
                    },
                    status=HTTPStatus.BAD_REQUEST,
                )

            # Create VM prepared for incoming migration
            execution = await pool.create_a_vm(
                vm_hash=vm_hash,
                message=message.content,
                original=original_message.content,
                persistent=True,
                incoming_migration_port=params.migration_port,
            )

            # Get the host IP from network configuration
            migration_host = pool.network.host_ipv4 if pool.network else "0.0.0.0"

            logger.info(f"Prepared VM {vm_hash} for incoming migration on {migration_host}:{params.migration_port}")

            # Start background task to monitor migration completion and finalize
            _start_migration_finalization_task(execution, pool)

            return web.json_response(
                {
                    "status": "ready",
                    "migration_host": migration_host,
                    "migration_port": params.migration_port,
                    "vm_hash": str(vm_hash),
                },
                status=HTTPStatus.OK,
                dumps=dumps_for_json,
            )

        except ValueError as error:
            logger.error(f"Failed to prepare migration for {vm_hash}: {error}")
            return web.json_response(
                {"status": "error", "error": str(error), "vm_hash": str(vm_hash)},
                status=HTTPStatus.BAD_REQUEST,
            )
        except Exception as error:
            logger.exception(f"Failed to prepare migration for {vm_hash}: {error}")
            return web.json_response(
                {"status": "error", "error": f"Failed to prepare migration: {error}", "vm_hash": str(vm_hash)},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )


@cors_allow_all
async def migration_start(request: web.Request) -> web.Response:
    """
    POST /control/machine/{ref}/migration/start

    Start migration from source to destination.
    Called by the scheduler after destination is prepared.

    Auth: X-Auth-Signature header (scheduler token, same as /control/allocations)

    Body: {"destination_host": "...", "destination_port": 4444, "bandwidth_limit_mbps": 100}

    This endpoint:
    - Validates scheduler authentication (ALLOCATION_TOKEN_HASH)
    - Validates running VM
    - Sends QMP migrate command (with block migration)
    - Polls query-migrate until completion
    - After completion: auto-cleanup source VM

    Returns: {"status": "completed", "total_time_ms": ..., "downtime_ms": ..., "transferred_bytes": ...}
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)

    try:
        data = await request.json()
        params = MigrationStartRequest.model_validate(data)
    except pydantic.ValidationError as error:
        return web.json_response(data=error.json(), status=HTTPStatus.BAD_REQUEST)

    pool: VmPool = request.app["vm_pool"]
    execution: VmExecution = get_execution_or_404(vm_hash, pool)

    # Validate VM is running
    if not execution.is_running:
        return web.json_response(
            {"status": "error", "error": "VM is not running", "vm_hash": str(vm_hash)},
            status=HTTPStatus.BAD_REQUEST,
        )

    # Validate it's a QEMU instance
    if execution.hypervisor != HypervisorType.qemu:
        return web.json_response(
            {"status": "error", "error": "Live migration only supported for QEMU instances", "vm_hash": str(vm_hash)},
            status=HTTPStatus.BAD_REQUEST,
        )

    # Check that VM object exists
    if not execution.vm:
        return web.json_response(
            {"status": "error", "error": "VM not properly initialized", "vm_hash": str(vm_hash)},
            status=HTTPStatus.BAD_REQUEST,
        )

    try:
        # Update migration state
        execution.migration_state = MigrationState.MIGRATING

        # Connect to QMP
        vm_client = QemuVmClient(execution.vm)

        # Build destination URI
        destination_uri = f"tcp:{params.destination_host}:{params.destination_port}"
        logger.info(f"Starting migration of {vm_hash} to {destination_uri}")

        # Start migration
        start_time = time.monotonic()
        vm_client.migrate(destination_uri, bandwidth_limit_mbps=params.bandwidth_limit_mbps)

        # Poll for migration completion
        migration_result = await _wait_for_migration_completion(vm_client, vm_hash)

        if migration_result["status"] == "completed":
            total_time_ms = int((time.monotonic() - start_time) * 1000)

            # Extract stats from migration result
            downtime_ms = migration_result.get("downtime", 0)
            transferred_bytes = migration_result.get("ram", {}).get("transferred", 0)
            if "disk" in migration_result:
                transferred_bytes += migration_result["disk"].get("transferred", 0)

            logger.info(
                f"Migration of {vm_hash} completed in {total_time_ms}ms, "
                f"downtime: {downtime_ms}ms, transferred: {transferred_bytes} bytes"
            )

            # Cleanup source VM after successful migration
            execution.migration_state = MigrationState.COMPLETED
            await _cleanup_source_vm(pool, execution)

            return web.json_response(
                {
                    "status": "completed",
                    "vm_hash": str(vm_hash),
                    "total_time_ms": total_time_ms,
                    "downtime_ms": downtime_ms,
                    "transferred_bytes": transferred_bytes,
                },
                status=HTTPStatus.OK,
                dumps=dumps_for_json,
            )
        else:
            # Migration failed
            execution.migration_state = MigrationState.FAILED
            error_msg = migration_result.get("error-desc", "Unknown error")
            logger.error(f"Migration of {vm_hash} failed: {error_msg}")
            return web.json_response(
                {"status": "error", "error": f"Migration failed: {error_msg}", "vm_hash": str(vm_hash)},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    except Exception as error:
        execution.migration_state = MigrationState.FAILED
        logger.exception(f"Migration of {vm_hash} failed: {error}")
        return web.json_response(
            {"status": "error", "error": f"Migration failed: {error}", "vm_hash": str(vm_hash)},
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )


async def _wait_for_migration_completion(
    vm_client: QemuVmClient,
    vm_hash: ItemHash,
    poll_interval: float = 1.0,
    timeout: float = 3600.0,
) -> dict:
    """
    Poll migration status until completion or timeout.

    :param vm_client: QMP client for the VM
    :param vm_hash: VM hash for logging
    :param poll_interval: Seconds between status checks
    :param timeout: Maximum time to wait in seconds
    :return: Final migration status dict
    """
    start_time = time.monotonic()

    while True:
        elapsed = time.monotonic() - start_time
        if elapsed > timeout:
            logger.warning(f"Migration of {vm_hash} timed out after {timeout}s")
            vm_client.migrate_cancel()
            return {"status": "failed", "error-desc": f"Migration timed out after {timeout}s"}

        status = vm_client.query_migrate()
        migration_status = status.get("status", "unknown")

        logger.debug(f"Migration status for {vm_hash}: {migration_status}")

        if migration_status == "completed":
            return status
        elif migration_status in ("failed", "cancelled"):
            return status
        elif migration_status in ("active", "setup", "pre-switchover", "postcopy-active"):
            # Migration in progress, log progress
            if "ram" in status:
                ram = status["ram"]
                transferred = ram.get("transferred", 0)
                total = ram.get("total", 0)
                if total > 0:
                    progress = (transferred / total) * 100
                    logger.debug(f"Migration progress for {vm_hash}: {progress:.1f}%")

        await asyncio.sleep(poll_interval)


async def _cleanup_source_vm(pool: VmPool, execution: VmExecution) -> None:
    """
    Cleanup source VM after successful migration.

    This stops the VM and removes it from the pool.
    The VM on the source has already been paused by QEMU during migration.

    :param pool: The VM pool
    :param execution: The VM execution to cleanup
    """
    vm_hash = execution.vm_hash
    logger.info(f"Cleaning up source VM {vm_hash} after migration")

    try:
        # Stop the VM (this also handles network teardown)
        await pool.stop_vm(vm_hash)

        # Remove from pool
        pool.forget_vm(vm_hash)

        logger.info(f"Source VM {vm_hash} cleanup completed")
    except Exception as error:
        logger.error(f"Error cleaning up source VM {vm_hash}: {error}")
        # Don't raise - migration was successful, cleanup failure is non-fatal


def _start_migration_finalization_task(execution: VmExecution, pool: VmPool) -> None:
    """
    Start a background task to monitor migration completion and finalize on destination.

    This task monitors the VM status until it transitions from "inmigrate" to "running",
    then reconfigures the guest network with the new IP address.

    :param execution: The VM execution waiting for migration
    :param pool: The VM pool
    """
    vm_hash = execution.vm_hash

    # Cancel any existing task for this VM
    if vm_hash in _migration_finalization_tasks:
        _migration_finalization_tasks[vm_hash].cancel()

    task = create_task_log_exceptions(
        _finalize_migration_on_destination(execution, pool),
        name=f"migration-finalize-{vm_hash}",
    )
    _migration_finalization_tasks[vm_hash] = task


async def _finalize_migration_on_destination(
    execution: VmExecution,
    pool: VmPool,
    poll_interval: float = 10.0,
    timeout: float = 3600.0,
) -> None:
    """
    Monitor migration completion on destination and reconfigure guest network.

    This background task:
    1. Waits for the VM to transition from "inmigrate" to "running" status
    2. Waits for the guest agent to become available
    3. Reconfigures the guest network with the new IP address

    :param execution: The VM execution waiting for migration
    :param pool: The VM pool
    :param poll_interval: Seconds between status checks
    :param timeout: Maximum time to wait in seconds
    """
    vm_hash = execution.vm_hash
    logger.info(f"Starting migration finalization monitor for {vm_hash}")

    start_time = time.monotonic()

    try:
        # Wait for QMP socket to be available
        while not execution.vm or not execution.vm.qmp_socket_path.exists():
            if time.monotonic() - start_time > timeout:
                logger.error(f"Timeout waiting for QMP socket for {vm_hash}")
                execution.migration_state = MigrationState.FAILED
                return
            await asyncio.sleep(poll_interval)

        # Monitor VM status until migration completes
        vm_running = False
        while not vm_running:
            elapsed = time.monotonic() - start_time
            if elapsed > timeout:
                logger.error(f"Migration finalization timed out for {vm_hash} after {timeout}s")
                execution.migration_state = MigrationState.FAILED
                return

            try:
                vm_client = QemuVmClient(execution.vm)
                status = vm_client.query_status()

                logger.debug(f"Destination VM {vm_hash} status: {status.status.value}, running: {status.running}")

                if status.is_running:
                    logger.info(f"Migration completed for {vm_hash}, VM is now running on destination")
                    vm_client.close()
                    break
                elif status.is_migrating or status.status in (VmRunStatus.PAUSED, VmRunStatus.PRELAUNCH):
                    # Still waiting for migration data
                    pass
                elif status.is_error:
                    logger.error(f"VM {vm_hash} in error state: {status.status.value}")
                    execution.migration_state = MigrationState.FAILED
                    vm_client.close()
                    return

                vm_client.close()
            except Exception as e:
                logger.debug(f"Could not query VM status for {vm_hash}: {e}")

            await asyncio.sleep(poll_interval)

        # Migration completed, now reconfigure guest network
        await _reconfigure_guest_network(execution)

        # Update migration state and mark as started
        execution.migration_state = MigrationState.COMPLETED
        execution.times.started_at = datetime.now(tz=timezone.utc)
        logger.info(f"Migration finalization completed for {vm_hash}")

    except asyncio.CancelledError:
        logger.info(f"Migration finalization task cancelled for {vm_hash}")
        raise
    except Exception as error:
        logger.exception(f"Error during migration finalization for {vm_hash}: {error}")
        execution.migration_state = MigrationState.FAILED
    finally:
        # Clean up task reference
        if vm_hash in _migration_finalization_tasks:
            del _migration_finalization_tasks[vm_hash]


async def _reconfigure_guest_network(
    execution: VmExecution,
    guest_agent_timeout: int = 120,
) -> None:
    """
    Reconfigure guest network after migration completes.

    This connects to the guest via qemu-guest-agent and updates the netplan
    configuration with the new IP address assigned on this host.

    :param execution: The VM execution
    :param guest_agent_timeout: Timeout for guest agent availability
    """
    vm_hash = execution.vm_hash

    if not execution.vm or not execution.vm.tap_interface:
        logger.warning(f"Cannot reconfigure network for {vm_hash}: no tap interface")
        return

    tap = execution.vm.tap_interface
    new_ip = tap.guest_ip.with_prefixlen  # e.g., "10.0.0.5/24"
    gateway = str(tap.host_ip.ip)  # e.g., "10.0.0.1"
    nameservers = list(settings.DNS_NAMESERVERS) if hasattr(settings, "DNS_NAMESERVERS") else ["8.8.8.8", "8.8.4.4"]

    logger.info(f"Reconfiguring guest network for {vm_hash}: IP={new_ip}, gateway={gateway}")

    try:
        vm_client = QemuVmClient(execution.vm)

        # Wait for guest agent to be available
        logger.debug(f"Waiting for guest agent on {vm_hash}")
        if not vm_client.wait_for_guest_agent(timeout_seconds=guest_agent_timeout):
            logger.warning(f"Guest agent not available for {vm_hash}, skipping network reconfiguration")
            vm_client.close()
            return

        # Reconfigure the network
        result = vm_client.reconfigure_guest_network(
            new_ip=str(new_ip),
            gateway=gateway,
            nameservers=nameservers,
        )

        logger.info(f"Network reconfiguration initiated for {vm_hash}, pid={result.get('pid')}")

        # Wait a moment for the command to complete
        await asyncio.sleep(2)

        # Check if the command completed successfully
        if "pid" in result:
            try:
                status = vm_client.guest_exec_status(result["pid"])
                if status.get("exited") and status.get("exitcode", -1) == 0:
                    logger.info(f"Network reconfiguration successful for {vm_hash}")
                elif status.get("exited"):
                    logger.warning(
                        f"Network reconfiguration may have failed for {vm_hash}, "
                        f"exit code: {status.get('exitcode')}"
                    )
            except Exception as e:
                logger.debug(f"Could not get guest-exec status for {vm_hash}: {e}")

        vm_client.close()

    except Exception as error:
        logger.error(f"Failed to reconfigure guest network for {vm_hash}: {error}")
