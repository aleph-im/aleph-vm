"""
Cold (stop/start) migration endpoints for VM migration between CRN hosts.

These endpoints are called by the scheduler to coordinate VM migration:
1. POST /control/machine/{ref}/migration/export - Stop VM on source, compress disks, serve for download
2. GET /control/machine/{ref}/migration/disk/{filename} - Download a compressed disk file
3. POST /control/migrate - Import a VM on the destination from source disk files
4. POST /control/machine/{ref}/migration/cleanup - Clean up source VM after successful migration
"""

import asyncio
import logging
import os
import secrets
import shutil
import time
from http import HTTPStatus
from pathlib import Path

import aiohttp
import pydantic
from aiohttp import web
from aleph_message.models import ItemHash, MessageType
from aleph_message.models.execution.environment import HypervisorType
from pydantic import BaseModel

from aleph.vm.conf import settings
from aleph.vm.controllers.qemu.client import QemuVmClient
from aleph.vm.models import MigrationState, VmExecution
from aleph.vm.orchestrator.messages import load_updated_message
from aleph.vm.pool import VmPool
from aleph.vm.storage import get_rootfs_base_path
from aleph.vm.utils import cors_allow_all, create_task_log_exceptions, dumps_for_json

from . import authenticate_api_request
from .operator import get_execution_or_404, get_itemhash_or_400

logger = logging.getLogger(__name__)

# Lock to prevent concurrent migration operations
migration_lock: asyncio.Lock | None = None

# Track export TTL cleanup tasks
_export_cleanup_tasks: dict[ItemHash, asyncio.Task] = {}

# Store temporary download routes info: vm_hash -> {token, disk_files, export_paths}
_export_state: dict[ItemHash, dict] = {}

EXPORT_TTL_SECONDS = 1800  # 30 minutes
GRACEFUL_SHUTDOWN_TIMEOUT = 30  # seconds


class DiskFileInfo(BaseModel):
    """Information about an exported disk file."""

    name: str
    size_bytes: int
    download_path: str


class MigrationExportResponse(BaseModel):
    """Response from the export endpoint."""

    status: str
    vm_hash: str
    disk_files: list[DiskFileInfo]
    export_token: str


class ColdMigrationImportRequest(BaseModel):
    """Request body for POST /control/migrate."""

    vm_hash: str
    source_host: str
    source_port: int = 443
    export_token: str
    disk_files: list[DiskFileInfo]


# --- Helpers ---


async def _graceful_shutdown(execution: VmExecution, timeout: int = GRACEFUL_SHUTDOWN_TIMEOUT) -> None:
    """Gracefully shut down a QEMU VM via QMP system_powerdown, with fallback to quit.

    :param execution: The VM execution to shut down
    :param timeout: Seconds to wait for graceful shutdown before forcing quit
    """
    vm = execution.vm
    if not vm:
        msg = "VM not initialized"
        raise RuntimeError(msg)

    try:
        client = QemuVmClient(vm)
        client.system_powerdown()
        client.close()
    except Exception as e:
        logger.warning("Failed to send system_powerdown for %s: %s", execution.vm_hash, e)

    # Wait for QEMU process to exit
    start = time.monotonic()
    while time.monotonic() - start < timeout:
        # Check if systemd service is still active
        if execution.systemd_manager and not execution.systemd_manager.is_service_active(execution.controller_service):
            logger.info("VM %s shut down gracefully", execution.vm_hash)
            return
        await asyncio.sleep(1)

    # Timeout — force quit via systemd stop
    logger.warning("VM %s did not shut down within %ds, forcing stop", execution.vm_hash, timeout)
    if execution.systemd_manager:
        execution.systemd_manager.stop_and_disable(execution.controller_service)


async def _compress_disk(source_path: Path, dest_path: Path) -> None:
    """Compress a QCOW2 disk using qemu-img convert.

    :param source_path: Path to the source QCOW2 file
    :param dest_path: Path for the compressed output
    """
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img,
        "convert",
        "-c",
        "-O",
        "qcow2",
        str(source_path),
        str(dest_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img convert failed: {stderr.decode()}"
        raise RuntimeError(msg)


async def _export_ttl_cleanup(vm_hash: ItemHash, timeout: int = EXPORT_TTL_SECONDS) -> None:
    """Background task to clean up stale export files after TTL expires."""
    try:
        await asyncio.sleep(timeout)
        logger.info("Export TTL expired for %s, cleaning up", vm_hash)
        _cleanup_export_files(vm_hash)
    except asyncio.CancelledError:
        pass
    finally:
        _export_cleanup_tasks.pop(vm_hash, None)


def _cleanup_export_files(vm_hash: ItemHash) -> None:
    """Remove export files and state for a VM."""
    state = _export_state.pop(vm_hash, None)
    if state:
        for path in state.get("export_paths", []):
            try:
                Path(path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning("Failed to delete export file %s: %s", path, e)


async def _download_disk_from_source(
    session: aiohttp.ClientSession,
    url: str,
    dest_path: Path,
    token: str,
) -> int:
    """Download a disk file from the source CRN.

    :param session: aiohttp client session
    :param url: Full URL to download from
    :param dest_path: Local path to save the file
    :param token: Export token for authentication
    :return: Number of bytes downloaded
    """
    part_path = dest_path.with_suffix(dest_path.suffix + ".part")
    part_path.parent.mkdir(parents=True, exist_ok=True)
    total_bytes = 0

    async with session.get(url, params={"token": token}) as resp:
        if resp.status != 200:
            body = await resp.text()
            msg = f"Failed to download {url}: HTTP {resp.status} - {body}"
            raise RuntimeError(msg)
        with open(part_path, "wb") as f:
            async for chunk in resp.content.iter_chunked(1024 * 1024):  # 1MB chunks
                f.write(chunk)
                total_bytes += len(chunk)

    # Atomic rename
    part_path.rename(dest_path)
    return total_bytes


async def _rebase_overlay(overlay_path: Path, parent_path: Path, parent_format: str) -> None:
    """Rebase a QCOW2 overlay to point to a local backing file.

    :param overlay_path: Path to the overlay QCOW2
    :param parent_path: Path to the local parent image
    :param parent_format: Format of the parent image (e.g., 'qcow2', 'raw')
    """
    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img,
        "rebase",
        "-u",
        "-b",
        str(parent_path),
        "-F",
        parent_format,
        str(overlay_path),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img rebase failed: {stderr.decode()}"
        raise RuntimeError(msg)


async def _detect_parent_format(parent_path: Path) -> str:
    """Detect the format of a parent image using qemu-img info."""
    import json as _json

    qemu_img = shutil.which("qemu-img")
    if not qemu_img:
        msg = "qemu-img not found in PATH"
        raise RuntimeError(msg)

    proc = await asyncio.create_subprocess_exec(
        qemu_img,
        "info",
        str(parent_path),
        "--output=json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    if proc.returncode != 0:
        msg = f"qemu-img info failed: {stderr.decode()}"
        raise RuntimeError(msg)

    info = _json.loads(stdout)
    fmt = info.get("format")
    if not fmt:
        msg = f"Could not detect format for {parent_path}"
        raise RuntimeError(msg)
    return fmt


# --- Endpoints ---


@cors_allow_all
async def migration_export(request: web.Request) -> web.Response:
    """
    POST /control/machine/{ref}/migration/export

    Stop VM on source, compress disks, make them downloadable.
    Called by scheduler on the source CRN.

    Auth: ALLOCATION_TOKEN_HASH (scheduler token)
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution: VmExecution = get_execution_or_404(vm_hash, pool)

    # Validate: running, QEMU, not confidential
    if not execution.is_running:
        return web.json_response(
            {"status": "error", "error": "VM is not running"},
            status=HTTPStatus.BAD_REQUEST,
        )
    if execution.hypervisor != HypervisorType.qemu:
        return web.json_response(
            {"status": "error", "error": "Migration only supported for QEMU instances"},
            status=HTTPStatus.BAD_REQUEST,
        )
    if execution.is_confidential:
        return web.json_response(
            {"status": "error", "error": "Migration is not supported for confidential VMs"},
            status=HTTPStatus.BAD_REQUEST,
        )
    if execution.migration_state not in (MigrationState.NONE, MigrationState.FAILED):
        return web.json_response(
            {"status": "error", "error": f"Migration already in progress: {execution.migration_state}"},
            status=HTTPStatus.CONFLICT,
        )

    try:
        execution.migration_state = MigrationState.EXPORTING

        # 1. Graceful shutdown
        await _graceful_shutdown(execution)

        # 2. Find and compress disk files
        namespace = execution.vm_hash
        volumes_dir = settings.PERSISTENT_VOLUMES_DIR / namespace
        disk_files: list[DiskFileInfo] = []
        export_paths: list[str] = []

        if volumes_dir.exists():
            for qcow2_file in sorted(volumes_dir.glob("*.qcow2")):
                export_path = qcow2_file.with_suffix(".qcow2.export.qcow2")
                await _compress_disk(qcow2_file, export_path)
                export_paths.append(str(export_path))

                disk_files.append(
                    DiskFileInfo(
                        name=qcow2_file.name,
                        size_bytes=export_path.stat().st_size,
                        download_path=f"/control/machine/{vm_hash}/migration/disk/{qcow2_file.name}",
                    )
                )

        if not disk_files:
            execution.migration_state = MigrationState.FAILED
            return web.json_response(
                {"status": "error", "error": "No disk files found to export"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )

        # 3. Generate export token
        export_token = secrets.token_urlsafe(32)
        execution.export_token = export_token

        # 4. Store export state for download route
        _export_state[vm_hash] = {
            "token": export_token,
            "disk_files": disk_files,
            "export_paths": export_paths,
            "volumes_dir": str(volumes_dir),
        }

        # 5. Start TTL cleanup task
        if vm_hash in _export_cleanup_tasks:
            _export_cleanup_tasks[vm_hash].cancel()
        _export_cleanup_tasks[vm_hash] = create_task_log_exceptions(
            _export_ttl_cleanup(vm_hash),
            name=f"export-ttl-{vm_hash}",
        )

        execution.migration_state = MigrationState.EXPORTED

        return web.json_response(
            MigrationExportResponse(
                status="ready",
                vm_hash=str(vm_hash),
                disk_files=disk_files,
                export_token=export_token,
            ).model_dump(),
            status=HTTPStatus.OK,
            dumps=dumps_for_json,
        )

    except Exception as error:
        logger.exception("Export failed for %s: %s", vm_hash, error)
        execution.migration_state = MigrationState.FAILED

        # Clean up any partial export files
        _cleanup_export_files(vm_hash)

        # Try to restart the VM via systemd
        try:
            if execution.systemd_manager:
                await execution.systemd_manager.enable_and_start(execution.controller_service)
                logger.info("Restarted VM %s after failed export", vm_hash)
        except Exception as restart_error:
            logger.error("Failed to restart VM %s after export failure: %s", vm_hash, restart_error)

        return web.json_response(
            {"status": "error", "error": f"Export failed: {error}"},
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )


@cors_allow_all
async def migration_disk_download(request: web.Request) -> web.Response:
    """
    GET /control/machine/{ref}/migration/disk/{filename}

    Stream a compressed disk file. Auth via ?token= query parameter.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    filename = request.match_info.get("filename", "")

    # Validate token
    token = request.query.get("token", "")
    state = _export_state.get(vm_hash)

    if not state or not secrets.compare_digest(token, state["token"]):
        return web.HTTPUnauthorized(text="Invalid or missing export token")

    # Find the export file
    volumes_dir = Path(state["volumes_dir"])
    export_path = volumes_dir / f"{filename}.export.qcow2"

    if not export_path.exists():
        return web.HTTPNotFound(text=f"Disk file not found: {filename}")

    return web.FileResponse(export_path)


@cors_allow_all
async def migration_import(request: web.Request) -> web.Response:
    """
    POST /control/migrate

    Import a VM on the destination from source disk files.
    Called by scheduler on the destination CRN.

    Auth: ALLOCATION_TOKEN_HASH (scheduler token)
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    global migration_lock
    if migration_lock is None:
        migration_lock = asyncio.Lock()

    try:
        data = await request.json()
        params = ColdMigrationImportRequest.model_validate(data)
    except pydantic.ValidationError as error:
        return web.json_response(data=error.json(), status=HTTPStatus.BAD_REQUEST)

    pool: VmPool = request.app["vm_pool"]
    vm_hash = ItemHash(params.vm_hash)

    async with migration_lock:
        # Validate: not already running on this host
        existing = pool.executions.get(vm_hash)
        if existing and existing.is_running:
            return web.json_response(
                {"status": "error", "error": "VM already running on this host"},
                status=HTTPStatus.CONFLICT,
            )

        downloaded_files: list[Path] = []
        start_time = time.monotonic()
        total_bytes = 0

        try:
            # 1. Fetch VM message from Aleph network
            message, original_message = await load_updated_message(vm_hash)

            if message.type != MessageType.instance:
                return web.json_response(
                    {"status": "error", "error": "Message is not an instance"},
                    status=HTTPStatus.BAD_REQUEST,
                )

            hypervisor = message.content.environment.hypervisor or HypervisorType.firecracker
            if hypervisor != HypervisorType.qemu:
                return web.json_response(
                    {"status": "error", "error": "Migration only supported for QEMU instances"},
                    status=HTTPStatus.BAD_REQUEST,
                )

            if message.content.environment.trusted_execution is not None:
                return web.json_response(
                    {"status": "error", "error": "Migration not supported for confidential VMs"},
                    status=HTTPStatus.BAD_REQUEST,
                )

            # 2. Download parent image
            parent_ref = message.content.rootfs.parent.ref
            parent_path = await get_rootfs_base_path(parent_ref)
            parent_format = await _detect_parent_format(parent_path)

            # 3. Download each disk file from source
            dest_dir = settings.PERSISTENT_VOLUMES_DIR / str(vm_hash)
            dest_dir.mkdir(parents=True, exist_ok=True)

            scheme = "https" if params.source_port == 443 else "http"
            base_url = f"{scheme}://{params.source_host}:{params.source_port}"

            async with aiohttp.ClientSession() as session:
                for disk_file in params.disk_files:
                    url = f"{base_url}{disk_file.download_path}"
                    dest_path = dest_dir / disk_file.name
                    downloaded_files.append(dest_path)

                    logger.info("Downloading %s from %s", disk_file.name, url)
                    bytes_downloaded = await _download_disk_from_source(
                        session,
                        url,
                        dest_path,
                        params.export_token,
                    )
                    total_bytes += bytes_downloaded

            # 4. Rebase overlay(s) to point to local parent
            for disk_file in params.disk_files:
                overlay_path = dest_dir / disk_file.name
                if overlay_path.exists():
                    await _rebase_overlay(overlay_path, parent_path, parent_format)

            # 5. Create VM via pool — make_writable_volume() sees existing file with host persistence, skips
            execution = await pool.create_a_vm(
                vm_hash=vm_hash,
                message=message.content,
                original=original_message.content,
                persistent=True,
            )

            transfer_time_ms = int((time.monotonic() - start_time) * 1000)

            return web.json_response(
                {
                    "status": "completed",
                    "vm_hash": str(vm_hash),
                    "transfer_time_ms": transfer_time_ms,
                    "total_bytes_transferred": total_bytes,
                },
                status=HTTPStatus.OK,
                dumps=dumps_for_json,
            )

        except Exception as error:
            logger.exception("Import failed for %s: %s", vm_hash, error)

            # Clean up downloaded files
            for path in downloaded_files:
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass

            return web.json_response(
                {"status": "error", "error": f"Import failed: {error}"},
                status=HTTPStatus.INTERNAL_SERVER_ERROR,
            )


@cors_allow_all
async def migration_cleanup(request: web.Request) -> web.Response:
    """
    POST /control/machine/{ref}/migration/cleanup

    Clean up source VM after successful migration to destination.
    Called by scheduler on the source CRN.

    Auth: ALLOCATION_TOKEN_HASH (scheduler token)
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]

    try:
        # Cancel TTL cleanup task
        ttl_task = _export_cleanup_tasks.pop(vm_hash, None)
        if ttl_task:
            ttl_task.cancel()

        # Stop and forget VM
        await pool.stop_vm(vm_hash)
        pool.forget_vm(vm_hash)

        # Delete export files
        _cleanup_export_files(vm_hash)

        return web.json_response(
            {"status": "completed", "vm_hash": str(vm_hash)},
            status=HTTPStatus.OK,
        )

    except Exception as error:
        logger.exception("Cleanup failed for %s: %s", vm_hash, error)
        return web.json_response(
            {"status": "error", "error": f"Cleanup failed: {error}"},
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
