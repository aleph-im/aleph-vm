"""
Cold (stop/start) migration endpoints for VM migration between CRN hosts.

These endpoints are called by the scheduler to coordinate VM migration:
1. POST /control/machine/{ref}/migration/export - Stop VM on source, compress disks, serve for download
2. GET /control/machine/{ref}/migration/disk/{filename} - Download a compressed disk file
3. POST /control/migrate - Import a VM on the destination from source disk files
4. POST /control/machine/{ref}/migration/cleanup - Clean up source VM after successful migration
"""

import logging
import secrets
import shutil
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path

import pydantic
from aiohttp import web
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import HypervisorType
from pydantic import BaseModel, Field

from aleph.vm.migration.jobs import DiskFileInfo, ExportJob, ImportJob, export_jobs, import_jobs
from aleph.vm.migration.runner import _run_export, _run_import
from aleph.vm.models import MigrationState, VmExecution
from aleph.vm.pool import VmPool
from aleph.vm.utils import cors_allow_all, create_task_log_exceptions, dumps_for_json

from . import authenticate_api_request
from .operator import get_execution_or_404, get_itemhash_or_400

logger = logging.getLogger(__name__)


class MigrationExportResponse(BaseModel):
    """Response from the export endpoint."""

    status: str
    vm_hash: str
    disk_files: list[DiskFileInfo]
    export_token: str


class ColdMigrationImportRequest(BaseModel):
    vm_hash: str
    source_host: str
    source_port: int = 443
    export_token: str
    disk_files: list[DiskFileInfo] = Field(..., min_length=1)


# --- Endpoints ---


@cors_allow_all
async def migration_export(request: web.Request) -> web.Response:
    """POST /control/machine/{ref}/migration/export — start an async export job.

    Returns 202 immediately. Caller polls GET /export/status for progress.
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution: VmExecution = get_execution_or_404(vm_hash, pool)

    if not execution.is_running:
        return web.json_response({"status": "error", "error": "VM is not running"}, status=HTTPStatus.BAD_REQUEST)
    if execution.hypervisor != HypervisorType.qemu:
        return web.json_response({"status": "error", "error": "Migration only supported for QEMU instances"}, status=HTTPStatus.BAD_REQUEST)
    if execution.is_confidential:
        return web.json_response({"status": "error", "error": "Migration is not supported for confidential VMs"}, status=HTTPStatus.BAD_REQUEST)

    # Read-modify-write of the registry below MUST stay await-free so two simultaneous
    # POSTs for the same vm_hash can't both pass the existence check.
    existing = export_jobs.get(vm_hash)
    if existing is not None:
        if existing.state == MigrationState.EXPORTING:
            return _export_job_descriptor_response(existing, status=HTTPStatus.ACCEPTED)
        if existing.state == MigrationState.EXPORT_FAILED:
            _reset_failed_export(existing)
        else:
            return _export_job_descriptor_response(existing, status=HTTPStatus.CONFLICT)

    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    export_jobs[vm_hash] = job
    job.task = create_task_log_exceptions(_run_export(job, execution), name=f"export-{vm_hash}")

    return _export_job_descriptor_response(job, status=HTTPStatus.ACCEPTED)


def _reset_failed_export(job: ExportJob) -> None:
    """Clear an EXPORT_FAILED slot so the caller's retry can start fresh."""
    logger.info("Resetting failed export for %s (previous error: %s)", job.vm_hash, job.error)
    if job.ttl_task is not None and not job.ttl_task.done():
        job.ttl_task.cancel()
    for path in job.export_paths:
        try:
            Path(path).unlink(missing_ok=True)
        except Exception as e:
            logger.warning("Failed to delete partial export %s: %s", path, e)
    export_jobs.pop(job.vm_hash, None)


def _export_job_descriptor_response(job: ExportJob, status: int) -> web.Response:
    return web.json_response(
        {
            "state": job.state.value,
            "vm_hash": str(job.vm_hash),
            "started_at": job.started_at.isoformat(),
            "status_url": f"/control/machine/{job.vm_hash}/migration/export/status",
            **({"error": job.error} if job.error else {}),
        },
        status=status,
        dumps=dumps_for_json,
    )


@cors_allow_all
async def migration_export_status(request: web.Request) -> web.Response:
    """GET /control/machine/{ref}/migration/export/status — return live export job state."""
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    job = export_jobs.get(vm_hash)
    if job is None:
        return web.json_response({"status": "error", "error": "No export job"}, status=HTTPStatus.NOT_FOUND)

    return web.json_response(
        {
            "vm_hash": str(job.vm_hash),
            "state": job.state.value,
            "started_at": job.started_at.isoformat(),
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "error": job.error,
            "disk_files": [df.model_dump() for df in job.disk_files] if job.disk_files else None,
            "export_token": job.token,
        },
        status=HTTPStatus.OK,
        dumps=dumps_for_json,
    )


@cors_allow_all
async def migration_disk_download(request: web.Request) -> web.StreamResponse:
    """GET /control/machine/{ref}/migration/disk/{filename} — stream a compressed disk file.

    Auth via ?token= query parameter. Increments job.active_downloads while the
    response is in flight so cleanup can refuse to run during a transfer.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    filename = request.match_info.get("filename", "")

    job = export_jobs.get(vm_hash)
    if job is None or job.token is None:
        return web.HTTPUnauthorized(text="Invalid or missing export token")

    token = request.query.get("token", "")
    if not secrets.compare_digest(token, job.token):
        return web.HTTPUnauthorized(text="Invalid or missing export token")

    if job.volumes_dir is None:
        return web.HTTPNotFound(text=f"Disk file not found: {filename}")
    export_path = job.volumes_dir / f"{filename}.export.qcow2"
    if not export_path.exists():
        return web.HTTPNotFound(text=f"Disk file not found: {filename}")

    # Increment AFTER all early-return validation paths so a 401/404 doesn't leak the counter.
    job.active_downloads += 1
    try:
        response = web.StreamResponse(
            status=200,
            headers={"Content-Type": "application/octet-stream", "Content-Length": str(export_path.stat().st_size)},
        )
        await response.prepare(request)
        with open(export_path, "rb") as f:
            while chunk := f.read(1024 * 1024):
                await response.write(chunk)
        await response.write_eof()
        return response
    finally:
        job.active_downloads -= 1


@cors_allow_all
async def migration_import(request: web.Request) -> web.Response:
    """POST /control/migrate — start an async import job."""
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    try:
        data = await request.json()
        params = ColdMigrationImportRequest.model_validate(data)
    except pydantic.ValidationError as error:
        return web.json_response(data=error.json(), status=HTTPStatus.BAD_REQUEST)

    pool: VmPool = request.app["vm_pool"]
    vm_hash = ItemHash(params.vm_hash)

    existing_exec = pool.executions.get(vm_hash)
    if existing_exec is not None and existing_exec.is_running:
        return web.json_response(
            {"status": "error", "error": "VM already running on this host"},
            status=HTTPStatus.CONFLICT,
        )

    # Read-modify-write of the registry below MUST stay await-free so two simultaneous
    # POSTs for the same vm_hash can't both pass the existence check.
    existing = import_jobs.get(vm_hash)
    if existing is not None:
        if existing.state == MigrationState.IMPORTING:
            return _import_job_descriptor_response(existing, status=HTTPStatus.ACCEPTED)
        if existing.state == MigrationState.IMPORT_FAILED:
            _reset_failed_import(existing, pool)
        else:
            return _import_job_descriptor_response(existing, status=HTTPStatus.CONFLICT)

    job = ImportJob(
        vm_hash=vm_hash,
        state=MigrationState.IMPORTING,
        started_at=datetime.now(timezone.utc),
        source_host=params.source_host,
        source_port=params.source_port,
    )
    import_jobs[vm_hash] = job
    job.task = create_task_log_exceptions(
        _run_import(job, pool, disk_files=params.disk_files, export_token=params.export_token),
        name=f"import-{vm_hash}",
    )

    return _import_job_descriptor_response(job, status=HTTPStatus.ACCEPTED)


def _reset_failed_import(job: ImportJob, pool: VmPool) -> None:
    """Clear an IMPORT_FAILED slot so the caller's retry can start fresh.

    Mirrors the safety check in _run_import's failure path: only rmtree the
    dest dir if the pool has no execution for this vm_hash.
    """
    logger.info("Resetting failed import for %s (previous error: %s)", job.vm_hash, job.error)
    if job.ttl_task is not None and not job.ttl_task.done():
        job.ttl_task.cancel()
    if job.dest_dir is not None and pool.executions.get(job.vm_hash) is None:
        shutil.rmtree(job.dest_dir, ignore_errors=True)
    import_jobs.pop(job.vm_hash, None)


def _import_job_descriptor_response(job: ImportJob, status: int) -> web.Response:
    return web.json_response(
        {
            "state": job.state.value,
            "vm_hash": str(job.vm_hash),
            "started_at": job.started_at.isoformat(),
            "status_url": f"/control/migrate/{job.vm_hash}/status",
            **({"error": job.error} if job.error else {}),
        },
        status=status,
        dumps=dumps_for_json,
    )


@cors_allow_all
async def migration_import_status(request: web.Request) -> web.Response:
    """GET /control/migrate/{vm_hash}/status — return live import job state."""
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)

    job = import_jobs.get(vm_hash)
    if job is None:
        return web.json_response({"status": "error", "error": "No import job"}, status=HTTPStatus.NOT_FOUND)

    return web.json_response(
        {
            "vm_hash": str(job.vm_hash),
            "state": job.state.value,
            "started_at": job.started_at.isoformat(),
            "finished_at": job.finished_at.isoformat() if job.finished_at else None,
            "bytes_downloaded": job.bytes_downloaded,
            "total_bytes_expected": job.total_bytes_expected,
            "current_step": job.current_step,
            "error": job.error,
            "transfer_time_ms": job.transfer_time_ms,
        },
        status=HTTPStatus.OK,
        dumps=dumps_for_json,
    )


@cors_allow_all
async def migration_cleanup(request: web.Request) -> web.Response:
    """POST /control/machine/{ref}/migration/cleanup — release source after dest reports IMPORTED.

    Refuses if no EXPORTED job exists (catches scheduler bugs that call cleanup too early).
    """
    if not authenticate_api_request(request):
        return web.HTTPUnauthorized(text="Authentication token received is invalid")

    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]

    job = export_jobs.get(vm_hash)
    if job is None or job.state != MigrationState.EXPORTED:
        return web.json_response(
            {"status": "error", "error": "No completed export to clean up"},
            status=HTTPStatus.CONFLICT,
        )

    if job.active_downloads > 0:
        return web.json_response(
            {"status": "error", "error": "Cannot clean up while disk download in progress"},
            status=HTTPStatus.CONFLICT,
        )

    try:
        if job.ttl_task is not None and not job.ttl_task.done():
            job.ttl_task.cancel()
        await pool.stop_vm(vm_hash)
        pool.forget_vm(vm_hash)
        for path in job.export_paths:
            try:
                Path(path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning("Failed to delete export file %s: %s", path, e)
        export_jobs.pop(vm_hash, None)

        return web.json_response({"status": "completed", "vm_hash": str(vm_hash)}, status=HTTPStatus.OK)

    except Exception as error:
        logger.exception("Cleanup failed for %s: %s", vm_hash, error)
        return web.json_response(
            {"status": "error", "error": f"Cleanup failed: {error}"},
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
