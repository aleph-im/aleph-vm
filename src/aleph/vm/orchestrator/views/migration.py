"""
Cold (stop/start) migration endpoints for VM migration between CRN hosts.

These endpoints are called by the scheduler to coordinate VM migration:
1. POST /control/machine/{ref}/migration/export - Stop VM on source, compress disks, serve for download
2. GET /control/machine/{ref}/migration/disk/{filename} - Download a compressed disk file
3. POST /control/migrate - Import a VM on the destination from source disk files
4. POST /control/machine/{ref}/migration/cleanup - Clean up source VM after successful migration
"""

import asyncio
import ipaddress
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

from aleph.vm.migration.jobs import (
    DiskFileInfo,
    ExportJob,
    ImportJob,
    export_jobs,
    import_jobs,
)
from aleph.vm.migration.runner import run_export, run_import
from aleph.vm.models import MigrationState, VmExecution
from aleph.vm.pool import VmPool
from aleph.vm.utils import cors_allow_all, create_task_log_exceptions, dumps_for_json

from . import requires_allocation_auth
from .operator import get_execution_or_404, get_itemhash_or_400

logger = logging.getLogger(__name__)


class ColdMigrationImportRequest(BaseModel):
    vm_hash: str
    source_host: str
    source_port: int = 443
    export_token: str
    disk_files: list[DiskFileInfo] = Field(..., min_length=1)

    @pydantic.field_validator("source_host")
    @classmethod
    def _reject_unsafe_hosts(cls, value: str) -> str:
        """Reject obvious SSRF targets at the request boundary.

        Hostnames are passed through untouched — full protection requires DNS
        resolution against a per-deployment CRN allow-list and belongs at a
        higher layer.
        """
        if not value:
            msg = "source_host must not be empty"
            raise ValueError(msg)
        if value.lower() in {"localhost", "localhost.localdomain"}:
            msg = "source_host cannot reference loopback"
            raise ValueError(msg)
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return value
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            msg = f"source_host {value} is not a routable address"
            raise ValueError(msg)
        return value


# --- Endpoints ---


@cors_allow_all
@requires_allocation_auth
async def migration_export(request: web.Request) -> web.Response:
    """POST /control/machine/{ref}/migration/export — start an async export job.

    Returns 202 immediately. Caller polls GET /export/status for progress.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]
    execution: VmExecution = get_execution_or_404(vm_hash, pool)

    if not execution.is_running:
        return web.json_response({"error": "VM is not running"}, status=HTTPStatus.BAD_REQUEST)
    if execution.hypervisor != HypervisorType.qemu:
        return web.json_response(
            {"error": "Migration only supported for QEMU instances"},
            status=HTTPStatus.BAD_REQUEST,
        )
    if execution.is_confidential:
        return web.json_response(
            {"error": "Migration is not supported for confidential VMs"},
            status=HTTPStatus.BAD_REQUEST,
        )

    # Read-modify-write of the registry below MUST stay await-free so two simultaneous
    # POSTs for the same vm_hash can't both pass the existence check. The prior task
    # (if any) is captured here and awaited inside run_export, not here.
    prior_task: asyncio.Task | None = None
    existing = export_jobs.get(vm_hash)
    if existing is not None:
        if existing.state == MigrationState.EXPORTING:
            return _export_job_descriptor_response(existing, status=HTTPStatus.ACCEPTED)
        if existing.state == MigrationState.EXPORT_FAILED:
            prior_task = existing.task
            _reset_failed_export(existing)
        else:
            return _export_job_descriptor_response(existing, status=HTTPStatus.CONFLICT)

    job = ExportJob(
        vm_hash=vm_hash,
        state=MigrationState.EXPORTING,
        started_at=datetime.now(timezone.utc),
    )
    export_jobs[vm_hash] = job
    job.task = create_task_log_exceptions(run_export(job, execution, prior_task=prior_task), name=f"export-{vm_hash}")

    return _export_job_descriptor_response(job, status=HTTPStatus.ACCEPTED)


def _reset_failed_export(job: ExportJob) -> None:
    """Clear an EXPORT_FAILED slot so the caller's retry can start fresh.

    Synchronous on purpose: the caller relies on this returning before yielding
    to the event loop so concurrent retry POSTs see the slot freed. The prior
    runner task is awaited later, inside the new run_export.
    """
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
@requires_allocation_auth
async def migration_export_status(request: web.Request) -> web.Response:
    """GET /control/machine/{ref}/migration/export/status — return live export job state."""
    vm_hash = get_itemhash_or_400(request.match_info)
    job = export_jobs.get(vm_hash)
    if job is None:
        return web.json_response({"error": "No export job"}, status=HTTPStatus.NOT_FOUND)

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
        # Sync read on the event loop would block the supervisor for the whole
        # transfer; offload each chunk to a worker thread.
        loop = asyncio.get_running_loop()
        with open(export_path, "rb") as f:
            while True:
                chunk = await loop.run_in_executor(None, f.read, 1024 * 1024)
                if not chunk:
                    break
                await response.write(chunk)
        await response.write_eof()
        return response
    finally:
        job.active_downloads -= 1


@cors_allow_all
@requires_allocation_auth
async def migration_import(request: web.Request) -> web.Response:
    """POST /control/migrate — start an async import job."""
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
            {"error": "VM already running on this host"},
            status=HTTPStatus.CONFLICT,
        )

    # Read-modify-write of the registry below MUST stay await-free so two simultaneous
    # POSTs for the same vm_hash can't both pass the existence check. The prior task
    # (if any) is captured here and awaited inside run_import, not here.
    prior_task: asyncio.Task | None = None
    existing = import_jobs.get(vm_hash)
    if existing is not None:
        if existing.state == MigrationState.IMPORTING:
            return _import_job_descriptor_response(existing, status=HTTPStatus.ACCEPTED)
        if existing.state == MigrationState.IMPORT_FAILED:
            prior_task = existing.task
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
        run_import(
            job,
            pool,
            disk_files=params.disk_files,
            export_token=params.export_token,
            prior_task=prior_task,
        ),
        name=f"import-{vm_hash}",
    )

    return _import_job_descriptor_response(job, status=HTTPStatus.ACCEPTED)


def _reset_failed_import(job: ImportJob, pool: VmPool) -> None:
    """Clear an IMPORT_FAILED slot so the caller's retry can start fresh.

    Synchronous on purpose: the caller relies on this returning before yielding
    to the event loop so concurrent retry POSTs see the slot freed. The prior
    runner task is awaited later, inside the new run_import. Mirrors the
    safety check in run_import's failure path: only rmtree if the pool has no
    execution.
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
@requires_allocation_auth
async def migration_import_status(request: web.Request) -> web.Response:
    """GET /control/migrate/{vm_hash}/status — return live import job state."""
    vm_hash = get_itemhash_or_400(request.match_info)

    job = import_jobs.get(vm_hash)
    if job is None:
        return web.json_response({"error": "No import job"}, status=HTTPStatus.NOT_FOUND)

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
@requires_allocation_auth
async def migration_cleanup(request: web.Request) -> web.Response:
    """POST /control/machine/{ref}/migration/cleanup — release source after dest reports IMPORTED.

    Refuses if no EXPORTED job exists (catches scheduler bugs that call cleanup too early).
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    pool: VmPool = request.app["vm_pool"]

    job = export_jobs.get(vm_hash)
    if job is None or job.state != MigrationState.EXPORTED:
        return web.json_response(
            {"error": "No completed export to clean up"},
            status=HTTPStatus.CONFLICT,
        )

    if job.active_downloads > 0:
        return web.json_response(
            {"error": "Cannot clean up while disk download in progress"},
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
            {"error": f"Cleanup failed: {error}"},
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
        )
