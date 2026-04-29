"""Background coroutines that drive ExportJob and ImportJob to terminal state."""

import asyncio
import logging
import secrets
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path

import aiohttp
from aleph_message.models import MessageType
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.conf import settings
from aleph.vm.migration.helpers import (
    compress_disk,
    compute_sha256,
    detect_parent_format,
    download_disk_from_source,
    graceful_shutdown,
    rebase_overlay,
)
from aleph.vm.migration.jobs import (
    DiskFileInfo,
    ExportJob,
    ImportJob,
    export_jobs,
    get_migration_semaphore,
    import_jobs,
)
from aleph.vm.models import MigrationState, VmExecution
from aleph.vm.orchestrator.messages import load_updated_message
from aleph.vm.storage import get_rootfs_base_path

logger = logging.getLogger(__name__)

EXPORT_TTL_SECONDS = 1800  # 30 minutes — matches today's behaviour
IMPORT_TTL_SECONDS = 1800


async def _export_ttl_cleanup(job: ExportJob, timeout: int) -> None:
    """Background task: delete export files and forget the job after TTL."""
    try:
        await asyncio.sleep(timeout)
        logger.info("Export TTL expired for %s, cleaning up", job.vm_hash)
        for path in job.export_paths:
            try:
                Path(path).unlink(missing_ok=True)
            except Exception as e:
                logger.warning("Failed to delete export file %s: %s", path, e)
        export_jobs.pop(job.vm_hash, None)
    except asyncio.CancelledError:
        pass


def schedule_export_ttl(job: ExportJob, timeout: int) -> None:
    """Cancel any prior TTL task and schedule a fresh one."""
    if job.ttl_task is not None and not job.ttl_task.done():
        job.ttl_task.cancel()
    job.ttl_task = asyncio.create_task(_export_ttl_cleanup(job, timeout))


async def _run_export(
    job: ExportJob,
    execution: VmExecution,
    *,
    prior_task: asyncio.Task | None = None,
) -> None:
    """Drive an ExportJob from EXPORTING to a terminal state.

    Mutates the job in place. Never raises; failures are recorded on the job.

    prior_task: when this run replaces a FAILED slot, the previous task — wait
    for its cleanup (file unlink, VM restart) to finish before touching the VM.
    """
    if prior_task is not None and not prior_task.done():
        try:
            await asyncio.wait_for(asyncio.shield(prior_task), timeout=30)
        except asyncio.TimeoutError:
            logger.warning("Prior export task for %s did not finish within 30s; proceeding", job.vm_hash)
        except Exception as e:
            logger.debug("Prior export task for %s ended with error: %s", job.vm_hash, e)
    sem = get_migration_semaphore()
    export_paths: list[Path] = []
    async with sem:
        try:
            await graceful_shutdown(execution)

            namespace = execution.vm_hash
            volumes_dir = settings.PERSISTENT_VOLUMES_DIR / namespace
            job.volumes_dir = volumes_dir

            disk_files: list[DiskFileInfo] = []

            if volumes_dir.exists():
                for qcow2_file in sorted(volumes_dir.glob("*.qcow2")):
                    export_path = qcow2_file.with_suffix(".qcow2.export.qcow2")
                    await compress_disk(qcow2_file, export_path)
                    export_paths.append(export_path)
                    sha256 = await compute_sha256(export_path)
                    disk_files.append(
                        DiskFileInfo(
                            name=qcow2_file.name,
                            size_bytes=export_path.stat().st_size,
                            sha256=sha256,
                            download_path=f"/control/machine/{job.vm_hash}/migration/disk/{qcow2_file.name}",
                        )
                    )

            if not disk_files:
                msg = "No disk files found to export"
                raise RuntimeError(msg)

            job.export_paths = export_paths
            job.disk_files = disk_files
            job.token = secrets.token_urlsafe(32)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.EXPORTED
            try:
                schedule_export_ttl(job, EXPORT_TTL_SECONDS)
            except Exception as e:
                logger.warning("Failed to schedule TTL cleanup for %s: %s", job.vm_hash, e)

        except Exception as error:
            logger.exception("Export failed for %s: %s", job.vm_hash, error)
            job.error = str(error)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.EXPORT_FAILED

            for path in export_paths:
                try:
                    path.unlink(missing_ok=True)
                except Exception as e:
                    logger.warning("Failed to delete partial export %s: %s", path, e)

            try:
                if execution.systemd_manager:
                    await execution.systemd_manager.enable_and_start(execution.controller_service)
                    logger.info("Restarted VM %s after failed export", job.vm_hash)
            except Exception as restart_error:
                logger.error("Failed to restart VM %s after export failure: %s", job.vm_hash, restart_error)

            try:
                schedule_export_ttl(job, EXPORT_TTL_SECONDS)
            except Exception as e:
                logger.warning("Failed to schedule TTL cleanup for %s: %s", job.vm_hash, e)


async def _import_ttl_cleanup(job: ImportJob, timeout: int) -> None:
    """Background task: forget the import job after TTL."""
    try:
        await asyncio.sleep(timeout)
        import_jobs.pop(job.vm_hash, None)
    except asyncio.CancelledError:
        pass


def schedule_import_ttl(job: ImportJob, timeout: int) -> None:
    """Cancel any prior TTL task and schedule a fresh one for an import job."""
    if job.ttl_task is not None and not job.ttl_task.done():
        job.ttl_task.cancel()
    job.ttl_task = asyncio.create_task(_import_ttl_cleanup(job, timeout))


async def _run_import(
    job: ImportJob,
    pool,
    *,
    disk_files: list[DiskFileInfo],
    export_token: str,
    prior_task: asyncio.Task | None = None,
) -> None:
    """Drive an ImportJob from IMPORTING to a terminal state.

    Mutates the job in place. Never raises; failures are recorded on the job.

    prior_task: when this run replaces a FAILED slot, the previous task — wait
    for its dest-dir rmtree to finish before recreating the same path.
    """
    if prior_task is not None and not prior_task.done():
        try:
            await asyncio.wait_for(asyncio.shield(prior_task), timeout=30)
        except asyncio.TimeoutError:
            logger.warning("Prior import task for %s did not finish within 30s; proceeding", job.vm_hash)
        except Exception as e:
            logger.debug("Prior import task for %s ended with error: %s", job.vm_hash, e)
    sem = get_migration_semaphore()
    start = time.monotonic()
    async with sem:
        try:
            job.current_step = "fetching_message"
            message, original_message = await load_updated_message(job.vm_hash)

            if message.type != MessageType.instance:
                msg = "Message is not an instance"
                raise RuntimeError(msg)
            hypervisor = message.content.environment.hypervisor or HypervisorType.firecracker
            if hypervisor != HypervisorType.qemu:
                msg = "Migration only supported for QEMU instances"
                raise RuntimeError(msg)
            if message.content.environment.trusted_execution is not None:
                msg = "Migration not supported for confidential VMs"
                raise RuntimeError(msg)

            job.current_step = "downloading_parent"
            parent_ref = message.content.rootfs.parent.ref
            parent_path = await get_rootfs_base_path(parent_ref)
            parent_format = await detect_parent_format(parent_path)

            dest_dir = settings.PERSISTENT_VOLUMES_DIR / str(job.vm_hash)
            dest_dir.mkdir(parents=True, exist_ok=True)
            job.dest_dir = dest_dir
            job.total_bytes_expected = sum(df.size_bytes for df in disk_files)

            job.current_step = "downloading_disks"
            scheme = "https" if job.source_port == 443 else "http"
            base_url = f"{scheme}://{job.source_host}:{job.source_port}"

            # No total cap (transfers can be large), but require steady progress —
            # without this a hung peer leaves the import task running forever and
            # holding the migration semaphore slot.
            timeout = aiohttp.ClientTimeout(total=None, sock_connect=30, sock_read=300)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for disk_file in disk_files:
                    url = f"{base_url}{disk_file.download_path}"
                    dest_path = dest_dir / disk_file.name
                    job.downloaded_files.append(dest_path)
                    base_so_far = job.bytes_downloaded

                    def _progress(file_total: int, _b=base_so_far) -> None:
                        job.bytes_downloaded = _b + file_total

                    await download_disk_from_source(
                        session,
                        url,
                        dest_path,
                        export_token,
                        expected_sha256=disk_file.sha256,
                        on_chunk=_progress,
                    )

            job.current_step = "rebasing"
            for disk_file in disk_files:
                overlay_path = dest_dir / disk_file.name
                if not overlay_path.exists():
                    msg = f"Expected overlay {overlay_path} missing after download"
                    raise RuntimeError(msg)
                await rebase_overlay(overlay_path, parent_path, parent_format)

            job.current_step = "creating_vm"
            await pool.create_a_vm(
                vm_hash=job.vm_hash,
                message=message.content,
                original=original_message.content,
                persistent=True,
            )

            job.transfer_time_ms = int((time.monotonic() - start) * 1000)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.IMPORTED
            try:
                schedule_import_ttl(job, IMPORT_TTL_SECONDS)
            except Exception as e:
                logger.warning("Failed to schedule TTL cleanup for %s: %s", job.vm_hash, e)

        except Exception as error:
            logger.exception("Import failed for %s: %s", job.vm_hash, error)
            job.error = str(error)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.IMPORT_FAILED

            if job.dest_dir is not None and pool.executions.get(job.vm_hash) is None:
                shutil.rmtree(job.dest_dir, ignore_errors=True)
            try:
                schedule_import_ttl(job, IMPORT_TTL_SECONDS)
            except Exception as e:
                logger.warning("Failed to schedule TTL cleanup for %s: %s", job.vm_hash, e)
