"""Background coroutines that drive ExportJob and ImportJob to terminal state."""

import asyncio
import logging
import secrets
import shutil
import time
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

import aiohttp
from aleph_message.models import MessageType
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.agent.capacity import CapacityManager, requested_gpu_ids
from aleph.vm.agent.messages import load_updated_message
from aleph.vm.agent.migration.helpers import (
    compress_disk,
    compute_sha256,
    detect_parent_format,
    download_disk_from_source,
    rebase_overlay,
)
from aleph.vm.agent.migration.jobs import (
    DiskFileInfo,
    ExportJob,
    ImportJob,
    MigrationState,
    export_jobs,
    get_migration_semaphore,
    import_jobs,
)
from aleph.vm.agent.run import finish_instance_create
from aleph.vm.agent.translate import build_create_vm_spec
from aleph.vm.conf import settings
from aleph.vm.storage import get_rootfs_base_path
from aleph.vm.storage_pools import iter_namespace_dirs, select_pool
from aleph.vm.supervisor_interface.errors import VmNotFoundError

if TYPE_CHECKING:
    from aleph.vm.supervisor_interface.abc import Supervisor

logger = logging.getLogger(__name__)

EXPORT_TTL_SECONDS = 1800  # 30 minutes — matches today's behaviour
IMPORT_TTL_SECONDS = 1800


def _collect_export_disks(vm_hash: str) -> list[Path]:
    """The qcow2 files to export for a VM, one per basename across all pools.

    A basename can legitimately appear in several pools (e.g. a complete
    orphan preserved by the reaper after a failed import, plus a retried
    staging in another pool). The boot-time volume lookup resolves such
    duplicates to the lowest-index pool's copy, so export must ship exactly
    that copy: duplicates from higher-index pools are skipped with a warning.
    """
    disks: list[Path] = []
    seen_names: set[str] = set()
    for volumes_dir in iter_namespace_dirs(vm_hash):
        for qcow2_file in sorted(volumes_dir.glob("*.qcow2")):
            if qcow2_file.name.endswith(".export.qcow2"):
                # A stale export artifact from an earlier failed run: the
                # reaper only sweeps at startup, so a retry without an agent
                # restart would otherwise collect it as a source disk and
                # re-export an export.
                continue
            if qcow2_file.name in seen_names:
                logger.warning(
                    "Volume %s for %s found in multiple pools; exporting the copy from %s",
                    qcow2_file.name,
                    vm_hash,
                    next(disk.parent for disk in disks if disk.name == qcow2_file.name),
                )
                continue
            seen_names.add(qcow2_file.name)
            disks.append(qcow2_file)
    return disks


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
    """Cancel any prior TTL task and schedule a fresh one. Logs and swallows failures."""
    try:
        if job.ttl_task is not None and not job.ttl_task.done():
            job.ttl_task.cancel()
        job.ttl_task = asyncio.create_task(_export_ttl_cleanup(job, timeout))
    except Exception as e:
        logger.warning("Failed to schedule TTL cleanup for %s: %s", job.vm_hash, e)


async def run_export(
    job: ExportJob,
    supervisor: "Supervisor",
    *,
    prior_task: asyncio.Task | None = None,
) -> None:
    """Drive an ExportJob from EXPORTING to a terminal state.

    Mutates the job in place. Never raises; failures are recorded on the job.

    The supervisor owns the disk/VM work: it stops the VM and reports its
    persistent-volumes directory; this runner owns the network transport,
    compressing and serving the disk files it finds there.

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
            # stop_vm already performs a graceful, disk-quiescing powerdown: it
            # stops the controller unit and blocks (wait_for_controller_stopped)
            # until the controller's SIGTERM handler has ACPI-powered the guest
            # down and QMP-quit QEMU with a cache flush. The exported overlay is
            # therefore consistent once stop_vm returns; no separate graceful
            # step is needed. The volumes dir is the same settings-derived path
            # the import runner stages into.
            await supervisor.stop_vm(job.vm_hash)
            # A VM's volumes may span pools (each volume is placed
            # independently); export from every namespace dir, one copy per
            # basename (lowest-index pool wins, like the boot-time lookup).
            volume_dirs = list(iter_namespace_dirs(str(job.vm_hash)))
            job.volumes_dir = volume_dirs[0] if volume_dirs else None

            disk_files: list[DiskFileInfo] = []

            for qcow2_file in _collect_export_disks(str(job.vm_hash)):
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
            schedule_export_ttl(job, EXPORT_TTL_SECONDS)

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
                # The VM is not leaving after all; bring it back through the
                # standard lifecycle RPC. Best-effort: if the VM is already
                # gone, start_vm raises and we log it.
                await supervisor.start_vm(job.vm_hash)
                logger.info("Restarted VM %s after failed export", job.vm_hash)
            except Exception as restart_error:
                logger.error("Failed to restart VM %s after export failure: %s", job.vm_hash, restart_error)

            schedule_export_ttl(job, EXPORT_TTL_SECONDS)


async def _import_ttl_cleanup(job: ImportJob, timeout: int) -> None:
    """Background task: forget the import job after TTL."""
    try:
        await asyncio.sleep(timeout)
        import_jobs.pop(job.vm_hash, None)
    except asyncio.CancelledError:
        pass


def schedule_import_ttl(job: ImportJob, timeout: int) -> None:
    """Cancel any prior TTL task and schedule a fresh one. Logs and swallows failures."""
    try:
        if job.ttl_task is not None and not job.ttl_task.done():
            job.ttl_task.cancel()
        job.ttl_task = asyncio.create_task(_import_ttl_cleanup(job, timeout))
    except Exception as e:
        logger.warning("Failed to schedule TTL cleanup for %s: %s", job.vm_hash, e)


async def run_import(
    job: ImportJob,
    supervisor: "Supervisor",
    *,
    capacity: CapacityManager,
    disk_files: list[DiskFileInfo],
    export_token: str,
    prior_task: asyncio.Task | None = None,
) -> None:
    """Drive an ImportJob from IMPORTING to a terminal state.

    Mutates the job in place. Never raises; failures are recorded on the job.

    This runner owns the network transport (message fetch, parent download,
    disk download, overlay rebase) and staging, then drives the standard
    create_vm RPC with a spec built from the fetched message; the supervisor
    owns the create-and-boot step and answers whether the VM already exists.

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
            message, _original_message = await load_updated_message(job.vm_hash)

            if message.type != MessageType.instance:
                msg = "Message is not an instance"
                raise RuntimeError(msg)
            # Resolve the hypervisor exactly as the create path does
            # (translate.build_create_vm_spec): an instance message that omits
            # the field (the CLI never sets it) falls back to
            # INSTANCE_DEFAULT_HYPERVISOR, which is QEMU. A hardcoded Firecracker
            # fallback here rejected every default instance before create_vm,
            # so migrated VMs never booted on the destination.
            hypervisor = message.content.environment.hypervisor or settings.INSTANCE_DEFAULT_HYPERVISOR
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

            # Stage onto the pool with the most room for the whole transfer;
            # build_create_vm_spec later adopts the staged overlay wherever it
            # is (the downloader's volume lookup scans every pool).
            incoming_mib = sum(df.size_bytes for df in disk_files) // (1024 * 1024)
            dest_dir = select_pool(incoming_mib).path / str(job.vm_hash)
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
            # The standard instance-create path: build the same spec a normal
            # persistent-instance create uses (run.create_vm_execution ->
            # build_create_vm_spec). The spec's rootfs path resolves through
            # the pool-aware volume lookup, which finds the overlay exactly
            # where the download+rebase staged it, and build_create_vm_spec
            # adopts an already-present host-persistence overlay rather than
            # recreating it, so create_vm reuses the staged disk (no
            # re-download).
            spec = await build_create_vm_spec(job.vm_hash, message.content)
            # Same agent-side admission as the normal create: bucket from the
            # message type, GPU requests resolved to concrete host cards on
            # this destination (owner = message.address).
            capacity.check_capacity(
                memory_mib=message.content.resources.memory,
                vcpus=message.content.resources.vcpus,
                disk_mib=0,
                is_instance=True,
                exclude_vm_hash=job.vm_hash,
            )
            requested_gpus = requested_gpu_ids(message.content)
            if requested_gpus:
                resolved_gpus = await capacity.resolve_gpus(requested_gpus, owner=message.content.address)
                spec = replace(spec, gpus=resolved_gpus)
            await supervisor.create_vm(spec)

            # A fresh destination has no persisted port mappings, and
            # create_vm_from_spec only reloads those - it never applies the
            # agent's port-forwarding policy. Run the same post-create tail the
            # normal create path runs so the migrated instance gets its SSH (and
            # any aggregate) host port forwards; without this mapped_ports stays
            # empty and the VM is unreachable on the new CRN.
            job.current_step = "port_forwards"
            await finish_instance_create(supervisor, spec.vm_id, message.content)

            job.transfer_time_ms = int((time.monotonic() - start) * 1000)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.IMPORTED
            schedule_import_ttl(job, IMPORT_TTL_SECONDS)

        except Exception as error:
            logger.exception("Import failed for %s: %s", job.vm_hash, error)
            job.error = str(error)
            job.finished_at = datetime.now(timezone.utc)
            job.state = MigrationState.IMPORT_FAILED

            if job.dest_dir is not None and not await _vm_exists(supervisor, job.vm_hash):
                shutil.rmtree(job.dest_dir, ignore_errors=True)
            schedule_import_ttl(job, IMPORT_TTL_SECONDS)


async def _vm_exists(supervisor: "Supervisor", vm_hash) -> bool:
    """Whether the supervisor holds a VM for this hash. Absence (the create
    step never ran, or never registered the VM) means the dest dir is safe to
    rmtree; presence means the import created it and the disks are in use."""
    try:
        await supervisor.get_vm(vm_hash)
        return True
    except VmNotFoundError:
        return False
