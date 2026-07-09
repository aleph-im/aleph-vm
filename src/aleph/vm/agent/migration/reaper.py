"""Startup reaper for orphan cold-migration files."""

import logging
import shutil

from aleph.vm.storage_pools import iter_namespace_dirs

logger = logging.getLogger(__name__)


async def reap_orphan_migration_files(known_vm_ids: set[str]) -> None:
    """Reap orphan export and partial-import files left behind by a prior agent run.

    Cold migration is agent-side: the agent stages the disk (the ``.part``
    download and the ``.export.qcow2`` export) before asking the supervisor to
    CreateVm, so this cleanup is owned by the agent. ``known_vm_ids`` is the set
    of VMs the supervisor currently holds (from ``list_vms``); it is used only to
    avoid touching a live VM's volume directory. Run at agent startup, where the
    agent's own in-flight imports do not yet exist, so any ``.part`` is genuinely
    an aborted prior run.

    On each <vm_hash> directory in every volume pool:
      - Always delete *.qcow2.export.qcow2 (orphan exports — never reused).
      - If the vm_hash is not a known live VM AND the dir contains *.part files:
          → rmtree the directory (clear evidence of an aborted import).
      - If not known AND the dir has only completed .qcow2 files:
          → keep, log warning. A subsequent import retry can detect the existing files.
    """
    n_exports = 0
    n_dirs = 0

    for entry in iter_namespace_dirs():
        # Pass 1: orphan .export.qcow2 files always go.
        for export_file in entry.glob("*.qcow2.export.qcow2"):
            try:
                export_file.unlink()
                logger.info("Reaped orphan export file %s", export_file)
                n_exports += 1
            except Exception as e:
                logger.warning("Failed to delete orphan export %s: %s", export_file, e)

        # Pass 2: orphan dest dirs.
        if entry.name in known_vm_ids:
            continue

        part_files = list(entry.glob("*.part"))
        if part_files:
            try:
                shutil.rmtree(entry)
                logger.info("Reaped orphan import dir %s (had %d .part files)", entry, len(part_files))
                n_dirs += 1
            except Exception as e:
                logger.warning("Failed to reap orphan dir %s: %s", entry, e)
        else:
            qcow_files = list(entry.glob("*.qcow2"))
            if qcow_files:
                logger.warning(
                    "Found orphan complete volumes dir %s with %d qcow2 files; leaving in place",
                    entry,
                    len(qcow_files),
                )

    logger.info("Migration reaper: removed %d orphan export files, %d orphan import dirs", n_exports, n_dirs)
