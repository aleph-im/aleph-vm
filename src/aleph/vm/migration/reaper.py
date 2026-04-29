"""Startup reaper for orphan cold-migration files."""

import logging
import shutil

from aleph.vm.conf import settings

logger = logging.getLogger(__name__)


async def reap_orphan_migration_files(pool) -> None:
    """Reap orphan export and partial-import files left behind by a prior supervisor run.

    On each <vm_hash> directory under PERSISTENT_VOLUMES_DIR:
      - Always delete *.qcow2.export.qcow2 (orphan exports — pool can't claim them).
      - If pool has no execution for this vm_hash AND the dir contains *.part files:
          → rmtree the directory (clear evidence of an aborted import).
      - If pool has no execution AND the dir has only completed .qcow2 files:
          → keep, log warning. A subsequent import retry can detect the existing files.
    """
    base = settings.PERSISTENT_VOLUMES_DIR
    if not base.exists():
        return

    # Pool keys may be strings or ItemHash objects; normalise to strings for matching.
    known = {str(k) for k in pool.executions}

    n_exports = 0
    n_dirs = 0

    for entry in base.iterdir():
        if not entry.is_dir():
            continue

        # Pass 1: orphan .export.qcow2 files always go.
        for export_file in entry.glob("*.qcow2.export.qcow2"):
            try:
                export_file.unlink()
                logger.info("Reaped orphan export file %s", export_file)
                n_exports += 1
            except Exception as e:
                logger.warning("Failed to delete orphan export %s: %s", export_file, e)

        # Pass 2: orphan dest dirs.
        if entry.name in known:
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
