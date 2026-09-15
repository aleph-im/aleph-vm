"""Startup reaper for orphan cold-migration export files."""

import logging

from aleph.vm.storage_pools import iter_namespace_dirs

logger = logging.getLogger(__name__)


async def reap_orphan_migration_files() -> None:
    """Delete the ``*.qcow2.export.qcow2`` files a prior agent run left behind.

    An export is staged by the agent for the destination node to download and
    is never reused, so at agent startup every one of them is an orphan.

    Nothing else is touched. A half-imported directory, with its ``.part``
    files, belongs to the storage reconciler: it runs after the registry is
    rehydrated, honours the create guard and the retention markers, and asks
    both the registry and the supervisor before it removes anything. This
    hook runs before all of that and used to remove such directories on the
    supervisor's word alone.
    """
    n_exports = 0
    for entry in iter_namespace_dirs():
        for export_file in entry.glob("*.qcow2.export.qcow2"):
            try:
                export_file.unlink()
                logger.info("Reaped orphan export file %s", export_file)
                n_exports += 1
            except Exception as e:
                logger.warning("Failed to delete orphan export %s: %s", export_file, e)
    logger.info("Migration reaper: removed %d orphan export files", n_exports)
