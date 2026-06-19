"""Neutral backup staging helpers shared by the agent and the supervisor.

The agent stages restore bytes (an upload or a downloaded volume) to a host
path, then hands the disk/VM work to the supervisor over the boundary; the
supervisor stores its backup archives in the same directory. These two helpers
are the shared, neutral surface (they touch only ``settings`` and
``aleph.vm.storage``), kept out of the QEMU backup controller so the agent does
not import ``aleph.vm.supervisor.controllers``.
"""

from pathlib import Path

from aleph.vm.conf import settings


def get_backup_directory() -> Path:
    """Return the directory used to store VM disk backups."""
    path = settings.BACKUP_DIRECTORY or (settings.EXECUTION_ROOT / "backups")
    path.mkdir(parents=True, exist_ok=True)
    return path


async def download_volume_by_ref(
    item_hash: str,
    destination: Path,
) -> Path:
    """Download a volume from the aleph network by item hash.

    Args:
        item_hash: The aleph message item hash of the volume.
        destination: Directory to save the downloaded file.

    Returns:
        Path to the downloaded file.
    """
    from aleph.vm.storage import _get_content_url, download_file

    dest_path = destination / f"{item_hash}.qcow2"
    url = await _get_content_url(item_hash)
    await download_file(url, dest_path)
    return dest_path
