"""Hypervisor-agnostic VM host resources.

A VM's host resources (kernel image, root filesystem, extra volumes) are the
same concept whether the VM runs under Firecracker or QEMU. This module holds
that shared, message-agnostic surface. The hypervisor-specific resource classes
specialise it and own how (and whether) an Aleph message drives them:

- the Firecracker lineage always has a message (``message_content`` is required);
- the QEMU lineage may be built from a message *or* from a message-free
  ``CreateVmSpec`` (``message_content`` is optional).

Keeping the shared mechanics here lets those two lineages diverge on the
message contract without one inheriting the other's assumptions.
"""

import logging
from dataclasses import dataclass
from os.path import isfile
from pathlib import Path

from aleph_message.models import ExecutableContent
from aleph_message.models.execution.volume import MachineVolume, PersistentVolume

from aleph.vm.conf import settings
from aleph.vm.storage import get_volume_path

logger = logging.getLogger(__name__)


@dataclass
class HostVolume:
    mount: str
    path_on_host: Path
    read_only: bool
    size_mib: int | None


async def host_volumes_from_message(message_content: ExecutableContent, namespace: str) -> list[HostVolume]:
    """Resolve the extra (non-rootfs) volumes declared in a message to on-host paths."""
    volumes = []
    # TODO: Download in parallel and prevent duplicated volume names
    volume: MachineVolume
    for i, volume in enumerate(message_content.volumes):
        # only persistent volume has name and mount
        if isinstance(volume, PersistentVolume):
            if not volume.name:
                volume.name = f"unamed_volume_{i}"
            if not volume.mount:
                volume.mount = f"/mnt/{volume.name}"
        volumes.append(
            HostVolume(
                mount=volume.mount,
                path_on_host=(await get_volume_path(volume=volume, namespace=namespace)),
                read_only=volume.is_read_only(),
                size_mib=getattr(volume, "size_mib", None),
            )
        )
    return volumes


def disk_usage_delta(message_content: ExecutableContent | None, rootfs_path: Path, volumes: list[HostVolume]) -> int:
    """Difference between the size requested and what is currently used on disk.

    Counts rootfs and volumes. Used to estimate the disk resource available for
    use. Value is in bytes and is negative. A message-free resources holder
    (``message_content is None``) has no requested rootfs size, so only the
    already-resolved volumes contribute.
    """
    total_delta = 0
    # Root fs (only instances carry a rootfs in their message)
    if message_content is not None and hasattr(message_content, "rootfs"):
        volume = message_content.rootfs
        used_size = rootfs_path.stat().st_size if rootfs_path.exists() else 0
        requested_size = int(volume.size_mib * 1024 * 1024)
        total_delta += used_size - requested_size

    # Count each extra volume
    for host_volume in volumes:
        if not host_volume.size_mib:
            # planned size not set on immutable volume
            size_delta = 0
        else:
            used_size = host_volume.path_on_host.stat().st_size if host_volume.path_on_host.exists() else 0
            requested_size = int(host_volume.size_mib * 1024 * 1024)
            size_delta = used_size - requested_size
        total_delta += size_delta
    return total_delta


class VmResources:
    """Host resources any VM needs, independent of the hypervisor and of whether
    an Aleph message drives them.

    Hypervisor-specific subclasses add a ``message_content`` field (required for
    Firecracker, optional for QEMU) and their own download/build logic.
    """

    kernel_image_path: Path
    rootfs_path: Path
    volumes: list[HostVolume]
    namespace: str

    def __init__(self, namespace: str):
        self.namespace = namespace

    def to_dict(self):
        return self.__dict__

    async def download_kernel(self):
        # Assumes kernel is already present on the host
        self.kernel_image_path = Path(settings.LINUX_PATH)
        assert isfile(self.kernel_image_path)
