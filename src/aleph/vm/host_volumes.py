"""Shared host-volume types, neutral between the agent and the supervisor.

A VM's extra (non-rootfs) volumes resolve to on-host paths the same way whether
the VM runs under Firecracker or QEMU, and whether the resolution happens
agent-side (download from an Aleph message) or supervisor-side (a message-free
``CreateVmSpec``). This module holds that shared vocabulary so neither side has
to import the other's package: it depends only on stdlib, ``aleph_message`` and
``aleph.vm.storage``.
"""

from dataclasses import dataclass
from pathlib import Path

from aleph_message.models import ExecutableContent
from aleph_message.models.execution.volume import MachineVolume, PersistentVolume

from aleph.vm.storage import get_volume_path


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
