"""Agent-side resource downloaders.

The create path resolves an Aleph message's resources (rootfs, code, runtime,
data, extra volumes, firmware) into on-host paths *agent-side*, before the
Supervisor boundary. The supervisor then boots from the resolved paths carried
on the ``CreateVmSpec`` and never downloads.

These downloaders *compose* the host-resource surface (they hold the
``message_content`` and expose ``rootfs_path`` / ``volumes`` / the program code
fields ``translate.py`` and ``program_client`` read); they deliberately do NOT
subclass the supervisor's ``VmResources`` controller classes, which is what
keeps the agent free of an ``aleph.vm.supervisor.controllers`` import.

They raise the neutral contract vocabulary
(``aleph.vm.supervisor_interface.errors``), not the controller exception
classes.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from os.path import isfile
from pathlib import Path

from aiohttp import ClientResponseError
from aleph_message.models import InstanceContent, ProgramContent
from aleph_message.models.execution.instance import RootfsVolume
from aleph_message.models.execution.volume import PersistentVolume, VolumePersistence

from aleph.vm.conf import settings
from aleph.vm.host_volumes import HostVolume, host_volumes_from_message
from aleph.vm.program_config import Interface
from aleph.vm.storage import (
    get_code_path,
    get_data_path,
    get_rootfs_base_path,
    get_runtime_path,
)
from aleph.vm.supervisor_interface.errors import ResourceDownloadError, VmSetupError
from aleph.vm.utils import run_in_subprocess


async def _make_writable_volume(
    parent_image_path: Path,
    volume: PersistentVolume | RootfsVolume,
    namespace: str,
) -> Path:
    """Create a new qcow2 image file based on the passed one, that we give to the VM to write onto."""
    qemu_img_path: str | None = shutil.which("qemu-img")
    if not qemu_img_path:
        msg = "qemu-img not found in PATH"
        raise VmSetupError(msg)

    volume_name = volume.name if isinstance(volume, PersistentVolume) else "rootfs"

    # detect the image format
    out_json = await run_in_subprocess([qemu_img_path, "info", str(parent_image_path), "--output=json"])
    out = json.loads(out_json)
    parent_format = out.get("format", None)
    if parent_format is None:
        msg = f"Failed to detect format for {volume}: {out_json}"
        raise VmSetupError(msg)
    if parent_format not in ("qcow2", "raw"):
        msg = f"Format {parent_format} for {volume} unhandled by QEMU hypervisor"
        raise VmSetupError(msg)

    dest_path = settings.PERSISTENT_VOLUMES_DIR / namespace / f"{volume_name}.qcow2"
    # Do not override if user asked for host persistence.
    if dest_path.exists() and volume.persistence == VolumePersistence.host:
        return dest_path

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    size_in_bytes = int(volume.size_mib * 1024 * 1024)

    await run_in_subprocess(
        [
            qemu_img_path,
            "create",
            "-f",  # Format
            "qcow2",
            "-F",
            parent_format,
            "-b",
            str(parent_image_path),
            str(dest_path),
            str(size_in_bytes),
        ]
    )
    return dest_path


class QemuDownloader:
    """Resolve a QEMU instance message's resources to on-host paths."""

    message_content: InstanceContent
    namespace: str
    rootfs_path: Path
    volumes: list[HostVolume]

    def __init__(self, message_content: InstanceContent, namespace: str):
        self.message_content = message_content
        self.namespace = namespace
        self.volumes = []

    async def make_writable_volume(self, parent_image_path: Path, volume: PersistentVolume | RootfsVolume) -> Path:
        return await _make_writable_volume(parent_image_path, volume, self.namespace)

    async def download_runtime(self) -> None:
        volume = self.message_content.rootfs
        parent_image_path = await get_rootfs_base_path(volume.parent.ref)
        self.rootfs_path = await self.make_writable_volume(parent_image_path, volume)

    async def download_volumes(self) -> None:
        self.volumes = await host_volumes_from_message(self.message_content, self.namespace)

    async def download_all(self) -> None:
        await asyncio.gather(
            self.download_runtime(),
            self.download_volumes(),
        )


class ProgramDownloader:
    """Resolve a Firecracker program message's resources to on-host paths.

    Exposes the fields ``translate.py`` (rootfs/kernel/code/volumes) and the
    agent program client (code_*/data_path/volumes) read.
    """

    message_content: ProgramContent
    namespace: str
    kernel_image_path: Path
    rootfs_path: Path
    volumes: list[HostVolume]
    code_path: Path
    code_entrypoint: str
    code_interface: Interface
    data_path: Path | None

    def __init__(self, message_content: ProgramContent, namespace: str):
        self.message_content = message_content
        self.namespace = namespace
        self.volumes = []
        self.code_encoding = message_content.code.encoding
        self.code_entrypoint = message_content.code.entrypoint
        self.code_interface = Interface.from_entrypoint(
            entrypoint=message_content.code.entrypoint,
            interface_hint=message_content.code.interface,
        )

    async def download_kernel(self) -> None:
        # Assumes kernel is already present on the host
        self.kernel_image_path = Path(settings.LINUX_PATH)
        assert isfile(self.kernel_image_path)

    async def download_code(self) -> None:
        code_ref: str = self.message_content.code.ref
        try:
            self.code_path = await get_code_path(code_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(str(error)) from error
        assert self.code_path.is_file(), f"Code not found on '{self.code_path}'"

    async def download_runtime(self) -> None:
        runtime_ref: str = self.message_content.runtime.ref
        try:
            self.rootfs_path = await get_runtime_path(runtime_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(str(error)) from error
        assert self.rootfs_path.is_file(), f"Runtime not found on {self.rootfs_path}"

    async def download_volumes(self) -> None:
        self.volumes = await host_volumes_from_message(self.message_content, self.namespace)

    async def download_data(self) -> None:
        if self.message_content.data:
            data_ref: str = self.message_content.data.ref
            try:
                data_path = await get_data_path(data_ref)
                self.data_path = data_path
            except ClientResponseError as error:
                raise ResourceDownloadError(str(error)) from error
            assert data_path.is_file(), f"Data not found on {data_path}"
        else:
            self.data_path = None

    async def download_all(self) -> None:
        await asyncio.gather(
            self.download_kernel(),
            self.download_runtime(),
            self.download_code(),
            self.download_volumes(),
            self.download_data(),
        )
