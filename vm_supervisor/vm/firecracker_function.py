import asyncio
import dataclasses
import logging
import os.path
from dataclasses import dataclass, field
from multiprocessing import Process, set_start_method
from os.path import isfile
from pathlib import Path
from typing import Dict, List, Optional

import msgpack

try:
    import psutil as psutil
except ImportError:
    psutil = None
from aiohttp import ClientResponseError
from aleph_message.models.execution.base import Encoding
from aleph_message.models.execution.environment import MachineResources

from firecracker.config import (
    BootSource,
    Drive,
    FirecrackerConfig,
    MachineConfig,
    NetworkInterface,
    Vsock,
)
from firecracker.microvm import MicroVM, setfacl

from .firecracker_microvm import AlephFirecrackerVM, AlephFirecrackerResources, VmSetupError, VmInitNotConnected, \
    Interface, Volume
from ..conf import settings
from ..models import ExecutableContent
from ..network.interfaces import TapInterface
from ..storage import get_code_path, get_data_path, get_runtime_path

logger = logging.getLogger(__name__)
set_start_method("spawn")


def load_file_content(path: Path) -> bytes:
    if path:
        with open(path, "rb") as fd:
            return fd.read()
    else:
        return b""


class FileTooLargeError(Exception):
    pass


class ResourceDownloadError(ClientResponseError):
    """An error occurred while downloading a VM resource file"""

    def __init__(self, error: ClientResponseError):
        super().__init__(
            request_info=error.request_info,
            history=error.history,
            status=error.status,
            message=error.message,
            headers=error.headers,
        )


@dataclass
class ConfigurationPayload:
    input_data: bytes
    interface: Interface
    vm_hash: str
    code: Optional[bytes] = None
    encoding: Optional[Encoding] = None
    entrypoint: Optional[str] = None
    ip: Optional[str] = None
    route: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    volumes: List[Volume] = field(default_factory=list)
    variables: Optional[Dict[str, str]] = None

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


@dataclass
class ConfigurationResponse:
    success: bool
    error: Optional[str] = None
    traceback: Optional[str] = None


@dataclass
class RunCodePayload:
    scope: Dict

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


class AlephFunctionResources(AlephFirecrackerResources):

    code_path: Path
    code_encoding: Encoding
    code_entrypoint: str
    data_path: Optional[Path]

    def __init__(self, message_content: ExecutableContent, namespace: str):
        super().__init__(message_content, namespace)
        if hasattr(message_content, "code"):
            self.code_encoding = message_content.code.encoding
            self.code_entrypoint = message_content.code.entrypoint
        else:
            self.code_path = None
            self.code_encoding = None
            self.code_entrypoint = None

    async def download_code(self):
        code_ref: str = self.message_content.code.ref
        try:
            self.code_path = await get_code_path(code_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert isfile(self.code_path), f"Code not found on '{self.code_path}'"

    async def download_runtime(self):
        runtime_ref: str = self.message_content.runtime.ref
        try:
            self.rootfs_path = await get_runtime_path(runtime_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert isfile(self.rootfs_path), f"Runtime not found on {self.rootfs_path}"

    async def download_data(self):
        if self.message_content.data:
            data_ref: str = self.message_content.data.ref
            try:
                self.data_path = await get_data_path(data_ref)
            except ClientResponseError as error:
                raise ResourceDownloadError(error)
            assert isfile(self.data_path)

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_runtime(),
            self.download_code(),
            self.download_volumes(),
            self.download_data(),
        )


class AlephFirecrackerFunction(AlephFirecrackerVM):
    vm_id: int
    vm_hash: str
    resources: AlephFunctionResources
    enable_console: bool
    enable_networking: bool
    is_instance: bool
    hardware_resources: MachineResources
    fvm: Optional[MicroVM] = None
    guest_api_process: Optional[Process] = None
    tap_interface: Optional[TapInterface] = None

    def __init__(
        self,
        vm_id: int,
        vm_hash: str,
        resources: AlephFunctionResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: Optional[TapInterface] = None
    ):
        super().__init__(vm_id, vm_hash, resources, enable_networking, enable_console, hardware_resources, tap_interface)
        self.is_instance = False

    async def setup(self):
        logger.debug("setup started")
        await setfacl()

        config = FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(
                    self.fvm.enable_kernel(self.resources.kernel_image_path)
                ),
                boot_args=BootSource.args(enable_console=self.enable_console, writable=self.is_instance),
            ),
            drives=[
                Drive(
                    drive_id="rootfs",
                    path_on_host=self.fvm.enable_rootfs(self.resources.rootfs_path),
                    is_root_device=True,
                    is_read_only=True,
                ),
            ]
            + (
                [self.fvm.enable_drive(self.resources.code_path)]
                if hasattr(self.resources, "code_encoding") and self.resources.code_encoding == Encoding.squashfs
                else []
            )
            + [
                self.fvm.enable_drive(volume.path_on_host, read_only=volume.read_only)
                for volume in self.resources.volumes
            ],
            machine_config=MachineConfig(
                vcpu_count=self.hardware_resources.vcpus,
                mem_size_mib=self.hardware_resources.memory,
            ),
            vsock=Vsock(),
            network_interfaces=[
                NetworkInterface(
                    iface_id="eth0", host_dev_name=self.tap_interface.device_name
                )
            ]
            if self.enable_networking
            else [],
        )

        await super().setup(config)

    async def configure(self):
        """Configure the VM by sending configuration info to it's init"""

        if (
            hasattr(self.resources, "data_path") and self.resources.data_path
            and os.path.getsize(self.resources.data_path)
            > settings.MAX_DATA_ARCHIVE_SIZE
        ):
            raise FileTooLargeError(f"Data file too large to pass as an inline zip")

        input_data: bytes = load_file_content(self.resources.data_path) if \
            hasattr(self.resources, "data_path") else None

        interface = Interface.asgi

        volumes: List[Volume]
        if self.resources.code_encoding == Encoding.squashfs:
            code = b""
            volumes = [Volume(mount="/opt/code", device="vdb", read_only=True)] + [
                Volume(
                    mount=volume.mount,
                    device=self.fvm.drives[index + 1].drive_id,
                    read_only=volume.read_only,
                )
                for index, volume in enumerate(self.resources.volumes)
            ]
        else:
            if (
                hasattr(self.resources, "data_path") and self.resources.data_path
                and os.path.getsize(self.resources.code_path)
                > settings.MAX_PROGRAM_ARCHIVE_SIZE
            ):
                raise FileTooLargeError(
                    f"Program file too large to pass as an inline zip"
                )

            code: Optional[bytes] = load_file_content(self.resources.code_path) if self.resources.code_path else None
            volumes = [
                Volume(
                    mount=volume.mount,
                    device=self.fvm.drives[index].drive_id,
                    read_only=volume.read_only,
                )
                for index, volume in enumerate(self.resources.volumes)
            ]

        await super().configure(volumes, interface)
        reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)

        # The ip and route should not contain the network mask in order to maintain
        # compatibility with the existing runtimes.
        ip = self.tap_interface.guest_ip.with_prefixlen.split("/", 1)[0]
        route = str(self.tap_interface.host_ip).split("/", 1)[0]

        config = ConfigurationPayload(
            ip=ip if self.enable_networking else None,
            route=route if self.enable_networking else None,
            dns_servers=settings.DNS_NAMESERVERS,
            code=code,
            encoding=self.resources.code_encoding,
            entrypoint=self.resources.code_entrypoint,
            input_data=input_data,
            interface=interface,
            vm_hash=self.vm_hash,
            volumes=volumes,
            variables=self.resources.message_content.variables,
        )
        payload = config.as_msgpack()
        length = f"{len(payload)}\n".encode()
        writer.write(b"CONNECT 52\n" + length + payload)
        await writer.drain()

        await reader.readline()  # Ignore the acknowledgement from the socket
        response_raw = await reader.read(1000_000)
        response = ConfigurationResponse(**msgpack.loads(response_raw, raw=False))
        if response.success is False:
            logger.exception(response.traceback)
            raise VmSetupError(response.error)

    async def run_code(
        self,
        scope: Optional[dict] = None,
    ):
        if not self.fvm:
            raise ValueError("MicroVM must be created first")
        logger.debug("running code")
        scope = scope or {}

        async def communicate(reader, writer, scope):
            payload = RunCodePayload(scope=scope)

            writer.write(b"CONNECT 52\n" + payload.as_msgpack())
            await writer.drain()

            ack: bytes = await reader.readline()
            logger.debug(f"ack={ack.decode()}")

            logger.debug("waiting for VM response")
            response: bytes = await reader.read()

            return response

        try:
            reader, writer = await asyncio.open_unix_connection(
                path=self.fvm.vsock_path
            )
        except ConnectionRefusedError:
            raise VmInitNotConnected("MicroVM may have crashed")
        try:
            return await asyncio.wait_for(
                communicate(reader, writer, scope),
                timeout=self.hardware_resources.seconds,
            )
        finally:
            logger.debug("Cleaning VM socket resources")
            writer.close()
            await writer.wait_closed()
