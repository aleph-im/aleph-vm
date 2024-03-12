import asyncio
import dataclasses
import logging
import os.path
from dataclasses import dataclass, field
from enum import Enum
from multiprocessing import set_start_method
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import msgpack
from aleph_message.models import ItemHash

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
from firecracker.microvm import setfacl

from ..conf import settings
from ..models import ExecutableContent
from ..network.interfaces import TapInterface
from ..storage import get_code_path, get_data_path, get_runtime_path
from .firecracker_executable import (
    AlephFirecrackerExecutable,
    AlephFirecrackerResources,
    VmInitNotConnected,
    VmSetupError,
    Volume,
)

logger = logging.getLogger(__name__)
set_start_method("spawn")


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


def read_input_data(path_to_data: Path) -> Optional[bytes]:
    if not path_to_data:
        return None

    if os.path.getsize(path_to_data) > settings.MAX_DATA_ARCHIVE_SIZE:
        raise FileTooLargeError(f"Data file too large to pass as an inline zip")

    return path_to_data.read_bytes()


class Interface(str, Enum):
    asgi = "asgi"
    executable = "executable"

    @classmethod
    def from_entrypoint(cls, entrypoint: str):
        """Determine the interface type (Python ASGI or executable HTTP service) from the entrypoint of the program."""
        # Only Python ASGI entrypoints contain a column `:` in their name.
        # We use this to differentiate Python ASGI programs from executable HTTP service mode.
        if ":" in entrypoint:
            return cls.asgi
        else:
            return cls.executable


@dataclass
class ConfigurationPayload:
    """Configuration passed to the init of the virtual machine in order to start the program."""

    input_data: bytes
    interface: Interface
    vm_hash: str
    code: bytes = None
    encoding: Encoding = None
    entrypoint: str = None
    ip: Optional[str] = None
    route: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    volumes: List[Volume] = field(default_factory=list)
    variables: Optional[Dict[str, str]] = None

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


@dataclass
class ConfigurationResponse:
    """Response received from the virtual machine in response to a request."""

    success: bool
    error: Optional[str] = None
    traceback: Optional[str] = None


@dataclass
class RunCodePayload:
    """Information passed to the init of the virtual machine to launch a function/path of the program."""

    scope: Dict

    def as_msgpack(self) -> bytes:
        return msgpack.dumps(dataclasses.asdict(self), use_bin_type=True)


class AlephProgramResources(AlephFirecrackerResources):
    """Resources required by the virtual machine in order to launch the program.
    Extends the resources required by all Firecracker VMs."""

    code_path: Path
    code_encoding: Encoding
    code_entrypoint: str
    data_path: Optional[Path]

    def __init__(self, message_content: ExecutableContent, namespace: str):
        super().__init__(message_content, namespace)
        self.code_encoding = message_content.code.encoding
        self.code_entrypoint = message_content.code.entrypoint

    async def download_code(self):
        code_ref: str = self.message_content.code.ref
        try:
            self.code_path = await get_code_path(code_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert self.code_path.is_file(), f"Code not found on '{self.code_path}'"

    async def download_runtime(self):
        runtime_ref: str = self.message_content.runtime.ref
        try:
            self.rootfs_path = await get_runtime_path(runtime_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert self.rootfs_path.is_file(), f"Runtime not found on {self.rootfs_path}"

    async def download_data(self):
        if self.message_content.data:
            data_ref: str = self.message_content.data.ref
            try:
                self.data_path = await get_data_path(data_ref)
            except ClientResponseError as error:
                raise ResourceDownloadError(error)
            assert self.data_path.is_file(), f"Data nout found on {self.data_path}"

    async def download_all(self):
        await asyncio.gather(
            self.download_kernel(),
            self.download_runtime(),
            self.download_code(),
            self.download_volumes(),
            self.download_data(),
        )


def get_volumes_for_program(
    resources: AlephProgramResources, drives: List[Drive]
) -> Tuple[Optional[bytes], List[Volume]]:
    if resources.code_encoding == Encoding.squashfs:
        code = b""
        volumes = [Volume(mount="/opt/code", device="vdb", read_only=True)] + [
            Volume(
                mount=volume.mount,
                device=drives[index + 1].drive_id,
                read_only=volume.read_only,
            )
            for index, volume in enumerate(resources.volumes)
        ]
    else:
        if os.path.getsize(resources.code_path) > settings.MAX_PROGRAM_ARCHIVE_SIZE:
            raise FileTooLargeError(f"Program file too large to pass as an inline zip")

        code: Optional[bytes] = (
            resources.code_path.read_bytes() if resources.code_path else None
        )
        volumes = [
            Volume(
                mount=volume.mount,
                device=drives[index].drive_id,
                read_only=volume.read_only,
            )
            for index, volume in enumerate(resources.volumes)
        ]
    return code, volumes


class AlephFirecrackerProgram(AlephFirecrackerExecutable):
    resources: AlephProgramResources
    is_instance = False

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephProgramResources,
        enable_networking: bool = False,
        enable_console: Optional[bool] = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: Optional[TapInterface] = None,
    ):
        super().__init__(
            vm_id,
            vm_hash,
            resources,
            enable_networking,
            enable_console,
            hardware_resources,
            tap_interface,
        )

    async def setup(self):
        logger.debug(f"Setup started for VM={self.vm_id}")
        await setfacl()

        self._firecracker_config = FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(
                    self.fvm.enable_kernel(self.resources.kernel_image_path)
                ),
                boot_args=BootSource.args(
                    enable_console=self.enable_console, writable=False
                ),
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
                if hasattr(self.resources, "code_encoding")
                and self.resources.code_encoding == Encoding.squashfs
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

    async def configure(self):
        """Configure the VM by sending configuration info to it's init"""

        code: Optional[bytes]
        volumes: List[Volume]

        code, volumes = get_volumes_for_program(
            resources=self.resources, drives=self.fvm.drives
        )
        interface: Interface = Interface.from_entrypoint(self.resources.code_entrypoint)
        input_data: Optional[bytes] = read_input_data(self.resources.data_path)

        self._setup_configuration(
            code=code, input_data=input_data, interface=interface, volumes=volumes
        )

    def _setup_configuration(
        self,
        code: Optional[bytes],
        input_data: Optional[bytes],
        interface: Interface,
        volumes: List[Volume],
    ):
        """Set up the VM configuration. The program mode uses a VSOCK connection to the custom init of the virtual
        machine to send this configuration. Other modes may use Cloud-init, ..."""
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
