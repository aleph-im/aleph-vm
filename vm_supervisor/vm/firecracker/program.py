from __future__ import annotations

import asyncio
import dataclasses
import logging
import os.path
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import ipaddress

import msgpack
from aiohttp import ClientResponseError
from aleph_message.models import ItemHash
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
from firecracker.microvm import RuntimeConfiguration, setfacl
from vm_supervisor.conf import settings
from vm_supervisor.models import ExecutableContent
from vm_supervisor.network.interfaces import TapInterface
from vm_supervisor.storage import get_code_path, get_data_path, get_runtime_path

from ...utils import MsgpackSerializable
from .executable import (
    AlephFirecrackerExecutable,
    AlephFirecrackerResources,
    VmInitNotConnected,
    VmSetupError,
    Volume,
)


logger = logging.getLogger(__name__)


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


def read_input_data(path_to_data: Optional[Path]) -> Optional[bytes]:
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
class ProgramVmConfiguration(MsgpackSerializable):
    interface: Interface
    vm_hash: ItemHash
    ip: Optional[str] = None
    ipv6: Optional[str] = None
    route: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    volumes: List[Volume] = field(default_factory=list)
    variables: Optional[Dict[str, str]] = None


@dataclass
class ConfigurationPayload(MsgpackSerializable):
    ...


@dataclass
class ConfigurationPayloadV1(ConfigurationPayload):
    """
    Configuration payload for runtime v1.
    """

    input_data: Optional[bytes]
    interface: Interface
    vm_hash: str
    encoding: Encoding
    entrypoint: str
    code: Optional[bytes]
    ip: Optional[str]
    route: Optional[str]
    dns_servers: List[str]
    volumes: List[Volume]
    variables: Optional[Dict[str, str]]

    @classmethod
    def from_program_config(
        cls, program_config: ProgramConfiguration
    ) -> ConfigurationPayload:
        """Converts a program configuration into a configuration payload
        to be sent to a runtime.
        """
        field_names = set(f.name for f in dataclasses.fields(cls))
        return cls(
            **{
                k: v
                for k, v in dataclasses.asdict(program_config).items()
                if k in field_names
            }
        )


@dataclass
class ConfigurationPayloadV2(ConfigurationPayloadV1):
    """
    Configuration payload for runtime v2.
    Adds support for IPv6.
    """

    ipv6: Optional[str]
    ipv6_gateway: Optional[str]
    authorized_keys: Optional[List[str]]


@dataclass
class ProgramConfiguration:
    """Configuration passed to the init of the virtual machine in order to start the program."""

    input_data: Optional[bytes]
    interface: Interface
    vm_hash: str
    encoding: Encoding
    entrypoint: str
    code: Optional[bytes] = None
    ip: Optional[str] = None
    ipv6: Optional[str] = None
    route: Optional[str] = None
    ipv6_gateway: Optional[str] = None
    dns_servers: List[str] = field(default_factory=list)
    volumes: List[Volume] = field(default_factory=list)
    variables: Optional[Dict[str, str]] = None
    authorized_keys: Optional[List[str]] = None

    def to_runtime_format(
        self, runtime_config: RuntimeConfiguration
    ) -> ConfigurationPayload:
        if runtime_config.version == "1.0.0":
            return ConfigurationPayloadV1.from_program_config(self)

        if runtime_config.version != "2.0.0":
            logger.warning(
                "This runtime version may be unsupported: %s", runtime_config.version
            )

        return ConfigurationPayloadV2.from_program_config(self)


@dataclass
class ConfigurationResponse:
    """Response received from the virtual machine in response to a request."""

    success: bool
    error: Optional[str] = None
    traceback: Optional[str] = None


@dataclass
class RunCodePayload(MsgpackSerializable):
    """Information passed to the init of the virtual machine to launch a function/path of the program."""

    scope: Dict


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

    async def download_code(self) -> None:
        code_ref: str = self.message_content.code.ref
        try:
            self.code_path = await get_code_path(code_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert self.code_path.is_file(), f"Code not found on '{self.code_path}'"

    async def download_runtime(self) -> None:
        runtime_ref: str = self.message_content.runtime.ref
        try:
            self.rootfs_path = await get_runtime_path(runtime_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error)
        assert self.rootfs_path.is_file(), f"Runtime not found on {self.rootfs_path}"

    async def download_data(self) -> None:
        if self.message_content.data:
            data_ref: str = self.message_content.data.ref
            try:
                self.data_path = await get_data_path(data_ref)
            except ClientResponseError as error:
                raise ResourceDownloadError(error)
            assert self.data_path.is_file(), f"Data not found on {self.data_path}"
        else:
            self.data_path = None

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
    code: Optional[bytes]
    volumes: List[Volume]
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
            raise FileTooLargeError("Program file too large to pass as an inline zip")

        code = resources.code_path.read_bytes() if resources.code_path else None
        volumes = [
            Volume(
                mount=volume.mount,
                device=drives[index].drive_id,
                read_only=volume.read_only,
            )
            for index, volume in enumerate(resources.volumes)
        ]
    return code, volumes


class AlephFirecrackerProgram(AlephFirecrackerExecutable[ProgramVmConfiguration]):
    vm_configuration: Optional[ProgramVmConfiguration]
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

    async def wait_for_init(self) -> None:
        """Wait for the custom init inside the virtual machine to signal it is ready."""
        await self.fvm.wait_for_init()

    async def configure(self) -> None:
        """Configure the VM by sending configuration info to it's init"""

        code: Optional[bytes]
        volumes: List[Volume]

        code, volumes = get_volumes_for_program(
            resources=self.resources, drives=self.fvm.drives
        )
        interface: Interface = Interface.from_entrypoint(self.resources.code_entrypoint)
        input_data: Optional[bytes] = read_input_data(self.resources.data_path)

        await self._setup_configuration(
            code=code, input_data=input_data, interface=interface, volumes=volumes
        )

    async def _setup_configuration(
        self,
        code: Optional[bytes],
        input_data: Optional[bytes],
        interface: Interface,
        volumes: List[Volume],
    ):
        """Set up the VM configuration. The program mode uses a VSOCK connection to the custom init of the virtual
        machine to send this configuration. Other modes may use Cloud-init, ..."""
        reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)

        ip = self.get_vm_ip()
        if ip:
            # The ip and route should not contain the network mask in order to maintain
            # compatibility with the existing runtimes.
            ip = ip.split("/", 1)[0]
        route = self.get_vm_route()
        ipv6 = self.get_vm_ipv6()
        ipv6_gateway = self.get_vm_ipv6_gateway()
        dns_servers = settings.dns_servers(False)

        runtime_config = self.fvm.runtime_config
        assert runtime_config

        authorized_keys: Optional[List[str]]
        if settings.USE_DEVELOPER_SSH_KEYS:
            authorized_keys = settings.DEVELOPER_SSH_KEYS
        else:
            authorized_keys = self.resources.message_content.authorized_keys

        program_config = ProgramConfiguration(
            ip=ip,
            ipv6=ipv6,
            route=route,
            ipv6_gateway=ipv6_gateway,
            dns_servers=dns_servers,
            code=code,
            encoding=self.resources.code_encoding,
            entrypoint=self.resources.code_entrypoint,
            input_data=input_data,
            interface=interface,
            vm_hash=self.vm_hash,
            volumes=volumes,
            variables=self.resources.message_content.variables,
            authorized_keys=authorized_keys,
        )
        # Convert the configuration in a format compatible with the runtime
        versioned_config = program_config.to_runtime_format(runtime_config)
        payload = versioned_config.as_msgpack()
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

        async def communicate(reader, writer, scope) -> bytes:
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
