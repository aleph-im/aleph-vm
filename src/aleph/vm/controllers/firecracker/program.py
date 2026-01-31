from __future__ import annotations

import asyncio
import dataclasses
import logging
import os.path
from asyncio import StreamReader, StreamWriter
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import msgpack
from aiohttp import ClientResponseError
from aleph_message.models import ExecutableContent, ItemHash
from aleph_message.models.execution.base import Encoding
from aleph_message.models.execution.environment import MachineResources

from aleph.vm.conf import settings
from aleph.vm.hypervisors.firecracker.config import (
    BootSource,
    Drive,
    FirecrackerConfig,
    MachineConfig,
    NetworkInterface,
    Vsock,
)
from aleph.vm.hypervisors.firecracker.microvm import RuntimeConfiguration, setfacl
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.storage import get_code_path, get_data_path, get_runtime_path
from aleph.vm.utils import MsgpackSerializable

from .executable import (
    AlephFirecrackerExecutable,
    AlephFirecrackerResources,
    ResourceDownloadError,
    VmInitNotConnectedError,
    VmSetupError,
    Volume,
)

logger = logging.getLogger(__name__)


class FileTooLargeError(Exception):
    pass


def read_input_data(path_to_data: Path | None) -> bytes | None:
    if not path_to_data:
        return None

    if os.path.getsize(path_to_data) > settings.MAX_DATA_ARCHIVE_SIZE:
        msg = "Data file too large to pass as an inline zip"
        raise FileTooLargeError(msg)

    return path_to_data.read_bytes()


class Interface(str, Enum):
    asgi = "asgi"
    executable = "executable"

    @classmethod
    def from_entrypoint(cls, entrypoint: str, interface_hint: str | None = None):
        """Determine the interface type (Python ASGI or executable HTTP service) from the entrypoint of the program.
        
        If an explicit interface_hint is provided (from the message's code.interface field), it takes precedence.
        Otherwise, we use the presence of ':' in the entrypoint to differentiate between Python ASGI and executable.
        """
        # If an explicit interface is specified in the message, use it
        if interface_hint:
            try:
                return cls(interface_hint)
            except ValueError:
                pass  # Fall back to auto-detection if invalid value
        
        # Only Python ASGI entrypoints contain a colon `:` in their name.
        # We use this to differentiate Python ASGI programs from executable HTTP service mode.
        if ":" in entrypoint:
            return cls.asgi
        else:
            return cls.executable


@dataclass
class ProgramVmConfiguration(MsgpackSerializable):
    interface: Interface
    vm_hash: ItemHash
    ip: str | None = None
    ipv6: str | None = None
    route: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    volumes: list[Volume] = field(default_factory=list)
    variables: dict[str, str] | None = None


@dataclass
class ConfigurationPayload(MsgpackSerializable):
    pass


@dataclass
class ConfigurationPayloadV1(ConfigurationPayload):
    """
    Configuration payload for runtime v1.
    """

    input_data: bytes | None
    interface: Interface
    vm_hash: str
    encoding: Encoding
    entrypoint: str
    code: bytes | None
    ip: str | None
    route: str | None
    dns_servers: list[str]
    volumes: list[Volume]
    variables: dict[str, str] | None

    @classmethod
    def from_program_config(cls, program_config: ProgramConfiguration) -> ConfigurationPayload:
        """Converts a program configuration into a configuration payload
        to be sent to a runtime.
        """
        field_names = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in dataclasses.asdict(program_config).items() if k in field_names})


@dataclass
class ConfigurationPayloadV2(ConfigurationPayloadV1):
    """
    Configuration payload for runtime v2.
    Adds support for IPv6.
    """

    ipv6: str | None
    ipv6_gateway: str | None
    authorized_keys: list[str] | None


@dataclass
class ProgramConfiguration:
    """Configuration passed to the init of the virtual machine in order to start the program."""

    input_data: bytes | None
    interface: Interface
    vm_hash: str
    encoding: Encoding
    entrypoint: str
    code: bytes | None = None
    ip: str | None = None
    ipv6: str | None = None
    route: str | None = None
    ipv6_gateway: str | None = None
    dns_servers: list[str] = field(default_factory=list)
    volumes: list[Volume] = field(default_factory=list)
    variables: dict[str, str] | None = None
    authorized_keys: list[str] | None = None

    def to_runtime_format(self, runtime_config: RuntimeConfiguration) -> ConfigurationPayload:
        if runtime_config.version == "1.0.0":
            return ConfigurationPayloadV1.from_program_config(self)

        if runtime_config.version != "2.0.0":
            logger.warning("This runtime version may be unsupported: %s", runtime_config.version)

        return ConfigurationPayloadV2.from_program_config(self)


@dataclass
class ConfigurationResponse:
    """Response received from the virtual machine in response to a request."""

    success: bool
    error: str | None = None
    traceback: str | None = None


@dataclass
class RunCodePayload(MsgpackSerializable):
    """Information passed to the init of the virtual machine to launch a function/path of the program."""

    scope: dict


class AlephProgramResources(AlephFirecrackerResources):
    """Resources required by the virtual machine in order to launch the program.
    Extends the resources required by all Firecracker VMs."""

    code_path: Path
    code_encoding: Encoding
    code_entrypoint: str
    code_interface: str | None  # Explicit interface type from message (asgi or executable)
    data_path: Path | None

    def __init__(self, message_content: ExecutableContent, namespace: str):
        super().__init__(message_content, namespace)
        self.code_encoding = message_content.code.encoding
        self.code_entrypoint = message_content.code.entrypoint
        # Get explicit interface if specified in the message
        self.code_interface = getattr(message_content.code, 'interface', None)

    async def download_code(self) -> None:
        code_ref: str = self.message_content.code.ref
        try:
            self.code_path = await get_code_path(code_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error) from error
        assert self.code_path.is_file(), f"Code not found on '{self.code_path}'"

    async def download_runtime(self) -> None:
        runtime_ref: str = self.message_content.runtime.ref
        try:
            self.rootfs_path = await get_runtime_path(runtime_ref)
        except ClientResponseError as error:
            raise ResourceDownloadError(error) from error
        assert self.rootfs_path.is_file(), f"Runtime not found on {self.rootfs_path}"

    async def download_data(self) -> None:
        if self.message_content.data:
            data_ref: str = self.message_content.data.ref
            try:
                data_path = await get_data_path(data_ref)
                self.data_path = data_path
            except ClientResponseError as error:
                raise ResourceDownloadError(error) from error
            assert data_path.is_file(), f"Data not found on {data_path}"
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


def get_volumes_for_program(resources: AlephProgramResources, drives: list[Drive]) -> tuple[bytes | None, list[Volume]]:
    code: bytes | None
    volumes: list[Volume]
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
            msg = "Program file too large to pass as an inline zip"
            raise FileTooLargeError(msg)

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
    vm_configuration: ProgramVmConfiguration | None
    resources: AlephProgramResources
    is_instance = False
    support_snapshot = False

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephProgramResources,
        enable_networking: bool = False,
        enable_console: bool | None = None,
        hardware_resources: MachineResources = MachineResources(),
        tap_interface: TapInterface | None = None,
        persistent: bool = False,
        prepare_jailer: bool = True,
    ):
        super().__init__(
            vm_id,
            vm_hash,
            resources,
            enable_networking,
            enable_console,
            hardware_resources,
            tap_interface,
            persistent,
            prepare_jailer,
        )

    async def setup(self) -> None:
        logger.debug(f"Setup started for VM={self.vm_id}")
        await setfacl()

        self._firecracker_config = FirecrackerConfig(
            boot_source=BootSource(
                kernel_image_path=Path(self.fvm.enable_kernel(self.resources.kernel_image_path)),
                boot_args=BootSource.args(enable_console=self.enable_console, writable=False),
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
            network_interfaces=(
                [NetworkInterface(iface_id="eth0", host_dev_name=self.tap_interface.device_name)]
                if self.enable_networking and self.tap_interface
                else []
            ),
        )

    async def wait_for_init(self) -> None:
        """Wait for the custom init inside the virtual machine to signal it is ready."""
        await self.fvm.wait_for_init()

    async def load_configuration(self) -> None:
        code: bytes | None
        volumes: list[Volume]

        code, volumes = get_volumes_for_program(resources=self.resources, drives=self.fvm.drives)
        interface: Interface = Interface.from_entrypoint(
            self.resources.code_entrypoint,
            interface_hint=self.resources.code_interface
        )
        input_data: bytes | None = read_input_data(self.resources.data_path)

        await self._setup_configuration(code=code, input_data=input_data, interface=interface, volumes=volumes)

    async def _setup_configuration(
        self,
        code: bytes | None,
        input_data: bytes | None,
        interface: Interface,
        volumes: list[Volume],
    ) -> None:
        """Set up the VM configuration. The program mode uses a VSOCK connection to the custom init of the virtual
        machine to send this configuration. Other modes may use Cloud-init, ..."""
        logger.debug("Sending configuration")
        reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)

        ip = self.get_ip()
        if ip:
            # The ip and route should not contain the network mask in order to maintain
            # compatibility with the existing runtimes.
            ip = ip.split("/", 1)[0]
        route = self.get_ip_route()
        ipv6 = self.get_ipv6()
        ipv6_gateway = self.get_ipv6_gateway()

        if settings.ALLOW_VM_NETWORKING and not settings.DNS_NAMESERVERS:
            msg = "Invalid configuration: DNS nameservers missing"
            raise ValueError(msg)

        runtime_config = self.fvm.runtime_config
        assert runtime_config

        authorized_keys: list[str] | None
        if settings.USE_DEVELOPER_SSH_KEYS:
            authorized_keys = settings.DEVELOPER_SSH_KEYS
        else:
            authorized_keys = self.resources.message_content.authorized_keys
        nameservers_ip = []
        if ip:
            nameservers_ip = settings.DNS_NAMESERVERS_IPV4
        if ipv6:
            nameservers_ip += settings.DNS_NAMESERVERS_IPV6

        program_config = ProgramConfiguration(
            ip=ip,
            ipv6=ipv6,
            route=route,
            ipv6_gateway=ipv6_gateway,
            dns_servers=nameservers_ip,
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
        scope: dict | None = None,
    ):
        if not self.fvm:
            msg = "MicroVM must be created first"
            raise ValueError(msg)
        logger.debug("running code")
        scope = scope or {}

        async def communicate(reader_: StreamReader, writer_: StreamWriter, scope_: dict) -> bytes:
            payload = RunCodePayload(scope=scope_)

            writer_.write(b"CONNECT 52\n" + payload.as_msgpack())
            await writer_.drain()

            ack: bytes = await reader_.readline()
            logger.debug(f"ack={ack.decode()}")

            logger.debug("waiting for VM response")
            response: bytes = await reader_.read()

            return response

        try:
            reader, writer = await asyncio.open_unix_connection(path=self.fvm.vsock_path)
        except ConnectionRefusedError as error:
            msg = "MicroVM may have crashed"
            raise VmInitNotConnectedError(msg) from error
        try:
            return await asyncio.wait_for(
                communicate(reader, writer, scope),
                timeout=self.hardware_resources.seconds,
            )
        finally:
            logger.debug("Cleaning VM socket resources")
            writer.close()
            await writer.wait_closed()
