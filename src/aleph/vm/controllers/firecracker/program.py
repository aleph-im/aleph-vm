from __future__ import annotations

import asyncio
import dataclasses
import logging
import os.path
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from aiohttp import ClientResponseError
from aleph_message.models import ProgramContent
from aleph_message.models.execution.base import Encoding

from aleph.vm.conf import settings
from aleph.vm.hypervisors.firecracker.config import Drive
from aleph.vm.hypervisors.firecracker.microvm import RuntimeConfiguration
from aleph.vm.storage import get_code_path, get_data_path, get_runtime_path
from aleph.vm.utils import MsgpackSerializable

from .executable import AlephFirecrackerResources, ResourceDownloadError, Volume

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
        # Map aleph-message interface values to our enum values.
        # aleph-message uses "binary" while our enum uses "executable".
        _INTERFACE_MAP = {
            "binary": cls.executable,
        }

        # If an explicit interface is specified in the message, use it
        if interface_hint is not None:
            if interface_hint in _INTERFACE_MAP:
                return _INTERFACE_MAP[interface_hint]
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

    # A Firecracker program is always driven by a ProgramContent.
    message_content: ProgramContent

    code_path: Path
    code_encoding: Encoding
    code_entrypoint: str
    # Explicit interface type from message (asgi or executable)
    code_interface: Interface
    data_path: Path | None

    def __init__(self, message_content: ProgramContent, namespace: str):
        super().__init__(message_content, namespace)
        self.code_encoding = message_content.code.encoding
        self.code_entrypoint = message_content.code.entrypoint
        # Get explicit interface if specified in the message
        self.code_interface = Interface.from_entrypoint(
            entrypoint=message_content.code.entrypoint, interface_hint=message_content.code.interface
        )

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
