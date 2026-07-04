"""Program guest-protocol vocabulary, neutral between agent and supervisor.

The configuration payloads, volume descriptors and run-code payload the Aleph
runtime exchanges over its guest channel are needed on both sides of the
Supervisor boundary:

- the **agent** builds the configuration push and runs code from
  ``aleph.vm.agent.vm.program_client``;
- the **supervisor** runs code over the channel for persistent programs
  (``aleph.vm.supervisor.local``).

Keeping these types here (depending only on stdlib, ``aleph_message``,
``aleph.vm.conf`` and the neutral ``RuntimeConfiguration``) lets neither side
import the other's package.
"""

from __future__ import annotations

import dataclasses
import logging
import os.path
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from aleph_message.models.execution.base import Encoding

from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.types import RuntimeConfiguration
from aleph.vm.utils import MsgpackSerializable

logger = logging.getLogger(__name__)


class VmInitNotConnectedError(Exception):
    """Raised when the guest channel of a (micro)VM cannot be reached."""


def read_input_data(path_to_data: Path | None) -> bytes | None:
    if not path_to_data:
        return None

    if os.path.getsize(path_to_data) > settings.MAX_DATA_ARCHIVE_SIZE:
        from aleph.vm.supervisor_interface.errors import FileTooLargeError

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
class Volume:
    mount: str
    device: str
    read_only: bool


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
