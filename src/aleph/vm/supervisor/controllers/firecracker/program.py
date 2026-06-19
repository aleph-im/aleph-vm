from __future__ import annotations

import logging

from aleph_message.models import ProgramContent

# Guest-protocol vocabulary moved to the neutral foundation module so the agent
# (program_client) and the supervisor (local) can share it without crossing the
# import boundary. Re-exported here for the controllers and tests that import
# these names from this module.
from aleph.vm.program_config import (
    ConfigurationPayload,
    ConfigurationPayloadV1,
    ConfigurationPayloadV2,
    ConfigurationResponse,
    Interface,
    ProgramConfiguration,
    RunCodePayload,
    read_input_data,
)

from .executable import AlephFirecrackerResources

logger = logging.getLogger(__name__)

__all__ = [
    "ConfigurationPayload",
    "ConfigurationPayloadV1",
    "ConfigurationPayloadV2",
    "ConfigurationResponse",
    "FileTooLargeError",
    "Interface",
    "ProgramConfiguration",
    "RunCodePayload",
    "read_input_data",
    "AlephProgramResources",
]


class FileTooLargeError(Exception):
    pass


class AlephProgramResources(AlephFirecrackerResources):
    """Resources required by the virtual machine in order to launch the program.

    Extends the resources required by all Firecracker VMs. This is the
    supervisor-side runtime holder; the Aleph-message download path lives
    agent-side in ``aleph.vm.agent.vm.downloader.ProgramDownloader``.
    """

    # A Firecracker program is always driven by a ProgramContent.
    message_content: ProgramContent

    def __init__(self, message_content: ProgramContent, namespace: str):
        super().__init__(message_content, namespace)
        self.code_encoding = message_content.code.encoding
        self.code_entrypoint = message_content.code.entrypoint
        # Get explicit interface if specified in the message
        self.code_interface = Interface.from_entrypoint(
            entrypoint=message_content.code.entrypoint, interface_hint=message_content.code.interface
        )
