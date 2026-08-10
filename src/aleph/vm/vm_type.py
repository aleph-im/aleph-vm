from enum import Enum

from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ProgramContent,
    VerifiableProgramContent,
)


class VmType(Enum):
    microvm = 1
    persistent_program = 2
    instance = 3
    v_program = 4

    @staticmethod
    def from_message_content(content: ExecutableContent) -> "VmType":
        if isinstance(content, InstanceContent):
            return VmType.instance

        elif isinstance(content, VerifiableProgramContent):
            return VmType.v_program

        elif isinstance(content, ProgramContent):
            if content.on.persistent:
                return VmType.persistent_program
            return VmType.microvm

        msg = f"Unexpected message content type: {type(content)}"
        raise TypeError(msg)
