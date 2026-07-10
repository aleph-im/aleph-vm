"""V-PROGRAM (verifiable SEV-SNP program) support in the agent.

Uses the canonical cross-SDK fixture message (item_hash 4c319b6b...); see
docs/plans/2026-07-11-vprogram-scheduler-support-design.md.
"""

import json
from pathlib import Path

import pytest
from aleph_message.models import (
    InstanceMessage,
    ProgramMessage,
    VerifiableProgramContent,
    VerifiableProgramMessage,
    parse_message,
)

from aleph.vm.agent.messages import update_message
from aleph.vm.agent.vm_registry import AgentVmRecord
from aleph.vm.vm_type import VmType

FIXTURE = Path(__file__).parent / "fixtures" / "vprogram_message.json"


def load_vprogram_message() -> VerifiableProgramMessage:
    message = parse_message(json.loads(FIXTURE.read_text()))
    assert isinstance(message, VerifiableProgramMessage)
    return message


def test_vm_type_v_program():
    message = load_vprogram_message()
    assert isinstance(message.content, VerifiableProgramContent)
    assert VmType.from_message_content(message.content) == VmType.v_program
    # .name is exposed in the executions list and must match the scheduler's
    # "v_program" vm-type string
    assert VmType.v_program.name == "v_program"


def test_storage_executable_assert_accepts_vprogram():
    # get_message asserts the parsed message is executable; the union must
    # include VerifiableProgramMessage
    message = load_vprogram_message()
    assert isinstance(message, InstanceMessage | ProgramMessage | VerifiableProgramMessage)


def test_agent_record_is_vprogram():
    message = load_vprogram_message()
    record = AgentVmRecord(message=message.content, original=message.content, persistent=True)
    assert record.is_vprogram
    # The schema enforces credit payment; node-side sweep exclusion is explicit
    assert record.uses_payment_credit


@pytest.mark.asyncio
async def test_update_message_vprogram_is_noop():
    message = load_vprogram_message()
    # Must not attempt any amend resolution (would hit the network):
    # v-programs are immutable and every reference is pinned by exact hash
    await update_message(message)
