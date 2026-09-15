"""get_message_executable_content rebuilds a content model from a dict that
lost its message type, which is what every persisted execution record is."""

import json
from pathlib import Path

import pytest
from aleph_message.models import InstanceContent, ProgramContent, VerifiableProgramContent

from aleph.vm.utils import get_message_executable_content

EXAMPLES = Path(__file__).parent.parent.parent / "examples"
FIXTURES = Path(__file__).parent / "fixtures"


def _content(path: Path) -> dict:
    return json.loads(path.read_text())["content"]


@pytest.mark.parametrize(
    ("path", "model"),
    [
        (EXAMPLES / "program_message_from_aleph.json", ProgramContent),
        (EXAMPLES / "instance_message_from_aleph.json", InstanceContent),
        (EXAMPLES / "confidential_instance_message_from_aleph.json", InstanceContent),
        (FIXTURES / "vprogram_message.json", VerifiableProgramContent),
    ],
)
def test_parses_every_executable_content_type(path, model):
    assert isinstance(get_message_executable_content(_content(path)), model)


@pytest.mark.parametrize(
    "path",
    [
        EXAMPLES / "program_message_from_aleph.json",
        EXAMPLES / "instance_message_from_aleph.json",
        FIXTURES / "vprogram_message.json",
    ],
)
def test_survives_the_execution_record_round_trip(path):
    """What persist_record stores (model_dump_json) parses back to the same
    content: the agent registry is rebuilt from exactly this after a restart."""
    parsed = get_message_executable_content(_content(path))
    again = get_message_executable_content(json.loads(parsed.model_dump_json()))
    assert type(again) is type(parsed)
    assert again == parsed
