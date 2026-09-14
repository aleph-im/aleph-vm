"""The agent's storage hooks are one value, installed in one write.

They used to be three module globals set one after another at startup, so a
raise between two of the calls left a node in a state neither module could
report on: evicting retained volumes for a placement but not budgeting
downloads, or the reverse.
"""

from __future__ import annotations

import pytest

import aleph.vm.agent.vm.retire as retire_module
import aleph.vm.storage as storage_module
import aleph.vm.storage_pools as storage_pools_module
from aleph.vm.hooks import AgentHooks, current_hooks, install_hooks, installed_hooks


async def _after_gone() -> None:
    return None


def _admit(*_args: object) -> None:
    return None


def _make_room(*_args: object) -> int:
    return 0


@pytest.fixture(autouse=True)
def clean_hooks():
    """Every case here starts from an unwired node and leaves one behind."""
    with installed_hooks(AgentHooks()):
        yield


def test_a_single_slot_setter_leaves_the_other_two_alone():
    """The setters the storage modules still expose write one slot into the
    installed object. A setter that replaced the object outright would
    silently unwire the other two hooks whenever a test used one."""
    install_hooks(AgentHooks(after_gone=_after_gone, cache_admission=_admit, room_maker=_make_room))

    storage_pools_module.set_room_maker(None)
    assert current_hooks() == AgentHooks(after_gone=_after_gone, cache_admission=_admit, room_maker=None)

    storage_module.set_cache_admission(None)
    assert current_hooks() == AgentHooks(after_gone=_after_gone, cache_admission=None, room_maker=None)

    retire_module.set_after_gone_hook(None)
    assert current_hooks() == AgentHooks()


def test_installed_hooks_puts_back_what_was_there():
    """Restoring the previous instance rather than clearing it: a fixture that
    wires a node and a test that wires one inside it both get their state
    back."""
    outer = AgentHooks(room_maker=_make_room)
    install_hooks(outer)

    with installed_hooks(AgentHooks(cache_admission=_admit)):
        assert current_hooks().cache_admission is _admit
        assert current_hooks().room_maker is None

    assert current_hooks() is outer
