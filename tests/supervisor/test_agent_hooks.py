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


def test_a_wiring_that_fails_halfway_installs_no_slot_at_all():
    """The point of the whole object: the arguments are evaluated before
    anything is published, so a failure while building the wiring leaves the
    previous wiring untouched. Three separate setters could not do this, the
    first two having already landed."""

    def explodes():
        msg = "the registry is not ready"
        raise RuntimeError(msg)

    with pytest.raises(RuntimeError):
        install_hooks(
            AgentHooks(
                after_gone=_after_gone,
                cache_admission=explodes(),
                room_maker=_make_room,
            )
        )

    assert current_hooks() == AgentHooks()


def test_the_three_consumers_read_one_installed_object():
    """storage, storage_pools and retire each look their slot up in the same
    place, so one install wires the node and one read tells you what it is."""
    hooks = AgentHooks(after_gone=_after_gone, cache_admission=_admit, room_maker=_make_room)
    install_hooks(hooks)

    assert current_hooks() is hooks
    assert current_hooks().after_gone is _after_gone
    assert current_hooks().cache_admission is _admit
    assert current_hooks().room_maker is _make_room


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


def test_an_unwired_node_has_every_slot_empty():
    """A storage CLI run, or any test that imports these modules without the
    agent app, keeps the behaviour the storage code had before the hooks
    existed."""
    assert current_hooks() == AgentHooks()
    assert current_hooks().after_gone is None
    assert current_hooks().cache_admission is None
    assert current_hooks().room_maker is None
