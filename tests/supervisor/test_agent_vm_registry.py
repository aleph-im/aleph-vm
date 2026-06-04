"""AgentVmRegistry: the agent-side message cache keyed by vm_hash."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator.vm_registry import (
    AgentVmRecord,
    AgentVmRegistry,
    rehydrate_registry,
)

_HASH = ItemHash("deadbeef" * 8)


def test_record_and_get():
    registry = AgentVmRegistry()
    message, original = MagicMock(), MagicMock()

    record = registry.record(_HASH, message=message, original=original)

    assert record == AgentVmRecord(message=message, original=original)
    assert registry.get(_HASH) is record
    assert _HASH in registry
    assert len(registry) == 1


def test_get_unknown_returns_none():
    assert AgentVmRegistry().get(_HASH) is None
    assert _HASH not in AgentVmRegistry()


def test_forget_is_idempotent():
    registry = AgentVmRegistry()
    registry.record(_HASH, message=MagicMock(), original=MagicMock())

    registry.forget(_HASH)
    assert registry.get(_HASH) is None
    assert _HASH not in registry

    registry.forget(_HASH)  # forgetting an unknown hash must not raise


def test_record_carries_persistent_flag():
    registry = AgentVmRegistry()
    record = registry.record(_HASH, message=MagicMock(), original=MagicMock(), persistent=True)
    assert record.persistent is True
    assert registry.record(_HASH, message=MagicMock(), original=MagicMock()).persistent is False


def test_items_iterates_records():
    registry = AgentVmRegistry()
    record = registry.record(_HASH, message=MagicMock(), original=MagicMock())
    assert list(registry.items()) == [(_HASH, record)]


@pytest.mark.asyncio
async def test_rehydrate_registry_from_db(monkeypatch):
    db_record = SimpleNamespace(
        vm_hash=str(_HASH),
        message='{"address": "0xabc"}',  # parsing is mocked below; content shape is irrelevant
        original_message='{"address": "0xabc"}',
        persistent=True,
    )
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(return_value=[db_record]),
    )
    parsed = MagicMock()
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_message_executable_content",
        MagicMock(return_value=parsed),
    )
    registry = AgentVmRegistry()

    count = await rehydrate_registry(registry)

    assert count == 1
    record = registry.get(_HASH)
    assert record.message is parsed and record.persistent is True


@pytest.mark.asyncio
async def test_rehydrate_skips_messageless_and_duplicate_records(monkeypatch):
    newest = SimpleNamespace(vm_hash=str(_HASH), message='{"k": 1}', original_message=None, persistent=True)
    older = SimpleNamespace(vm_hash=str(_HASH), message='{"k": 2}', original_message=None, persistent=False)
    no_message = SimpleNamespace(vm_hash="ee" * 32, message=None, original_message=None, persistent=True)
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(return_value=[newest, older, no_message]),  # newest-first, as get_execution_records orders
    )
    parsed_newest = MagicMock()
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_message_executable_content",
        MagicMock(side_effect=[parsed_newest]),
    )
    registry = AgentVmRegistry()

    count = await rehydrate_registry(registry)

    assert count == 1
    assert registry.get(_HASH).message is parsed_newest
    assert ItemHash("ee" * 32) not in registry


@pytest.mark.asyncio
async def test_rehydrate_skips_unparseable_message(monkeypatch):
    db_record = SimpleNamespace(
        vm_hash=str(_HASH),
        message='{"address": "0xabc"}',
        original_message=None,
        persistent=False,
    )
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(return_value=[db_record]),
    )
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_message_executable_content",
        MagicMock(side_effect=ValueError("bad message")),
    )
    registry = AgentVmRegistry()

    count = await rehydrate_registry(registry)

    assert count == 0
    assert registry.get(_HASH) is None


@pytest.mark.asyncio
async def test_rehydrate_propagates_db_error(monkeypatch):
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(side_effect=RuntimeError("DB unavailable")),
    )
    with pytest.raises(RuntimeError, match="DB unavailable"):
        await rehydrate_registry(AgentVmRegistry())
