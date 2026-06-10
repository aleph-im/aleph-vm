"""AgentVmRegistry: the agent-side message cache keyed by vm_hash."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator.metrics import ExecutionRecord
from aleph.vm.orchestrator.vm_registry import (
    AgentVmRecord,
    AgentVmRegistry,
    persist_record,
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


def test_record_payment_helpers():
    stream = AgentVmRecord(
        message=SimpleNamespace(payment=SimpleNamespace(is_stream=True, is_credit=False)),
        original=MagicMock(),
    )
    credit = AgentVmRecord(
        message=SimpleNamespace(payment=SimpleNamespace(is_stream=False, is_credit=True)),
        original=MagicMock(),
    )
    hold = AgentVmRecord(message=SimpleNamespace(payment=None), original=MagicMock())

    assert stream.uses_payment_stream is True and stream.uses_payment_credit is False
    assert credit.uses_payment_stream is False and credit.uses_payment_credit is True
    assert hold.uses_payment_stream is False and hold.uses_payment_credit is False


@pytest.mark.asyncio
async def test_persist_record_writes_agent_fields(monkeypatch):
    saved: list[ExecutionRecord] = []
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.save_record",
        AsyncMock(side_effect=saved.append),
    )
    message = MagicMock()
    message.resources.vcpus = 2
    message.resources.memory = 1024
    message.model_dump_json.return_value = '{"m": 1}'
    original = MagicMock()
    original.model_dump_json.return_value = '{"o": 1}'

    await persist_record(_HASH, AgentVmRecord(message=message, original=original, persistent=True))

    assert len(saved) == 1
    db = saved[0]
    assert db.vm_hash == str(_HASH)
    assert db.vm_id is None  # numeric hypervisor id unknown agent-side (debug-only column)
    assert db.vcpus == 2 and db.memory == 1024
    assert db.message == '{"m": 1}'
    assert db.original_message == '{"o": 1}'
    assert db.persistent is True
    assert db.mapped_ports is None  # the PortMapping table is the authority
    assert db.time_defined is not None
    assert db.uuid  # fresh uuid per create, matching the old per-execution behavior


@pytest.mark.asyncio
async def test_persist_then_rehydrate_round_trip(monkeypatch):
    """What persist_record writes is exactly what rehydrate_registry needs."""
    saved: list[ExecutionRecord] = []
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.save_record",
        AsyncMock(side_effect=saved.append),
    )
    message = MagicMock()
    message.resources.vcpus = 1
    message.resources.memory = 256
    message.model_dump_json.return_value = '{"address": "0xabc"}'
    original = MagicMock()
    original.model_dump_json.return_value = '{"address": "0xabc"}'
    await persist_record(_HASH, AgentVmRecord(message=message, original=original, persistent=True))

    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(return_value=saved),
    )
    parsed = MagicMock()
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_message_executable_content",
        MagicMock(return_value=parsed),
    )
    registry = AgentVmRegistry()

    count = await rehydrate_registry(registry)

    assert count == 1
    rec = registry.get(_HASH)
    assert rec.message is parsed
    assert rec.original is parsed
    assert rec.persistent is True
