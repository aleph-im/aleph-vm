"""AgentVmRegistry: the agent-side message cache keyed by vm_hash."""

from __future__ import annotations

from unittest.mock import MagicMock

from aleph_message.models import ItemHash

from aleph.vm.orchestrator.vm_registry import AgentVmRecord, AgentVmRegistry

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
