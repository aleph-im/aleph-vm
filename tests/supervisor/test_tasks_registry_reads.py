"""Agent-side registry reads in tasks.py: payment grouping and the domains aggregate."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import Chain, ItemHash, Payment, PaymentType

from aleph.vm.conf import settings
from aleph.vm.orchestrator.tasks import _group_executions_by_payment
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry

_HASH = ItemHash("deadbeef" * 8)


def _execution(vm_hash: ItemHash, *, is_running: bool = True) -> SimpleNamespace:
    # Message-less, structurally-typed stand-in for a spec-built pool execution.
    return SimpleNamespace(vm_hash=vm_hash, is_running=is_running)


def _registry_with(vm_hash: ItemHash, *, payment: Payment | None, address: str = "0xabc") -> AgentVmRegistry:
    registry = AgentVmRegistry()
    registry.record(
        vm_hash,
        message=SimpleNamespace(payment=payment, address=address),
        original=MagicMock(),
        persistent=True,
    )
    return registry


def test_grouping_sources_message_from_registry():
    """A message-less (spec-built / restored) execution with a registry record is grouped."""
    payment = Payment(chain=Chain.ETH, type=PaymentType.superfluid)
    registry = _registry_with(_HASH, payment=payment)
    pool = SimpleNamespace(executions={_HASH: _execution(_HASH)})

    groups = _group_executions_by_payment(pool, registry, PaymentType.superfluid)

    assert list(groups) == ["0xabc"]
    assert list(groups["0xabc"]) == [Chain.ETH]
    assert groups["0xabc"][Chain.ETH][0].vm_hash == _HASH


def test_grouping_skips_unrecorded_executions():
    """No registry record -> the agent knows no message -> not grouped."""
    pool = SimpleNamespace(executions={_HASH: _execution(_HASH)})

    groups = _group_executions_by_payment(pool, AgentVmRegistry(), PaymentType.superfluid)

    assert groups == {}


def test_grouping_defaults_to_hold_and_filters_by_type():
    registry = _registry_with(_HASH, payment=None)  # no payment -> hold tier
    pool = SimpleNamespace(executions={_HASH: _execution(_HASH)})

    assert _group_executions_by_payment(pool, registry, PaymentType.superfluid) == {}
    hold_groups = _group_executions_by_payment(pool, registry, PaymentType.hold)
    assert hold_groups["0xabc"][Chain.ETH][0].vm_hash == _HASH


def test_grouping_skips_stopped_and_diagnostic_executions():
    payment = Payment(chain=Chain.ETH, type=PaymentType.hold)
    registry = _registry_with(_HASH, payment=payment)
    fake_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    registry.record(
        fake_hash,
        message=SimpleNamespace(payment=payment, address="0xabc"),
        original=MagicMock(),
        persistent=True,
    )
    diag = SimpleNamespace(vm_hash=ItemHash(settings.CHECK_FASTAPI_VM_ID), is_running=True)
    registry.record(
        diag.vm_hash,
        message=SimpleNamespace(payment=payment, address="0xabc"),
        original=MagicMock(),
        persistent=True,
    )
    legacy = SimpleNamespace(vm_hash=ItemHash(settings.LEGACY_CHECK_FASTAPI_VM_ID), is_running=True)
    registry.record(
        legacy.vm_hash,
        message=SimpleNamespace(payment=payment, address="0xabc"),
        original=MagicMock(),
        persistent=True,
    )
    pool = SimpleNamespace(
        executions={
            _HASH: _execution(_HASH, is_running=False),  # stopped -> skipped
            diag.vm_hash: diag,  # diagnostic -> skipped
            legacy.vm_hash: legacy,  # legacy diagnostic -> skipped
        }
    )

    assert _group_executions_by_payment(pool, registry, PaymentType.hold) == {}


def test_pool_has_no_message_reads():
    """pool.py must not learn messages off executions; that is registry territory."""
    import inspect

    from aleph.vm import pool as pool_module

    source = inspect.getsource(pool_module)
    assert "execution.message" not in source
    assert "get_executions_by_address" not in source
