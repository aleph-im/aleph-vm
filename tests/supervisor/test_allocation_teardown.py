"""The stop half of an allocation: who may be stopped, and what stopping means.

Both rules are shared by the legacy endpoint and the v2 reconciler, so they
live in one module.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.agent.allocation.teardown import (
    is_removable_by_allocation,
    retention_reason,
    teardown_vm,
)
from aleph.vm.agent.vm.retire import RetireReason

_HASH = ItemHash("deadbeef" * 8)


def _record(*, vprogram=False, persistent=True):
    return SimpleNamespace(persistent=persistent, is_vprogram=vprogram, message=MagicMock())


class TestRetentionReason:
    """The answer a push gets for a VM it asked to have stopped and did not.

    The verdict reports this rather than keeping a list of its own, so a
    reason one grew and the other did not cannot have a retained VM reported
    under the wrong reason, or under a catch-all that means nothing.
    """

    @pytest.mark.parametrize("record", [_record(), _record(vprogram=True)], ids=["instance", "vprogram"])
    def test_a_persistent_vm_the_plan_dropped_is_stopped(self, record):
        """Payment tier, GPUs and confidential mode are the scheduler's
        business: it validated them when it placed the VM, and dropping the VM
        from the plan is how it says they no longer hold."""
        assert retention_reason(record) is None
        assert is_removable_by_allocation(record) is True

    def test_a_non_persistent_vm_is_the_one_thing_kept(self):
        """No allocation ever listed it, so no allocation gets to stop it."""
        record = _record(persistent=False)

        assert retention_reason(record) == "non_persistent"
        assert is_removable_by_allocation(record) is False


class TestTeardown:
    @pytest.mark.asyncio
    async def test_teardown_retires_the_vm_as_gone(self, monkeypatch):
        """The composite this module used to spell out by hand (supervisor
        delete, registry forget, DB rows, staging) is exactly what GONE does,
        so stopping is one retire_vm call and nothing else."""
        retire = AsyncMock()
        monkeypatch.setattr("aleph.vm.agent.allocation.teardown.retire_vm", retire)
        supervisor = SimpleNamespace(delete_vm=AsyncMock())
        registry = MagicMock()

        await teardown_vm(_HASH, supervisor=supervisor, registry=registry)

        retire.assert_awaited_once_with(_HASH, RetireReason.GONE, supervisor=supervisor, registry=registry)
        supervisor.delete_vm.assert_not_awaited()
