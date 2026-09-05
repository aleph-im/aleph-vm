"""The stop half of an allocation: who may be stopped, and what stopping means.

Both rules are shared by the legacy endpoint and (soon) the v2 reconciler, so
they live in one module. The v-program inversion is the reason the predicate is
a named function rather than an inline boolean.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.agent.allocation.teardown import is_removable_by_allocation, teardown_vm
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import ConfidentialMode, GpuDevice, PciAddress

_HASH = ItemHash("deadbeef" * 8)


def _record(*, stream=False, credit=False, vprogram=False, persistent=True):
    return SimpleNamespace(
        persistent=persistent,
        uses_payment_stream=stream,
        uses_payment_credit=credit,
        is_vprogram=vprogram,
        message=MagicMock(),
    )


def _info(*, gpus=(), confidential=ConfidentialMode.NONE):
    return SimpleNamespace(vm_id=str(_HASH), gpus=list(gpus), confidential_mode=confidential)


class TestRemovability:
    def test_a_plain_persistent_vm_is_removable(self):
        assert is_removable_by_allocation(_record(), _info()) is True

    def test_a_stream_paid_vm_is_retained(self):
        assert is_removable_by_allocation(_record(stream=True), _info()) is False

    def test_a_credit_paid_vm_is_retained(self):
        assert is_removable_by_allocation(_record(credit=True), _info()) is False

    def test_a_gpu_vm_is_retained(self):
        gpu = GpuDevice(pci_host=PciAddress("0000:01:00.0"), device_id="10de:2504", model="x", supports_x_vga=True)
        assert is_removable_by_allocation(_record(), _info(gpus=[gpu])) is False

    def test_a_confidential_vm_is_retained(self):
        assert is_removable_by_allocation(_record(), _info(confidential=ConfidentialMode.SEV_SNP)) is False

    def test_a_vprogram_is_removable_despite_being_credit_paid_and_confidential(self):
        """The scheduler is the single source of truth for v-programs, so
        absence from the plan stops them. This inverts every rule above."""
        record = _record(credit=True, vprogram=True)
        assert is_removable_by_allocation(record, _info(confidential=ConfidentialMode.SEV_SNP)) is True

    def test_a_non_persistent_vm_is_not_touched(self):
        assert is_removable_by_allocation(_record(persistent=False), _info()) is False


class TestTeardown:
    @pytest.mark.asyncio
    async def test_deletes_forgets_and_clears_every_side_channel(self, monkeypatch):
        delete_records = AsyncMock()
        vprogram_staging = MagicMock()
        snp_staging = MagicMock()
        monkeypatch.setattr("aleph.vm.agent.allocation.teardown.delete_records_for_vm", delete_records)
        monkeypatch.setattr("aleph.vm.agent.allocation.teardown.remove_vprogram_staging", vprogram_staging)
        monkeypatch.setattr("aleph.vm.agent.allocation.teardown.remove_snp_instance_staging", snp_staging)
        supervisor = SimpleNamespace(delete_vm=AsyncMock())
        registry = MagicMock()

        await teardown_vm(_HASH, supervisor=supervisor, registry=registry)

        supervisor.delete_vm.assert_awaited_once()
        registry.forget.assert_called_once_with(_HASH)
        delete_records.assert_awaited_once_with(str(_HASH))
        vprogram_staging.assert_called_once_with(_HASH)
        snp_staging.assert_called_once_with(_HASH)

    @pytest.mark.asyncio
    async def test_a_vm_the_supervisor_does_not_know_is_still_cleaned_up(self, monkeypatch):
        """The supervisor forgetting first must not strand the agent's own
        state: the registry entry, the DB rows and the staging dirs are ours."""
        delete_records = AsyncMock()
        vprogram_staging = MagicMock()
        snp_staging = MagicMock()
        monkeypatch.setattr("aleph.vm.agent.allocation.teardown.delete_records_for_vm", delete_records)
        monkeypatch.setattr("aleph.vm.agent.allocation.teardown.remove_vprogram_staging", vprogram_staging)
        monkeypatch.setattr("aleph.vm.agent.allocation.teardown.remove_snp_instance_staging", snp_staging)
        supervisor = SimpleNamespace(delete_vm=AsyncMock(side_effect=VmNotFoundError(str(_HASH))))
        registry = MagicMock()

        await teardown_vm(_HASH, supervisor=supervisor, registry=registry)

        registry.forget.assert_called_once_with(_HASH)
        delete_records.assert_awaited_once_with(str(_HASH))
        vprogram_staging.assert_called_once_with(_HASH)
        snp_staging.assert_called_once_with(_HASH)
