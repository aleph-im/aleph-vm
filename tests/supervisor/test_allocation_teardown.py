"""The stop half of an allocation: who may be stopped, and what stopping means.

Both rules are shared by the legacy endpoint and (soon) the v2 reconciler, so
they live in one module. The v-program inversion is the reason the predicate is
a named function rather than an inline boolean.
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


class TestRetentionReason:
    """The answer a push gets for a VM it asked to have stopped and did not.

    Written out twice until now, once as the predicate above and once in the
    verdict, so a reason one grew and the other did not would have reported a
    retained VM under the wrong reason, or under a catch-all that meant
    nothing.
    """

    def test_a_removable_vm_has_no_reason_to_be_kept(self):
        assert retention_reason(_record(), _info()) is None

    @pytest.mark.parametrize(
        ("record", "info", "expected"),
        [
            (_record(persistent=False), _info(), "non_persistent"),
            (_record(stream=True), _info(), "payment_stream"),
            (_record(credit=True), _info(), "payment_credit"),
            (
                _record(),
                _info(
                    gpus=[
                        GpuDevice(
                            pci_host=PciAddress("0000:01:00.0"),
                            device_id="10de:2504",
                            model="x",
                            supports_x_vga=True,
                        )
                    ]
                ),
                "gpu",
            ),
            (_record(), _info(confidential=ConfidentialMode.SEV_SNP), "confidential"),
        ],
    )
    def test_each_retained_vm_says_what_keeps_it(self, record, info, expected):
        assert retention_reason(record, info) == expected

    def test_the_reason_and_the_predicate_cannot_disagree(self):
        """A v-program is the case that used to be answered wrong: removable by
        the predicate, and reported as retained for being credit-paid by the
        reason, had anything ever asked the two about the same VM."""
        record = _record(credit=True, vprogram=True)
        info = _info(confidential=ConfidentialMode.SEV_SNP)

        assert retention_reason(record, info) is None
        assert is_removable_by_allocation(record, info) is True


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
