"""The immediate answer to a plan push: what we take, drop, refuse or keep."""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock

from aleph_message.models import ItemHash
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent.allocation.plan import AllocationPlan, PlannedVm
from aleph.vm.agent.allocation.verdict import build_plan, compute_verdict
from aleph.vm.agent.capacity import AdmissionVerdict
from aleph.vm.supervisor_interface.types import ConfidentialMode, VmStatus

NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)
HASH_A = ItemHash("a" * 64)
HASH_B = ItemHash("b" * 64)
HASH_C = ItemHash("c" * 64)


def _info(vm_hash, *, status=VmStatus.RUNNING, gpus=(), confidential=ConfidentialMode.NONE):
    return SimpleNamespace(
        vm_id=str(vm_hash),
        status=status,
        gpus=list(gpus),
        confidential_mode=confidential,
        awaiting_confidential_init=False,
    )


def _record(*, stream=False, credit=False, vprogram=False):
    return SimpleNamespace(
        persistent=True,
        uses_payment_stream=stream,
        uses_payment_credit=credit,
        is_vprogram=vprogram,
        message=_make_qemu_instance_message(),
    )


def _registry(records):
    return SimpleNamespace(get=lambda vm_hash: records.get(vm_hash))


def _capacity(verdicts):
    return SimpleNamespace(simulate=MagicMock(return_value=verdicts))


def _plan(*hashes, verified=True, content=None):
    message = SimpleNamespace(content=content or _make_qemu_instance_message())
    entries = {
        h: PlannedVm(vm_hash=h, verified=SimpleNamespace(message=message, original=message) if verified else None)
        for h in hashes
    }
    return AllocationPlan(plan_id="sha256:test", received_at=NOW, entries=entries)


def test_a_running_vm_still_in_the_plan_is_unchanged():
    verdict = compute_verdict(
        _plan(HASH_A), infos=[_info(HASH_A)], registry=_registry({HASH_A: _record()}), capacity=_capacity([])
    )

    assert verdict.unchanged == [HASH_A]
    assert verdict.accepted == []


def test_a_new_vm_that_fits_is_accepted():
    verdict = compute_verdict(
        _plan(HASH_C), infos=[], registry=_registry({}), capacity=_capacity([AdmissionVerdict(HASH_C, True)])
    )

    assert verdict.accepted == [HASH_C]


def test_a_new_vm_that_does_not_fit_is_rejected_with_a_code():
    capacity = _capacity([AdmissionVerdict(HASH_C, False, "insufficient_capacity", "no room")])

    verdict = compute_verdict(_plan(HASH_C), infos=[], registry=_registry({}), capacity=capacity)

    assert verdict.accepted == []
    assert verdict.rejected[HASH_C]["code"] == "insufficient_capacity"


def test_an_entry_without_a_verified_message_is_pending():
    """No embedded message means no verdict yet: the agent must fetch it."""
    verdict = compute_verdict(_plan(HASH_C, verified=False), infos=[], registry=_registry({}), capacity=_capacity([]))

    assert verdict.pending == [HASH_C]
    assert verdict.rejected == {}


def test_a_running_vm_absent_from_the_plan_is_removing():
    verdict = compute_verdict(
        _plan(), infos=[_info(HASH_B)], registry=_registry({HASH_B: _record()}), capacity=_capacity([])
    )

    assert verdict.removing == [HASH_B]


def test_a_stream_paid_vm_absent_from_the_plan_is_retained_with_its_reason():
    verdict = compute_verdict(
        _plan(), infos=[_info(HASH_B)], registry=_registry({HASH_B: _record(stream=True)}), capacity=_capacity([])
    )

    assert verdict.removing == []
    assert verdict.retained[HASH_B] == "payment_stream"


def test_a_vprogram_absent_from_the_plan_is_removing_despite_being_confidential():
    """The scheduler is the single source of truth for v-programs."""
    info = _info(HASH_B, confidential=ConfidentialMode.SEV_SNP)

    verdict = compute_verdict(
        _plan(),
        infos=[info],
        registry=_registry({HASH_B: _record(credit=True, vprogram=True)}),
        capacity=_capacity([]),
    )

    assert verdict.removing == [HASH_B]
    assert verdict.retained == {}


def test_admission_counts_the_removals_as_freed():
    """The plan drops B and adds C, so C is judged against B's release."""
    capacity = _capacity([AdmissionVerdict(HASH_C, True)])

    compute_verdict(_plan(HASH_C), infos=[_info(HASH_B)], registry=_registry({HASH_B: _record()}), capacity=capacity)

    assert capacity.simulate.call_args.kwargs["releasing"] == frozenset({HASH_B})


def test_a_vm_pinned_to_another_node_is_rejected():
    """The scheduler picks which messages run here; one naming a different CRN
    is not among them."""
    content = _make_qemu_instance_message()
    content.requirements = SimpleNamespace(node=SimpleNamespace(node_hash="other-node"), gpu=None)

    verdict = compute_verdict(
        _plan(HASH_C, content=content),
        infos=[],
        registry=_registry({}),
        capacity=_capacity([]),
        node_hash="our-node",
    )

    assert verdict.rejected[HASH_C]["code"] == "node_mismatch"


def test_a_vm_pinned_to_this_node_is_admitted():
    content = _make_qemu_instance_message()
    content.requirements = SimpleNamespace(node=SimpleNamespace(node_hash="our-node"), gpu=None)

    verdict = compute_verdict(
        _plan(HASH_C, content=content),
        infos=[],
        registry=_registry({}),
        capacity=_capacity([AdmissionVerdict(HASH_C, True)]),
        node_hash="our-node",
    )

    assert verdict.accepted == [HASH_C]


def test_the_same_plan_produces_the_same_plan_id():
    body = {"vms": [{"item_hash": str(HASH_A)}, {"item_hash": str(HASH_C)}]}
    reversed_body = {"vms": [{"item_hash": str(HASH_C)}, {"item_hash": str(HASH_A)}]}

    first, _ = build_plan(body, now=NOW)
    second, _ = build_plan(reversed_body, now=NOW)

    assert first.plan_id == second.plan_id


def test_a_different_plan_produces_a_different_plan_id():
    first, _ = build_plan({"vms": [{"item_hash": str(HASH_A)}]}, now=NOW)
    second, _ = build_plan({"vms": [{"item_hash": str(HASH_B)}]}, now=NOW)

    assert first.plan_id != second.plan_id


def test_an_entry_with_an_unusable_item_hash_is_rejected_not_raised():
    """build_plan is the validation boundary for a body the scheduler controls,
    so one bad entry must not take the whole push down with it."""
    body = {"vms": [{"item_hash": "not-a-hash"}, {}, {"item_hash": str(HASH_A)}]}

    plan, rejected = build_plan(body, now=NOW)

    assert list(plan.entries) == [HASH_A]
    assert rejected["not-a-hash"]["code"] == "invalid_message"
    assert rejected["None"]["code"] == "invalid_message"


def test_a_pinned_vm_is_not_refused_when_we_do_not_know_our_own_hash():
    """Node identity not yet discovered is a retry, not a verdict: answering
    node_mismatch would tell the scheduler to place it elsewhere for good."""
    content = _make_qemu_instance_message()
    content.requirements = SimpleNamespace(node=SimpleNamespace(node_hash="some-node"), gpu=None)

    verdict = compute_verdict(
        _plan(HASH_C, content=content), infos=[], registry=_registry({}), capacity=_capacity([]), node_hash=None
    )

    assert verdict.rejected[HASH_C]["code"] == "node_hash_unknown"


def test_a_planned_vm_the_supervisor_holds_dead_is_not_judged_against_itself():
    """A recreate: the stale registry record still counts as committed, so it
    has to be discounted or the VM is admitted against its own resources. The
    enforced path does this with check_capacity's exclude_vm_hash."""
    capacity = _capacity([AdmissionVerdict(HASH_C, True)])

    compute_verdict(
        _plan(HASH_C),
        infos=[_info(HASH_C, status=VmStatus.STOPPED)],
        registry=_registry({HASH_C: _record()}),
        capacity=capacity,
    )

    assert HASH_C in capacity.simulate.call_args.kwargs["releasing"]
