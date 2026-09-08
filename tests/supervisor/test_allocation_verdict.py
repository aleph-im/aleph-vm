"""The immediate answer to a plan push: what we take, drop, refuse or keep."""

from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent.allocation.plan import AllocationPlan, PlannedVm
from aleph.vm.agent.allocation.verdict import build_plan, compute_verdict
from aleph.vm.agent.capacity import AdmissionVerdict
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
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


def _record(*, stream=False, credit=False, vprogram=False, persistent=True):
    return SimpleNamespace(
        persistent=persistent,
        uses_payment_stream=stream,
        uses_payment_credit=credit,
        is_vprogram=vprogram,
        message=_make_qemu_instance_message(),
    )


def _registry(records):
    return SimpleNamespace(get=lambda vm_hash: records.get(vm_hash))


def _capacity(verdicts):
    return SimpleNamespace(simulate=MagicMock(return_value=verdicts))


def _verified(content=None):
    message = SimpleNamespace(content=content or _make_qemu_instance_message())
    return SimpleNamespace(message=message, original=message)


def _plan(*hashes, verified=True, content=None):
    entries = {h: PlannedVm(vm_hash=h, verified=_verified(content) if verified else None) for h in hashes}
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


@pytest.mark.parametrize(
    ("record", "info", "reason"),
    [
        (_record(persistent=False), _info(HASH_B), "non_persistent"),
        (_record(stream=True), _info(HASH_B), "payment_stream"),
        (_record(credit=True), _info(HASH_B), "payment_credit"),
        (_record(), _info(HASH_B, gpus=["0000:01:00.0"]), "gpu"),
        (_record(), _info(HASH_B, confidential=ConfidentialMode.SEV_SNP), "confidential"),
    ],
)
def test_every_reason_an_allocation_may_not_stop_a_vm_is_reported(record, info, reason):
    """_retention_reason has to stay a mirror of is_removable_by_allocation:
    a VM the one keeps and the other has no reason for comes back as
    operator_policy, which says nothing to the scheduler."""
    verdict = compute_verdict(_plan(), infos=[info], registry=_registry({HASH_B: record}), capacity=_capacity([]))

    assert verdict.removing == []
    assert verdict.retained[HASH_B] == reason


def test_a_vm_waiting_on_its_confidential_session_is_left_alone():
    """A confidential VM is created but not started: only its owner can boot
    it, by uploading the session certificates. It is not running, so the
    status alone reads as a recreate, and re-creating it would throw away the
    VM the owner is about to send its secret to."""
    awaiting = _info(HASH_A, status=VmStatus.STOPPED)
    awaiting.awaiting_confidential_init = True

    verdict = compute_verdict(
        _plan(HASH_A), infos=[awaiting], registry=_registry({HASH_A: _record()}), capacity=_capacity([])
    )

    assert verdict.unchanged == [HASH_A]
    assert verdict.accepted == []


@pytest.mark.parametrize(
    ("record", "info"),
    [
        (None, _info(HASH_B)),
        (_record(), _info(HASH_B, status=VmStatus.STOPPED)),
    ],
    ids=["no record of it", "not running"],
)
def test_a_vm_outside_the_plan_we_cannot_speak_for_is_not_reported(record, info):
    """Neither dropped nor kept. One we hold no record for we know nothing
    about, and one already stopped needs nothing done to it."""
    verdict = compute_verdict(
        _plan(), infos=[info], registry=_registry({HASH_B: record} if record else {}), capacity=_capacity([])
    )

    assert verdict.removing == [] and verdict.retained == {}


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


@pytest.mark.parametrize("body", [{"vms": 5}, {"vms": None}, {"vms": "abc"}, {}, []])
def test_a_body_we_cannot_read_is_refused_not_read_as_an_empty_plan(body):
    """An empty plan stops everything this node runs, so a malformed body must
    not resolve to one. The string case is the dangerous one: it was walked
    character by character and answered as a plan of nothing at all."""
    with pytest.raises(ValueError, match="vms"):
        build_plan(body, now=NOW)


def test_an_explicitly_empty_plan_is_still_accepted():
    """The scheduler wanting nothing here is a real push, not a malformed one."""
    plan, rejected = build_plan({"vms": []}, now=NOW)

    assert plan.entries == {} and rejected == {}


def test_a_hash_refused_once_does_not_enter_the_plan_on_a_second_entry():
    """A duplicate hash used to land in both halves of the answer, telling the
    scheduler the same VM was refused and pending at once, and the plan then
    carried an entry the answer had refused."""
    refused_first = {"vms": [{"item_hash": str(HASH_A), "message": "not-an-object"}, {"item_hash": str(HASH_A)}]}
    refused_second = {"vms": [{"item_hash": str(HASH_A)}, {"item_hash": str(HASH_A), "message": "not-an-object"}]}

    for body in (refused_first, refused_second):
        plan, rejected = build_plan(body, now=NOW)

        assert HASH_A in rejected
        assert list(plan.entries) == []


def test_swapping_which_half_a_hash_lands_in_changes_the_plan_id():
    """One merged sorted list gave the same identity to a push that planned A
    and refused B as to one that planned B and refused A."""
    planned_a = {"vms": [{"item_hash": str(HASH_A)}, {"item_hash": str(HASH_B), "message": "not-an-object"}]}
    planned_b = {"vms": [{"item_hash": str(HASH_B)}, {"item_hash": str(HASH_A), "message": "not-an-object"}]}

    first, first_rejected = build_plan(planned_a, now=NOW)
    second, second_rejected = build_plan(planned_b, now=NOW)

    assert list(first.entries) == [HASH_A] and list(first_rejected) == [HASH_B]
    assert list(second.entries) == [HASH_B] and list(second_rejected) == [HASH_A]
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


def _real_capacity(mocker, *, memory_gib=64, registry=None):
    """A real CapacityManager over a stubbed host.

    The double the other tests use answers whatever it was handed, so nothing
    it agrees to says anything about what simulate does with a plan.
    """
    from unittest.mock import AsyncMock

    from aleph.vm.agent.capacity import CapacityManager
    from aleph.vm.agent.vm_registry import AgentVmRegistry
    from aleph.vm.supervisor_interface.types import HostInfo

    mocker.patch(
        "aleph.vm.agent.capacity.psutil.virtual_memory",
        return_value=mocker.Mock(total=memory_gib * 1024**3),
    )
    mocker.patch("aleph.vm.agent.capacity.psutil.cpu_count", return_value=16)
    mocker.patch.object(CapacityManager, "_available_disk_bytes", return_value=100 * 1024**3)
    # The per-volume check walks the pools directly, not _available_disk_bytes,
    # and asks each what it could reclaim. Neither exists on a CI runner.
    mocker.patch(
        "aleph.vm.agent.capacity.storage_pools.eligible_pool_free_bytes",
        return_value=[(SimpleNamespace(path=Path("/pool0"), index=0), 100 * 1024**3)],
    )
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=0)
    supervisor = SimpleNamespace(get_host_info=AsyncMock(return_value=HostInfo(gpu_inventory=[], available_gpus=[])))
    return CapacityManager(supervisor, registry or AgentVmRegistry())


def _tight_host(mocker):
    """40 GiB, less the two reservations, leaves a 30720 MiB instance bucket:
    room for one 16384 MiB instance and not two."""
    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)


def _registry_holding(vm_hash, memory_mib):
    registry = AgentVmRegistry()
    recorded = _make_qemu_instance_message(memory=memory_mib)
    registry.record(vm_hash, message=recorded, original=recorded, persistent=True)
    return registry


def test_compute_verdict_drives_the_real_capacity_manager(mocker):
    """Every other test here hands compute_verdict a double, so the shape of
    CapacityManager.simulate is never exercised: when the candidate tuple lost
    its third element, the double kept agreeing with a signature production no
    longer had and all of these stayed green. Wire the real one in once.
    """
    capacity = _real_capacity(mocker)

    verdict = compute_verdict(_plan(HASH_C), infos=[], registry=_registry({}), capacity=capacity)

    assert verdict.accepted == [HASH_C]


def test_a_recreate_is_not_judged_against_its_own_stale_record(mocker):
    """The supervisor holds C dead and the registry still has its record, so
    the memory it asks for is counted twice unless the record is discounted.
    simulate does that for every candidate, which is why compute_verdict no
    longer lists a recreate as released.
    """
    _tight_host(mocker)
    registry = _registry_holding(HASH_C, 16384)
    capacity = _real_capacity(mocker, memory_gib=40, registry=registry)

    verdict = compute_verdict(
        _plan(HASH_C, content=_make_qemu_instance_message(memory=16384)),
        infos=[_info(HASH_C, status=VmStatus.STOPPED)],
        registry=registry,
        capacity=capacity,
    )

    assert verdict.accepted == [HASH_C]


def test_a_recreate_still_waiting_on_its_message_frees_nothing(mocker):
    """C is planned but carries no message, so it is pending a CCN fetch and
    nothing is stopping it. Releasing it would hand its 16384 MiB to A and
    answer yes where the enforced path, which still sees C's record, answers
    no: an advisory verdict must never be the stronger of the two.
    """
    _tight_host(mocker)
    registry = _registry_holding(HASH_C, 16384)
    capacity = _real_capacity(mocker, memory_gib=40, registry=registry)
    plan = AllocationPlan(
        plan_id="sha256:test",
        received_at=NOW,
        entries={
            HASH_C: PlannedVm(vm_hash=HASH_C, verified=None),
            HASH_A: PlannedVm(vm_hash=HASH_A, verified=_verified(_make_qemu_instance_message(memory=16384))),
        },
    )

    verdict = compute_verdict(
        plan, infos=[_info(HASH_C, status=VmStatus.STOPPED)], registry=registry, capacity=capacity
    )

    assert verdict.pending == [HASH_C]
    assert verdict.rejected[HASH_A]["code"] == "insufficient_capacity"
