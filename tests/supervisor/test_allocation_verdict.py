"""The immediate answer to a plan push: what we take, drop, refuse or keep."""

import asyncio
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from conftest import instance_content_dict, sign_message
from eth_account import Account
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent.allocation import verdict as verdict_module
from aleph.vm.agent.allocation.plan import AllocationPlan, PlannedVm, PlanVerdict
from aleph.vm.agent.allocation.verdict import build_plan, compute_verdict, narrow_plan
from aleph.vm.agent.capacity import AdmissionVerdict, CapacityManager
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.resources import GpuDevice, GpuDeviceClass
from aleph.vm.supervisor_interface.types import ConfidentialMode, HostInfo, VmStatus

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
    return SimpleNamespace(message=SimpleNamespace(content=content or _make_qemu_instance_message()))


def _plan(*hashes, verified=True, content=None):
    entries = {h: PlannedVm(vm_hash=h, verified=_verified(content) if verified else None) for h in hashes}
    return AllocationPlan(plan_id="sha256:test", received_at=NOW, entries=entries)


def test_a_running_vm_still_in_the_plan_is_unchanged():
    verdict = compute_verdict(
        _plan(HASH_A), infos=[_info(HASH_A)], registry=_registry({HASH_A: _record()}), capacity=_capacity([])
    )

    assert verdict.unchanged == [HASH_A]
    assert verdict.accepted == []


def test_a_stopped_vm_still_in_the_plan_is_unchanged_and_never_sized():
    """A VM this node holds stopped is a VM this node holds. The scheduler's
    belief that it is allocated here is exactly what has not changed, so the
    answer says so instead of sizing it: sized as a candidate, a node that is
    tight on room refuses a VM it is already holding, and a refusal is what
    takes the VM out of the plan the loop converges on."""
    capacity = _capacity([])

    verdict = compute_verdict(
        _plan(HASH_A),
        infos=[_info(HASH_A, status=VmStatus.STOPPED)],
        registry=_registry({HASH_A: _record()}),
        capacity=capacity,
    )

    assert verdict.unchanged == [HASH_A]
    assert verdict.accepted == []
    assert capacity.simulate.call_args.args[0] == []


def test_a_vm_caught_mid_stop_is_unchanged_too():
    """STOPPING is a stop in flight, not a VM to rebuild."""
    verdict = compute_verdict(
        _plan(HASH_A),
        infos=[_info(HASH_A, status=VmStatus.STOPPING)],
        registry=_registry({HASH_A: _record()}),
        capacity=_capacity([]),
    )

    assert verdict.unchanged == [HASH_A]


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


def test_a_vm_id_that_is_not_a_hash_is_dropped_not_raised_on():
    """The supervisor's list is not ours to vouch for: an operator's own VM, or
    a second tenant's, carries an id we cannot parse. Converting it unguarded
    took the whole push down over a VM the push says nothing about, which is
    the rule build_plan already holds its own entries to."""
    verdict = compute_verdict(
        _plan(HASH_C),
        infos=[_info("operator-scratch-vm"), _info(HASH_B)],
        registry=_registry({HASH_B: _record()}),
        capacity=_capacity([AdmissionVerdict(HASH_C, True)]),
    )

    assert verdict.accepted == [HASH_C]
    assert verdict.removing == [HASH_B]


def test_a_running_vm_absent_from_the_plan_is_removing():
    verdict = compute_verdict(
        _plan(), infos=[_info(HASH_B)], registry=_registry({HASH_B: _record()}), capacity=_capacity([])
    )

    assert verdict.removing == [HASH_B]


def test_a_running_vm_the_push_refused_is_retained_not_removing():
    """A hash the push named and this node refused is not one the push took
    away. The loop keeps that VM, so the answer has to say the same: told the
    VM is going away, a scheduler that believes it and stops naming the hash
    has the VM torn down on the very next push, which is the destruction
    refusing it was supposed to avoid. Its memory is not being freed either,
    so it must not reach simulate as released capacity and buy room for the
    other candidates.
    """
    plan = AllocationPlan(plan_id="sha256:test", received_at=NOW, entries={}, refused=frozenset({HASH_B}))
    capacity = _capacity([])

    verdict = compute_verdict(plan, infos=[_info(HASH_B)], registry=_registry({HASH_B: _record()}), capacity=capacity)

    assert verdict.removing == []
    assert verdict.retained[HASH_B] == "refused"
    assert capacity.simulate.call_args.kwargs["releasing"] == frozenset()


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


def test_a_vm_whose_teardown_is_in_flight_is_not_answered_unchanged():
    """The supervisor still lists a VM whose delete is running, so the status
    alone says "up" for one that is on its way to GONE with its disks reaped.
    Answering unchanged would tell the scheduler nothing is happening to a VM
    the loop is about to rebuild from scratch, so the push is judged as what
    it is: a request to have this VM here again."""
    verdict = compute_verdict(
        _plan(HASH_A),
        infos=[_info(HASH_A)],
        registry=_registry({HASH_A: _record()}),
        capacity=_capacity([AdmissionVerdict(HASH_A, True)]),
        removing_now=frozenset({HASH_A}),
    )

    assert verdict.unchanged == []
    assert verdict.accepted == [HASH_A]
    # Named by the push, so never reported as something this push stops.
    assert verdict.removing == []


def test_a_vm_being_torn_down_with_no_message_is_pending_not_unchanged():
    """The same rule where the push carries no message to size: the honest
    answer is that the agent has not judged it yet, not that it is up."""
    verdict = compute_verdict(
        _plan(HASH_A, verified=False),
        infos=[_info(HASH_A)],
        registry=_registry({HASH_A: _record()}),
        capacity=_capacity([]),
        removing_now=frozenset({HASH_A}),
    )

    assert verdict.unchanged == []
    assert verdict.pending == [HASH_A]


def test_a_vm_being_torn_down_that_the_push_drops_is_still_removing():
    """The in-flight set only speaks about VMs the push names. One it does not
    name is being removed, which is exactly what the answer already said."""
    verdict = compute_verdict(
        _plan(),
        infos=[_info(HASH_B)],
        registry=_registry({HASH_B: _record()}),
        capacity=_capacity([]),
        removing_now=frozenset({HASH_B}),
    )

    assert verdict.removing == [HASH_B]


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


@pytest.mark.asyncio
async def test_the_same_plan_produces_the_same_plan_id():
    body = {"vms": [{"item_hash": str(HASH_A)}, {"item_hash": str(HASH_C)}]}
    reversed_body = {"vms": [{"item_hash": str(HASH_C)}, {"item_hash": str(HASH_A)}]}

    first, _ = await build_plan(body, now=NOW)
    second, _ = await build_plan(reversed_body, now=NOW)

    assert first.plan_id == second.plan_id


@pytest.mark.asyncio
async def test_a_different_plan_produces_a_different_plan_id():
    first, _ = await build_plan({"vms": [{"item_hash": str(HASH_A)}]}, now=NOW)
    second, _ = await build_plan({"vms": [{"item_hash": str(HASH_B)}]}, now=NOW)

    assert first.plan_id != second.plan_id


@pytest.mark.parametrize("body", [{"vms": 5}, {"vms": None}, {"vms": "abc"}, {}, []])
@pytest.mark.asyncio
async def test_a_body_we_cannot_read_is_refused_not_read_as_an_empty_plan(body):
    """An empty plan stops everything this node runs, so a malformed body must
    not resolve to one. The string case is the dangerous one: it was walked
    character by character and answered as a plan of nothing at all."""
    with pytest.raises(ValueError, match="vms"):
        await build_plan(body, now=NOW)


@pytest.mark.asyncio
async def test_an_explicitly_empty_plan_is_still_accepted():
    """The scheduler wanting nothing here is a real push, not a malformed one."""
    plan, rejected = await build_plan({"vms": []}, now=NOW)

    assert plan.entries == {} and rejected == {}


@pytest.mark.asyncio
async def test_a_rejected_key_holding_the_separator_does_not_pass_for_two():
    """Rejected keys are whatever the push sent in place of a hash, so one
    refusing a single key with a newline in it must not share an identity with
    one refusing the two keys either side of that newline."""
    one, _ = await build_plan({"vms": [{"item_hash": "a\nb"}]}, now=NOW)
    two, _ = await build_plan({"vms": [{"item_hash": "a"}, {"item_hash": "b"}]}, now=NOW)

    assert one.plan_id != two.plan_id


@pytest.mark.asyncio
async def test_a_hash_refused_once_does_not_enter_the_plan_on_a_second_entry():
    """A duplicate hash used to land in both halves of the answer, telling the
    scheduler the same VM was refused and pending at once, and the plan then
    carried an entry the answer had refused."""
    refused_first = {"vms": [{"item_hash": str(HASH_A), "message": "not-an-object"}, {"item_hash": str(HASH_A)}]}
    refused_second = {"vms": [{"item_hash": str(HASH_A)}, {"item_hash": str(HASH_A), "message": "not-an-object"}]}

    for body in (refused_first, refused_second):
        plan, rejected = await build_plan(body, now=NOW)

        assert HASH_A in rejected
        assert list(plan.entries) == []


@pytest.mark.asyncio
async def test_swapping_which_half_a_hash_lands_in_changes_the_plan_id():
    """One merged sorted list gave the same identity to a push that planned A
    and refused B as to one that planned B and refused A."""
    planned_a = {"vms": [{"item_hash": str(HASH_A)}, {"item_hash": str(HASH_B), "message": "not-an-object"}]}
    planned_b = {"vms": [{"item_hash": str(HASH_B)}, {"item_hash": str(HASH_A), "message": "not-an-object"}]}

    first, first_rejected = await build_plan(planned_a, now=NOW)
    second, second_rejected = await build_plan(planned_b, now=NOW)

    assert list(first.entries) == [HASH_A] and list(first_rejected) == [HASH_B]
    assert list(second.entries) == [HASH_B] and list(second_rejected) == [HASH_A]
    assert first.plan_id != second.plan_id


@pytest.mark.asyncio
async def test_an_entry_with_an_unusable_item_hash_is_rejected_not_raised():
    """build_plan is the validation boundary for a body the scheduler controls,
    so one bad entry must not take the whole push down with it."""
    body = {"vms": [{"item_hash": "not-a-hash"}, {}, {"item_hash": str(HASH_A)}]}

    plan, rejected = await build_plan(body, now=NOW)

    assert list(plan.entries) == [HASH_A]
    assert rejected["not-a-hash"]["code"] == "invalid_message"
    assert rejected["None"]["code"] == "invalid_message"
    # Neither key names a VM this node could be running, so neither is worth
    # protecting from the teardown pass.
    assert plan.refused == frozenset()


@pytest.mark.asyncio
async def test_a_hash_whose_message_will_not_verify_is_still_a_hash_the_push_named():
    """The push named this VM; all we refused is the message it carried. The
    convergence loop deletes what the push left out, so leaving the hash out
    of the plan entirely means a corrupt entry, from a scheduler bug or a bad
    CCN read, reaps the disks of a VM that is running here perfectly well."""
    body = {"vms": [{"item_hash": str(HASH_A), "message": "not-an-object"}, {"item_hash": str(HASH_B)}]}

    plan, rejected = await build_plan(body, now=NOW)

    assert rejected[HASH_A]["code"] == "invalid_message"
    assert list(plan.entries) == [HASH_B]
    assert plan.refused == frozenset({HASH_A})


@pytest.mark.asyncio
async def test_narrowing_carries_the_refusals_the_plan_arrived_with():
    """Two refusals reach the loop by different routes: build_plan's, over a
    message it would not verify, and the answer's, over a host with no room.
    Both name a VM the push listed, so both have to survive narrowing."""
    plan, _ = await build_plan(
        {"vms": [{"item_hash": str(HASH_A), "message": "not-an-object"}, {"item_hash": str(HASH_B)}]}, now=NOW
    )
    verdict = PlanVerdict(rejected={HASH_B: {"code": "insufficient_capacity"}})

    narrowed = narrow_plan(plan, verdict)

    assert narrowed.entries == {}
    assert narrowed.refused == frozenset({HASH_A, HASH_B})


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


def test_a_stopped_vm_keeps_its_capacity_committed(mocker):
    """Not restarting a stopped VM is not forgetting it. The definition and
    the volumes are still allocated, so its memory and vCPUs stay committed
    and the headroom the node advertises stays reduced by them. Freeing them
    on a stop is how a node over-provisions: it would promise the same room
    to somebody else and then have nowhere to put the VM when its owner
    starts it again."""
    _tight_host(mocker)
    registry = _registry_holding(HASH_C, 16384)
    capacity = _real_capacity(mocker, memory_gib=40, registry=registry)

    verdict = compute_verdict(
        _plan(HASH_C),
        infos=[_info(HASH_C, status=VmStatus.STOPPED)],
        registry=registry,
        capacity=capacity,
    )

    assert verdict.unchanged == [HASH_C]
    # 40 GiB less the two reservations is a 30720 MiB bucket, less the
    # stopped VM's 16384 MiB.
    assert capacity.headroom()["instance_memory_mib"] == 30720 - 16384


def test_a_newcomer_is_refused_the_room_a_stopped_vm_holds(mocker):
    """The same guarantee from the other side. A is only admissible if C's
    memory has been handed back, and it has not been: C is stopped, not gone.
    The answer has to be no, or the node ends up with two VMs claiming one
    bucket the moment C's owner starts it again."""
    _tight_host(mocker)
    registry = _registry_holding(HASH_C, 16384)
    capacity = _real_capacity(mocker, memory_gib=40, registry=registry)
    plan = AllocationPlan(
        plan_id="sha256:test",
        received_at=NOW,
        entries={
            HASH_C: PlannedVm(vm_hash=HASH_C, verified=_verified(_make_qemu_instance_message(memory=16384))),
            HASH_A: PlannedVm(vm_hash=HASH_A, verified=_verified(_make_qemu_instance_message(memory=16384))),
        },
    )

    verdict = compute_verdict(
        plan, infos=[_info(HASH_C, status=VmStatus.STOPPED)], registry=registry, capacity=capacity
    )

    assert verdict.unchanged == [HASH_C]
    assert verdict.rejected[HASH_A]["code"] == "insufficient_capacity"


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
        infos=[_info(HASH_C, status=VmStatus.FAILED)],
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

    verdict = compute_verdict(plan, infos=[_info(HASH_C, status=VmStatus.FAILED)], registry=registry, capacity=capacity)

    assert verdict.pending == [HASH_C]
    assert verdict.rejected[HASH_A]["code"] == "insufficient_capacity"


DEVICE_ID = "10de:2504"


def _gpu_message(device_id=DEVICE_ID):
    from aleph_message.models.execution.environment import (
        GpuProperties,
        HostRequirements,
    )

    card = GpuProperties(vendor="NVIDIA", device_name="GH100", device_class="0300", device_id=device_id)
    return _make_qemu_instance_message().model_copy(update={"requirements": HostRequirements(gpu=[card])})


def _card(device_id=DEVICE_ID):
    return GpuDevice(
        vendor="NVIDIA",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host="0000:01:00.0",
        device_id=device_id,
    )


def test_a_gpu_candidate_is_refused_when_no_inventory_reached_the_verdict(mocker):
    """simulate's rule, seen from here: with nothing to judge a card against,
    a candidate asking for one is refused rather than admitted on memory."""
    verdict = compute_verdict(
        _plan(HASH_C, content=_gpu_message()), infos=[], registry=_registry({}), capacity=_real_capacity(mocker)
    )

    assert verdict.rejected[HASH_C]["code"] == "gpu_unavailable"


def test_a_gpu_candidate_is_judged_against_the_inventory_the_caller_read(mocker):
    """Reading the host's cards is async and this is not, so the handler reads
    them and hands them in; from here on a GPU VM can be placed."""
    verdict = compute_verdict(
        _plan(HASH_C, content=_gpu_message()),
        infos=[],
        registry=_registry({}),
        capacity=_real_capacity(mocker),
        available_gpus=[_card()],
    )

    assert verdict.accepted == [HASH_C]
    assert verdict.rejected == {}


def test_narrowing_drops_what_the_answer_refused_and_nothing_else():
    """What reaches the reconciler is the push less its refusals. A refused
    entry left in would be retried forever at backoff rate, and started the
    moment room appeared, after the scheduler was told no and placed it
    elsewhere. Pending entries were not judged and stay; so does the identity,
    which is the push's, not the host's room at the time."""
    plan = AllocationPlan(
        plan_id="sha256:push",
        received_at=NOW,
        entries={
            HASH_A: PlannedVm(vm_hash=HASH_A, verified=_verified()),
            HASH_B: PlannedVm(vm_hash=HASH_B, verified=_verified()),
            HASH_C: PlannedVm(vm_hash=HASH_C, verified=None),
        },
    )
    verdict = PlanVerdict(accepted=[HASH_A], pending=[HASH_C], rejected={HASH_B: {"code": "insufficient_capacity"}})

    narrowed = narrow_plan(plan, verdict)

    assert set(narrowed.entries) == {HASH_A, HASH_C}
    assert narrowed.entries[HASH_A] is plan.entries[HASH_A]
    assert (narrowed.plan_id, narrowed.received_at) == (plan.plan_id, plan.received_at)
    assert narrowed.refused == frozenset({HASH_B})


def test_a_dead_vm_the_answer_refused_is_carried_as_refused():
    """The chain the reconciler reads. The supervisor holds C dead, so the
    answer sizes it as a candidate to rebuild instead of reading it as
    unchanged, and a node with no room left refuses it. Narrowing has to keep it out of the
    entries, or the loop would retry it forever, but dropping it silently is
    what turned "rejected" into "deleted": to the loop a hash the plan does
    not list is one the scheduler took away, and it reaps the disks of every
    VM it takes away."""
    plan = _plan(HASH_C)
    capacity = _capacity([AdmissionVerdict(HASH_C, False, "insufficient_capacity", "not enough capacity on this CRN")])

    verdict = compute_verdict(
        plan,
        infos=[_info(HASH_C, status=VmStatus.FAILED)],
        registry=_registry({HASH_C: _record()}),
        capacity=capacity,
    )
    narrowed = narrow_plan(plan, verdict)

    assert verdict.rejected[HASH_C]["code"] == "insufficient_capacity"
    assert narrowed.entries == {}
    assert narrowed.refused == frozenset({HASH_C})


def test_a_vm_refused_for_an_undiscovered_node_hash_is_carried_as_refused():
    """The same, for the refusal that is purely transient: right after a
    restart the agent has not read its own hash back, so every VM the push
    pins to this node is refused for that one pass. Reading those refusals as
    deletions would make a restart wipe the node."""
    content = _make_qemu_instance_message()
    content.requirements = SimpleNamespace(node=SimpleNamespace(node_hash="some-node"), gpu=None)
    plan = _plan(HASH_C, content=content)

    verdict = compute_verdict(
        plan,
        infos=[_info(HASH_C, status=VmStatus.FAILED)],
        registry=_registry({HASH_C: _record()}),
        capacity=_capacity([]),
        node_hash=None,
    )
    narrowed = narrow_plan(plan, verdict)

    assert verdict.rejected[HASH_C]["code"] == "node_hash_unknown"
    assert narrowed.refused == frozenset({HASH_C})


def _signed_entry(account, index: int) -> dict:
    """One plan entry carrying a genuinely signed message, unique per index."""
    content = instance_content_dict(account.address)
    content["time"] = float(index)
    message = sign_message(content, account)
    return {"item_hash": message["item_hash"], "message": message}


@pytest.mark.asyncio
async def test_a_large_plan_is_verified_without_holding_the_event_loop():
    """A push is capped at 8 MiB, which is thousands of entries, and every one
    of them costs a pydantic parse and an ecrecover. Run inline, those seconds
    are seconds in which the agent answers nothing else: not a status request,
    not a supervisor callback, not the convergence loop.

    The pin is a second task that has to get its turns while the plan is being
    verified. With the work on the loop it never starts at all until the
    answer is ready, because nothing in build_plan yields.
    """
    account = Account.create()
    body = {"vms": [_signed_entry(account, index) for index in range(300)]}
    served = asyncio.Event()

    async def concurrent_work():
        for _ in range(50):
            await asyncio.sleep(0)
        served.set()

    ticking = asyncio.create_task(concurrent_work())
    plan, rejected = await build_plan(body, now=NOW)
    # Read before awaiting the task, or the reading is what let it run.
    served_during_verification = served.is_set()
    await ticking

    assert served_during_verification, "the event loop was held for the whole of the verification"
    assert rejected == {}
    assert len(plan.entries) == 300
    assert all(planned.verified is not None for planned in plan.entries.values())


@pytest.mark.asyncio
async def test_the_entries_reach_the_thread_in_bounded_batches(monkeypatch):
    """One hop for the whole push would hold a worker thread for as long as the
    plan is long, and give the loop a single checkpoint at the very start of
    it. The batch bounds both."""
    batches: list[int] = []
    judge = verdict_module.judge_entries

    def counting_judge(entries):
        batches.append(len(entries))
        return judge(entries)

    monkeypatch.setattr(verdict_module, "judge_entries", counting_judge)
    body = {"vms": [{"item_hash": f"{index:064x}"} for index in range(70)]}

    plan, rejected = await build_plan(body, now=NOW)

    assert len(plan.entries) == 70 and rejected == {}
    assert batches == [32, 32, 6]
    assert max(batches) <= verdict_module.VERIFICATION_BATCH_SIZE
