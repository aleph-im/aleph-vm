"""What the CRN advertises per VM once allocation is asynchronous.

Two disjoint fields: `state` is the supervisor's VmStatus, verbatim, and
`allocation` covers the phases that precede the supervisor knowing the VM at
all. They are never merged into one enum, which would have to be maintained in
lockstep with VmStatus forever.
"""

import json
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent.allocation import reconciler as reconciler_module
from aleph.vm.agent.allocation.plan import (
    AllocationPlan,
    AllocationState,
    FailureRecord,
    PlannedVm,
)
from aleph.vm.agent.allocation.refusal import (
    AllocationFailureCode,
    public_failure_message,
)
from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.supervisor_interface.types import (
    Backend,
    HostInfo,
    IpAssignment,
    VmId,
    VmInfo,
    VmStatus,
)

NOW = datetime(2026, 8, 25, tzinfo=timezone.utc)
HASH_A = ItemHash("a" * 64)
HASH_C = ItemHash("c" * 64)
LIST = "/v2/about/executions/list"


def _info(vm_hash, status=VmStatus.RUNNING) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(vm_hash)),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


def _reconciler(*, planned=(), pending=(), states=None):
    """A double over the three reads the list makes: the plan, the entries
    still waiting on their message, and the loop's own state per VM."""
    states = states or {}
    return SimpleNamespace(
        planned_hashes=lambda: set(planned),
        pending_hashes=lambda: set(pending),
        state_for=lambda vm_hash: states.get(vm_hash, (None, None)),
        # The app starts the loop and wires the event watcher to it.
        run=AsyncMock(),
        notify_vm_down=MagicMock(),
    )


def _app(*, infos=(), reconciler=None, real_reconciler=False):
    """The agent app over a fake supervisor. The reconciler is a double unless
    a test needs a record the loop itself wrote."""
    supervisor = MagicMock(
        list_vms=AsyncMock(return_value=list(infos)),
        get_host_info=AsyncMock(return_value=HostInfo(host_ipv4="10.0.0.1")),
        list_port_forwards=AsyncMock(return_value=[]),
    )
    app = setup_webapp(supervisor=supervisor)
    if not real_reconciler:
        app["allocation_reconciler"] = reconciler or _reconciler()
    return app


async def _listing(aiohttp_client, app):
    client = await aiohttp_client(app)
    response = await client.get(LIST)
    assert response.status == 200
    return await response.json()


@pytest.mark.asyncio
async def test_a_planned_vm_the_loop_has_not_reached_is_visible(aiohttp_client):
    """Otherwise the scheduler cannot tell 'working on it' from 'never heard
    of it', which is exactly what it used to have to guess."""
    body = await _listing(aiohttp_client, _app(reconciler=_reconciler(planned=[HASH_C])))

    assert body[str(HASH_C)]["state"] is None
    assert body[str(HASH_C)]["allocation"]["state"] == "planned"
    assert body[str(HASH_C)]["running"] is False


@pytest.mark.asyncio
async def test_a_planned_vm_still_waiting_on_its_message_says_so(aiohttp_client):
    reconciler = _reconciler(planned=[HASH_C], pending=[HASH_C])

    body = await _listing(aiohttp_client, _app(reconciler=reconciler))

    assert body[str(HASH_C)]["allocation"]["state"] == "resolving"


@pytest.mark.asyncio
async def test_the_loops_own_state_wins_over_the_derived_one(aiohttp_client):
    reconciler = _reconciler(planned=[HASH_C], pending=[HASH_C], states={HASH_C: (AllocationState.DOWNLOADING, None)})

    body = await _listing(aiohttp_client, _app(reconciler=reconciler))

    assert body[str(HASH_C)]["allocation"]["state"] == "downloading"


@pytest.mark.asyncio
async def test_a_failed_allocation_reports_its_reason_and_retry_time(aiohttp_client):
    """The reason is the code and the sentence that belongs to it. This
    listing is unauthenticated, so it never carries a line written by an
    exception, only one written for a reader."""
    failure = FailureRecord(
        code=AllocationFailureCode.DOWNLOAD_FAILED,
        attempts=2,
        first_failed_at=NOW,
        last_failed_at=NOW,
        next_retry_at=NOW + timedelta(seconds=60),
    )
    reconciler = _reconciler(planned=[HASH_C], states={HASH_C: (AllocationState.FAILED, failure)})

    body = await _listing(aiohttp_client, _app(reconciler=reconciler))

    allocation = body[str(HASH_C)]["allocation"]
    assert allocation["state"] == "failed"
    assert allocation["error"] == {
        "code": "download_failed",
        "message": public_failure_message(AllocationFailureCode.DOWNLOAD_FAILED),
    }
    assert allocation["attempts"] == 2
    # Rendered the way the status times are, by the same serializer.
    assert allocation["next_retry_at"] == "2026-08-25 00:01:00+00:00"


@pytest.mark.asyncio
async def test_a_start_that_raised_never_publishes_the_exceptions_text(aiohttp_client, monkeypatch):
    """End to end, from the exception the create raised to the JSON: a start
    that failed for a reason nobody classified says so and no more. The text
    of a create failure quotes host paths, download URLs and the node's own
    capacity, and this endpoint answers anyone who asks."""
    secret = "/var/lib/aleph/vm/deadbeef/private-volume.img"

    async def fails(*_args, **_kwargs):
        raise RuntimeError(f"could not open {secret}")

    monkeypatch.setattr(reconciler_module, "start_persistent_vm", fails)
    app = _app(real_reconciler=True)
    reconciler = app["allocation_reconciler"]
    reconciler.submit(AllocationPlan(plan_id="sha256:test", received_at=NOW, entries={HASH_C: PlannedVm(HASH_C)}))
    await reconciler._converge_once()

    body = await _listing(aiohttp_client, app)

    assert body[str(HASH_C)]["allocation"]["error"] == {"code": "internal", "message": "Unhandled error"}
    assert secret not in json.dumps(body)


@pytest.mark.asyncio
async def test_a_start_refused_for_want_of_room_says_which_kind_of_failure_it_was(aiohttp_client, monkeypatch):
    """The other half: a typed refusal keeps its own code, so the scheduler
    can tell a full node from a broken one, and still publishes none of the
    figures the refusal was written with."""

    async def fails(*_args, **_kwargs):
        raise InsufficientResourcesError(
            "Insufficient capacity to create VM. Node has 512 MiB free",
            required={"memory_mib": 4096},
            available={"memory_mib": 512},
        )

    monkeypatch.setattr(reconciler_module, "start_persistent_vm", fails)
    app = _app(real_reconciler=True)
    reconciler = app["allocation_reconciler"]
    reconciler.submit(AllocationPlan(plan_id="sha256:test", received_at=NOW, entries={HASH_C: PlannedVm(HASH_C)}))
    await reconciler._converge_once()

    body = await _listing(aiohttp_client, app)

    error = body[str(HASH_C)]["allocation"]["error"]
    assert error["code"] == "insufficient_capacity"
    assert error["message"] == public_failure_message(AllocationFailureCode.INSUFFICIENT_CAPACITY)
    assert "512 MiB" not in json.dumps(body)


@pytest.mark.asyncio
async def test_a_running_vm_reports_the_supervisors_status_and_no_allocation_block(aiohttp_client):
    body = await _listing(aiohttp_client, _app(infos=[_info(HASH_A)]))

    assert body[str(HASH_A)]["state"] == "running"
    assert body[str(HASH_A)]["allocation"] is None
    # Existing consumers keep working: an alias of state, not a second truth.
    assert body[str(HASH_A)]["running"] is True


@pytest.mark.asyncio
async def test_a_planned_vm_the_supervisor_runs_is_listed_once_with_no_allocation_block(aiohttp_client):
    """The plan's entry and the supervisor's are the same VM."""
    body = await _listing(aiohttp_client, _app(infos=[_info(HASH_A)], reconciler=_reconciler(planned=[HASH_A])))

    assert list(body) == [str(HASH_A)]
    assert body[str(HASH_A)]["allocation"] is None


@pytest.mark.asyncio
async def test_a_vm_the_supervisor_holds_dead_still_carries_the_agents_failure(aiohttp_client):
    """Disjoint fields, both present: the supervisor's word on the VM it has,
    and the agent's on why the recreate is not happening."""
    failure = FailureRecord(
        code=AllocationFailureCode.INTERNAL,
        attempts=1,
        first_failed_at=NOW,
        last_failed_at=NOW,
        next_retry_at=NOW,
    )
    reconciler = _reconciler(planned=[HASH_A], states={HASH_A: (AllocationState.FAILED, failure)})

    body = await _listing(aiohttp_client, _app(infos=[_info(HASH_A, VmStatus.FAILED)], reconciler=reconciler))

    assert body[str(HASH_A)]["state"] == "failed"
    assert body[str(HASH_A)]["allocation"]["state"] == "failed"


@pytest.mark.asyncio
async def test_a_planned_vm_the_owner_stopped_reports_only_the_supervisors_word(aiohttp_client):
    """A VM waiting for the next push to be started again is not failing and
    is not being worked on, so the agent has nothing to add: the reconciler
    keeps no state for it and the listing renders no allocation block. Saying
    "failed" here would report an owner's stop as a fault of the node."""
    reconciler = _reconciler(planned=[HASH_A])

    body = await _listing(aiohttp_client, _app(infos=[_info(HASH_A, VmStatus.STOPPED)], reconciler=reconciler))

    assert body[str(HASH_A)]["state"] == "stopped"
    assert body[str(HASH_A)]["allocation"] is None
    assert body[str(HASH_A)]["running"] is False


@pytest.mark.asyncio
async def test_a_vm_the_supervisor_holds_dead_shows_the_recreate_in_flight(aiohttp_client):
    """The other half of the same claim: the loop is downloading for a VM
    the supervisor still lists as dead, so both words are out at once."""
    reconciler = _reconciler(planned=[HASH_A], states={HASH_A: (AllocationState.DOWNLOADING, None)})

    body = await _listing(aiohttp_client, _app(infos=[_info(HASH_A, VmStatus.FAILED)], reconciler=reconciler))

    assert body[str(HASH_A)]["state"] == "failed"
    assert body[str(HASH_A)]["allocation"] == {
        "state": "downloading",
        "attempts": 0,
        "error": None,
        "next_retry_at": None,
    }


@pytest.mark.asyncio
async def test_an_absent_vm_keeps_the_shape_consumers_read(aiohttp_client):
    """Same keys as a live entry, so a reader iterating the list does not
    special-case the ones that are not up yet. The type comes from the
    record when there is one, a recreate for instance."""
    app = _app(reconciler=_reconciler(planned=[HASH_C]))
    content = _make_qemu_instance_message()
    app["vm_registry"].record(HASH_C, message=content, original=content, persistent=True)
    body = await _listing(aiohttp_client, app)
    live = (await _listing(aiohttp_client, _app(infos=[_info(HASH_A)])))[str(HASH_A)]

    assert set(body[str(HASH_C)]) == set(live)
    assert set(body[str(HASH_C)]["status"]) == set(live["status"])
    assert body[str(HASH_C)]["vm_type"] == "instance"


@pytest.mark.asyncio
async def test_the_listing_answers_cross_origin_readers(aiohttp_client):
    """The console reads this from a browser, like the legacy list. CORS
    comes from the route's registration in setup_webapp, not from the
    decorator on the view, which only sets an attribute nothing reads."""
    client = await aiohttp_client(_app())
    origin = {"Origin": "https://console.example"}

    preflight = await client.options(LIST, headers={**origin, "Access-Control-Request-Method": "GET"})
    response = await client.get(LIST, headers=origin)

    assert preflight.status == 200
    assert preflight.headers["Access-Control-Allow-Origin"] == "https://console.example"
    assert response.status == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://console.example"
