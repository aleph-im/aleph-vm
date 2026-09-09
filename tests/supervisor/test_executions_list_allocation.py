"""What the CRN advertises per VM once allocation is asynchronous.

Two disjoint fields: `state` is the supervisor's VmStatus, verbatim, and
`allocation` covers the phases that precede the supervisor knowing the VM at
all. They are never merged into one enum, which would have to be maintained in
lockstep with VmStatus forever.
"""

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent.allocation.plan import AllocationState, FailureRecord
from aleph.vm.agent.supervisor import setup_webapp
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


def _app(*, infos=(), reconciler=None):
    supervisor = MagicMock(
        list_vms=AsyncMock(return_value=list(infos)),
        get_host_info=AsyncMock(return_value=HostInfo(host_ipv4="10.0.0.1")),
        list_port_forwards=AsyncMock(return_value=[]),
    )
    app = setup_webapp(supervisor=supervisor)
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
    failure = FailureRecord(
        code="resource_download_error",
        message="rootfs 404",
        attempts=2,
        first_failed_at=NOW,
        last_failed_at=NOW,
        next_retry_at=NOW + timedelta(seconds=60),
    )
    reconciler = _reconciler(planned=[HASH_C], states={HASH_C: (AllocationState.FAILED, failure)})

    body = await _listing(aiohttp_client, _app(reconciler=reconciler))

    allocation = body[str(HASH_C)]["allocation"]
    assert allocation["state"] == "failed"
    assert allocation["error"] == {"code": "resource_download_error", "message": "rootfs 404"}
    assert allocation["attempts"] == 2
    # Rendered the way the status times are, by the same serializer.
    assert allocation["next_retry_at"] == "2026-08-25 00:01:00+00:00"


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
        code="x", message="y", attempts=1, first_failed_at=NOW, last_failed_at=NOW, next_retry_at=NOW
    )
    reconciler = _reconciler(planned=[HASH_A], states={HASH_A: (AllocationState.FAILED, failure)})

    body = await _listing(aiohttp_client, _app(infos=[_info(HASH_A, VmStatus.FAILED)], reconciler=reconciler))

    assert body[str(HASH_A)]["state"] == "failed"
    assert body[str(HASH_A)]["allocation"]["state"] == "failed"


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
