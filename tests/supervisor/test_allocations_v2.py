"""The v2 endpoints answer now and converge later.

Each test drives the real app around a fake supervisor, so what is asserted
is the wiring: the answer, what reaches the reconciler, what the check
touches, and that the legacy route is what it was.
"""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import aiohttp
import pytest
from aleph_message.models import ItemHash

from aleph.vm.agent.allocation import reconciler as reconciler_module
from aleph.vm.agent.capacity import AdmissionVerdict, CapacityManager
from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.agent.views.allocation_auth import (
    MAX_SIGNED_PLAN_BODY_BYTES,
    MAX_SIGNED_REQUEST_BODY_BYTES,
)
from aleph.vm.resources import GpuDevice, GpuDeviceClass
from aleph.vm.supervisor_interface.types import HostInfo

HASH_C = ItemHash("c" * 64)
PLAN = "/v2/control/allocations"
CHECK = "/v2/control/capacity/check"
DEVICE_ID = "10de:2504"


def _app(*, host_info=None, real_reconciler=False):
    """The agent app over a fake supervisor. The reconciler is a double
    unless a test needs the real loop to pick the plan up."""
    supervisor = MagicMock(
        list_vms=AsyncMock(return_value=[]),
        get_host_info=AsyncMock(return_value=host_info or HostInfo()),
        delete_vm=AsyncMock(),
    )
    app = setup_webapp(supervisor=supervisor)
    app["pubsub"] = None
    if not real_reconciler:
        app["allocation_reconciler"] = MagicMock(submit=MagicMock(), run=AsyncMock(), notify_vm_down=MagicMock())
    return app


def _stub_host(mocker, *, memory_gib=64):
    """A 64 GiB, 16 core host with 100 GiB of disk, for the real CapacityManager."""
    mocker.patch("aleph.vm.agent.capacity.psutil.virtual_memory", return_value=mocker.Mock(total=memory_gib * 1024**3))
    mocker.patch("aleph.vm.agent.capacity.psutil.cpu_count", return_value=16)
    mocker.patch.object(CapacityManager, "_available_disk_bytes", return_value=100 * 1024**3)
    mocker.patch(
        "aleph.vm.agent.capacity.storage_pools.eligible_pool_free_bytes",
        return_value=[(SimpleNamespace(path="/pool0", index=0), 100 * 1024**3)],
    )
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=0)


def _card():
    return GpuDevice(
        vendor="NVIDIA",
        device_name="GH100",
        device_class=GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER,
        pci_host="0000:01:00.0",
        device_id=DEVICE_ID,
    )


def _entry(message):
    return {"item_hash": message["item_hash"], "message": message}


@pytest.mark.asyncio
async def test_the_answer_comes_before_the_vm_is_created(aiohttp_client, scheduler_auth, monkeypatch):
    """The whole feature in one request: the create it authorizes never
    finishes, and the answer arrives anyway. Then the loop does pick it up."""
    started = asyncio.Event()

    async def never_finishes(*_args, **_kwargs):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(reconciler_module, "start_persistent_vm", never_finishes)
    client = await aiohttp_client(_app(real_reconciler=True))
    body, headers = scheduler_auth({"vms": [{"item_hash": str(HASH_C)}]}, path=PLAN)

    response = await client.post(PLAN, data=body, headers=headers, timeout=aiohttp.ClientTimeout(total=2))

    assert response.status == 202
    payload = await response.json()
    assert payload["pending"] == [str(HASH_C)]  # no embedded message: judged after the fetch
    assert payload["plan_id"].startswith("sha256:")
    await asyncio.wait_for(started.wait(), timeout=1)


@pytest.mark.asyncio
async def test_an_unsigned_request_is_refused(aiohttp_client):
    client = await aiohttp_client(_app())

    response = await client.post(PLAN, json={"vms": []})

    assert response.status == 401


@pytest.mark.asyncio
@pytest.mark.parametrize("body", [{"vms": "not-a-list"}, {"vms": 5}, {}, []])
async def test_a_body_that_is_not_a_plan_is_a_bad_request(aiohttp_client, scheduler_auth, body):
    """Never read as the empty plan, which is the instruction to stop
    everything this node runs."""
    app = _app()
    client = await aiohttp_client(app)
    signed, headers = scheduler_auth(body, path=PLAN)

    response = await client.post(PLAN, data=signed, headers=headers)

    assert response.status == 400
    app["allocation_reconciler"].submit.assert_not_called()


@pytest.mark.asyncio
async def test_a_tampered_message_is_refused_and_never_reaches_the_reconciler(
    aiohttp_client, scheduler_auth, signed_message
):
    """A body the scheduler could not have obtained from the network must not
    reach the reconciler, whatever it claims."""
    message = signed_message()
    content = json.loads(message["item_content"])
    content["resources"]["vcpus"] = 64
    message["item_content"] = json.dumps(content)
    message["content"] = content
    app = _app()
    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"vms": [_entry(message)]}, path=PLAN)

    response = await client.post(PLAN, data=body, headers=headers)

    assert response.status == 202
    assert (await response.json())["rejected"][message["item_hash"]]["code"] == "invalid_message"
    submitted = app["allocation_reconciler"].submit.call_args.args[0]
    assert submitted.entries == {}


@pytest.mark.asyncio
async def test_an_entry_the_host_refuses_is_answered_and_not_submitted(
    aiohttp_client, scheduler_auth, signed_message, monkeypatch
):
    """Capacity gating: what the answer refused never reaches the loop, which
    would otherwise retry it forever and start it the moment room appeared."""
    message = signed_message()
    app = _app()
    monkeypatch.setattr(
        app["capacity"],
        "simulate",
        lambda candidates, **_: [AdmissionVerdict(h, False, "insufficient_capacity", "no room") for h, _ in candidates],
    )
    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"vms": [_entry(message)]}, path=PLAN)

    response = await client.post(PLAN, data=body, headers=headers)

    payload = await response.json()
    assert payload["rejected"][message["item_hash"]]["code"] == "insufficient_capacity"
    assert payload["accepted"] == []
    submitted = app["allocation_reconciler"].submit.call_args.args[0]
    assert ItemHash(message["item_hash"]) not in submitted.entries


@pytest.mark.asyncio
async def test_a_message_the_host_can_take_is_accepted_and_submitted(
    aiohttp_client, scheduler_auth, signed_message, mocker
):
    _stub_host(mocker)
    message = signed_message()
    app = _app()
    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"vms": [_entry(message)]}, path=PLAN)

    response = await client.post(PLAN, data=body, headers=headers)

    assert (await response.json())["accepted"] == [message["item_hash"]]
    submitted = app["allocation_reconciler"].submit.call_args.args[0]
    assert set(submitted.entries) == {ItemHash(message["item_hash"])}


@pytest.mark.asyncio
async def test_the_hosts_cards_reach_the_verdict(aiohttp_client, scheduler_auth, signed_message, mocker):
    """The one read the pure verdict cannot do for itself: the handler reads
    the inventory from the supervisor and hands it in, so a GPU VM can be
    placed at all."""
    _stub_host(mocker)
    card = _card()
    app = _app(host_info=HostInfo(available_gpus=[card.model_dump()]))
    simulate = mocker.spy(app["capacity"], "simulate")
    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"vms": [_entry(signed_message())]}, path=PLAN)

    await client.post(PLAN, data=body, headers=headers)

    assert simulate.call_args.kwargs["available_gpus"] == [card]


@pytest.mark.asyncio
async def test_a_plan_body_over_the_legacy_cap_reaches_the_handler(aiohttp_client, scheduler_auth):
    """A plan carries a signed message per VM, so it outgrows the 1 MiB
    aiohttp bounds a body to by default. That default stays for every other
    route; this one re-bounds the request to its own cap before reading,
    where the app-wide limit used to cut the plan off inside the verifier
    and report it as a bad signature."""
    client = await aiohttp_client(_app())
    body, headers = scheduler_auth({"vms": [], "padding": "x" * (MAX_SIGNED_REQUEST_BODY_BYTES + 1)}, path=PLAN)

    response = await client.post(PLAN, data=body, headers=headers)

    assert response.status == 202


@pytest.mark.asyncio
async def test_a_plan_body_of_exactly_the_cap_is_taken(aiohttp_client, scheduler_auth):
    """The cap is inclusive, and it is the verifier's. aiohttp refuses a body
    at its own limit rather than over it, so a request bounded to exactly the
    cap failed on the last byte, inside the verifier, as a 401."""
    client = await aiohttp_client(_app())
    frame = len(json.dumps({"vms": [], "padding": ""}))
    body, headers = scheduler_auth({"vms": [], "padding": "x" * (MAX_SIGNED_PLAN_BODY_BYTES - frame)}, path=PLAN)
    assert len(body) == MAX_SIGNED_PLAN_BODY_BYTES

    response = await client.post(PLAN, data=body, headers=headers)

    assert response.status == 202


@pytest.mark.asyncio
async def test_a_plan_body_over_its_own_cap_is_too_large(aiohttp_client, scheduler_auth):
    """The route's cap is still a cap: over it, 413 and not 202, before a
    byte of the body is read."""
    app = _app()
    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"vms": [], "padding": "x" * MAX_SIGNED_PLAN_BODY_BYTES}, path=PLAN)

    response = await client.post(PLAN, data=body, headers=headers)

    assert response.status == 413
    app["allocation_reconciler"].submit.assert_not_called()


@pytest.mark.asyncio
async def test_a_legacy_route_answers_too_large_to_a_plan_sized_body(aiohttp_client, scheduler_auth):
    """The mirror of the test above. The legacy allocation route calls the
    verifier directly, without the decorator, so once the app ceiling let a
    plan-sized body through, the verifier's refusal escaped it as a 500."""
    client = await aiohttp_client(_app())
    body, headers = scheduler_auth({"persistent_vms": [], "padding": "x" * (MAX_SIGNED_REQUEST_BODY_BYTES + 1)})

    response = await client.post("/control/allocations", data=body, headers=headers)

    assert response.status == 413


@pytest.mark.asyncio
async def test_a_body_that_is_not_text_is_a_bad_request(aiohttp_client, scheduler_auth):
    """request.json() decodes before it parses, and a body that is not UTF-8
    raises a ValueError that is not a JSONDecodeError. It was a 500, with the
    decoder's message in the response."""
    app = _app()
    client = await aiohttp_client(app)
    body, headers = scheduler_auth(b'{"vms": "\xff\xfe"}', path=PLAN)

    response = await client.post(PLAN, data=body, headers=headers)

    assert response.status == 400
    app["allocation_reconciler"].submit.assert_not_called()


@pytest.mark.asyncio
async def test_the_capacity_check_judges_without_touching_anything(
    aiohttp_client, scheduler_auth, signed_message, mocker
):
    """A scheduler asks several CRNs before committing to one, so a check
    must record no plan and hold nothing. An entry without its message cannot
    be sized and says so; one with it is judged as a create would judge it."""
    _stub_host(mocker)
    message = signed_message()
    app = _app()
    client = await aiohttp_client(app)
    body, headers = scheduler_auth({"vms": [_entry(message), {"item_hash": str(HASH_C)}]}, path=CHECK)

    response = await client.post(CHECK, data=body, headers=headers)

    assert response.status == 200
    payload = await response.json()
    assert payload["results"][message["item_hash"]] == {"accepted": True}
    assert payload["results"][str(HASH_C)]["code"] == "message_required"
    assert payload["capacity"]["instance_memory_mib"] > 0
    assert payload["capacity"]["gpus"] == []
    app["allocation_reconciler"].submit.assert_not_called()
    assert app["capacity"].holds == {}


@pytest.mark.asyncio
async def test_the_capacity_check_refuses_what_a_create_would_refuse(
    aiohttp_client, scheduler_auth, signed_message, mocker
):
    """Advisory and enforced answer alike: a message asking for more than
    the host has is refused here with the same code the plan route gives."""
    _stub_host(mocker, memory_gib=1)
    message = signed_message()
    client = await aiohttp_client(_app())
    body, headers = scheduler_auth({"vms": [_entry(message)]}, path=CHECK)

    response = await client.post(CHECK, data=body, headers=headers)

    result = (await response.json())["results"][message["item_hash"]]
    assert result["accepted"] is False
    assert result["code"] == "insufficient_capacity"


@pytest.mark.asyncio
async def test_the_legacy_endpoint_is_untouched(aiohttp_client, scheduler_auth):
    """The compatibility guarantee: an old scheduler keeps working."""
    client = await aiohttp_client(_app())
    body, headers = scheduler_auth({"persistent_vms": []}, path="/control/allocations")

    response = await client.post("/control/allocations", data=body, headers=headers)

    assert response.status == 200
    assert (await response.json())["success"] is True
