"""The v2 allocation endpoints: answer now, converge later.

POST /v2/control/allocations records the plan and returns a per-VM verdict at
once; the reconciler converges on it in the background. POST
/v2/control/capacity/check answers the same admission question with no side
effects, so a scheduler can ask several CRNs before committing to one.

Both take a body the legacy cap would refuse: a plan carries one signed
message per VM.
"""

import logging
from datetime import datetime, timezone
from http import HTTPStatus

from aiohttp import web

from aleph.vm.agent.allocation.plan import AllocationPlan
from aleph.vm.agent.allocation.refusal import AllocationFailureCode, Refusal, Refusals
from aleph.vm.agent.allocation.verdict import build_plan, compute_verdict, narrow_plan
from aleph.vm.agent.capacity import requirements_from_message
from aleph.vm.agent.node_identity import NodeIdentity
from aleph.vm.agent.views.allocation_auth import (
    MAX_SIGNED_PLAN_BODY_BYTES,
    requires_allocation_auth,
)
from aleph.vm.utils import dumps_for_json

logger = logging.getLogger(__name__)


async def _read_plan(request: web.Request) -> tuple[AllocationPlan, Refusals]:
    """The body as a plan, or the 400 that says why it is not one.

    One validation boundary for both routes: build_plan owns what an entry
    must look like and what a body must not be read as, so the check and the
    push cannot disagree about a request.

    It yields while the entries are verified in a worker thread, which is why
    it is called before anything the answer is computed from is read.
    """
    try:
        body = await request.json()
    except ValueError as error:
        # JSONDecodeError and the UnicodeDecodeError of a body that is not
        # text: request.json() decodes before it parses.
        raise web.HTTPBadRequest(text="Body is not valid JSON") from error
    try:
        return await build_plan(body, now=datetime.now(tz=timezone.utc))
    except ValueError as error:
        raise web.HTTPBadRequest(text="Body is not a plan: 'vms' must be a list") from error


@requires_allocation_auth(max_body_bytes=MAX_SIGNED_PLAN_BODY_BYTES)
async def update_allocations_v2(request: web.Request) -> web.Response:
    """Record the scheduler's plan and answer for each VM right away."""
    plan, rejected = await _read_plan(request)
    app = request.app
    node_identity: NodeIdentity | None = app.get("node_identity")
    # Both reads are async, so both are done up front. The window that must
    # not yield is the one after the last of them: from there through the
    # verdict to submit(), a push landing in between would invalidate the
    # answer about to be returned; see allocation.verdict.
    #
    # The gpu read does yield, and the VM list is already in hand when it
    # does, so what this handler believes is running can be a moment stale by
    # the time the verdict is computed. That is what removing_now covers
    # below: a teardown starting in that gap would otherwise be answered as a
    # VM that never moved. Two pushes overlapping here are settled by
    # whichever submits last, the same as two arriving in either order.
    infos = await app["supervisor"].list_vms()
    available_gpus = await app["capacity"].available_gpus()
    reconciler = app["allocation_reconciler"]
    verdict = compute_verdict(
        plan,
        infos=infos,
        registry=app["vm_registry"],
        capacity=app["capacity"],
        node_hash=node_identity.get_node_hash() if node_identity else None,
        available_gpus=available_gpus,
        # Read after the two awaits, in the same turn as the verdict, so a
        # teardown that starts while this handler is parked in list_vms is
        # still accounted for: the list it holds says that VM is running.
        removing_now=reconciler.removing_hashes(),
    )
    verdict.rejected.update(rejected)
    reconciler.submit(narrow_plan(plan, verdict))

    logger.info(
        "Plan %s: %d accepted, %d pending, %d unchanged, %d rejected, %d removing, %d retained",
        plan.plan_id,
        len(verdict.accepted),
        len(verdict.pending),
        len(verdict.unchanged),
        len(verdict.rejected),
        len(verdict.removing),
        len(verdict.retained),
    )
    return web.json_response(
        {
            "plan_id": plan.plan_id,
            "accepted": [str(vm_hash) for vm_hash in verdict.accepted],
            "pending": [str(vm_hash) for vm_hash in verdict.pending],
            "unchanged": [str(vm_hash) for vm_hash in verdict.unchanged],
            "removing": [str(vm_hash) for vm_hash in verdict.removing],
            "rejected": {str(key): refusal.as_dict() for key, refusal in verdict.rejected.items()},
            "retained": {str(vm_hash): reason for vm_hash, reason in verdict.retained.items()},
            "status_url": "/v2/about/executions/list",
        },
        status=HTTPStatus.ACCEPTED,
        dumps=dumps_for_json,
    )


@requires_allocation_auth(max_body_bytes=MAX_SIGNED_PLAN_BODY_BYTES)
async def capacity_check(request: web.Request) -> web.Response:
    """Advisory: would these be admitted here, as things stand?

    Side-effect free by design: no plan is recorded and nothing is held, so
    a scheduler can ask several CRNs and place on one. Every entry is a
    candidate and nothing running here is read as dropped, since this is not
    a plan. A race with a real allocation is settled by the allocation, which
    judges again and can still refuse.
    """
    plan, rejected = await _read_plan(request)
    capacity = request.app["capacity"]
    results: dict[str, dict] = {key: {"accepted": False, **refusal.as_dict()} for key, refusal in rejected.items()}
    candidates = []
    for vm_hash, planned in plan.entries.items():
        if planned.verified is None:
            # Without the message there is nothing to size, and a check must
            # not go and fetch one: say so rather than guess.
            results[str(vm_hash)] = {
                "accepted": False,
                **Refusal.for_code(AllocationFailureCode.MESSAGE_REQUIRED).as_dict(),
            }
            continue
        candidates.append((vm_hash, requirements_from_message(planned.verified.message.content)))
    available_gpus = await capacity.available_gpus()
    for admission in capacity.simulate(candidates, available_gpus=available_gpus):
        results[str(admission.vm_hash)] = (
            {"accepted": True} if admission.refusal is None else {"accepted": False, **admission.refusal.as_dict()}
        )
    return web.json_response(
        {"results": results, "capacity": capacity.headroom(available_gpus)},
        dumps=dumps_for_json,
    )
