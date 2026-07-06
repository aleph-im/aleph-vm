"""Single-process agent+supervisor harnesses for benchmarks and CI.

The benchmark and --run-test-instance / --run-fake-instance CLI paths build
the daemon's engine (VmPool + LocalSupervisor) directly in-process instead of
dialing a running daemon over gRPC. They are single-shot developer/CI
harnesses (the droplet CI drives --run-fake-instance), deliberately exempt
from the agent's gRPC-only rule, which is why they live OUTSIDE
``aleph.vm.agent``: the agent package itself imports neither the supervisor
implementation nor the pool.
"""

import asyncio
import logging
import time
from collections.abc import Callable
from statistics import mean
from typing import cast

from aiohttp.web import Request, Response
from aleph_message.models import ItemHash

from aleph.vm.agent.capacity import CapacityManager
from aleph.vm.agent.expiry import ExpiryManager
from aleph.vm.agent.pubsub import PubSub
from aleph.vm.agent.run import (
    run_code_on_event,
    run_code_on_request,
    start_persistent_vm,
)
from aleph.vm.agent.update_watcher import UpdateWatcher
from aleph.vm.agent.vm.program_client import ProgramGuestClient
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.pool import VmPool
from aleph.vm.supervisor.local import LocalSupervisor

logger = logging.getLogger(__name__)


class FakeRequest:
    app: dict
    headers: dict[str, str]
    raw_headers: list[tuple[bytes, bytes]]
    match_info: dict
    method: str
    query_string: str
    read: Callable


async def benchmark(runs: int):
    """Measure program performance by immediately running the supervisor
    with fake requests.
    """
    ref = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")
    settings.FAKE_DATA_PROGRAM = settings.BENCHMARK_FAKE_DATA_PROGRAM

    fake_request = FakeRequest()  # type: ignore[operator]
    fake_request.match_info = {"ref": ref, "suffix": "/"}
    fake_request.method = "GET"
    fake_request.query_string = ""

    fake_request.headers = {"host": "127.0.0.1", "content-type": "application/json"}
    fake_request.raw_headers = [(name.encode(), value.encode()) for name, value in fake_request.headers.items()]

    async def fake_read() -> bytes:
        return b""

    fake_request.read = fake_read

    logger.info("--- Start benchmark ---")

    bench: list[float] = []

    loop = asyncio.get_event_loop()
    pool = VmPool()
    await pool.setup()
    bench_supervisor = LocalSupervisor(pool)
    bench_registry = AgentVmRegistry()
    bench_capacity = CapacityManager(bench_supervisor, bench_registry)
    bench_update_watcher = UpdateWatcher(bench_supervisor, bench_registry)
    bench_expiry = ExpiryManager(bench_supervisor)
    bench_program_client = ProgramGuestClient()
    fake_request.app = {
        "supervisor": bench_supervisor,
        "expiry": bench_expiry,
        "update_watcher": bench_update_watcher,
        "vm_registry": bench_registry,
        "capacity": bench_capacity,
        "program_client": bench_program_client,
        "pubsub": PubSub(),
    }
    bench_expiry.on_reaped = bench_update_watcher.cancel
    bench_update_watcher.on_reaped = bench_expiry.cancel

    # Does not make sense in benchmarks
    settings.WATCH_FOR_MESSAGES = False
    settings.WATCH_FOR_UPDATES = False

    # Finish setting up the settings
    settings.setup()
    settings.check()

    # First test all methods
    settings.REUSE_TIMEOUT = 0.1
    for path in (
        "/",
        "/lifespan",
        "/environ",
        "/messages",
        "/internet",
        "/post_a_message",
        "/cache/set/foo/bar",
        "/cache/get/foo",
        "/cache/keys",
    ):
        fake_request.match_info["suffix"] = path
        response: Response = await run_code_on_request(vm_hash=ref, path=path, request=cast(Request, fake_request))
        assert response.status == 200

    # Disable VM timeout to exit benchmark properly
    settings.REUSE_TIMEOUT = 0 if runs == 1 else 0.1
    path = "/"
    for _run in range(runs):
        t0 = time.time()
        fake_request.match_info["suffix"] = path
        response2: Response = await run_code_on_request(vm_hash=ref, path=path, request=cast(Request, fake_request))
        assert response2.status == 200
        bench.append(time.time() - t0)

    logger.info(f"BENCHMARK: n={len(bench)} avg={mean(bench):03f} min={min(bench):03f} max={max(bench):03f}")
    logger.info(bench)

    result = await run_code_on_event(
        vm_hash=ref,
        event=None,
        pubsub=PubSub(),
        supervisor=bench_supervisor,
        expiry=fake_request.app["expiry"],
        update_watcher=bench_update_watcher,
        registry=bench_registry,
        capacity=bench_capacity,
        program_client=bench_program_client,
    )
    print("Event result", result)


async def start_instance(item_hash: ItemHash, pubsub: PubSub | None, pool) -> None:
    """Run an instance from an InstanceMessage."""
    supervisor = LocalSupervisor(pool)
    registry = AgentVmRegistry()
    capacity = CapacityManager(supervisor, registry)
    expiry = ExpiryManager(supervisor)
    update_watcher = UpdateWatcher(supervisor, registry)
    expiry.on_reaped = update_watcher.cancel
    update_watcher.on_reaped = expiry.cancel
    await start_persistent_vm(
        item_hash,
        pubsub,
        supervisor=supervisor,
        registry=registry,
        capacity=capacity,
        expiry=expiry,
        update_watcher=update_watcher,
    )


async def run_instances(instances: list[ItemHash]) -> None:
    """Run instances from a list of message identifiers."""
    logger.info(f"Instances to run: {instances}")
    loop = asyncio.get_event_loop()
    pool = VmPool()
    # Bind the supervisor DB engine (port mappings) and set up the network;
    # the create path hits that DB on its first port-mapping lookup.
    await pool.setup()
    # The main program uses a singleton pubsub instance in order to watch for updates.
    # We create another instance here since that singleton is not initialized yet.
    # Watching for updates on this instance will therefore not work.
    pubsub: PubSub | None = None

    await asyncio.gather(*[start_instance(instance_id, pubsub, pool) for instance_id in instances])

    await asyncio.Event().wait()  # wait forever
