"""Regression tests for the --run-test-instance / --run-fake-instance CLI path
(the single-process harness in aleph.vm.testing.harness)."""

import asyncio
import contextlib
from unittest.mock import AsyncMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.conf import settings
from aleph.vm.testing import harness

FAKE_INSTANCE_ID = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")


@pytest.mark.asyncio
async def test_run_instances_sets_up_pool(monkeypatch):
    """run_instances must await VmPool.setup() before starting instances:
    the pool setup binds the supervisor DB engine (port mappings), and the
    create path hits that DB on its first port-mapping lookup."""
    calls: list[str] = []

    async def fake_setup(self) -> None:
        calls.append("pool.setup")

    async def fake_start_instance(item_hash, pubsub, pool) -> None:
        calls.append("start_instance")

    # Keep VmPool() construction host-independent.
    monkeypatch.setattr(settings, "ALLOW_VM_NETWORKING", False)
    monkeypatch.setattr(harness.VmPool, "setup", fake_setup)
    monkeypatch.setattr(harness, "start_instance", AsyncMock(side_effect=fake_start_instance))

    # run_instances waits forever after starting the instances; run it as a
    # task and cancel it once the startup sequence has been observed.
    task = asyncio.create_task(harness.run_instances([FAKE_INSTANCE_ID]))
    try:
        for _ in range(100):
            if "start_instance" in calls:
                break
            await asyncio.sleep(0.01)
        assert calls == ["pool.setup", "start_instance"]
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
