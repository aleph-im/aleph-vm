"""Tests for the graceful drain mechanism.

Tests the drain middleware (real aiohttp pipeline) and
VmPool.drain() waiting logic (real asyncio events).
"""

import asyncio
from unittest.mock import patch

import pytest
from aiohttp import web
from aleph_message.models import InstanceContent, ItemHash

from aleph.vm.conf import settings
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.supervisor import setup_webapp

FAKE_HASH = ItemHash("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")

FAKE_INSTANCE_CONTENT = {
    "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
    "time": 1713874241.800818,
    "allow_amend": False,
    "metadata": None,
    "authorized_keys": None,
    "variables": None,
    "environment": {
        "reproducible": False,
        "internet": True,
        "aleph_api": True,
        "shared_cache": False,
    },
    "resources": {
        "vcpus": 1,
        "memory": 256,
        "seconds": 30,
        "published_ports": None,
    },
    "payment": {"type": "superfluid", "chain": "BASE"},
    "requirements": None,
    "replaces": None,
    "rootfs": {
        "parent": {
            "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
        },
        "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
        "use_latest": True,
        "comment": "",
        "persistence": "host",
        "size_mib": 1000,
    },
}


def _make_execution(persistent: bool = False) -> VmExecution:
    """Create a real VmExecution with minimal dependencies."""
    message = InstanceContent.model_validate(FAKE_INSTANCE_CONTENT)
    return VmExecution(
        vm_hash=FAKE_HASH,
        message=message,
        original=message,
        persistent=persistent,
        snapshot_manager=None,
        systemd_manager=None,
    )


class _DrainablePool:
    """Minimal pool that supports drain state for middleware tests.

    Uses only the attributes the drain middleware inspects, avoiding
    the full VmPool constructor (which needs network/systemd).
    """

    def __init__(self, draining: bool = False):
        self._draining = draining
        self.executions: dict = {}

    @property
    def is_draining(self) -> bool:
        return self._draining


# ---------------------------------------------------------------------------
# drain_middleware — real aiohttp pipeline, no mocks
# ---------------------------------------------------------------------------


class TestDrainMiddleware:
    """Verify the drain middleware blocks/allows the right paths."""

    @pytest.mark.asyncio
    async def test_vm_path_blocked_while_draining(self, aiohttp_client):
        app = setup_webapp(pool=_DrainablePool(draining=True))
        client = await aiohttp_client(app)

        response = await client.get("/vm/abc123/some/path")
        assert response.status == 503
        body = await response.json()
        assert "draining" in body["error"]

    @pytest.mark.asyncio
    async def test_vm_path_allowed_when_not_draining(self, aiohttp_client):
        app = setup_webapp(pool=_DrainablePool(draining=False))
        client = await aiohttp_client(app)

        response = await client.get("/vm/abc123/")
        # Will fail downstream (no real VM) but must NOT be 503
        assert response.status != 503

    @pytest.mark.asyncio
    async def test_status_allowed_while_draining(self, aiohttp_client):
        app = setup_webapp(pool=_DrainablePool(draining=True))
        client = await aiohttp_client(app)

        response = await client.get("/status/config")
        assert response.status == 200

    @pytest.mark.asyncio
    async def test_about_allowed_while_draining(self, aiohttp_client):
        app = setup_webapp(pool=_DrainablePool(draining=True))
        app["secret_token"] = "test-token"
        client = await aiohttp_client(app)

        response = await client.get("/about/config", cookies={"token": "test-token"})
        assert response.status == 200

    @pytest.mark.asyncio
    async def test_control_allowed_while_draining(self, aiohttp_client):
        app = setup_webapp(pool=_DrainablePool(draining=True))
        client = await aiohttp_client(app)

        response = await client.get("/control/nonexistent")
        # Unknown path → 404, but NOT 503
        assert response.status == 404

    @pytest.mark.asyncio
    async def test_hostname_routing_blocked_while_draining(self, aiohttp_client):
        app = setup_webapp(pool=_DrainablePool(draining=True))
        client = await aiohttp_client(app)

        response = await client.get("/", headers={"Host": "somevmhash.example.com"})
        assert response.status == 503

    @pytest.mark.asyncio
    async def test_root_on_supervisor_domain_allowed(self, aiohttp_client):
        """Root path on the supervisor's own domain is NOT a VM request."""
        app = setup_webapp(pool=_DrainablePool(draining=True))
        client = await aiohttp_client(app)

        with patch.object(settings, "DOMAIN_NAME", "127.0.0.1"):
            response = await client.get("/")
            assert response.status != 503


# ---------------------------------------------------------------------------
# VmPool.drain() — real asyncio events, real VmExecution objects
# ---------------------------------------------------------------------------


class TestVmPoolDrain:
    """Test VmPool.drain() waiting logic with real objects."""

    def _make_pool_for_drain(self):
        """Build a pool-like object with only the drain-relevant state.

        Avoids the full VmPool constructor (network, systemd, etc.)
        but uses the real drain() method.
        """
        from aleph.vm.pool import VmPool

        pool = object.__new__(VmPool)
        pool._draining = False
        pool.executions = {}
        return pool

    @pytest.mark.asyncio
    async def test_drain_sets_flag(self):
        pool = self._make_pool_for_drain()

        await pool.drain(timeout=1.0)

        assert pool.is_draining is True

    @pytest.mark.asyncio
    async def test_drain_completes_immediately_no_in_flight(self):
        pool = self._make_pool_for_drain()
        ex = _make_execution(persistent=False)
        # concurrent_runs == 0 → no in-flight
        pool.executions[FAKE_HASH] = ex

        await pool.drain(timeout=1.0)

        assert pool.is_draining is True

    @pytest.mark.asyncio
    async def test_drain_ignores_persistent_executions(self):
        pool = self._make_pool_for_drain()
        ex = _make_execution(persistent=True)
        ex.concurrent_runs = 3
        ex.runs_done_event.clear()
        pool.executions[FAKE_HASH] = ex

        # Should complete immediately — persistent VMs are skipped
        await pool.drain(timeout=0.1)

        assert pool.is_draining is True

    @pytest.mark.asyncio
    async def test_drain_waits_for_in_flight_then_completes(self):
        pool = self._make_pool_for_drain()
        ex = _make_execution(persistent=False)
        ex.concurrent_runs = 1
        ex.runs_done_event.clear()
        pool.executions[FAKE_HASH] = ex

        async def finish_request():
            await asyncio.sleep(0.05)
            ex.concurrent_runs = 0
            ex.runs_done_event.set()

        asyncio.create_task(finish_request())

        await pool.drain(timeout=2.0)

        assert pool.is_draining is True
        assert ex.concurrent_runs == 0

    @pytest.mark.asyncio
    async def test_drain_times_out_gracefully(self):
        pool = self._make_pool_for_drain()
        ex = _make_execution(persistent=False)
        ex.concurrent_runs = 1
        ex.runs_done_event.clear()
        pool.executions[FAKE_HASH] = ex

        # Request never finishes — drain should still return after timeout
        await pool.drain(timeout=0.1)

        assert pool.is_draining is True
        # The execution still has an in-flight request
        assert ex.concurrent_runs == 1
