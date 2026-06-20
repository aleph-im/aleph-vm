"""Tests for the graceful drain mechanism.

Tests the drain middleware (real aiohttp pipeline) and
VmPool.drain() waiting logic (real asyncio events).
"""

import asyncio
from unittest.mock import patch

import pytest
from aleph_message.models import ItemHash
from conftest import make_spec

from aleph.vm.agent.supervisor import setup_webapp
from aleph.vm.conf import settings
from aleph.vm.models import VmExecution

FAKE_HASH = ItemHash("decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca")


def _make_execution(persistent: bool = False) -> VmExecution:
    """Create a real spec-built VmExecution with minimal dependencies."""
    spec = make_spec(vm_hash=str(FAKE_HASH), persistent=persistent)
    return VmExecution.from_spec(spec, snapshot_manager=None, systemd_manager=None)


def _draining_app(draining: bool = True):
    """A webapp with no in-process pool (split mode) and the agent-owned drain
    flag set. The middleware reads app["draining"], not the pool, so this proves
    drain works without an embedded pool."""
    app = setup_webapp(pool=None)
    app["draining"] = draining
    return app


# ---------------------------------------------------------------------------
# drain_middleware — real aiohttp pipeline, no mocks
# ---------------------------------------------------------------------------


class TestDrainMiddleware:
    """Verify the drain middleware blocks/allows the right paths."""

    @pytest.mark.asyncio
    async def test_vm_path_blocked_while_draining(self, aiohttp_client):
        client = await aiohttp_client(_draining_app(draining=True))

        response = await client.get("/vm/abc123/some/path")
        assert response.status == 503
        body = await response.json()
        assert "draining" in body["error"]

    @pytest.mark.asyncio
    async def test_vm_path_allowed_when_not_draining(self, aiohttp_client):
        client = await aiohttp_client(_draining_app(draining=False))

        response = await client.get("/vm/abc123/")
        # Will fail downstream (no real VM) but must NOT be 503
        assert response.status != 503

    @pytest.mark.asyncio
    async def test_status_allowed_while_draining(self, aiohttp_client):
        client = await aiohttp_client(_draining_app(draining=True))

        response = await client.get("/status/config")
        assert response.status == 200

    @pytest.mark.asyncio
    async def test_about_allowed_while_draining(self, aiohttp_client):
        app = _draining_app(draining=True)
        app["secret_token"] = "test-token"
        client = await aiohttp_client(app)

        response = await client.get("/about/config", cookies={"token": "test-token"})
        assert response.status == 200

    @pytest.mark.asyncio
    async def test_control_allowed_while_draining(self, aiohttp_client):
        client = await aiohttp_client(_draining_app(draining=True))

        response = await client.get("/control/nonexistent")
        # Unknown path → 404, but NOT 503
        assert response.status == 404

    @pytest.mark.asyncio
    async def test_hostname_routing_blocked_while_draining(self, aiohttp_client):
        client = await aiohttp_client(_draining_app(draining=True))

        with patch.object(settings, "DOMAIN_NAME", "supervisor.local"):
            response = await client.get("/", headers={"Host": "somevmhash.example.com"})
            assert response.status == 503

    @pytest.mark.asyncio
    async def test_root_on_supervisor_domain_allowed(self, aiohttp_client):
        """Root path on the supervisor's own domain is NOT a VM request."""
        client = await aiohttp_client(_draining_app(draining=True))

        with patch.object(settings, "DOMAIN_NAME", "127.0.0.1"):
            response = await client.get("/")
            assert response.status != 503


# ---------------------------------------------------------------------------
# drain_in_flight_requests — the on_shutdown hook, both modes
# ---------------------------------------------------------------------------


class TestDrainShutdownHook:
    @pytest.mark.asyncio
    async def test_split_mode_flips_flag_without_pool(self):
        """Split mode (no embedded pool): the hook flips the flag and returns;
        the daemon owns the pool and keeps VMs running across its own restart."""
        from aleph.vm.agent.supervisor import drain_in_flight_requests

        app = {"_engine_pool": None, "draining": False}
        await drain_in_flight_requests(app)
        assert app["draining"] is True

    @pytest.mark.asyncio
    async def test_in_process_flips_flag_and_drains_pool(self):
        """In-process: the hook flips the flag AND drains the embedded pool."""
        from unittest.mock import AsyncMock

        from aleph.vm.agent.supervisor import drain_in_flight_requests

        pool = AsyncMock()
        app = {"_engine_pool": pool, "draining": False}
        await drain_in_flight_requests(app)
        assert app["draining"] is True
        pool.drain.assert_awaited_once()


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
