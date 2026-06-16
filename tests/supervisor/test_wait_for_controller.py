"""Tests for VmExecution.wait_for_controller_ready/_stopped polling logic."""

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import InstanceContent, ItemHash

from aleph.vm.models import VmExecution

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


def _make_execution(systemd_manager: MagicMock) -> VmExecution:
    """Create a real persistent VmExecution with a mock systemd_manager."""
    message = InstanceContent.model_validate(FAKE_INSTANCE_CONTENT)
    return VmExecution(
        vm_hash=FAKE_HASH,
        message=message,
        original=message,
        persistent=True,
        snapshot_manager=None,
        systemd_manager=systemd_manager,
    )


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Replace asyncio.sleep with a no-op so tests don't wait 60s."""

    async def _instant_sleep(_seconds):
        pass

    monkeypatch.setattr(asyncio, "sleep", _instant_sleep)


class TestWaitForControllerReady:
    """Test the polling logic in wait_for_controller_ready."""

    @pytest.mark.asyncio
    async def test_returns_when_stably_active(self):
        """'active' must hold on a confirmation re-check: a unit whose
        process dies right after start samples as active between crashes."""
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "active"
        ex = _make_execution(mgr)

        await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 2
        mgr.get_service_active_state.assert_called_with(ex.controller_service)

    @pytest.mark.asyncio
    async def test_fails_when_active_does_not_hold(self):
        """Crash loop: active on first sight, dead on the re-check."""
        mgr = MagicMock()
        mgr.get_service_active_state.side_effect = ["active", "failed"]
        ex = _make_execution(mgr)

        with pytest.raises(RuntimeError, match="crash loop"):
            await ex.wait_for_controller_ready()

    @pytest.mark.asyncio
    async def test_polls_until_active(self):
        mgr = MagicMock()
        # activating for 2 attempts, then stably active
        mgr.get_service_active_state.side_effect = [
            "activating",
            "activating",
            "active",
            "active",
        ]
        ex = _make_execution(mgr)

        await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 4

    @pytest.mark.asyncio
    async def test_fast_fails_on_failed_state(self):
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "failed"
        ex = _make_execution(mgr)

        with pytest.raises(RuntimeError, match="failed"):
            await ex.wait_for_controller_ready()

        # Should fail on the very first attempt, not wait 60s
        mgr.get_service_active_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_inactive_is_retried_not_fast_failed(self):
        """inactive is legitimate between StartUnit and activating."""
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "inactive"
        ex = _make_execution(mgr)

        with pytest.raises(RuntimeError, match="did not become active"):
            await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 30

    @pytest.mark.asyncio
    async def test_inactive_then_active(self):
        """Service starts inactive (pre-StartUnit window), then becomes active."""
        mgr = MagicMock()
        mgr.get_service_active_state.side_effect = [
            "inactive",
            "activating",
            "active",
            "active",
        ]
        ex = _make_execution(mgr)

        await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 4

    @pytest.mark.asyncio
    async def test_fast_fails_on_failed_after_activating(self):
        mgr = MagicMock()
        mgr.get_service_active_state.side_effect = [
            "activating",
            "activating",
            "failed",
        ]
        ex = _make_execution(mgr)

        with pytest.raises(RuntimeError, match="failed"):
            await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 3

    @pytest.mark.asyncio
    async def test_raises_after_max_attempts(self):
        mgr = MagicMock()
        # Always activating — never reaches active
        mgr.get_service_active_state.return_value = "activating"
        ex = _make_execution(mgr)

        with pytest.raises(RuntimeError, match="did not become active"):
            await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 30

    @pytest.mark.asyncio
    async def test_asserts_persistent_and_systemd_manager(self):
        message = InstanceContent.model_validate(FAKE_INSTANCE_CONTENT)

        # Non-persistent execution
        ex_non_persistent = VmExecution(
            vm_hash=FAKE_HASH,
            message=message,
            original=message,
            persistent=False,
            snapshot_manager=None,
            systemd_manager=MagicMock(),
        )
        with pytest.raises(RuntimeError, match="requires a persistent VM"):
            await ex_non_persistent.wait_for_controller_ready()

        # No systemd_manager
        ex_no_manager = VmExecution(
            vm_hash=FAKE_HASH,
            message=message,
            original=message,
            persistent=True,
            snapshot_manager=None,
            systemd_manager=None,
        )
        with pytest.raises(RuntimeError, match="requires a persistent VM"):
            await ex_no_manager.wait_for_controller_ready()

    @pytest.mark.asyncio
    async def test_unknown_state_is_retried(self):
        """D-Bus transient errors return 'unknown' and should be retried."""
        mgr = MagicMock()
        mgr.get_service_active_state.side_effect = [
            "unknown",
            "unknown",
            "active",
            "active",
        ]
        ex = _make_execution(mgr)

        await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 4

    @pytest.mark.asyncio
    async def test_unknown_state_times_out(self):
        """Persistent 'unknown' state should timeout, not fast-fail."""
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "unknown"
        ex = _make_execution(mgr)

        with pytest.raises(RuntimeError, match="did not become active"):
            await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 30


class TestWaitForControllerStopped:
    """StopUnit only queues a job; stop() must wait for the unit to really
    stop before tearing down the network, or qemu dies unflushed."""

    @pytest.mark.asyncio
    async def test_returns_immediately_when_inactive(self):
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "inactive"
        ex = _make_execution(mgr)

        await ex.wait_for_controller_stopped()

        mgr.get_service_active_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_waits_through_active_and_deactivating(self):
        mgr = MagicMock()
        mgr.get_service_active_state.side_effect = ["active", "deactivating", "inactive"]
        ex = _make_execution(mgr)

        await ex.wait_for_controller_stopped()

        assert mgr.get_service_active_state.call_count == 3

    @pytest.mark.asyncio
    async def test_failed_counts_as_stopped(self):
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "failed"
        ex = _make_execution(mgr)

        await ex.wait_for_controller_stopped()

        mgr.get_service_active_state.assert_called_once()

    @pytest.mark.asyncio
    async def test_not_loaded_counts_as_stopped(self):
        """systemd garbage-collects a cleanly stopped unit; a poll can go
        straight from 'deactivating' to NoSuchUnit without ever sampling
        'inactive'. Treating that as still-stopping burned the full 75s
        timeout on every stop."""
        mgr = MagicMock()
        mgr.get_service_active_state.side_effect = ["deactivating", "not-loaded"]
        ex = _make_execution(mgr)

        await ex.wait_for_controller_stopped()

        assert mgr.get_service_active_state.call_count == 2

    @pytest.mark.asyncio
    async def test_gives_up_after_timeout_without_raising(self):
        """A unit stuck past systemd's own SIGKILL deadline: log and proceed
        with teardown rather than blocking stop() forever."""
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "active"
        ex = _make_execution(mgr)

        await ex.wait_for_controller_stopped()

        assert mgr.get_service_active_state.call_count == 75


class TestStopWaitsForController:
    @pytest.mark.asyncio
    async def test_teardown_happens_only_after_unit_stopped(self):
        """The TAP interface must outlive qemu: deleting it while the guest
        is still shutting down makes qemu abort without flushing the disk."""
        events: list[str] = []
        states = iter(["active", "deactivating", "inactive"])

        mgr = MagicMock()
        mgr.stop_and_disable = MagicMock(side_effect=lambda _svc: events.append("stop_unit"))

        def poll(_svc):
            events.append("poll")
            return next(states)

        mgr.get_service_active_state = MagicMock(side_effect=poll)

        ex = _make_execution(mgr)
        ex.vm = MagicMock()
        ex.vm.support_snapshot = False
        ex.vm.teardown = AsyncMock(side_effect=lambda: events.append("teardown"))
        ex.record_usage = AsyncMock()
        ex.removed_all_ports_redirection = AsyncMock()

        await ex.stop()

        assert events == ["stop_unit", "poll", "poll", "poll", "teardown"]
        assert ex.times.stopped_at is not None
        assert ex.stop_event.is_set()
