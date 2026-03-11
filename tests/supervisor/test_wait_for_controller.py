"""Tests for VmExecution.wait_for_controller_ready polling logic."""

import asyncio
from unittest.mock import MagicMock, patch

import pytest
from aleph_message.models import InstanceContent, ItemHash

from aleph.vm.models import VmExecution


FAKE_HASH = ItemHash(
    "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
)

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
    async def test_returns_immediately_when_active(self):
        mgr = MagicMock()
        mgr.get_service_active_state.return_value = "active"
        ex = _make_execution(mgr)

        await ex.wait_for_controller_ready()

        mgr.get_service_active_state.assert_called_once_with(
            ex.controller_service,
        )

    @pytest.mark.asyncio
    async def test_polls_until_active(self):
        mgr = MagicMock()
        # activating for 2 attempts, then active
        mgr.get_service_active_state.side_effect = [
            "activating",
            "activating",
            "active",
        ]
        ex = _make_execution(mgr)

        await ex.wait_for_controller_ready()

        assert mgr.get_service_active_state.call_count == 3

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
        with pytest.raises(AssertionError):
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
        with pytest.raises(AssertionError):
            await ex_no_manager.wait_for_controller_ready()
