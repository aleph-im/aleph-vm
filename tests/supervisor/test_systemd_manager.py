"""Tests for SystemDManager's stop/disable gating logic."""

from unittest.mock import MagicMock

import pytest

from aleph.vm.systemd import SystemDManager

SERVICE = "aleph-vm-controller@decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca.service"


@pytest.fixture
def manager(mocker) -> SystemDManager:
    mocker.patch.object(SystemDManager, "_connect")
    mgr = SystemDManager()
    mgr.stop = MagicMock()
    mgr.disable = MagicMock()
    mgr.get_service_active_state = MagicMock()
    mgr.is_service_enabled = MagicMock(return_value=False)
    return mgr


class TestStopAndDisable:
    def test_stops_an_active_unit_even_when_not_enabled(self, manager):
        """The stop must be gated on ActiveState, never on enablement: a
        unit can be active without being enabled (a template without an
        [Install] section cannot be enabled at all). Gating on enablement
        silently skipped the stop and left qemu running while the caller
        tore down its network."""
        manager.get_service_active_state.return_value = "active"
        manager.is_service_enabled.return_value = False

        manager.stop_and_disable(SERVICE)

        manager.stop.assert_called_once_with(SERVICE)
        manager.disable.assert_not_called()

    @pytest.mark.parametrize("state", ["inactive", "failed", "not-loaded"])
    def test_skips_stop_when_unit_is_down(self, manager, state):
        manager.get_service_active_state.return_value = state

        manager.stop_and_disable(SERVICE)

        manager.stop.assert_not_called()

    @pytest.mark.parametrize("state", ["activating", "deactivating", "unknown"])
    def test_stops_on_transitional_or_unknown_state(self, manager, state):
        """StopUnit on a unit that is already deactivating, or whose state
        could not be read, is harmless; skipping it is not."""
        manager.get_service_active_state.return_value = state

        manager.stop_and_disable(SERVICE)

        manager.stop.assert_called_once_with(SERVICE)

    def test_disables_an_enabled_unit(self, manager):
        manager.get_service_active_state.return_value = "inactive"
        manager.is_service_enabled.return_value = True

        manager.stop_and_disable(SERVICE)

        manager.stop.assert_not_called()
        manager.disable.assert_called_once_with(SERVICE)
