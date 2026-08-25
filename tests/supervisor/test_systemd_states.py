"""Batched ActiveState lookup keeps the raw systemd string.

get_services_active_states collapses ActiveState to `== "active"`, which
throws away the distinction between a unit that never started and one that
failed. get_services_states preserves it, with the boolean helper expressed
on top so both come from a single ListUnits() call.
"""

from unittest.mock import MagicMock

import pytest

from aleph.vm.systemd import SystemDManager

SERVICE = "aleph-vm-controller@decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca.service"
OTHER = "aleph-vm-controller@beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef.service"


def _unit(name: str, active_state: str):
    """One ListUnits() row: (name, description, load_state, active_state,
    sub_state, following, unit_path, job_id, job_type, job_path)."""
    return (name, "", "loaded", active_state, "", "", "/org/freedesktop/systemd1/unit/x", 0, "", "/job/x")


@pytest.fixture
def manager(mocker) -> SystemDManager:
    mocker.patch.object(SystemDManager, "_connect")
    return SystemDManager()


def _with_units(manager: SystemDManager, *units) -> SystemDManager:
    manager._get_manager = MagicMock(return_value=MagicMock(ListUnits=MagicMock(return_value=list(units))))
    manager._call_with_reconnect = MagicMock(side_effect=lambda call: call())
    return manager


class TestGetServicesStates:
    def test_reports_the_raw_active_state(self, manager):
        _with_units(manager, _unit(SERVICE, "failed"))
        assert manager.get_services_states([SERVICE]) == {SERVICE: "failed"}

    def test_reports_not_loaded_for_a_unit_systemd_does_not_list(self, manager):
        _with_units(manager, _unit(OTHER, "active"))
        assert manager.get_services_states([SERVICE]) == {SERVICE: "not-loaded"}

    def test_one_call_covers_every_service(self, manager):
        _with_units(manager, _unit(SERVICE, "active"), _unit(OTHER, "failed"))
        assert manager.get_services_states([SERVICE, OTHER]) == {SERVICE: "active", OTHER: "failed"}
        assert manager._call_with_reconnect.call_count == 1

    def test_no_services_needs_no_dbus_call(self, manager):
        _with_units(manager)
        assert manager.get_services_states([]) == {}
        assert manager._call_with_reconnect.call_count == 0


class TestActiveStatesStillBoolean:
    """The existing boolean API keeps its exact semantics."""

    def test_active_is_true(self, manager):
        _with_units(manager, _unit(SERVICE, "active"))
        assert manager.get_services_active_states([SERVICE]) == {SERVICE: True}

    def test_failed_is_false(self, manager):
        _with_units(manager, _unit(SERVICE, "failed"))
        assert manager.get_services_active_states([SERVICE]) == {SERVICE: False}

    def test_unlisted_is_false(self, manager):
        _with_units(manager)
        assert manager.get_services_active_states([SERVICE]) == {SERVICE: False}
