"""Unit tests for aleph.vm.systemd.SystemDManager.

Focus on the stale-proxy retry path: when a call raises one of
``_STALE_CONNECTION_ERRORS`` (e.g. after ``systemctl daemon-reexec``
rotates systemd's unique bus name), the manager must reconnect and
retry the same D-Bus method against the NEW manager, not re-invoke the
stale ``_ProxyMethod`` against a closed connection.
"""

from unittest.mock import MagicMock

import pytest
from dbus.exceptions import DBusException

from aleph.vm.systemd import SystemDManager


def _make_dbus_error(name: str, msg: str = "boom") -> DBusException:
    """Build a DBusException whose ``get_dbus_name()`` returns ``name``.

    Mirrors what dbus-python raises when the daemon replies with an
    error name, without touching a real bus.
    """
    err = DBusException(msg, name=name)
    return err


@pytest.fixture
def fake_manager(monkeypatch):
    """Instantiate a SystemDManager backed by a MagicMock manager.

    Yields ``(manager_instance, initial_dbus_manager, install_new_manager_fn)``.
    Calling ``install_new_manager_fn(new_mgr)`` patches ``_connect`` so the
    NEXT reconnect installs ``new_mgr`` (simulating systemd daemon-reexec).
    """
    initial = MagicMock(name="initial_manager")

    def install(mgr):
        def fake_connect(self, max_retries: int = 3) -> None:
            self._bus = MagicMock()
            self._bus.get_is_connected.return_value = True
            self._manager = mgr

        monkeypatch.setattr(SystemDManager, "_connect", fake_connect)

    install(initial)
    sm = SystemDManager()
    return sm, initial, install


def test_happy_path_no_reconnect(fake_manager):
    sm, initial, _ = fake_manager
    method = MagicMock(return_value="ok")
    method._method_name = "StartUnit"

    assert sm._call_with_reconnect(method, "svc", "replace") == "ok"

    method.assert_called_once_with("svc", "replace")
    # No rebind against the manager happened
    initial.get_dbus_method.assert_not_called()


def test_non_stale_error_reraises_without_reconnect(fake_manager):
    sm, initial, _ = fake_manager
    real_error = _make_dbus_error("org.freedesktop.systemd1.NoSuchUnit")
    method = MagicMock(side_effect=real_error)
    method._method_name = "GetUnit"

    with pytest.raises(DBusException) as excinfo:
        sm._call_with_reconnect(method, "svc")

    assert excinfo.value is real_error
    initial.get_dbus_method.assert_not_called()
    # Manager was not swapped
    assert sm._manager is initial


def test_stale_error_reconnects_and_retries_via_new_manager(fake_manager):
    """The core regression test.

    Simulates systemd daemon-reexec:
      1. First call on the stale _ProxyMethod raises ServiceUnknown.
      2. _connect() runs and installs a fresh manager.
      3. Retry MUST go through new_manager.get_dbus_method(...), not
         through the stale method whose _connection was just closed.
    """
    sm, initial, install = fake_manager

    new_mgr = MagicMock(name="new_manager")
    fresh_method = MagicMock(return_value="ok-from-new")
    new_mgr.get_dbus_method.return_value = fresh_method
    install(new_mgr)

    stale_method = MagicMock(side_effect=_make_dbus_error("org.freedesktop.DBus.Error.ServiceUnknown"))
    stale_method._method_name = "EnableUnitFiles"

    result = sm._call_with_reconnect(stale_method, ["svc"], False, True)

    assert result == "ok-from-new"
    # Reconnect swapped the manager
    assert sm._manager is new_mgr
    # Method was looked up on the NEW manager by name
    new_mgr.get_dbus_method.assert_called_once_with("EnableUnitFiles")
    fresh_method.assert_called_once_with(["svc"], False, True)
    # Stale method was NOT retried (that would go through the closed connection)
    assert stale_method.call_count == 1


@pytest.mark.parametrize(
    "error_name",
    [
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NoReply",
        "org.freedesktop.DBus.Error.Disconnected",
    ],
)
def test_all_stale_error_names_trigger_retry(fake_manager, error_name):
    sm, _initial, install = fake_manager
    new_mgr = MagicMock()
    new_mgr.get_dbus_method.return_value = MagicMock(return_value="ok")
    install(new_mgr)

    stale = MagicMock(side_effect=_make_dbus_error(error_name))
    stale._method_name = "StartUnit"

    assert sm._call_with_reconnect(stale, "svc", "replace") == "ok"
    new_mgr.get_dbus_method.assert_called_once_with("StartUnit")


def test_reraises_when_method_name_missing(fake_manager):
    """A callable without ``_method_name`` can't be safely rebound.

    Retrying it directly would call through the connection ``_connect()``
    just closed. Better to surface the original failure than to fail
    obscurely.
    """
    sm, _initial, install = fake_manager
    new_mgr = MagicMock()
    install(new_mgr)

    original_error = _make_dbus_error("org.freedesktop.DBus.Error.Disconnected")
    plain_callable = MagicMock(side_effect=original_error)
    # No _method_name attribute
    del plain_callable._method_name

    with pytest.raises(DBusException) as excinfo:
        sm._call_with_reconnect(plain_callable, "arg")

    assert excinfo.value is original_error
    # Reconnect DID run (we discover the un-rebindable fn only after)
    assert sm._manager is new_mgr
    # But we didn't retry against the stale callable
    assert plain_callable.call_count == 1
    new_mgr.get_dbus_method.assert_not_called()
