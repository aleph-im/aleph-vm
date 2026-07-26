"""Unit tests for aleph.vm.systemd.SystemDManager.

Focus on the stale-proxy retry path: when a D-Bus call raises one of
``_STALE_CONNECTION_ERRORS`` (e.g. after ``systemctl daemon-reexec``
rotates systemd's unique bus name), ``_call_with_reconnect`` must
reconnect and re-run the callable so the second attempt routes through
the freshly-built manager, not the closed connection.
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
    return DBusException(msg, name=name)


@pytest.fixture
def fake_manager(monkeypatch):
    """Instantiate a SystemDManager backed by MagicMock buses/managers.

    Returns ``(manager_instance, initial_dbus_manager, install_new_manager_fn)``.
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
    work = MagicMock(return_value="ok")

    assert sm._call_with_reconnect(work) == "ok"

    work.assert_called_once_with()
    # No reconnect happened: manager unchanged.
    assert sm._manager is initial


def test_non_stale_error_reraises_without_reconnect(fake_manager):
    sm, initial, _ = fake_manager
    real_error = _make_dbus_error("org.freedesktop.systemd1.NoSuchUnit")
    work = MagicMock(side_effect=real_error)

    with pytest.raises(DBusException) as excinfo:
        sm._call_with_reconnect(work)

    assert excinfo.value is real_error
    work.assert_called_once_with()
    assert sm._manager is initial


def test_stale_error_reconnects_and_work_sees_new_manager(fake_manager):
    """The core regression test.

    Simulates systemd daemon-reexec:
      1. work() reads self._manager and calls it. First call raises
         ServiceUnknown from the stale manager.
      2. _connect() runs and installs a fresh manager.
      3. work() is re-invoked. It reads self._manager again — this time
         it sees the NEW manager, and the second call succeeds.

    The test asserts work observed the manager swap, which is exactly
    what the retry mechanism must guarantee.
    """
    sm, initial, install = fake_manager

    stale_error = _make_dbus_error("org.freedesktop.DBus.Error.ServiceUnknown")
    initial.SomeCall.side_effect = stale_error

    new_mgr = MagicMock(name="new_manager")
    new_mgr.SomeCall.return_value = "ok-from-new"
    install(new_mgr)

    managers_seen = []

    def work():
        mgr = sm._manager
        managers_seen.append(mgr)
        return mgr.SomeCall("arg")

    result = sm._call_with_reconnect(work)

    assert result == "ok-from-new"
    assert managers_seen == [initial, new_mgr]
    initial.SomeCall.assert_called_once_with("arg")
    new_mgr.SomeCall.assert_called_once_with("arg")


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
    new_mgr.SomeCall.return_value = "ok"
    install(new_mgr)

    calls = [0]

    def work():
        calls[0] += 1
        if calls[0] == 1:
            raise _make_dbus_error(error_name)
        return sm._manager.SomeCall()

    assert sm._call_with_reconnect(work) == "ok"
    assert calls[0] == 2
    new_mgr.SomeCall.assert_called_once_with()


def test_retry_failure_propagates(fake_manager):
    """If the retry itself fails with the same stale error, don't loop.

    The whole point of a single retry is to avoid infinite loops when
    something is fundamentally broken (bus daemon down, systemd not
    coming back). The second failure should propagate to the caller.
    """
    sm, _initial, install = fake_manager

    def broken_connect(self, max_retries: int = 3) -> None:
        self._bus = MagicMock()
        self._manager = MagicMock()

    # Both first call and post-reconnect retry raise the same stale error.
    stale = _make_dbus_error("org.freedesktop.DBus.Error.Disconnected")
    work = MagicMock(side_effect=stale)
    install(MagicMock())  # so reconnect doesn't blow up

    with pytest.raises(DBusException) as excinfo:
        sm._call_with_reconnect(work)

    assert excinfo.value is stale
    # First call + one retry = two attempts, no more.
    assert work.call_count == 2


@pytest.mark.asyncio
async def test_enable_and_start_runs_off_event_loop(fake_manager, monkeypatch):
    """enable_and_start must not block the event loop.

    Records the thread on which the sync body runs and asserts it is
    NOT the main thread (asyncio.to_thread hands work to the default
    executor). Prevents accidental regression to inline sync D-Bus.
    """
    import threading

    sm, _initial, _install = fake_manager

    main_thread = threading.get_ident()
    thread_seen = {}

    def fake_sync(service):
        thread_seen["ident"] = threading.get_ident()

    monkeypatch.setattr(sm, "_enable_and_start_sync", fake_sync)

    await sm.enable_and_start("aleph-vm-controller@svc.service")

    assert thread_seen["ident"] != main_thread


@pytest.mark.asyncio
async def test_enable_and_start_propagates_errors(fake_manager, monkeypatch):
    """Exceptions raised by the sync body must surface to the async caller."""
    sm, _initial, _install = fake_manager

    def raising(_):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(sm, "_enable_and_start_sync", raising)

    with pytest.raises(RuntimeError, match="kaboom"):
        await sm.enable_and_start("aleph-vm-controller@svc.service")
