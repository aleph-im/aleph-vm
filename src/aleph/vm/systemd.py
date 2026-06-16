"""
async SystemD Manager implementation.
"""

import asyncio
import logging
import threading

import dbus
from dbus import DBusException, SystemBus
from dbus.proxies import Interface

logger = logging.getLogger(__name__)


class SystemDManagerError(Exception):
    """Raised when SystemD manager operations fail."""

    pass


_NO_SUCH_UNIT = "org.freedesktop.systemd1.NoSuchUnit"

# DBus errors that mean "your cached proxy points at a dead unique
# name" (typically after systemctl daemon-reexec or a systemd package
# upgrade rotates its unique bus name). Reconnecting and retrying the
# call resolves the well-known name to the current owner.
#
# NoReply is included so we survive systemd being briefly unresponsive
# during a restart, at the cost of retrying legitimate slow calls once
# — worst case doubles that call's wall time. Acceptable tradeoff:
# genuine NoReply is rare on a healthy host and we still fail fast if
# the retry itself times out.
_STALE_CONNECTION_ERRORS = frozenset(
    {
        "org.freedesktop.DBus.Error.ServiceUnknown",
        "org.freedesktop.DBus.Error.NoReply",
        "org.freedesktop.DBus.Error.Disconnected",
    }
)


def _log_dbus_lookup_error(service: str, error: DBusException) -> None:
    """Log a unit lookup error at the right severity.

    NoSuchUnit is a routine outcome (instance was stopped or never
    loaded) and should not pollute ERROR logs. Other DBusExceptions
    are real and worth surfacing.
    """
    if error.get_dbus_name() == _NO_SUCH_UNIT:
        logger.debug("Service %s not loaded", service)
    else:
        logger.error("D-Bus lookup failed for %s: %s", service, error)


class SystemDManager:
    """SystemD Manager class.

    Used to manage the systemd services on the host on Linux.
    """

    def __init__(self):
        self._bus: SystemBus | None = None
        self._manager: Interface | None = None
        # Guards _connect(): concurrent callers (event loop + payment
        # monitor worker + enable_and_start worker) must not race on
        # close+reopen of self._bus.
        self._connect_lock = threading.Lock()
        self._connect()

    def _connect(self, max_retries: int = 3) -> None:
        """Establish connection to D-Bus with a retry mechanism.

        Each call resolves ``org.freedesktop.systemd1`` to systemd's
        current unique bus name at proxy creation time. A subsequent
        ``systemctl daemon-reexec`` or systemd package upgrade rotates
        that unique name, and the cached proxy then fails with
        ``org.freedesktop.DBus.Error.ServiceUnknown``. That failure is
        caught by ``_call_with_reconnect`` on every state-changing
        method, which calls ``_connect()`` again to rebuild the proxy
        against the new owner and retries the call.

        (The alternative — ``follow_name_owner_changes=True`` — would
        keep the proxy bound to the well-known name and avoid the
        first-call failure after a restart, but it internally subscribes
        to ``NameOwnerChanged`` signals, which requires a D-Bus main
        loop. Aleph-vm's asyncio supervisor has no such main loop, and
        constructing the proxy without one raises RuntimeError at
        import time in every context that instantiates SystemDManager.)
        """
        # Lock serializes concurrent reconnects across threads (event
        # loop + payment monitor worker + enable_and_start worker).
        # Two threads hitting the same stale error at the same moment
        # will each reconnect once inside the lock; the redundant work
        # is bounded and doesn't corrupt state. We do NOT fast-path on
        # get_is_connected(): callers reach _connect() precisely when
        # they know the proxy is stale, and get_is_connected() is a
        # local flag that stays True across bus-name rotations.
        with self._connect_lock:
            for attempt in range(max_retries):
                if self._bus:
                    self._bus.close()
                try:
                    self._bus = dbus.SystemBus()
                    systemd = self._bus.get_object(
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                    )
                    self._manager = dbus.Interface(systemd, "org.freedesktop.systemd1.Manager")
                    return
                except DBusException as e:
                    logger.warning(f"D-Bus connection attempt {attempt + 1} failed: {e}")
            msg = "Failed to establish D-Bus connection after multiple attempts"
            raise DBusException(msg)

    def _call_with_reconnect(self, work):
        """Run ``work()``; on stale-connection errors, reconnect and re-run once.

        ``work`` is a zero-argument callable that performs the D-Bus
        operation from scratch (typically a lambda that calls
        ``self._get_manager().SomeMethod(...)``). Passing a callable
        rather than a pre-resolved method matters: a pre-resolved
        ``_ProxyMethod`` is bound to the ``_connection`` we just closed
        via ``self._bus.close()``, so retrying it would go through the
        dead connection. Re-invoking ``work()`` after ``_connect()``
        reads the new ``self._manager`` and routes through the fresh
        proxy — no need to peek at ``_method_name`` or rebind.

        Also handles multi-call chains (e.g. ``manager.GetUnit`` then
        ``bus.get_object`` then ``properties.Get``): the whole sequence
        is redone against the fresh bus and manager.
        """
        try:
            return work()
        except DBusException as error:
            if error.get_dbus_name() not in _STALE_CONNECTION_ERRORS:
                raise
            logger.info(
                "Stale systemd D-Bus proxy (%s), reconnecting and retrying",
                error.get_dbus_name(),
            )
            self._connect()
            return work()

    def _ensure_connection(self) -> None:
        """Ensure D-Bus connection is active, reconnect if necessary.

        Uses ``get_is_connected()`` as a cheap local check. The previous
        implementation called ``ListUnits()`` here as a "test": that
        enumerates every loaded systemd unit on the host over D-Bus and
        ran ahead of every operation, turning a per-VM ``is_service_active``
        sweep into N full host enumerations and stalling the event loop
        for tens of seconds.

        Note: ``get_is_connected()`` is a local library-level flag and
        does not round-trip to the D-Bus daemon, so it cannot detect a
        hung or unresponsive daemon. Real call failures still trigger
        reconnect via the per-method ``DBusException`` handlers; this
        check exists only to short-circuit the obvious "bus closed"
        case before issuing the actual call.
        """
        if self._bus is None or self._manager is None:
            self._connect()
            return
        try:
            if not self._bus.get_is_connected():
                self._connect()
        except (DBusException, AttributeError):
            logger.info("D-Bus connection lost, reconnecting")
            self._connect()

    def _get_manager(self) -> Interface:
        """Get the D-Bus manager interface or raise an error."""
        self._ensure_connection()
        if self._manager is None:
            msg = "D-Bus manager is not initialized"
            raise SystemDManagerError(msg)
        return self._manager

    def _get_bus(self) -> SystemBus:
        """Get the D-Bus system bus or raise an error."""
        self._ensure_connection()
        if self._bus is None:
            msg = "D-Bus system bus is not initialized"
            raise SystemDManagerError(msg)
        return self._bus

    def stop_and_disable(self, service: str) -> None:
        # Gate the stop on the unit's actual ActiveState, never on its
        # enablement: a unit can be active without being enabled (e.g. a
        # template with no [Install] section cannot be enabled at all), and
        # skipping the stop silently leaves qemu running while the caller
        # tears down its network.
        if self.get_service_active_state(service) not in ("inactive", "failed", "not-loaded"):
            self.stop(service)
        if self.is_service_enabled(service):
            self.disable(service)

    def disable_service(self, service: str) -> None:
        """Disable a service that is already known to be inactive.

        Skips the active/enabled state checks that stop_and_disable
        performs, avoiding redundant D-Bus round-trips when the caller
        has already determined the service state via batch queries.
        """
        try:
            self.disable(service)
        except DBusException as error:
            logger.warning("Failed to disable %s: %s", service, error)

    def enable(self, service: str) -> None:
        self._call_with_reconnect(
            lambda: self._get_manager().EnableUnitFiles([service], False, True)  # noqa: FBT003
        )
        logger.debug(f"Enabled {service} service")

    def start(self, service: str) -> None:
        self._call_with_reconnect(lambda: self._get_manager().StartUnit(service, "replace"))
        logger.debug(f"Started {service} service")

    def stop(self, service: str) -> None:
        self._call_with_reconnect(lambda: self._get_manager().StopUnit(service, "replace"))
        logger.debug(f"Stopped {service} service")

    def restart(self, service: str) -> None:
        self._call_with_reconnect(lambda: self._get_manager().RestartUnit(service, "replace"))
        logger.debug(f"Restarted {service} service")

    def disable(self, service: str) -> None:
        self._call_with_reconnect(
            lambda: self._get_manager().DisableUnitFiles([service], False)  # noqa: FBT003
        )
        logger.debug(f"Disabled {service} service")

    def is_service_enabled(self, service: str) -> bool:
        try:
            return self._call_with_reconnect(lambda: self._get_manager().GetUnitFileState(service)) == "enabled"
        except DBusException as error:
            _log_dbus_lookup_error(service, error)
            return False

    def _read_active_state(self, service: str) -> str:
        """Fetch ActiveState for ``service`` via manager + property lookup.

        Extracted so the whole multi-call chain can be re-run atomically
        under ``_call_with_reconnect``: on a stale proxy, ``GetUnit``
        fails first, we reconnect, and the whole sequence re-runs against
        the fresh bus and manager (so ``bus.get_object`` and the properties
        interface are also fresh).
        """
        manager = self._get_manager()
        bus = self._get_bus()
        unit_path = manager.GetUnit(service)
        unit_proxy = bus.get_object("org.freedesktop.systemd1", object_path=unit_path)
        properties = dbus.Interface(unit_proxy, "org.freedesktop.DBus.Properties")
        return str(properties.Get("org.freedesktop.systemd1.Unit", "ActiveState"))

    def get_service_active_state(self, service: str) -> str:
        """Return the ActiveState string for a systemd service.

        Possible values: "active", "activating", "deactivating",
        "inactive", "failed", plus two synthetic ones: "not-loaded" when
        the unit is not loaded in systemd (GetUnit raises NoSuchUnit;
        happens before the first StartUnit, and again once a cleanly
        stopped unit is garbage-collected) and "unknown" on other D-Bus
        errors.  Callers should retry on "unknown"; "not-loaded" means
        the unit is positively not running.
        """
        try:
            return self._call_with_reconnect(lambda: self._read_active_state(service))
        except DBusException as error:
            _log_dbus_lookup_error(service, error)
            if error.get_dbus_name() == _NO_SUCH_UNIT:
                return "not-loaded"
            return "unknown"

    def is_service_active(self, service: str) -> bool:
        if not self.is_service_enabled(service):
            return False
        try:
            return self._call_with_reconnect(lambda: self._read_active_state(service)) == "active"
        except DBusException as error:
            _log_dbus_lookup_error(service, error)
            return False

    def get_services_active_states(self, services: list[str]) -> dict[str, bool]:
        """Get active state of multiple services in a single D-Bus call.

        This is much more efficient than calling is_service_active() for each service,
        as it uses ListUnits() which returns all loaded units in one call.

        Args:
            services: List of service names to check (e.g., ["aleph-vm-controller@hash.service"])

        Returns:
            Dictionary mapping service name to active state (True if active, False otherwise)
        """
        if not services:
            return {}

        try:
            units = self._call_with_reconnect(lambda: self._get_manager().ListUnits())

            # Build lookup from ListUnits() result
            # ListUnits returns: (name, description, load_state, active_state, sub_state,
            #                     following, unit_path, job_id, job_type, job_path)
            active_states: dict[str, bool] = {}
            service_set = set(services)

            for unit in units:
                name = str(unit[0])
                if name in service_set:
                    active_state = str(unit[3])
                    active_states[name] = active_state == "active"

            # Services not in ListUnits() output are not loaded (treat as inactive)
            for service in services:
                if service not in active_states:
                    active_states[service] = False

            return active_states
        except DBusException as error:
            logger.error(f"Failed to get services active states: {error}")
            # Return all as inactive on error
            return {service: False for service in services}

    def get_services_enabled_states(self, services: list[str]) -> dict[str, bool]:
        """Get enabled state of multiple services via individual GetUnitFileState calls.

        Args:
            services: List of service names to check.

        Returns:
            Dictionary mapping service name to enabled state.
        """
        if not services:
            return {}

        result: dict[str, bool] = {}
        try:
            manager = self._get_manager()
            for service in services:
                try:
                    result[service] = str(manager.GetUnitFileState(service)) == "enabled"
                except DBusException:
                    result[service] = False
        except DBusException as error:
            logger.error(f"Failed to get services enabled states: {error}")
            return {service: False for service in services}
        return result

    def _enable_and_start_sync(self, service: str) -> None:
        """Sync body of enable_and_start; runs in a worker thread."""
        if not self.is_service_enabled(service):
            self.enable(service)
        if not self.is_service_active(service):
            self.start(service)

    async def enable_and_start(self, service: str) -> None:
        """Enable and start a systemd unit without blocking the event loop.

        Each of the four underlying D-Bus round-trips is synchronous and
        would block the asyncio event loop if run inline (visible as
        multi-second TTFB spikes when many VMs start together). Push the
        whole sequence to a worker thread. Thread safety of the shared
        SystemDManager is provided by ``_connect_lock`` around the only
        state-mutating operation (reconnect); individual D-Bus calls go
        through dbus-python's own connection-level locking.
        """
        await asyncio.to_thread(self._enable_and_start_sync, service)
