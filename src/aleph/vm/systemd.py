"""
async SystemD Manager implementation.
"""

import logging

import dbus
from dbus import DBusException, SystemBus
from dbus.proxies import Interface

logger = logging.getLogger(__name__)


class SystemDManager:
    """SystemD Manager class.

    Used to manage the systemd services on the host on Linux.
    """

    bus: SystemBus | None
    manager: Interface | None

    def __init__(self):
        self.bus = None
        self.manager = None
        self._connect()

    def _connect(self, max_retries: int = 3) -> None:
        """Establish connection to D-Bus with a retry mechanism."""
        for attempt in range(max_retries):
            if self.bus:
                self.bus.close()
            try:
                self.bus = dbus.SystemBus()
                systemd = self.bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
                self.manager = dbus.Interface(systemd, "org.freedesktop.systemd1.Manager")
                return
            except DBusException as e:
                logger.warning(f"D-Bus connection attempt {attempt + 1} failed: {e}")
        msg = "Failed to establish D-Bus connection after multiple attempts"
        raise DBusException(msg)

    def _ensure_connection(self) -> None:
        """Ensure D-Bus connection is active, reconnect if necessary."""
        try:
            if self.bus is None or self.manager is None:
                self._connect()
            self.bus.get_is_connected()
            # Try a simple operation to test the connection
            self.manager.ListUnits()
        except (DBusException, AttributeError):
            logger.info("D-Bus connection lost, attempting to reconnect...")
            self._connect()

    def stop_and_disable(self, service: str) -> None:
        self._ensure_connection()
        if self.is_service_active(service):
            self.stop(service)
        if self.is_service_enabled(service):
            self.disable(service)

    def enable(self, service: str) -> None:
        self._ensure_connection()
        self.manager.EnableUnitFiles([service], False, True)  # noqa: FBT003
        logger.debug(f"Enabled {service} service")

    def start(self, service: str) -> None:
        self._ensure_connection()
        self.manager.StartUnit(service, "replace")
        logger.debug(f"Started {service} service")

    def stop(self, service: str) -> None:
        self._ensure_connection()
        self.manager.StopUnit(service, "replace")
        logger.debug(f"Stopped {service} service")

    def restart(self, service: str) -> None:
        self._ensure_connection()
        self.manager.RestartUnit(service, "replace")
        logger.debug(f"Restarted {service} service")

    def disable(self, service: str) -> None:
        self._ensure_connection()
        self.manager.DisableUnitFiles([service], False)  # noqa: FBT003
        logger.debug(f"Disabled {service} service")

    def is_service_enabled(self, service: str) -> bool:
        try:
            self._ensure_connection()
            return self.manager.GetUnitFileState(service) == "enabled"
        except DBusException as error:
            logger.error(error)
            return False

    def is_service_active(self, service: str) -> bool:
        try:
            self._ensure_connection()
            if not self.is_service_enabled(service):
                return False
            unit_path = self.manager.GetUnit(service)
            systemd_service = self.bus.get_object("org.freedesktop.systemd1", object_path=unit_path)
            unit = dbus.Interface(systemd_service, "org.freedesktop.systemd1.Unit")
            unit_properties = dbus.Interface(unit, "org.freedesktop.DBus.Properties")
            active_state = unit_properties.Get("org.freedesktop.systemd1.Unit", "ActiveState")
            return active_state == "active"
        except DBusException as error:
            logger.error(error)
            return False

    async def enable_and_start(self, service: str) -> None:
        self._ensure_connection()
        if not self.is_service_enabled(service):
            self.enable(service)
        if not self.is_service_active(service):
            self.start(service)
