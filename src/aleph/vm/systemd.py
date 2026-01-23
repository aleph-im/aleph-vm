"""
async SystemD Manager implementation.
"""

import logging

import dbus
from dbus import DBusException, SystemBus
from dbus.proxies import Interface

logger = logging.getLogger(__name__)


class SystemDManagerError(Exception):
    """Raised when SystemD manager operations fail."""

    pass


class SystemDManager:
    """SystemD Manager class.

    Used to manage the systemd services on the host on Linux.
    """

    def __init__(self):
        self._bus: SystemBus | None = None
        self._manager: Interface | None = None
        self._connect()

    def _connect(self, max_retries: int = 3) -> None:
        """Establish connection to D-Bus with a retry mechanism."""
        for attempt in range(max_retries):
            if self._bus:
                self._bus.close()
            try:
                self._bus = dbus.SystemBus()
                systemd = self._bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
                self._manager = dbus.Interface(systemd, "org.freedesktop.systemd1.Manager")
                return
            except DBusException as e:
                logger.warning(f"D-Bus connection attempt {attempt + 1} failed: {e}")
        msg = "Failed to establish D-Bus connection after multiple attempts"
        raise DBusException(msg)

    def _ensure_connection(self) -> None:
        """Ensure D-Bus connection is active, reconnect if necessary."""
        try:
            if self._bus is None or self._manager is None:
                self._connect()
                return
            self._bus.get_is_connected()
            # Try a simple operation to test the connection
            if self._manager is not None:
                self._manager.ListUnits()
        except (DBusException, AttributeError):
            logger.info("D-Bus connection lost, attempting to reconnect...")
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
        if self.is_service_active(service):
            self.stop(service)
        if self.is_service_enabled(service):
            self.disable(service)

    def enable(self, service: str) -> None:
        manager = self._get_manager()
        manager.EnableUnitFiles([service], False, True)  # noqa: FBT003
        logger.debug(f"Enabled {service} service")

    def start(self, service: str) -> None:
        manager = self._get_manager()
        manager.StartUnit(service, "replace")
        logger.debug(f"Started {service} service")

    def stop(self, service: str) -> None:
        manager = self._get_manager()
        manager.StopUnit(service, "replace")
        logger.debug(f"Stopped {service} service")

    def restart(self, service: str) -> None:
        manager = self._get_manager()
        manager.RestartUnit(service, "replace")
        logger.debug(f"Restarted {service} service")

    def disable(self, service: str) -> None:
        manager = self._get_manager()
        manager.DisableUnitFiles([service], False)  # noqa: FBT003
        logger.debug(f"Disabled {service} service")

    def is_service_enabled(self, service: str) -> bool:
        try:
            manager = self._get_manager()
            return manager.GetUnitFileState(service) == "enabled"
        except DBusException as error:
            logger.error(error)
            return False

    def is_service_active(self, service: str) -> bool:
        try:
            if not self.is_service_enabled(service):
                return False

            manager = self._get_manager()
            bus = self._get_bus()

            unit_path = manager.GetUnit(service)
            systemd_service = bus.get_object("org.freedesktop.systemd1", object_path=unit_path)
            unit = dbus.Interface(systemd_service, "org.freedesktop.systemd1.Unit")
            unit_properties = dbus.Interface(unit, "org.freedesktop.DBus.Properties")
            active_state = unit_properties.Get("org.freedesktop.systemd1.Unit", "ActiveState")
            return active_state == "active"
        except DBusException as error:
            logger.error(error)
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
            manager = self._get_manager()
            units = manager.ListUnits()

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

    async def enable_and_start(self, service: str) -> None:
        if not self.is_service_enabled(service):
            self.enable(service)
        if not self.is_service_active(service):
            self.start(service)
