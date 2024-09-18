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

    bus: SystemBus
    manager: Interface

    def __init__(self):
        self.bus = dbus.SystemBus()
        systemd = self.bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
        self.manager = dbus.Interface(systemd, "org.freedesktop.systemd1.Manager")

    def stop_and_disable(self, service: str) -> None:
        if self.is_service_active(service):
            self.stop(service)
        if self.is_service_enabled(service):
            self.disable(service)

    def enable(self, service: str) -> None:
        self.manager.EnableUnitFiles([service], False, True)
        logger.debug(f"Enabled {service} service")

    def start(self, service: str) -> None:
        self.manager.StartUnit(service, "replace")
        logger.debug(f"Started {service} service")

    def stop(self, service: str) -> None:
        self.manager.StopUnit(service, "replace")
        logger.debug(f"Stopped {service} service")

    def restart(self, service: str) -> None:
        self.manager.RestartUnit(service, "replace")
        logger.debug(f"Restarted {service} service")

    def disable(self, service: str) -> None:
        self.manager.DisableUnitFiles([service], False)
        logger.debug(f"Disabled {service} service")

    def is_service_enabled(self, service: str) -> bool:
        try:
            return self.manager.GetUnitFileState(service) == "enabled"
        except DBusException as error:
            logger.error(error)
            return False

    def is_service_active(self, service: str) -> bool:
        try:
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

    def enable_and_start(self, service: str) -> None:
        if not self.is_service_enabled(service):
            self.enable(service)
        if not self.is_service_active(service):
            self.start(service)
