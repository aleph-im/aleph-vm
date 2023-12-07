"""
async SystemD Manager implementation.
"""

import logging
import sys

import dbus
from dbus import DBusException, SystemBus
from dbus.proxies import Interface

logger = logging.getLogger(__name__)


class SystemDManager:
    bus: SystemBus
    interface: Interface

    def __init__(self):
        self.bus = dbus.SystemBus()
        systemd = self.bus.get_object("org.freedesktop.systemd1", "/org/freedesktop/systemd1")
        self.interface = dbus.Interface(systemd, "org.freedesktop.systemd1.Manager")

    def stop_and_disable(self, service: str) -> None:
        if self.is_service_active(service):
            self.stop(service)
        if self.is_service_enabled(service):
            self.disable(service)

    def enable(self, service: str) -> None:
        self.interface.EnableUnitFiles([service], False, True)
        logger.debug(f"Enabled {service} service")

    def start(self, service: str) -> None:
        self.interface.StartUnit(service, "replace")
        logger.debug(f"Started {service} service")

    def stop(self, service: str) -> None:
        self.interface.StopUnit(service, "replace")
        logger.debug(f"Stopped {service} service")

    def restart(self, service: str) -> None:
        self.interface.RestartUnit(service, "replace")
        logger.debug(f"Restarted {service} service")

    def disable(self, service: str) -> None:
        self.interface.DisableUnitFiles([service], False)
        logger.debug(f"Disabled {service} service")

    def is_service_enabled(self, service: str) -> bool:
        try:
            return self.interface.GetUnitFileState(service) == "enabled"
        except DBusException as error:
            logger.error(error)
            return False

    def is_service_active(self, service: str) -> bool:
        try:
            self.interface.GetUnit(service)
            return True
        except DBusException as error:
            logger.error(error)
            return False

    def enable_and_start(self, service: str) -> None:
        if not self.is_service_enabled(service):
            self.enable(service)
        if not self.is_service_active(service):
            self.start(service)
