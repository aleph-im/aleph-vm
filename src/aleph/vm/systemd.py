"""
async SystemD Manager implementation.
"""

import sys
import dbus

import logging

from dbus import SystemBus
from dbus.proxies import Interface

logger = logging.getLogger(__name__)


class SystemDManager:
    bus: SystemBus
    manager: Interface

    def __init__(self):
        self.bus = dbus.SystemBus()
        systemd = self.bus.get_object('org.freedesktop.systemd1', '/org/freedesktop/systemd1')
        self.manager = dbus.Interface(systemd, 'org.freedesktop.systemd1.Manager')

    def stop_and_disable(self, service: str) -> None:
        try:
            if self.is_service_active(service):
                self.start(service)
            if self.is_service_enabled(service):
                self.enable(service)
        except Exception:
            raise

    def enable(self, service: str) -> None:
        self.manager.EnableUnitFiles([service], False, True)
        logger.debug(f"Enabled {service} service")

    def start(self, service: str) -> None:
        self.manager.StartUnit(service, 'replace')
        logger.debug(f"Started {service} service")

    def stop(self, service: str) -> None:
        self.manager.StopUnit(service, 'replace')
        logger.debug(f"Stopped {service} service")

    def restart(self, service: str) -> None:
        self.manager.RestartUnit(service, 'replace')
        logger.debug(f"Restarted {service} service")

    def disable(self, service: str) -> None:
        self.manager.DisableUnitFiles([service], False)
        logger.debug(f"Disabled {service} service")

    def is_service_enabled(self, service: str) -> bool:
        try:
            return self.manager.GetUnitFileState(service) == 'enabled'
        except:
            return False

    def is_service_active(self, service: str) -> bool:
        try:
            self.manager.GetUnit(self, service)
            return True
        except:
            return False

    def enable_and_start(self, service: str) -> None:
        try:
            if not self.is_service_enabled(service):
                self.enable(service)
            if not self.is_service_active(service):
                self.start(service)
        except Exception:
            raise
