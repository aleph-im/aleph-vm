"""
async SystemD Manager implementation.
"""

import logging
from typing import Optional

from dbus_fast import BusType, DBusError
from dbus_fast.aio import MessageBus, ProxyObject

from aleph.vm.systemd_helpers import UnitFileState, Mode, ActiveState, SystemdProxy, UnitProxy

logger = logging.getLogger(__name__)


class SystemDManager:
    """SystemD Manager class.

    Used to manage the systemd services on the host on Linux.
    """

    _bus: Optional[MessageBus] = None
    _manager: Optional[SystemdProxy] = None

    def __init__(self):
        pass

    async def get_bus(self):
        if self._bus is None:
            self._bus = MessageBus(bus_type=BusType.SYSTEM)
            await self._bus.connect()
        return self._bus

    async def get_manager(self):
        if self._manager is None:
            bus = await self.get_bus()
            path = "/org/freedesktop/systemd1"
            bus_name = "org.freedesktop.systemd1"
            introspect = await bus.introspect(bus_name, path)
            systemd_proxy: ProxyObject = bus.get_proxy_object(bus_name, path, introspection=introspect)
            interface = systemd_proxy.get_interface("org.freedesktop.systemd1.Manager")
            # Check required method are implemented
            assert isinstance(interface, SystemdProxy)
            self._manager = interface
        return self._manager

    async def enable(self, service: str) -> None:
        manager = await self.get_manager()
        await manager.call_enable_unit_files([service], False, True)
        logger.debug(f"Enabled {service} service")

    async def start(self, service: str) -> None:
        manager = await self.get_manager()
        await manager.call_start_unit(service, Mode.REPLACE)
        logger.debug(f"Started {service} service")

    async def stop(self, service: str) -> None:
        manager = await self.get_manager()
        await manager.call_stop_unit(service, Mode.REPLACE)
        logger.debug(f"Stopped {service} service")

    async def restart(self, service: str) -> None:
        manager = await self.get_manager()
        await manager.call_restart_unit(service, Mode.REPLACE)
        logger.debug(f"Restarted {service} service")

    async def disable(self, service: str) -> None:
        manager = await self.get_manager()
        await manager.call_disable_unit_files([service], False)
        logger.debug(f"Disabled {service} service")

    async def is_service_enabled(self, service: str) -> bool:
        manager = await self.get_manager()
        try:
            state = await manager.call_get_unit_file_state(service)
            return state == UnitFileState.ENABLED
        except DBusError as error:
            logger.error(error)
            return False

    async def is_service_active(self, service: str) -> bool:
        manager = await self.get_manager()
        try:
            path = await manager.call_get_unit(service)
            bus = await self.get_bus()
            bus_name = "org.freedesktop.systemd1"
            introspect = await bus.introspect(bus_name, path)
            systemd_service = bus.get_proxy_object(bus_name, path, introspection=introspect)
            unit = systemd_service.get_interface("org.freedesktop.systemd1.Unit")
            # Check required method are implemented
            assert isinstance(unit, UnitProxy)
            active_state = await unit.get_active_state()
            return active_state == ActiveState.ACTIVE
        except DBusError as error:
            logger.error(error)
            return False

    async def enable_and_start(self, service: str) -> None:
        if not await self.is_service_enabled(service):
            await self.enable(service)
        if not await self.is_service_active(service):
            await self.start(service)

    async def stop_and_disable(self, service: str) -> None:
        if await self.is_service_active(service):
            await self.stop(service)
        if await self.is_service_enabled(service):
            await self.disable(service)
