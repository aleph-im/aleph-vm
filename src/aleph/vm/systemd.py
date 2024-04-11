"""
async SystemD Manager implementation.
"""

import enum
import logging
from typing import Literal, Optional, Protocol, runtime_checkable

from dbus_fast import BusType, DBusError
from dbus_fast.aio import MessageBus, ProxyObject

logger = logging.getLogger(__name__)


class UnitFileState(str, enum.Enum):
    """This StrEnum class represents the different possible states of a unit file."""

    ENABLED = "enabled"
    """Indicates that a unit file is permanently enabled."""

    ENABLED_RUNTIME = "enabled-runtime"
    """Indicates the unit file is only temporarily enabled and will no longer be enabled after a reboot
    (that means, it is enabled via /run/ symlinks, rather than /etc/)."""

    LINKED = "linked"
    """Indicates that a unit is linked into /etc/ permanently."""

    LINKED_RUNTIME = "linked-runtime"
    """Indicates that a unit is linked into /run/ temporarily (until the next reboot)."""

    MASKED = "masked"
    """Indicates that the unit file is masked permanently."""

    MASKED_RUNTIME = "masked-runtime"
    """Indicates that it is masked in /run/ temporarily (until the next reboot)."""

    STATIC = "static"
    """Indicates that the unit is statically enabled, i.e. always enabled and doesn't need to be enabled explicitly."""

    DISABLED = "disabled"
    """Indicates that the unit file is not enabled."""

    INVALID = "invalid"
    """Indicates that it could not be determined whether the unit file is enabled."""


UnitFileStateLiteral = Literal[
    "enabled",
    "enabled-runtime",
    "linked",
    "linked-runtime",
    "masked",
    "masked-runtime",
    "static",
    "disabled",
    "invalid",
]


class Mode(str, enum.Enum):
    REPLACE = "replace"
    FAIL = "fail"
    ISOLATE = "isolate"
    IGNORE_DEPENDENCIES = "ignore-dependencies"
    IGNORE_REQUIREMENTS = "ignore-requirements"


class ActiveState(str, enum.Enum):
    """
    ActiveState contains a state value that reflects the unit's current status.
    """

    ACTIVE = "active"
    """
    The unit is active.
    """

    RELOADING = "reloading"
    """
    The unit is active and reloading its configuration.
    """

    INACTIVE = "inactive"
    """
    The unit is inactive, previous run was successful or hasn't yet occurred.
    """

    FAILED = "failed"
    """
    The unit is inactive, previous run was unsuccessful.
    """

    ACTIVATING = "activating"
    """
    The unit is transitioning from inactive to active state.
    """

    DEACTIVATING = "deactivating"
    """
    The unit is in the process of deactivation.
    """


ActiveStateLiteral = Literal["active", "reloading", "inactive", "failed", "activating", "deactivating"]


@runtime_checkable
class SystemdProxy(Protocol):
    """ABC for typing.

    for description of methodsp
    see https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html#The%20Manager%20Object"""

    async def call_enable_unit_files(self, files: list[str], runtime: bool, force: bool): ...

    async def call_get_unit_file_state(self, service) -> UnitFileStateLiteral: ...

    async def call_start_unit(self, name, mode):
        pass

    async def call_stop_unit(self, name, mode): ...

    async def call_restart_unit(self, name, mode): ...

    async def call_disable_unit_files(self, files: list[str], runtime: bool): ...

    async def call_get_unit(self, name: str) -> str: ...


@runtime_checkable
class UnitProxy(Protocol):
    """for typing.

    for description of methods see
    https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.systemd1.html#Service%20Unit%20Objects"""

    async def get_active_state(self) -> ActiveStateLiteral: ...


class SystemDManager:
    """SystemD Manager class.

    Used to manage the systemd services on the host on Linux.
    """

    bus: Optional[MessageBus]
    manager: Optional[SystemdProxy]

    def __init__(self):
        pass

    async def connect(self):
        self.bus = MessageBus(bus_type=BusType.SYSTEM)
        await self.bus.connect()
        path = "/org/freedesktop/systemd1"
        bus_name = "org.freedesktop.systemd1"
        introspect = await self.bus.introspect(bus_name, path)
        systemd_proxy: ProxyObject = self.bus.get_proxy_object(bus_name, path, introspection=introspect)
        interface = systemd_proxy.get_interface("org.freedesktop.systemd1.Manager")
        # Check required method are implemented
        assert isinstance(interface, SystemdProxy)
        self.manager = interface

    async def enable(self, service: str) -> None:
        assert self.manager, "connect() not called"
        await self.manager.call_enable_unit_files([service], False, True)
        logger.debug(f"Enabled {service} service")

    async def start(self, service: str) -> None:
        assert self.manager, "connect() not called"
        await self.manager.call_start_unit(service, Mode.REPLACE)
        logger.debug(f"Started {service} service")

    async def stop(self, service: str) -> None:
        assert self.manager, "connect() not called"
        await self.manager.call_stop_unit(service, Mode.REPLACE)
        logger.debug(f"Stopped {service} service")

    async def restart(self, service: str) -> None:
        assert self.manager, "connect() not called"
        await self.manager.call_restart_unit(service, Mode.REPLACE)
        logger.debug(f"Restarted {service} service")

    async def disable(self, service: str) -> None:
        assert self.manager, "connect() not called"
        await self.manager.call_disable_unit_files([service], False)
        logger.debug(f"Disabled {service} service")

    async def is_service_enabled(self, service: str) -> bool:
        assert self.manager, "connect() not called"
        try:
            state = await self.manager.call_get_unit_file_state(service)
            return state == UnitFileState.ENABLED
        except DBusError as error:
            logger.error(error)
            return False

    async def is_service_active(self, service: str) -> bool:
        assert self.manager, "connect() not called"
        assert self.bus, "connect() not called"
        try:
            path = await self.manager.call_get_unit(service)
            bus_name = "org.freedesktop.systemd1"
            introspect = await self.bus.introspect(bus_name, path)
            systemd_service = self.bus.get_proxy_object(bus_name, path, introspection=introspect)
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
