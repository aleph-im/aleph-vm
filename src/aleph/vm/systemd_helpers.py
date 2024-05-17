"""Typing helpers for talking to systemd via dbus

The proxy object interface are determined at runtimes"""

import enum
from typing import Literal, runtime_checkable, Protocol


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

    for description of methods
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
