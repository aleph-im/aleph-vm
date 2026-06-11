"""Typed memory-size units with explicit, checked conversions.

This module is a Python port of the Rust ``memsizes`` crate.  Each unit
(``Bytes``, ``KiB``, ``MiB``, ``GiB``, ...) is a distinct type so that
passing MiB where MB is expected is caught by static analysis and by
equality checks at runtime.  The QEMU launch path previously mixed units
with a spurious formula that under-allocated guest memory; expressing
conversions through this module prevents that class of bug.

Semantics mirror the Rust crate closely:

* Methods that return ``Result`` in Rust either raise an exception
  (``to_bytes``, ``to_exact``, ``to_rounded``) or return ``None``
  (``checked_add``, ``checked_sub``).
* Arithmetic is bounded by a ``U64_MAX`` ceiling to match Rust ``u64``
  overflow behaviour.
* ``to_rounded`` uses ties-to-even (banker's rounding) on the quotient,
  matching the Rust ``Rounding::Nearest`` mode.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass
from typing import ClassVar, TypeVar

U64_MAX: int = 2**64 - 1


class Rounding(enum.Enum):
    """Rounding mode for inexact unit conversions."""

    FLOOR = "floor"
    CEIL = "ceil"
    NEAREST = "nearest"


class MemConvError(Exception):
    """Base class for memory-conversion errors."""


class MemConvOverflowError(MemConvError):
    """Raised when an intermediate byte value would exceed ``U64_MAX``."""


class MemConvInexactError(MemConvError):
    """Raised when a byte count is not exactly divisible by the target unit."""


T = TypeVar("T", bound="MemorySize")


@dataclass(frozen=True, order=True)
class MemorySize:
    """Base class for all memory-size unit types.

    Subclasses set ``BYTES_PER_UNIT`` and ``SUFFIX`` as class variables and
    add no new instance fields, so they inherit this dataclass ``__init__``,
    ``__eq__``, and ordering automatically.
    """

    count: int = 0

    BYTES_PER_UNIT: ClassVar[int]
    SUFFIX: ClassVar[str]

    def __post_init__(self) -> None:
        if self.count < 0:
            raise ValueError(f"memory size cannot be negative, got {self.count}")

    def to_float(self) -> float:
        """Return the unit count as a float (mirrors Rust ``to_f64``)."""
        return float(self.count)

    def __int__(self) -> int:
        """Return the raw unit count (mirrors Rust ``From<unit> for u64``)."""
        return self.count

    def to_bytes(self) -> Bytes:
        """Convert to raw bytes.

        Raises ``MemConvOverflowError`` if the result would exceed ``U64_MAX``.
        For ``Bytes`` itself this is a no-op and never overflows.
        """
        v = self.count * self.__class__.BYTES_PER_UNIT
        if v > U64_MAX:
            raise MemConvOverflowError(f"{self.count} {self.__class__.SUFFIX} overflows u64 when converted to bytes")
        return Bytes(v)

    def to_exact(self, target: type[T]) -> T:
        """Convert to *target* unit, raising ``MemConvInexactError`` if not exact."""
        b = self.to_bytes().count
        if b % target.BYTES_PER_UNIT == 0:
            return target(b // target.BYTES_PER_UNIT)
        raise MemConvInexactError(
            f"{b} bytes is not exactly divisible by {target.BYTES_PER_UNIT} " f"({target.__name__} unit size)"
        )

    def to_rounded(self, target: type[T], mode: Rounding) -> T:
        """Convert to *target* unit with rounding.

        ``Rounding.NEAREST`` uses ties-to-even on the quotient, matching the
        Rust ``Rounding::Nearest`` behaviour.

        Raises ``MemConvOverflowError`` if the rounded result exceeds ``U64_MAX``.
        """
        b = self.to_bytes().count
        d = target.BYTES_PER_UNIT
        q, r = divmod(b, d)

        if mode is Rounding.FLOOR:
            add = 0
        elif mode is Rounding.CEIL:
            add = 1 if r > 0 else 0
        else:
            twice_r = r * 2
            if twice_r > d or (twice_r == d and q % 2 == 1):
                add = 1
            else:
                add = 0

        result = q + add
        if result > U64_MAX:
            raise MemConvOverflowError(f"rounded result {result} {target.__name__} exceeds u64 maximum")
        return target(result)

    def checked_add(self: T, other: T) -> T | None:
        """Return ``self + other``, or ``None`` on overflow."""
        s = self.count + other.count
        if s > U64_MAX:
            return None
        return type(self)(s)

    def checked_sub(self: T, other: T) -> T | None:
        """Return ``self - other``, or ``None`` on underflow."""
        d = self.count - other.count
        if d < 0:
            return None
        return type(self)(d)

    def saturating_add(self: T, other: T) -> T:
        """Return ``self + other``, clamped at ``U64_MAX``."""
        return type(self)(min(self.count + other.count, U64_MAX))

    def saturating_sub(self: T, other: T) -> T:
        """Return ``self - other``, clamped at 0."""
        return type(self)(max(self.count - other.count, 0))

    def __str__(self) -> str:
        return f"{self.count} {self.__class__.SUFFIX}"


# ---------------------------------------------------------------------------
# Binary IEC units
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Bytes(MemorySize):
    """Raw bytes (1 byte per unit)."""

    BYTES_PER_UNIT: ClassVar[int] = 1
    SUFFIX: ClassVar[str] = "B"

    def to_bytes(self) -> Bytes:
        return self


@dataclass(frozen=True, order=True)
class KiB(MemorySize):
    """Kibibytes (1 024 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1024
    SUFFIX: ClassVar[str] = "KiB"


@dataclass(frozen=True, order=True)
class MiB(MemorySize):
    """Mebibytes (1 024^2 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1024**2
    SUFFIX: ClassVar[str] = "MiB"


@dataclass(frozen=True, order=True)
class GiB(MemorySize):
    """Gibibytes (1 024^3 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1024**3
    SUFFIX: ClassVar[str] = "GiB"


@dataclass(frozen=True, order=True)
class TiB(MemorySize):
    """Tebibytes (1 024^4 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1024**4
    SUFFIX: ClassVar[str] = "TiB"


@dataclass(frozen=True, order=True)
class PiB(MemorySize):
    """Pebibytes (1 024^5 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1024**5
    SUFFIX: ClassVar[str] = "PiB"


@dataclass(frozen=True, order=True)
class EiB(MemorySize):
    """Exbibytes (1 024^6 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1024**6
    SUFFIX: ClassVar[str] = "EiB"


# ---------------------------------------------------------------------------
# Decimal SI units
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class KB(MemorySize):
    """Kilobytes (1 000 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1000
    SUFFIX: ClassVar[str] = "KB"


@dataclass(frozen=True, order=True)
class MB(MemorySize):
    """Megabytes (1 000^2 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1000**2
    SUFFIX: ClassVar[str] = "MB"


@dataclass(frozen=True, order=True)
class GB(MemorySize):
    """Gigabytes (1 000^3 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1000**3
    SUFFIX: ClassVar[str] = "GB"


@dataclass(frozen=True, order=True)
class TB(MemorySize):
    """Terabytes (1 000^4 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1000**4
    SUFFIX: ClassVar[str] = "TB"


@dataclass(frozen=True, order=True)
class PB(MemorySize):
    """Petabytes (1 000^5 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1000**5
    SUFFIX: ClassVar[str] = "PB"


@dataclass(frozen=True, order=True)
class EB(MemorySize):
    """Exabytes (1 000^6 bytes)."""

    BYTES_PER_UNIT: ClassVar[int] = 1000**6
    SUFFIX: ClassVar[str] = "EB"
