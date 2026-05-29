"""Typed memory sizes with explicit unit conversions.

Avoids ad-hoc arithmetic between MiB, MB and bytes. The QEMU launch path
previously mixed units with a spurious formula that under-allocated guest
memory; expressing conversions through this type prevents that class of bug.
"""

from __future__ import annotations

from dataclasses import dataclass

BYTES_PER_MEBIBYTE = 1024 * 1024
BYTES_PER_MEGABYTE = 1000 * 1000


@dataclass(frozen=True)
class MemorySize:
    """An amount of memory, stored as a whole number of bytes."""

    num_bytes: int

    def __post_init__(self) -> None:
        if self.num_bytes < 0:
            raise ValueError("memory size cannot be negative")

    @classmethod
    def from_mebibytes(cls, mebibytes: int) -> "MemorySize":
        return cls(int(mebibytes) * BYTES_PER_MEBIBYTE)

    @classmethod
    def from_megabytes(cls, megabytes: int) -> "MemorySize":
        return cls(int(megabytes) * BYTES_PER_MEGABYTE)

    def to_mebibytes(self) -> int:
        return self.num_bytes // BYTES_PER_MEBIBYTE

    def to_megabytes(self) -> int:
        return self.num_bytes // BYTES_PER_MEGABYTE
