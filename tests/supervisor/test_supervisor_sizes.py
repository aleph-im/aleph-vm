"""Tests for aleph.vm.sizes.MemorySize."""

from __future__ import annotations

import pytest

from aleph.vm.sizes import MemorySize


def test_from_mebibytes_round_trip() -> None:
    assert MemorySize.from_mebibytes(2048).to_mebibytes() == 2048


def test_from_mebibytes_num_bytes() -> None:
    assert MemorySize.from_mebibytes(2048).num_bytes == 2048 * 1024 * 1024


def test_from_megabytes_num_bytes() -> None:
    assert MemorySize.from_megabytes(10).num_bytes == 10_000_000


def test_round_trip_megabytes() -> None:
    assert MemorySize.from_megabytes(500).to_megabytes() == 500


def test_negative_raises() -> None:
    with pytest.raises(ValueError, match="negative"):
        MemorySize(-1)
