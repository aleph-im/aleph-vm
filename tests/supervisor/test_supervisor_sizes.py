"""Tests for aleph.vm.sizes -- full port of the Rust memsizes crate test suite.

Every ``#[test]`` function from the Rust crate is ported one-to-one, plus
an extra negative-value test that has no Rust equivalent (Python does not
have unsigned integer types, so the guard must be explicit).
"""

from __future__ import annotations

import pytest

from aleph.vm.sizes import (
    EB,
    GB,
    KB,
    MB,
    PB,
    TB,
    U64_MAX,
    Bytes,
    EiB,
    GiB,
    KiB,
    MemConvInexactError,
    MemConvOverflowError,
    MiB,
    PiB,
    Rounding,
    TiB,
)

# ---------------------------------------------------------------------------
# 1. roundtrip_bytes  (Rust: roundtrip_bytes)
# ---------------------------------------------------------------------------


def test_roundtrip_bytes() -> None:
    m = MiB(5)
    b = m.to_bytes()
    assert b.count == 5 * MiB.BYTES_PER_UNIT
    assert m == b.to_exact(MiB)


# ---------------------------------------------------------------------------
# 2. to_exact_and_rounded  (Rust: to_exact_and_rounded)
# ---------------------------------------------------------------------------


def test_to_exact_and_rounded() -> None:
    g = GiB(2)
    assert g.to_exact(MiB).count == 2048

    floor_result = g.to_rounded(MB, Rounding.FLOOR)
    ceil_result = g.to_rounded(MB, Rounding.CEIL)
    assert ceil_result.count >= floor_result.count


# ---------------------------------------------------------------------------
# 3. overflow_guard  (Rust: overflow_guard)
# ---------------------------------------------------------------------------


def test_overflow_guard() -> None:
    big = GiB(U64_MAX // GiB.BYTES_PER_UNIT + 1)
    with pytest.raises(MemConvOverflowError):
        big.to_bytes()


# ---------------------------------------------------------------------------
# 4. rounding_nearest  (Rust: rounding_nearest)
# ---------------------------------------------------------------------------


def test_rounding_nearest() -> None:
    # Rounds down: 1500 / 1024 = 1.46..., nearest is 1
    assert Bytes(1500).to_rounded(KiB, Rounding.NEAREST).count == 1

    # Rounds up: 1800 / 1024 = 1.76..., nearest is 2
    assert Bytes(1800).to_rounded(KiB, Rounding.NEAREST).count == 2

    # Tie, q even (stays at 2): 2560 / 1024 = 2.5, q=2 is even -> 2
    assert Bytes(2560).to_rounded(KiB, Rounding.NEAREST).count == 2

    # Tie, q odd (rounds up): 1536 / 1024 = 1.5, q=1 is odd -> 2
    assert Bytes(1536).to_rounded(KiB, Rounding.NEAREST).count == 2


# ---------------------------------------------------------------------------
# 5. to_exact_inexact  (Rust: try_from_bytes_inexact)
# ---------------------------------------------------------------------------


def test_to_exact_inexact() -> None:
    with pytest.raises(MemConvInexactError):
        Bytes(1025).to_exact(KiB)


# ---------------------------------------------------------------------------
# 6. unit_to_bytes_overflow  (Rust: try_from_unit_to_bytes_overflow)
# ---------------------------------------------------------------------------


def test_unit_to_bytes_overflow() -> None:
    with pytest.raises(MemConvOverflowError):
        GiB(U64_MAX).to_bytes()


# ---------------------------------------------------------------------------
# 7. checked_add  (Rust: test_bytes_checked_add)
# ---------------------------------------------------------------------------


def test_checked_add() -> None:
    size = Bytes(100)

    assert size.checked_add(Bytes(0)) == Bytes(100)
    assert size.checked_add(Bytes(50)) == Bytes(150)
    assert Bytes(U64_MAX).checked_add(Bytes(1)) is None


# ---------------------------------------------------------------------------
# 8. checked_sub  (Rust: test_bytes_checked_sub)
# ---------------------------------------------------------------------------


def test_checked_sub() -> None:
    size = Bytes(100)

    assert size.checked_sub(Bytes(0)) == Bytes(100)
    assert size.checked_sub(Bytes(50)) == Bytes(50)
    assert size.checked_sub(Bytes(150)) is None


# ---------------------------------------------------------------------------
# 9. saturating_add  (Rust: test_bytes_saturating_add)
# ---------------------------------------------------------------------------


def test_saturating_add() -> None:
    size = Bytes(100)

    assert size.saturating_add(Bytes(50)) == Bytes(150)
    assert Bytes(U64_MAX).saturating_add(Bytes(1)) == Bytes(U64_MAX)


# ---------------------------------------------------------------------------
# 10. saturating_sub  (Rust: test_bytes_saturating_sub)
# ---------------------------------------------------------------------------


def test_saturating_sub() -> None:
    size = Bytes(100)

    assert size.saturating_sub(Bytes(50)) == Bytes(50)
    assert size.saturating_sub(Bytes(150)) == Bytes(0)


# ---------------------------------------------------------------------------
# 11. decimal_units_smoke  (Rust: decimal_units_smoke)
# ---------------------------------------------------------------------------


def test_decimal_units_smoke() -> None:
    assert MB(5).to_bytes().count == 5_000_000
    assert GB(2).to_exact(MB).count == 2000
    assert TB(1).to_exact(GB).count == 1000
    assert KB(3000).to_exact(MB).count == 3


# ---------------------------------------------------------------------------
# 12. display_formatting  (Rust: display_formatting)
# ---------------------------------------------------------------------------


def test_display_formatting() -> None:
    assert str(Bytes(42)) == "42 B"
    assert str(KiB(10)) == "10 KiB"
    assert str(MiB(5)) == "5 MiB"
    assert str(GiB(1)) == "1 GiB"
    assert str(TiB(2)) == "2 TiB"
    assert str(PiB(3)) == "3 PiB"
    assert str(EiB(4)) == "4 EiB"
    assert str(KB(7)) == "7 KB"
    assert str(MB(8)) == "8 MB"
    assert str(GB(9)) == "9 GB"
    assert str(TB(10)) == "10 TB"
    assert str(PB(11)) == "11 PB"
    assert str(EB(12)) == "12 EB"


# ---------------------------------------------------------------------------
# 13. default_is_zero  (Rust: default_is_zero)
# ---------------------------------------------------------------------------


def test_default_is_zero() -> None:
    assert Bytes().count == 0
    assert KiB().count == 0
    assert MiB().count == 0
    assert GiB().count == 0
    assert MB().count == 0
    assert GB().count == 0


# ---------------------------------------------------------------------------
# 14. into_int  (Rust: into_u64)
# ---------------------------------------------------------------------------


def test_into_int() -> None:
    assert int(Bytes(99)) == 99
    assert int(MiB(42)) == 42
    assert int(GB(7)) == 7


# ---------------------------------------------------------------------------
# 15. identity_conversion  (Rust: identity_conversion)
# ---------------------------------------------------------------------------


def test_identity_conversion() -> None:
    assert GiB(5).to_exact(GiB).count == 5
    assert MB(100).to_exact(MB).count == 100
    assert Bytes(1024).to_exact(Bytes).count == 1024


# ---------------------------------------------------------------------------
# 16. negative_raises  (Python-only: no unsigned integers in Python)
# ---------------------------------------------------------------------------


def test_negative_raises() -> None:
    with pytest.raises(ValueError):
        MiB(-1)
