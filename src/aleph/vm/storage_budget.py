"""Budget strings for on-disk classes ("10%" of a filesystem, or "50G")."""

from __future__ import annotations

import re

_UNITS = {"": 1, "K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
_ABSOLUTE = re.compile(r"^(\d+)\s*([KMGT]?)$")
_PERCENT = re.compile(r"^(\d+(?:\.\d+)?)\s*%$")
_MAX_PERCENT = 100.0


def parse_budget(value: str | int, total_bytes: int) -> int:
    """A budget as bytes: a percentage of ``total_bytes`` or an absolute size.

    Accepts "10%", "512M", "50G", "2T", or a plain byte count (str or int).
    """
    if isinstance(value, int):
        if value < 0:
            msg = f"Negative budget: {value}"
            raise ValueError(msg)
        return value
    text = value.strip().upper()
    if match := _PERCENT.match(text):
        percent = float(match.group(1))
        if percent > _MAX_PERCENT:
            msg = f"Budget above 100%: {value!r}"
            raise ValueError(msg)
        return int(total_bytes * percent / _MAX_PERCENT)
    if match := _ABSOLUTE.match(text):
        return int(match.group(1)) * _UNITS[match.group(2)]
    msg = f"Unparseable budget: {value!r} (expected e.g. '10%', '50G' or a byte count)"
    raise ValueError(msg)
