"""Simple async-compatible TTL cache for reducing redundant API calls.

Not thread-safe, but safe for asyncio single-threaded concurrency.
"""

import time
from typing import Any


class AsyncTTLCache:
    """Key-value cache where entries expire after a configurable TTL."""

    def __init__(self, ttl_seconds: float):
        self._ttl = ttl_seconds
        self._store: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        """Return cached value or None if missing/expired."""
        entry = self._store.get(key)
        if entry is None:
            return None
        timestamp, value = entry
        if time.monotonic() - timestamp > self._ttl:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        """Store a value with the current timestamp."""
        self._store[key] = (time.monotonic(), value)

    def invalidate(self, key: str) -> None:
        """Remove a single entry."""
        self._store.pop(key, None)

    def clear(self) -> None:
        """Remove all entries."""
        self._store.clear()
