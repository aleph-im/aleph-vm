"""One lock per VM hash, held across a whole create.

Several paths start the same VM, each running a read, record, download, create
sequence whose download lasts seconds. Unserialised, two callers both read
"this node does not have it" and both create it; the supervisor refuses the
second, and the teardown that follows deletes the VM the first brought up.

The lock is per hash, created on demand and dropped once nobody holds or waits
for it. Unlike ``creating()`` in the storage reconciler, which refcounts
overlapping spans, this is mutual exclusion between the creates themselves.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

# Hash to the lock serialising its creates, and to the number of callers
# holding or waiting for it: the last one out removes the lock.
_locks: dict[str, asyncio.Lock] = {}
_waiting: dict[str, int] = {}


@asynccontextmanager
async def vm_create_lock(namespace: str) -> AsyncIterator[None]:
    """Serialise the creates of one VM hash.

    Wraps the whole read-record-create sequence, not just the create call: it
    is the window between reading the supervisor and creating the VM that lets
    a second caller decide the VM is missing.
    """
    lock = _locks.get(namespace)
    if lock is None:
        # No await between the miss and the insert, so two callers cannot end
        # up holding two different locks for one hash.
        lock = asyncio.Lock()
        _locks[namespace] = lock
    # Counted before the acquire: a queued caller has to keep the lock alive,
    # or the holder's release would drop it and the next caller would build a
    # second one and walk straight in.
    _waiting[namespace] = _waiting.get(namespace, 0) + 1
    try:
        async with lock:
            yield
    finally:
        remaining = _waiting[namespace] - 1
        if remaining:
            _waiting[namespace] = remaining
        else:
            del _waiting[namespace]
            del _locks[namespace]
