"""One lock per VM hash, held across a whole create.

A VM is started from several places at once: the allocation reconciler, the v1
``/control/allocations`` handler and the single-VM ``notify_allocation``
endpoint all run the same read, record, download, create sequence, and the
download in the middle of it lasts seconds. With nothing serialising them, two
callers read "this node does not have this VM", both record it, both download
into the same directory and both create it. The supervisor refuses the second
create, the create path reads that refusal as its own failure and retires the
VM, and the retire deletes the VM the first caller had just brought up,
forgets its record and, when the disks were fresh, purges its volumes.

The lock is per hash, so starts of different VMs still run in parallel. It is
created on demand and dropped once nobody holds or waits for it, so a node
that has started thousands of VMs over its life keeps no lock for each.

This is a different thing from ``creating()`` in the storage reconciler, which
is a refcount on purpose: it tells a reconcile pass that a directory is being
built and must count every span, including two that overlap. This one is
mutual exclusion between the creates themselves.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

# Hash to the lock serialising its creates, and to the number of callers
# holding or waiting for it. The count is what says when the lock can be
# dropped: the last one out removes it.
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
        # There is no await between the miss and the insert, so the event loop
        # cannot interleave here and two callers cannot end up holding two
        # different locks for one hash.
        lock = asyncio.Lock()
        _locks[namespace] = lock
    # Counted before the acquire: a caller queued behind the lock has to keep
    # it alive, or the holder's release would drop it and the next caller
    # would build a second one and walk straight in.
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
