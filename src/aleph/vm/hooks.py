"""The callbacks the agent app hands down to the storage layer.

Three things the storage code has to ask the agent about, and cannot import
its way to: whether a download fits the cache budget, whether retained
volumes can be evicted to make a placement fit, and whether a reconcile pass
should run right after a VM is retired for good. All three point from
``aleph.vm.storage`` / ``aleph.vm.storage_pools`` / ``agent.vm.retire`` back
into the reconciler, which imports those modules itself, so the app is what
wires them together at startup.

They used to be three module globals with three setters, written one after
another. That made the wiring order load-bearing in a way nothing enforced:
a startup that raised between two of the calls left a node that would evict
retained volumes for a placement but let downloads blow the cache budget, or
the other way round, with no way to tell from either module which half had
landed. One frozen object, published in a single assignment, is either
installed or not.

This module sits at the top of the import graph on purpose: it pulls in
nothing from ``aleph.vm`` at runtime, so every module that needs a slot can
import it.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aleph.vm.storage_pools import StoragePool


# Runs after every GONE retire under VOLUME_RETENTION=keep, so the retention
# budget is enforced there and then. A budget enforced only once an hour is a
# budget an attacker bursts through: create, forget, repeat.
AfterGoneHook = Callable[[], Awaitable[None]]

# What the caches admit, called with ``(tmp_path, content_length, max_bytes)``
# as soon as a download's response headers are in, before a byte is written.
# The middle argument is None when the server did not say how big the body is,
# and the two are not interchangeable: a Content-Length is a measurement of
# this download, a cap is a ceiling on every download of that kind, and
# admission has to treat them differently. Deciding that here, by handing over
# one number, is what made a chunked-encoding response ask for the whole
# runtime cap. The ``.part`` path goes over rather than its directory: the
# room a download was admitted for is charged to that path until it ends.
CacheAdmission = Callable[[Path, int | None, int | None], None]

# The agent's evictor, called with ``(pool, needed_bytes)`` when no pool fits
# a placement, before the placement is refused. Retained volumes are
# advertised as free capacity, so a placement that does not fit has to be
# given the chance to take that space back before it fails.
RoomMaker = Callable[["StoragePool", int], int]


@dataclass(frozen=True)
class AgentHooks:
    """Every callback the agent installs for the storage layer, in one value.

    Frozen: a slot is changed by installing a new instance, never by writing
    into the installed one, so a reader either sees the whole wiring or the
    whole previous wiring. A node that installs nothing keeps the behaviour
    the storage code had before any of these existed, which is what the
    storage CLI and the tests that import these modules directly rely on.
    """

    after_gone: AfterGoneHook | None = None
    cache_admission: CacheAdmission | None = None
    room_maker: RoomMaker | None = None


_installed = AgentHooks()


def current_hooks() -> AgentHooks:
    """What is wired right now. Read at the point of use, never cached: the
    agent installs at startup, and tests install and restore around a case."""
    return _installed


def install_hooks(hooks: AgentHooks) -> None:
    """Publish a complete wiring, replacing whatever was there."""
    global _installed  # noqa: PLW0603
    _installed = hooks


@contextmanager
def installed_hooks(hooks: AgentHooks) -> Iterator[AgentHooks]:
    """Install ``hooks`` for the duration of the block, then put back what
    was there. Restores the previous instance rather than clearing, so nested
    use in a fixture and a test does not lose the outer wiring."""
    previous = current_hooks()
    install_hooks(hooks)
    try:
        yield hooks
    finally:
        install_hooks(previous)
