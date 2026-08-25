"""``aleph-vm storage``: show and drive reclamation from the node shell.

Storage is agent-side and, by design, readable from the filesystem plus the
agent DB, so these commands need no *agent process* running. They run the
same code the reconciler runs, including the same safety rule: a live set
built from the registry alone purges the disks of VMs the supervisor still
runs (that was PR A's Critical 1, guarded on the daemon side by
``reconciler._startup_refusal``). A CLI process holding only the registry is
exactly that state, so ``reconcile`` and ``reclaim`` ask the supervisor
daemon over the same gRPC socket the agent dials (``GrpcSupervisor``,
``settings.SUPERVISOR_GRPC_SOCKET``), with a short timeout, and union its
answer into the live set. When the daemon cannot be reached, both commands
fail closed: ``reconcile`` runs dry and warns, ``reclaim`` refuses, unless
``--trust-registry`` says to proceed on the registry alone. ``status`` and
``list`` are read-only and never touch the supervisor.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import shutil
import sys
from datetime import datetime, timezone
from typing import TextIO

from aleph.vm import storage_pools
from aleph.vm.agent import metrics
from aleph.vm.agent.vm.cache import cache_budget_bytes, cache_entries, cache_roots
from aleph.vm.agent.vm.purge import purge_vm_storage
from aleph.vm.agent.vm.reclaimable import (
    directory_size_bytes,
    iter_reclaimable,
    read_marker,
    reclaimable_bytes,
)
from aleph.vm.agent.vm.reconciler import (
    live_hashes,
    reconcile_storage,
    supervisor_hashes,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry, rehydrate_registry
from aleph.vm.conf import settings
from aleph.vm.storage_budget import parse_budget
from aleph.vm.storage_pools import iter_namespace_dirs
from aleph.vm.supervisor_interface.abc import Supervisor

# How long to wait for the supervisor to answer before treating it as
# unreachable. Short on purpose: an operator running this by hand should not
# sit through a 30 second RPC deadline just to learn the daemon is down.
SUPERVISOR_CONNECT_TIMEOUT_SECS = 3.0

logger = logging.getLogger(__name__)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="aleph-vm storage", description="VM storage reclamation")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="per-pool and per-cache usage against the budgets")
    list_parser = sub.add_parser("list", help="VM directories on every pool")
    list_parser.add_argument("--reclaimable", action="store_true", help="only directories no VM owns")
    reclaim_parser = sub.add_parser("reclaim", help="purge one reclaimable VM directory now")
    reclaim_parser.add_argument("vm_hash")
    reclaim_parser.add_argument(
        "--trust-registry",
        action="store_true",
        help="purge using the registry alone when the supervisor cannot be asked whether the hash is running",
    )
    reconcile_parser = sub.add_parser("reconcile", help="run one reconciler pass")
    reconcile_parser.add_argument("--dry-run", action="store_true")
    reconcile_parser.add_argument(
        "--trust-registry",
        action="store_true",
        help="purge using the registry alone when the supervisor cannot be asked which VMs it runs",
    )
    return parser.parse_args(argv)


_UNIT_STEP = 1024


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < _UNIT_STEP or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= _UNIT_STEP
    return f"{value:.1f} TiB"


def _age(since: datetime) -> str:
    delta = datetime.now(tz=timezone.utc) - since
    days, rem = divmod(int(delta.total_seconds()), 86400)
    hours = rem // 3600
    return f"{days}d {hours}h"


def _open_supervisor() -> Supervisor:
    """The agent's handle on the supervisor daemon, over the same gRPC socket
    the web app dials. A thin wrapper so tests can substitute a fake handle
    instead of a real gRPC channel."""
    from aleph.vm.supervisor_interface.client import GrpcSupervisor

    return GrpcSupervisor(settings.SUPERVISOR_GRPC_SOCKET)


async def _supervisor_running_hashes(timeout: float = SUPERVISOR_CONNECT_TIMEOUT_SECS) -> set[str] | None:
    """The item hashes the supervisor lists as running, or None when it could
    not be asked (unreachable, timed out, or answered with an error).

    Reuses ``reconciler.supervisor_hashes`` for the id-to-hash mapping, so a
    CLI pass and a daemon pass never disagree on what counts as a plausible
    VM id.
    """
    supervisor = _open_supervisor()
    try:
        return await asyncio.wait_for(supervisor_hashes(supervisor), timeout=timeout)
    except Exception:
        return None
    finally:
        close = getattr(supervisor, "close", None)
        if close is not None:
            try:
                await close()
            except Exception:
                logger.debug("Failed to close the supervisor handle", exc_info=True)


def _cli_live_set(registry: AgentVmRegistry) -> tuple[set[str], bool]:
    """(live hashes, whether the supervisor could be asked).

    The registry alone is never enough here: it is the same fail-closed
    reasoning ``reconciler._startup_refusal`` applies to the daemon's own
    startup pass, applied to a CLI process that by construction never has
    more than the registry unless it asks the daemon itself.
    """
    running = asyncio.run(_supervisor_running_hashes())
    live = live_hashes(registry)
    if running is None:
        return live, False
    return live | running, True


def _status(registry: AgentVmRegistry, out: TextIO) -> int:
    live = live_hashes(registry)
    out.write("POOL\tLIVE\tRECLAIMABLE\tBUDGET\tFREE\n")
    for pool in storage_pools.get_pools():
        live_bytes = sum(
            directory_size_bytes(directory)
            for directory in iter_namespace_dirs()
            if directory.parent == pool.path and directory.name in live
        )
        try:
            usage = shutil.disk_usage(str(pool.path))
            total, free = usage.total, usage.free
        except OSError:
            total = free = 0
        budget = 0 if settings.VOLUME_RETENTION == "reap" else parse_budget(settings.VOLUME_RETENTION_BUDGET, total)
        out.write(
            f"{pool.path}\t{_human(live_bytes)}\t{_human(reclaimable_bytes(pool.path))}\t"
            f"{_human(budget)}\t{_human(free)}\n"
        )
    out.write("CACHE\tUSED\tBUDGET\n")
    for root in cache_roots():
        used = sum(entry.size_bytes for entry in cache_entries(root))
        try:
            budget = cache_budget_bytes(root)
        except OSError:
            budget = 0
        out.write(f"{root}\t{_human(used)}\t{_human(budget)}\n")
    return 0


def _list(out: TextIO, *, reclaimable_only: bool) -> int:
    out.write("HASH\tPOOL\tSIZE\tREASON\tAGE\n")
    for directory in iter_namespace_dirs():
        marker = read_marker(directory)
        if reclaimable_only and marker is None:
            continue
        reason = marker.reason if marker else "live"
        age = _age(marker.reclaimable_since) if marker else "-"
        out.write(f"{directory.name}\t{directory.parent}\t{_human(directory_size_bytes(directory))}\t{reason}\t{age}\n")
    return 0


def _reclaim(registry: AgentVmRegistry, vm_hash: str, out: TextIO, *, trust_registry: bool) -> int:
    if vm_hash in live_hashes(registry):
        out.write(f"{vm_hash} is a live VM in the agent registry; refusing to purge it\n")
        return 1
    running = asyncio.run(_supervisor_running_hashes())
    if running is not None:
        if vm_hash in running:
            out.write(f"{vm_hash} is running (the supervisor lists it); refusing to purge it\n")
            return 1
    elif not trust_registry:
        out.write(
            f"Supervisor unreachable; cannot confirm {vm_hash} is not running. "
            "Pass --trust-registry to purge using the registry alone\n"
        )
        return 1
    marked = [directory for directory, _marker in iter_reclaimable() if directory.name == vm_hash]
    if not marked:
        out.write(
            f"{vm_hash} is not reclaimable (no .reclaimable marker); refusing to purge a directory a VM may own\n"
        )
        return 1
    deleted = purge_vm_storage(vm_hash)
    out.write(f"Purged {vm_hash}: {deleted} volume file(s)\n")
    return 0


def _reconcile(registry: AgentVmRegistry, out: TextIO, *, dry_run: bool, trust_registry: bool) -> int:
    live, reachable = _cli_live_set(registry)
    effective_dry_run = dry_run
    if not reachable and not trust_registry:
        effective_dry_run = True
        out.write(
            "Warning: supervisor unreachable; showing what a trusted pass would purge; "
            "pass --trust-registry to purge using the registry alone\n"
        )
    report = reconcile_storage(registry, dry_run=effective_dry_run, live=live)
    prefix = "Dry run: " if effective_dry_run else "Reconciled: "
    out.write(prefix + report.summary() + "\n")
    for name in report.purged_orphans + report.evicted:
        out.write(f"  {'would purge' if effective_dry_run else 'purged'} {name}\n")
    for name in report.marked_orphans:
        out.write(f"  {'would mark' if effective_dry_run else 'marked'} {name}\n")
    return 0


def run(args: argparse.Namespace, registry: AgentVmRegistry, out: TextIO) -> int:
    if args.command == "status":
        return _status(registry, out)
    if args.command == "list":
        return _list(out, reclaimable_only=args.reclaimable)
    if args.command == "reclaim":
        return _reclaim(registry, args.vm_hash, out, trust_registry=args.trust_registry)
    if args.command == "reconcile":
        return _reconcile(registry, out, dry_run=args.dry_run, trust_registry=args.trust_registry)
    return 2


async def _load_registry() -> AgentVmRegistry:
    metrics.setup_engine()
    registry = AgentVmRegistry()
    await rehydrate_registry(registry)
    return registry


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    settings.setup()
    storage_pools.setup_pools()
    registry = asyncio.run(_load_registry())
    return run(args, registry, sys.stdout)
