"""``aleph-vm storage``: show and drive reclamation from the node shell.

Storage is agent-side and, by design, readable from the filesystem plus the
agent DB, so these commands need no running daemon. They run the same code
the reconciler runs.

The live set these commands act against is the agent registry alone
(rehydrated from the agent DB, ``rehydrate_registry``): there is no daemon to
ask ``list_vms``, so unlike the startup pass (``reconciler._startup_refusal``)
this cannot cross-check against a supervisor's answer. An operator invoking
this by hand already knows whether the daemon is up; running it against a
stopped daemon (the normal case, since the daemon holds no lock these
commands need) is exactly the documented use.
"""

from __future__ import annotations

import argparse
import asyncio
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
from aleph.vm.agent.vm.reconciler import live_hashes, reconcile_storage
from aleph.vm.agent.vm_registry import AgentVmRegistry, rehydrate_registry
from aleph.vm.conf import settings
from aleph.vm.storage_budget import parse_budget
from aleph.vm.storage_pools import iter_namespace_dirs


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="aleph-vm storage", description="VM storage reclamation")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="per-pool and per-cache usage against the budgets")
    list_parser = sub.add_parser("list", help="VM directories on every pool")
    list_parser.add_argument("--reclaimable", action="store_true", help="only directories no VM owns")
    reclaim_parser = sub.add_parser("reclaim", help="purge one reclaimable VM directory now")
    reclaim_parser.add_argument("vm_hash")
    reconcile_parser = sub.add_parser("reconcile", help="run one reconciler pass")
    reconcile_parser.add_argument("--dry-run", action="store_true")
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


def _reclaim(vm_hash: str, out: TextIO) -> int:
    marked = [directory for directory, _marker in iter_reclaimable() if directory.name == vm_hash]
    if not marked:
        out.write(
            f"{vm_hash} is not reclaimable (no .reclaimable marker); refusing to purge a directory a VM may own\n"
        )
        return 1
    deleted = purge_vm_storage(vm_hash)
    out.write(f"Purged {vm_hash}: {deleted} volume file(s)\n")
    return 0


def _reconcile(registry: AgentVmRegistry, out: TextIO, *, dry_run: bool) -> int:
    report = reconcile_storage(registry, dry_run=dry_run)
    prefix = "Dry run: " if dry_run else "Reconciled: "
    out.write(prefix + report.summary() + "\n")
    for name in report.purged_orphans + report.evicted:
        out.write(f"  {'would purge' if dry_run else 'purged'} {name}\n")
    for name in report.marked_orphans:
        out.write(f"  {'would mark' if dry_run else 'marked'} {name}\n")
    return 0


def run(args: argparse.Namespace, registry: AgentVmRegistry, out: TextIO) -> int:
    if args.command == "status":
        return _status(registry, out)
    if args.command == "list":
        return _list(out, reclaimable_only=args.reclaimable)
    if args.command == "reclaim":
        return _reclaim(args.vm_hash, out)
    if args.command == "reconcile":
        return _reconcile(registry, out, dry_run=args.dry_run)
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
