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
fail closed: ``reconcile`` runs dry, warns on stderr and exits non-zero,
``reclaim`` refuses, unless ``--trust-registry`` says to proceed on the
registry alone. ``status`` and ``list`` are read-only and never touch the
supervisor.

What this process still cannot see, even with the supervisor reachable: a
create the daemon is in the middle of. ``reconciler.is_creating()`` is an
in-process set the running agent populates for the duration of a create; a
CLI invocation is a separate process and never sees it. What protects such
a create here is only the age of its directory: the directory purge and the
orphan-device teardown both leave a namespace whose directory is younger
than ``VOLUME_CREATE_GUARD`` alone, so a create that has outlived the guard
and has not yet landed in the registry DB or in ``list_vms`` looks exactly
like an orphan to a real ``reconcile`` here, directory and devices alike.
A CLI pass also shares no lock with the daemon's own passes and can run
concurrently with one; that is benign (purges are idempotent and tolerate a
directory that vanished under them, markers are written exclusively), but
it is one more reason the daemon's own pass (startup, periodic, at-GONE) is
always preferred when the daemon is up; this command exists mainly for when
it is not.

Running with no agent process also means setting up the process the way the
systemd units set it up for the daemon: the node's environment file is read
here (nothing else injects it into an operator's shell, and running a pass
on the built-in defaults would reconcile a node against a configuration it
does not have), the log records go to stderr, and the agent database is
created and migrated before anything reads it. The read-only verbs are the
exception to the last one: they refuse a database that is not there rather
than create it.
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import TextIO

from dotenv import load_dotenv
from pydantic import ValidationError

from aleph.vm import storage_pools
from aleph.vm.agent import metrics
from aleph.vm.agent.cli import LOG_LEVEL_NAMES, initialise_database
from aleph.vm.agent.vm.cache import cache_budget_bytes, cache_entries, cache_roots
from aleph.vm.agent.vm.purge import purge_vm_storage
from aleph.vm.agent.vm.reclaimable import (
    directory_size_bytes,
    iter_reclaimable,
    read_marker,
    reclaimable_bytes,
)
from aleph.vm.agent.vm.reconciler import (
    _plausible,
    _release_cache_devices,
    _still_on_disk,
    _teardown_orphan_devices,
    live_hashes,
    reconcile_storage,
    supervisor_hashes,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry, rehydrate_registry
from aleph.vm.conf import Settings, settings
from aleph.vm.storage_budget import parse_budget
from aleph.vm.storage_pools import iter_namespace_dirs
from aleph.vm.supervisor_interface.abc import Supervisor

# How long to wait for the supervisor to answer before treating it as
# unreachable. Short on purpose: an operator running this by hand should not
# sit through a 30 second RPC deadline just to learn the daemon is down.
SUPERVISOR_CONNECT_TIMEOUT_SECS = 3.0

# Exit code for a reconcile that silently downgraded to a dry run because the
# supervisor could not be asked and --trust-registry was not given. Distinct
# from an explicit --dry-run, which is a success (exit 0): nothing was
# downgraded, the caller asked for a preview and got one. Not 2, which
# argparse uses for a usage error: a wrapper script must be able to tell a
# degraded pass from a bad argument without parsing stderr.
DEGRADED_EXIT_CODE = 3

# The systemd units hand the daemon its configuration with
# EnvironmentFile=; nothing hands it to an operator's shell, so a hand-run
# command reads the same file itself or runs on the built-in defaults.
DEFAULT_ENV_FILE = Path("/etc/aleph-vm/supervisor.env")
ENV_FILE_VARIABLE = "ALEPH_VM_ENV_FILE"

# Verbs that only read. They must not bring an agent database into
# existence: an operator who ran the command with the wrong execution root
# has to see a refusal, not an empty listing backed by a file this very
# process just created.
READ_ONLY_COMMANDS = frozenset({"status", "list"})

# Name given to the handler this CLI installs on the root logger, so a
# second call in the same process replaces it instead of doubling every
# line.
_LOG_HANDLER_NAME = "aleph-vm-storage-cli"

logger = logging.getLogger(__name__)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Fill in the storage flags and verbs, on a standalone parser or on the
    subparser the agent CLI registers."""
    parser.add_argument(
        "--env-file",
        dest="env_file",
        default=None,
        help=(
            f"Environment file to load before reading the settings "
            f"(default: ${ENV_FILE_VARIABLE}, else {DEFAULT_ENV_FILE})"
        ),
    )
    parser.add_argument(
        "--loglevel",
        dest="loglevel",
        type=str.upper,
        choices=LOG_LEVEL_NAMES,
        # SUPPRESS, not a real default: this parser also runs as a subparser
        # of the agent CLI, whose own --loglevel and -v/-vv write the same
        # destination, and a subparser default overwrites what the parent
        # already parsed.
        default=argparse.SUPPRESS,
        help="Log level by name (DEBUG, INFO, WARNING, ERROR, CRITICAL); INFO by default",
    )
    sub = parser.add_subparsers(dest="storage_command", required=True)
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
    reconcile_parser = sub.add_parser(
        "reconcile",
        help="run one reconciler pass",
        description=(
            "Run one reconciler pass against the agent registry (unioned with the supervisor's "
            "list_vms() when it can be reached). This process cannot see a create the daemon is "
            "currently in the middle of: is_creating() is in-process state of the running agent, "
            "and only the age of the directory protects such a create here, so a create that has "
            "outlived VOLUME_CREATE_GUARD and is not yet in the registry DB or list_vms looks like "
            "an orphan and a real pass can remove its directory and its devices. Prefer the "
            "daemon's own pass (it runs at startup, periodically, and after every GONE) when the "
            "daemon is up; use this command mainly when it is not."
        ),
    )
    reconcile_parser.add_argument("--dry-run", action="store_true")
    reconcile_parser.add_argument(
        "--trust-registry",
        action="store_true",
        help="purge using the registry alone when the supervisor cannot be asked which VMs it runs",
    )


def add_subparser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    """Register ``storage`` on the agent CLI's own parser, so the agent's
    global flags placed before the verb parse instead of being handed to a
    second, unrelated parser."""
    parser = subparsers.add_parser(
        "storage",
        help="VM storage reclamation: status, list, reclaim, reconcile",
        description="VM storage reclamation: status, list, reclaim, reconcile.",
    )
    add_arguments(parser)
    return parser


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="aleph-vm storage",
        description="VM storage reclamation: status, list, reclaim, reconcile.",
    )
    add_arguments(parser)
    return parser.parse_args(argv)


_UNIT_STEP = 1024


def _human(size: int) -> str:
    value = float(size)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if value < _UNIT_STEP or unit == "TiB":
            return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= _UNIT_STEP
    msg = "unreachable: the loop above always returns on its last unit (TiB)"
    raise AssertionError(msg)


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


def _list(registry: AgentVmRegistry, out: TextIO, *, reclaimable_only: bool) -> int:
    # REASON is the marker's reason for a reclaimable directory. An unmarked
    # directory is "live" only when the registry knows its hash; otherwise
    # it is "unmarked", which is what an operator triaging by hand needs to
    # see: an orphan no pass has reached yet must not read as a live VM.
    # Registry only, like status: list never dials the supervisor.
    live = live_hashes(registry)
    out.write("HASH\tPOOL\tSIZE\tREASON\tAGE\n")
    for directory in iter_namespace_dirs():
        marker = read_marker(directory)
        if reclaimable_only and marker is None:
            continue
        if marker:
            reason = marker.reason
        else:
            reason = "live" if directory.name in live else "unmarked"
        age = _age(marker.reclaimable_since) if marker else "-"
        out.write(f"{directory.name}\t{directory.parent}\t{_human(directory_size_bytes(directory))}\t{reason}\t{age}\n")
    return 0


def _reclaim_refusal(registry: AgentVmRegistry, vm_hash: str, *, trust_registry: bool) -> str | None:
    """Why reclaim must not purge this hash, or None when it may.

    Cheapest, purely local checks first: a typo or an unrelated hash fails
    instantly instead of waiting out a supervisor dial that can only ever
    confirm what these checks already know. The name check mirrors the
    daemon's walk: a hand-made marker under a directory nobody named after a
    VM must be refused here, not tripped over as a ValueError inside
    purge_vm_storage after every other check passed.
    """
    if not _plausible(vm_hash):
        return f"{vm_hash!r} is not a VM hash; refusing to purge a directory not named after a VM"
    if not any(directory.name == vm_hash for directory, _marker in iter_reclaimable()):
        return f"{vm_hash} is not reclaimable (no .reclaimable marker); refusing to purge a directory a VM may own"
    if vm_hash in live_hashes(registry):
        return f"{vm_hash} is a live VM in the agent registry; refusing to purge it"
    running = asyncio.run(_supervisor_running_hashes())
    if running is not None:
        if vm_hash in running:
            return f"{vm_hash} is running (the supervisor lists it); refusing to purge it"
    elif not trust_registry:
        return (
            f"Supervisor unreachable; cannot confirm {vm_hash} is not running. "
            "Pass --trust-registry to purge using the registry alone"
        )
    return None


def _reclaim(registry: AgentVmRegistry, vm_hash: str, out: TextIO, *, trust_registry: bool) -> int:
    refusal = _reclaim_refusal(registry, vm_hash, trust_registry=trust_registry)
    if refusal is not None:
        out.write(refusal + "\n")
        return 1
    deleted = purge_vm_storage(vm_hash)
    if _still_on_disk(vm_hash):
        out.write(
            f"Purge of {vm_hash} left directories behind: a device-mapper target still holds its volumes. "
            "Run 'storage reconcile' to tear down the devices of every VM nothing owns, then retry\n"
        )
        return 1
    out.write(f"Purged {vm_hash}: {deleted} volume file(s)\n")
    return 0


def _reconcile(registry: AgentVmRegistry, out: TextIO, *, dry_run: bool, trust_registry: bool) -> int:
    live, reachable = _cli_live_set(registry)
    downgraded = not reachable and not trust_registry
    effective_dry_run = dry_run or downgraded
    if downgraded:
        sys.stderr.write(
            "Warning: supervisor unreachable; showing what a registry-only pass would purge; "
            "pass --trust-registry to purge using the registry alone\n"
        )
    # Mirrors reconcile_now: the devices of every namespace nothing owns go
    # before the walk, or the purge that follows refuses those directories
    # (a dm target still holds their volume files) exactly as the daemon's
    # passes used to. Only when the supervisor answered, since removing the
    # device of a VM that is merely unlisted takes that VM's disk with it:
    # --trust-registry buys a purge on the registry's word, not a teardown.
    if not effective_dry_run and reachable:
        asyncio.run(_teardown_orphan_devices(live))
    report = reconcile_storage(registry, dry_run=effective_dry_run, live=live, live_known=reachable)
    prefix = "Dry run: " if effective_dry_run else "Reconciled: "
    out.write(prefix + report.summary() + "\n")
    for name in report.purged_orphans + report.evicted:
        out.write(f"  {'would purge' if effective_dry_run else 'purged'} {name}\n")
    for name in report.marked_orphans:
        out.write(f"  {'would mark' if effective_dry_run else 'marked'} {name}\n")
    # Mirrors reconcile_now/reconcile_at_startup: tear down the devices of
    # evicted parent images, then sweep whatever an earlier teardown left
    # behind. _release_cache_devices no-ops under a dry run on its own, so
    # calling it unconditionally here matches the daemon's own passes.
    asyncio.run(_release_cache_devices(report, dry_run=effective_dry_run))
    return DEGRADED_EXIT_CODE if downgraded and not dry_run else 0


def run(args: argparse.Namespace, registry: AgentVmRegistry, out: TextIO) -> int:
    if args.storage_command == "status":
        return _status(registry, out)
    if args.storage_command == "list":
        return _list(registry, out, reclaimable_only=args.reclaimable)
    if args.storage_command == "reclaim":
        return _reclaim(registry, args.vm_hash, out, trust_registry=args.trust_registry)
    if args.storage_command == "reconcile":
        return _reconcile(registry, out, dry_run=args.dry_run, trust_registry=args.trust_registry)
    return 2


async def _load_registry() -> AgentVmRegistry:
    metrics.setup_engine()
    registry = AgentVmRegistry()
    await rehydrate_registry(registry)
    return registry


def _setup_logging(level: str | int) -> None:
    """Send the log records of this process to stderr.

    Most of what these commands have to report they report through the
    logger the reconciler, the purge and the marker already write to
    ("Deleted volume ...", "Removed volume directory ...", "Marked ...
    reclaimable"). With no handler configured those INFO lines are dropped
    and anything at WARNING or above reaches the terminal as a bare
    last-resort line with no level and no logger name, so an operator
    watching a purge sees almost nothing of what it did.

    Adds a named handler rather than calling basicConfig, so that repeated
    calls in one process replace it instead of stacking, and so that
    handlers something else installed are left alone.
    """
    root = logging.getLogger()
    root.setLevel(level)
    for existing in list(root.handlers):
        if getattr(existing, "name", None) == _LOG_HANDLER_NAME:
            root.removeHandler(existing)
    handler = logging.StreamHandler(sys.stderr)
    handler.name = _LOG_HANDLER_NAME
    handler.setFormatter(logging.Formatter("%(levelname)s | %(name)s | %(message)s"))
    root.addHandler(handler)
    # These two are chatty below WARNING and say nothing about storage, so
    # --loglevel DEBUG stays readable.
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)


def _env_file_path(explicit: str | None) -> tuple[Path, bool]:
    """The env file to load, and whether the operator named it (via
    --env-file or $ALEPH_VM_ENV_FILE) rather than this falling back to the
    node's default location. Both ways of naming a file are equally
    explicit operator intent: a missing one must refuse rather than run on
    defaults the operator did not choose.
    """
    if explicit:
        return Path(explicit), True
    from_environment = os.environ.get(ENV_FILE_VARIABLE)
    if from_environment:
        return Path(from_environment), True
    return DEFAULT_ENV_FILE, False


def _reload_settings() -> None:
    """Rebuild the settings singleton from the current environment.

    ``aleph.vm.conf`` builds its singleton when it is first imported, so
    anything this process adds to the environment afterwards is invisible
    to it. A second instance re-reads the environment, and copying its
    values onto the singleton keeps every module that already imported
    ``settings`` looking at the one object.
    """
    settings.__dict__.update(Settings().__dict__)


def _load_env_file(explicit: str | None) -> bool:
    """Load the node's environment file, if there is one. False when the
    operator named a file, via --env-file or $ALEPH_VM_ENV_FILE, that does
    not exist: running on the defaults they were trying to override is
    worse than refusing.

    Values already in the environment win, so a one-off override on the
    command line still works.
    """
    path, named = _env_file_path(explicit)
    if not path.is_file():
        if named:
            logger.error("No environment file at %s", path)
            return False
        logger.info("No environment file at %s; using the process environment alone", path)
        return True
    load_dotenv(path, override=False)
    _reload_settings()
    logger.info("Loaded the node configuration from %s", path)
    return True


def run_parsed(args: argparse.Namespace) -> int:
    """Set up the process (configuration, logging, database) and run the
    verb. Takes an already parsed namespace, so the agent CLI can hand over
    the one its own parser produced."""
    _setup_logging(getattr(args, "loglevel", None) or logging.INFO)
    try:
        if not _load_env_file(getattr(args, "env_file", None)):
            return 1
    except ValidationError as error:
        for field_error in error.errors():
            field = ".".join(str(part) for part in field_error["loc"])
            print(f"Invalid node configuration for {field}: {field_error['msg']}", file=sys.stderr)
        return 2
    settings.setup()
    storage_pools.setup_pools()

    database = settings.EXECUTION_DATABASE
    if not database.exists():
        if args.storage_command in READ_ONLY_COMMANDS:
            logger.error(
                "No agent database at %s: nothing has run on this node yet, or the execution root is not the one "
                "the agent uses",
                database,
            )
            return 1
        logger.info("Creating the agent database at %s", database)
    initialise_database()

    registry = asyncio.run(_load_registry())
    return run(args, registry, sys.stdout)


def main(argv: list[str]) -> int:
    return run_parsed(parse_args(argv))
