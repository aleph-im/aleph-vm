"""``aleph-vm storage``: show and drive reclamation from the node shell.

Storage is agent-side and, by design, readable from the filesystem plus the
agent DB, so these commands need no *agent process* running. They run the
same code the reconciler runs, including the same safety rule: a live set
built from the registry alone purges the disks of VMs the supervisor still
runs (guarded on the daemon side by ``reconciler._startup_refusal``, which
this module calls rather than restates). A CLI process holding only the
registry is exactly that state, so ``reconcile`` and ``reclaim`` ask the
supervisor daemon over the same gRPC socket the agent dials
(``GrpcSupervisor``, ``settings.SUPERVISOR_GRPC_SOCKET``), with a short
timeout, and union its answer into the live set. ``status`` and ``list``
are read-only and never touch the supervisor.

Two processes matter here, and they are not the same one. The *agent* is
this Python service (``aleph-vm-agent``, bound to
``settings.SUPERVISOR_HOST``/``SUPERVISOR_PORT``); it owns the reconciler
and the creates. The *supervisor* is the Rust daemon that runs the VMs and
answers ``list_vms`` on the gRPC socket. Either can be up without the
other, and the case an operator needs this command for is precisely the
awkward one: VMs running under a supervisor that is perfectly healthy while
the agent is down or will not start.

So a purge is decided in three states:

* The agent is running (or cannot be ruled out as running). A real pass and
  ``reclaim`` are refused. The one thing this process can never see is
  exactly what the running agent holds: the set of creates it has in flight
  (``reconciler.creating()`` is in-process state). A create that outlives
  ``VOLUME_CREATE_GUARD`` before its DB record exists (a long migration
  import routinely does) is invisible here and looks like an orphan,
  directory and devices alike, and a CLI pass holds no lock against the
  agent's own. The agent runs that pass itself at startup, periodically and
  after every VM goes away, and its pass sees the creates too.
  ``--dry-run`` is still allowed, and is how a running node is inspected.
* The agent is stopped and the supervisor answers. Nothing is being
  created, and the live set is a known one (registry union ``list_vms``), so
  the full pass runs: the orphan-namespace device teardown first, exactly as
  the agent's own passes do it, then the walk.
* The supervisor does not answer. The live set is the registry alone, which
  is not a safe one, so the pass runs dry, warns and exits non-zero unless
  ``--trust-registry`` says to proceed on the registry's word, and no device
  is torn down (that would take the disk of a VM that was merely unlisted).
  ``reclaim`` refuses on the same terms.

Both "is it running" questions are answered fail-closed, and neither claims
more than it can back up. The agent is called stopped only when nothing
accepts a connection on its bind address, on every loopback a wildcard bind
could be answering on; a probe that fails any other way leaves it possibly
running, and the refusal stands. One gap this cannot close: aiohttp runs
the agent's on_startup hooks, including the reconciler launch, before its
listener binds, so a starting agent can read as stopped for a moment; the
create guard covers most of that window. The supervisor is called down
only when its own socket is missing or refuses a connection; a dial that
failed for any other reason (a socket this user may not open, a deadline,
a reply that does not parse) leaves its state unknown, and the advice to
purge on the registry alone is then withheld, since it would invite the
one purge the union exists to prevent.

Every verb writes what it found or achieved to ``out`` and every warning,
refusal and diagnostic to ``err``, so a wrapper can parse one without
filtering the other.

Running with no agent process also means setting up the process the way the
systemd units set it up for the daemon: the node's environment file is read
here (nothing else injects it into an operator's shell, and running a pass
on the built-in defaults would reconcile a node against a configuration it
does not have), the log records go to stderr, and the agent database is
created and migrated before anything reads it.

``status`` and ``list`` are the exception, and they are read-only in the
literal sense: they refuse a database that is not there rather than create
one, and they refuse it before any of that setup runs, since
``settings.setup()`` makes every configured directory and the pool setup
adopts a pool on first sight (an operator who mistyped the execution root
got the refusal and a tree of empty directories at the typo, and a node
whose second disk was not mounted got that path adopted as a pool). They
also read a marker that does not parse without removing it, which is the
reconciler's repair and not a listing's. The one write they do make is the
schema migration of the database that is already there: the registry cannot
be read out of a database older than the code.
"""

from __future__ import annotations

import argparse
import asyncio
import errno
import logging
import os
import shutil
import socket
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TextIO

from dotenv import load_dotenv
from pydantic import ValidationError

from aleph.vm import storage_pools
from aleph.vm.agent import metrics
from aleph.vm.agent.cli import LOG_LEVEL_NAMES, initialise_database
from aleph.vm.agent.vm.cache import cache_budget_bytes, cache_entries, cache_roots
from aleph.vm.agent.vm.purge import PurgeResult, purge_vm_storage
from aleph.vm.agent.vm.reclaimable import (
    directory_size_bytes,
    iter_reclaimable,
    read_marker,
    reclaimable_bytes,
)
from aleph.vm.agent.vm.reconciler import (
    _plausible,
    _release_cache_devices,
    _startup_refusal,
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

# How long to wait for the agent's own bind address. Shorter still: it is a
# loopback connect, and a node that does not answer it in two seconds is a
# node this command must assume is alive anyway.
AGENT_PROBE_TIMEOUT_SECS = 2.0

# Exit code for a reconcile that did not reconcile: it was refused because
# the agent is running (its own pass covers the node), or it silently
# downgraded to a dry run because the supervisor could not be asked and
# --trust-registry was not given. Distinct from an explicit --dry-run, which
# is a success (exit 0): nothing was refused or downgraded, the caller asked
# for a preview and got one. Not 2, which argparse uses for a usage error: a
# wrapper script must be able to tell a pass that did not run from a bad
# argument without parsing stderr.
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
            "list_vms() when it can be reached). While the aleph-vm agent is running, or cannot be "
            "ruled out as running, only --dry-run runs: this process cannot see a create the agent "
            "is in the middle of (that state lives in the agent), so a create that has outlived "
            "VOLUME_CREATE_GUARD without reaching the registry DB would read as an orphan here, and "
            "the agent's own pass (at startup, periodically, and after every VM goes away) covers "
            "that node anyway. This command is for a node whose agent is down, whether or not the "
            "supervisor daemon under it still runs VMs."
        ),
    )
    reconcile_parser.add_argument("--dry-run", action="store_true")
    reconcile_parser.add_argument(
        "--trust-registry",
        action="store_true",
        help="purge using the registry alone when the supervisor is down and cannot say which VMs it runs",
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
    # Clamped at zero: a marker dated in the future (a node whose clock went
    # backwards, a marker copied from another host) would otherwise print an
    # age like "-1d 23h", which reads as a parsing bug to whoever sees it.
    seconds = max(int(delta.total_seconds()), 0)
    days, rem = divmod(seconds, 86400)
    hours = rem // 3600
    return f"{days}d {hours}h"


def _open_supervisor() -> Supervisor:
    """The agent's handle on the supervisor daemon, over the same gRPC socket
    the web app dials. A thin wrapper so tests can substitute a fake handle
    instead of a real gRPC channel."""
    from aleph.vm.supervisor_interface.client import GrpcSupervisor

    return GrpcSupervisor(settings.SUPERVISOR_GRPC_SOCKET)


class AgentReach(Enum):
    """How much this process knows about the agent service."""

    RUNNING = "running"
    # Verified stopped: nothing accepts a connection on its bind address.
    STOPPED = "stopped"
    # Could not tell, which counts as running: see AgentProbe.may_be_running.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class AgentProbe:
    """Whether the agent service is up, and on what evidence."""

    reach: AgentReach
    detail: str

    @property
    def may_be_running(self) -> bool:
        """Fail closed: only a refused connection rules the agent out.

        Everything a wrong answer here costs is asymmetric. Calling a
        stopped agent running costs an operator one refused command on a
        node they can then look at; calling a running agent stopped purges
        the disks of a VM it is at that moment creating.
        """
        return self.reach is not AgentReach.STOPPED


# Hosts that name no address to connect to. A wildcard bind is probed on
# both loopbacks, never on one: asyncio's server sets IPV6_V6ONLY on an
# AF_INET6 socket, so an agent bound to "::" accepts on ::1 and refuses on
# 127.0.0.1, and a probe that asked only the IPv4 loopback would call a
# running agent stopped and purge behind it.
_WILDCARD_HOSTS = frozenset({"", "*", "0.0.0.0", "::", "::0"})  # noqa: S104
_LOOPBACKS = ("127.0.0.1", "::1")

# Errnos that say the address family itself is unusable on this host rather
# than that the agent is up. Nothing can be serving on a loopback the kernel
# cannot reach, so these count with the refusals: without that, the probe on
# an IPv4-only node would answer "cannot tell" for ever and the command
# would refuse every purge on a node that has none of the risk.
_FAMILY_UNAVAILABLE = frozenset(
    {errno.EAFNOSUPPORT, errno.EPFNOSUPPORT, errno.ENETUNREACH, errno.EHOSTUNREACH, errno.EADDRNOTAVAIL}
)


def _format_address(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


def _probe_agent() -> AgentProbe:
    """Ask the agent's own HTTP bind address whether it is there.

    The cheapest evidence available, and it needs no privileges and no unit
    name: the agent binds that address for as long as its process lives, and
    this is a loopback connect that is either refused at once or accepted at
    once. Anything listening there is treated as the agent, which is the
    fail-closed reading; a socket configured but unreachable, a name that
    does not resolve or a deadline all leave the question open, and open
    counts as running. A wildcard bind is stopped only when every loopback
    it could be answering on refuses.

    The setting is spelled SUPERVISOR_HOST/PORT for historical reasons: it
    is this Python service's own bind, not the Rust supervisor's socket.
    """
    host = str(settings.SUPERVISOR_HOST)
    port = int(settings.SUPERVISOR_PORT)
    targets = _LOOPBACKS if host in _WILDCARD_HOSTS else (host,)
    silent: list[str] = []
    problems: list[str] = []
    for target in targets:
        address = _format_address(target, port)
        try:
            with socket.create_connection((target, port), timeout=AGENT_PROBE_TIMEOUT_SECS):
                pass
        except ConnectionRefusedError:
            silent.append(address)
        except OSError as error:
            if error.errno in _FAMILY_UNAVAILABLE:
                silent.append(f"{address} ({type(error).__name__}: {error})")
            else:
                problems.append(f"{address} ({type(error).__name__}: {error})")
        else:
            return AgentProbe(AgentReach.RUNNING, f"something is listening on {address}")
    if problems:
        return AgentProbe(AgentReach.UNKNOWN, "could not be probed: " + "; ".join(problems))
    return AgentProbe(AgentReach.STOPPED, "nothing accepts a connection on " + " or ".join(silent))


class SupervisorReach(Enum):
    """How much this process knows about the daemon after asking it."""

    ANSWERED = "answered"
    # Verified stopped: its socket is missing, or refuses a connection.
    DOWN = "down"
    # Could not be asked, and that is all: the daemon may well be running.
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class SupervisorAnswer:
    """What ``list_vms`` gave back, or why it gave nothing back."""

    reach: SupervisorReach
    running: frozenset[str] = frozenset()
    # Exception class and message, for the operator. Empty when the
    # supervisor answered.
    problem: str = ""

    @property
    def answered(self) -> bool:
        return self.reach is SupervisorReach.ANSWERED


@dataclass(frozen=True)
class LiveSet:
    """The hashes no CLI pass may touch, and what backs them."""

    hashes: frozenset[str]
    supervisor: SupervisorAnswer
    # The daemon's own reason to distrust its live set, when the supervisor
    # answered. None when it did not answer: the "unanswered" half of that
    # verdict is what the --trust-registry gate already covers.
    refusal: str | None


def _exception_chain(error: BaseException) -> Iterator[BaseException]:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = current.__cause__ or current.__context__


def _socket_reach(path: Path | None) -> SupervisorReach:
    """Whether the daemon's socket says it is stopped.

    Only two answers prove it: no socket at all, or one that refuses the
    connection (a stale file the daemon left behind). A connection that is
    accepted, one the kernel will not let this user attempt, or a path that
    cannot even be resolved all leave the daemon's state unknown.
    """
    if path is None:
        return SupervisorReach.UNKNOWN
    # os.stat rather than Path.exists(), which turns every error into a
    # plain False: a socket this user may not stat would then be reported as
    # a stopped daemon, which is the one mistake this function must not make.
    try:
        os.stat(path)
    except FileNotFoundError:
        return SupervisorReach.DOWN
    except OSError:
        return SupervisorReach.UNKNOWN
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
            probe.settimeout(SUPERVISOR_CONNECT_TIMEOUT_SECS)
            probe.connect(str(path))
    except ConnectionRefusedError:
        return SupervisorReach.DOWN
    except OSError:
        return SupervisorReach.UNKNOWN
    return SupervisorReach.UNKNOWN


def _reach_from_failure(error: BaseException) -> SupervisorReach:
    """Classify a failed dial, conservatively.

    The gRPC client rebuilds transport failures into its own error classes,
    so the exception alone rarely says whether the daemon is stopped; when
    it does not, the socket itself is asked. A refused connection anywhere
    in the chain is proof enough, checked across the whole chain before
    anything else: a PermissionError closer to the head of the chain must
    not hide a ConnectionRefusedError sitting deeper in it. A missing
    *file* is not proof, whatever the chain says: the client opens more
    than its socket (a TLS material path, a config file), and only a stat
    of the socket path itself can tell a stopped daemon from a running one
    that tripped over something else, so that case falls through to
    _socket_reach. A permission error on its own is never proof, and
    neither is a deadline (a daemon that is up but wedged is the textbook
    way to time out).
    """
    chain = list(_exception_chain(error))
    if any(isinstance(cause, ConnectionRefusedError) for cause in chain):
        return SupervisorReach.DOWN
    if any(isinstance(cause, PermissionError) for cause in chain):
        return SupervisorReach.UNKNOWN
    if isinstance(error, TimeoutError):
        return SupervisorReach.UNKNOWN
    return _socket_reach(settings.SUPERVISOR_GRPC_SOCKET)


async def _ask_supervisor(timeout: float = SUPERVISOR_CONNECT_TIMEOUT_SECS) -> SupervisorAnswer:
    """Ask the supervisor which VMs it runs, and classify the answer.

    Reuses ``reconciler.supervisor_hashes`` for the id-to-hash mapping, so a
    CLI pass and a daemon pass never disagree on what counts as a plausible
    VM id.
    """
    supervisor = _open_supervisor()
    try:
        running = await asyncio.wait_for(supervisor_hashes(supervisor), timeout=timeout)
    # Broad on purpose: every way this can fail (a transport error, a
    # deadline, a reply that does not parse) means the same thing here, that
    # there is no answer to union in, and the caller must fail closed. What
    # differs is only what the operator is told, which is why the exception
    # is kept rather than swallowed.
    except Exception as error:
        logger.debug("The supervisor could not be asked which VMs it runs", exc_info=True)
        return SupervisorAnswer(
            reach=_reach_from_failure(error),
            problem=f"{type(error).__name__}: {error}",
        )
    else:
        return SupervisorAnswer(SupervisorReach.ANSWERED, frozenset(running))
    finally:
        close = getattr(supervisor, "close", None)
        if close is not None:
            try:
                await close()
            except Exception:
                logger.debug("Failed to close the supervisor handle", exc_info=True)


def _cli_live_set(registry: AgentVmRegistry) -> LiveSet:
    """The live set for a CLI pass, and everything that qualifies it.

    The registry alone is never enough here: it is the same fail-closed
    reasoning ``reconciler._startup_refusal`` applies to the daemon's own
    startup pass, applied to a CLI process that by construction never has
    more than the registry unless it asks the daemon itself. That refusal is
    called, not restated, so the two passes cannot drift apart: an empty
    registry while the supervisor runs VMs means the agent DB was lost, and
    the union then hides nothing, since it is the registry half that would
    have named the VMs the supervisor has not started yet.
    """
    answer = asyncio.run(_ask_supervisor())
    live = live_hashes(registry)
    if not answer.answered:
        return LiveSet(frozenset(live), answer, None)
    return LiveSet(
        frozenset(live | set(answer.running)),
        answer,
        _startup_refusal(registry, len(answer.running)),
    )


def _pool_usage(path: Path) -> tuple[int | None, int | None]:
    """(total, free) bytes of the filesystem holding ``path``, or (None,
    None) when it cannot be read: a mountpoint that went away, a directory
    this user may not stat, a filesystem that is gone."""
    try:
        usage = shutil.disk_usage(str(path))
    except OSError:
        logger.warning("Could not read the usage of %s", path, exc_info=True)
        return None, None
    return usage.total, usage.free


def _retention_budget(total: int | None) -> int | None:
    """The retention budget in bytes, or None when it cannot be computed.

    Under ``reap`` it is zero and nothing else, whatever the filesystem
    says. Otherwise it is measured against the pool's size (typically a
    percentage of it), so a size this process could not read leaves the
    budget unknown rather than zero.
    """
    if settings.VOLUME_RETENTION == "reap":
        return 0
    if total is None:
        return None
    return parse_budget(settings.VOLUME_RETENTION_BUDGET, total)


def _figure(size: int | None) -> str:
    """A byte figure, or ``unknown`` for one this process could not measure.

    Zero is a measurement, and a pool printed as 0 bytes free with a 0 byte
    budget looks exactly like a full pool, which is the state an operator
    runs this command to find. An unreadable pool has to say so.
    """
    return "unknown" if size is None else _human(size)


def _status(registry: AgentVmRegistry, out: TextIO) -> int:
    live = live_hashes(registry)
    out.write("POOL\tLIVE\tRECLAIMABLE\tBUDGET\tFREE\n")
    for pool in storage_pools.get_pools():
        live_bytes = sum(
            directory_size_bytes(directory)
            for directory in iter_namespace_dirs()
            if directory.parent == pool.path and directory.name in live
        )
        total, free = _pool_usage(pool.path)
        out.write(
            f"{pool.path}\t{_human(live_bytes)}\t{_human(reclaimable_bytes(pool.path, repair=False))}\t"
            f"{_figure(_retention_budget(total))}\t{_figure(free)}\n"
        )
    out.write("CACHE\tUSED\tBUDGET\n")
    for root in cache_roots():
        used = sum(entry.size_bytes for entry in cache_entries(root))
        # The cache budget is a share of the filesystem holding the root, so
        # it is unknown for exactly the same reason a pool's is.
        try:
            budget: int | None = cache_budget_bytes(root)
        except OSError:
            logger.warning("Could not compute the cache budget of %s", root, exc_info=True)
            budget = None
        out.write(f"{root}\t{_human(used)}\t{_figure(budget)}\n")
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
        # repair=False: removing a marker that does not parse is the
        # reconciler's job, and a listing that unlinks a file is not the
        # read-only command this is documented to be (it may also be run by
        # a user who cannot unlink it, and the error would abort the whole
        # listing over one row).
        marker = read_marker(directory, repair=False)
        if reclaimable_only and marker is None:
            continue
        if marker:
            reason = marker.reason
        else:
            reason = "live" if directory.name in live else "unmarked"
        age = _age(marker.reclaimable_since) if marker else "-"
        out.write(f"{directory.name}\t{directory.parent}\t{_human(directory_size_bytes(directory))}\t{reason}\t{age}\n")
    return 0


def _is_marked_reclaimable(vm_hash: str) -> bool:
    """Whether any pool holds a marker for this hash.

    repair=False, like every marker read this process makes: the walk covers
    every directory on the node, and it runs before the refusals, so with
    the repair on, a reclaim that is about to be refused would first unlink
    the corrupt markers of unrelated VMs. Both callers (the refusal, and the
    second read immediately before the purge) go through here.
    """
    return any(directory.name == vm_hash for directory, _marker in iter_reclaimable(repair=False))


@dataclass(frozen=True)
class Refusal:
    """A reason not to purge, and the exit code that reports it.

    Most refusals say "not this hash" and exit 1. A node whose agent is
    live, or whose agent database was lost, is a different answer: nothing
    about the hash is wrong, the command simply may not run here, and a
    wrapper script has to be able to tell the two apart.
    """

    message: str
    code: int = 1


def _supervisor_reclaim_refusal(registry: AgentVmRegistry, vm_hash: str, *, trust_registry: bool) -> Refusal | None:
    """The half of the reclaim verdict that needs the daemon's answer."""
    answer = asyncio.run(_ask_supervisor())
    if answer.answered:
        if vm_hash in answer.running:
            return Refusal(f"{vm_hash} is running (the supervisor lists it); refusing to purge it")
        # The daemon's own reason to distrust a live set, asked here too: a
        # lost agent DB makes every marker on the node look purgeable, and
        # the supervisor's list is no second opinion on a VM it has not
        # started yet.
        lost_database = _startup_refusal(registry, len(answer.running))
        if lost_database is not None:
            return Refusal(f"Refusing to purge {vm_hash}: {lost_database}", DEGRADED_EXIT_CODE)
        return None
    if trust_registry:
        return None
    if answer.reach is SupervisorReach.DOWN:
        return Refusal(
            f"Supervisor unreachable ({answer.problem}); cannot confirm {vm_hash} is not running. "
            "Pass --trust-registry to purge using the registry alone"
        )
    return Refusal(
        f"The supervisor could not be asked ({answer.problem}); cannot confirm {vm_hash} is not "
        "running. That error is no proof the daemon is stopped, so purging on the registry alone "
        "is not offered here: fix it and retry"
    )


def _reclaim_refusal(registry: AgentVmRegistry, vm_hash: str, *, trust_registry: bool) -> Refusal | None:
    """Why reclaim must not purge this hash, or None when it may.

    Cheapest, purely local checks first: a typo or an unrelated hash fails
    instantly instead of waiting out a supervisor dial that can only ever
    confirm what these checks already know. The name check mirrors the
    daemon's walk: a hand-made marker under a directory nobody named after a
    VM must be refused here, not tripped over as a ValueError inside
    purge_vm_storage after every other check passed.
    """
    if not _plausible(vm_hash):
        return Refusal(f"{vm_hash!r} is not a VM hash; refusing to purge a directory not named after a VM")
    if not _is_marked_reclaimable(vm_hash):
        return Refusal(
            f"{vm_hash} is not reclaimable (no .reclaimable marker); refusing to purge a directory a VM may own"
        )
    if vm_hash in live_hashes(registry):
        return Refusal(f"{vm_hash} is a live VM in the agent registry; refusing to purge it")
    probe = _probe_agent()
    if probe.may_be_running:
        # A marked directory is not safe to purge merely because it is
        # marked: a create adopts it by clearing the marker, and this
        # process would have to win a race with that to notice.
        return Refusal(
            f"Refusing to purge {vm_hash}: {_agent_at_work_reason(probe)}. {_agent_pass_note()}; "
            "run 'storage reconcile --dry-run' to preview what the agent's own pass will find",
            DEGRADED_EXIT_CODE,
        )
    return _supervisor_reclaim_refusal(registry, vm_hash, trust_registry=trust_registry)


def _reclaim(registry: AgentVmRegistry, vm_hash: str, out: TextIO, err: TextIO, *, trust_registry: bool) -> int:
    # Every refusal and every diagnostic goes to err, as in reconcile: stdout
    # carries what the command achieved and nothing else, so a wrapper can
    # read it without filtering.
    refusal = _reclaim_refusal(registry, vm_hash, trust_registry=trust_registry)
    if refusal is not None:
        err.write(refusal.message + "\n")
        return refusal.code
    # Asked again, after the probe and the dial: a re-create adopts its
    # retained directories by clearing their markers, and a create that
    # started while the supervisor was being asked is in no answer this
    # process has. The marker is the one thing that says the disks are
    # nobody's.
    if not _is_marked_reclaimable(vm_hash):
        err.write(
            f"{vm_hash} is no longer marked reclaimable: a create adopted its directory while the "
            "supervisor was being asked. Refusing to purge it\n"
        )
        return 1
    result = purge_vm_storage(vm_hash)
    if result.kept:
        err.write(_incomplete_purge_report(vm_hash, result))
        return 1
    out.write(f"Purged {vm_hash}: {result.deleted} volume file(s)\n")
    return 0


def _incomplete_purge_report(vm_hash: str, result: PurgeResult) -> str:
    """What the purge could not remove, named, with advice that fits it.

    A device-mapper hold and a failed removal (a read-only filesystem, an
    immutable file, a directory this user may not write) leave the same
    thing on disk, so the directory alone cannot tell them apart. Only the
    first is fixed by tearing devices down, and sending an operator to
    'storage reconcile' for the others is advice that cannot work.
    """
    lines = [f"Purge of {vm_hash} left {len(result.kept)} directory(ies) behind:\n"]
    lines.extend(f"  {kept.path}: {kept.reason}\n" for kept in result.kept)
    lines.append(f"Deleted {result.deleted} volume file(s)\n")
    if any(kept.device_mapper for kept in result.kept):
        lines.append("Run 'storage reconcile' to tear down the devices of every VM nothing owns, then retry\n")
    else:
        lines.append(
            "No device-mapper target is holding these: the errors above are what stopped the removal, "
            "so fix those and retry\n"
        )
    return "".join(lines)


def _agent_at_work_reason(probe: AgentProbe) -> str:
    """Why a live agent takes the purge away from this command."""
    if probe.reach is AgentReach.RUNNING:
        opening = f"the agent is running ({probe.detail})"
    else:
        opening = f"the agent cannot be ruled out as running ({probe.detail})"
    return (
        f"{opening}, and the creates it has in flight are invisible to this process (that state "
        "lives in the agent itself), so a VM being built would read as an orphan here"
    )


def _agent_pass_note() -> str:
    return (
        "The agent runs its own pass at startup, periodically, and after every VM goes away, and "
        "that pass sees the creates too"
    )


def _agent_pass_refusal(probe: AgentProbe) -> str:
    return (
        f"Refusing to reconcile: {_agent_at_work_reason(probe)}. {_agent_pass_note()}; use "
        "--dry-run to preview what one would find.\n"
    )


def _lost_database_refusal(live_set: LiveSet) -> str | None:
    """The daemon's own reason to distrust a live set, once the agent is out
    of the way: an empty registry while the supervisor runs VMs means the
    agent DB was lost, and every directory on the node then reads as an
    orphan."""
    if live_set.refusal is None:
        return None
    return (
        f"Refusing to reconcile: {live_set.refusal}. Restore the agent database, or use "
        "--dry-run to see what a pass would find.\n"
    )


def _unanswered_warning(answer: SupervisorAnswer, *, dry_run: bool, trust_registry: bool) -> str:
    """Say what failed, then say what that does and does not license."""
    if answer.reach is SupervisorReach.DOWN:
        opening = f"Warning: the supervisor is unreachable ({answer.problem})\n"
    else:
        opening = f"Warning: the supervisor could not be asked which VMs it runs ({answer.problem})\n"
    if dry_run:
        return opening + "This preview is registry-only: a VM the registry has forgotten reads as an orphan here\n"
    if trust_registry:
        return opening + "Purging on the registry alone, as --trust-registry asked\n"
    if answer.reach is SupervisorReach.DOWN:
        return opening + (
            "Showing what a registry-only pass would purge; pass --trust-registry to purge using "
            "the registry alone\n"
        )
    return opening + (
        "Showing what a registry-only pass would purge. That error is no proof the daemon is "
        "stopped, so purging on the registry alone is not offered here: fix it and retry\n"
    )


def _reconcile(registry: AgentVmRegistry, out: TextIO, err: TextIO, *, dry_run: bool, trust_registry: bool) -> int:
    # The agent probe comes before the supervisor dial: it is a loopback
    # connect that answers at once, and it can refuse the whole pass, so a
    # refused pass should not first sit through a three second deadline for
    # an answer it then throws away.
    probe = _probe_agent()
    if probe.may_be_running:
        if not dry_run:
            err.write(_agent_pass_refusal(probe))
            return DEGRADED_EXIT_CODE
        err.write(
            f"Note: {_agent_at_work_reason(probe)}, so this preview can name a directory the "
            "agent is at that moment creating\n"
        )
    live_set = _cli_live_set(registry)
    answer = live_set.supervisor
    if not dry_run:
        lost_database = _lost_database_refusal(live_set)
        if lost_database is not None:
            err.write(lost_database)
            return DEGRADED_EXIT_CODE
    if not answer.answered:
        err.write(_unanswered_warning(answer, dry_run=dry_run, trust_registry=trust_registry))
    downgraded = not answer.answered and not trust_registry
    effective_dry_run = dry_run or downgraded
    live = set(live_set.hashes)
    # Mirrors reconcile_now: the devices of every namespace nothing owns go
    # before the walk, or the purge that follows refuses those directories
    # (a dm target still holds their volume files) exactly as the agent's
    # passes used to. Only when the supervisor answered, since removing the
    # device of a VM that is merely unlisted takes that VM's disk with it:
    # --trust-registry buys a purge on the registry's word, not a teardown.
    if not effective_dry_run and answer.answered:
        asyncio.run(_teardown_orphan_devices(live))
    report = reconcile_storage(registry, dry_run=effective_dry_run, live=live, live_known=answer.answered)
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


def run(args: argparse.Namespace, registry: AgentVmRegistry, out: TextIO, err: TextIO) -> int:
    """Run one verb. ``out`` carries what the command found or achieved,
    ``err`` every warning, refusal and diagnostic, so a wrapper can parse one
    without filtering the other."""
    if args.storage_command == "status":
        return _status(registry, out)
    if args.storage_command == "list":
        return _list(registry, out, reclaimable_only=args.reclaimable)
    if args.storage_command == "reclaim":
        return _reclaim(registry, args.vm_hash, out, err, trust_registry=args.trust_registry)
    if args.storage_command == "reconcile":
        return _reconcile(registry, out, err, dry_run=args.dry_run, trust_registry=args.trust_registry)
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
    # interpolate=False: systemd's EnvironmentFile= does no ${} expansion,
    # so the node's file is written with literal values. Expanding them here
    # would read a value the daemon never sees, and would silently truncate
    # any secret containing a dollar sign to whatever ${...} resolves to.
    load_dotenv(path, override=False, interpolate=False)
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

    read_only = args.storage_command in READ_ONLY_COMMANDS
    database = settings.EXECUTION_DATABASE
    if read_only and not database.exists():
        # Before anything else: settings.setup() makes every configured
        # directory, so an operator who mistyped the execution root used to
        # get this refusal and a tree of empty directories at the typo.
        logger.error(
            "No agent database at %s: nothing has run on this node yet, or the execution root is not the one "
            "the agent uses",
            database,
        )
        return 1
    if read_only:
        # settings.setup() creates the caches, the execution root, the pool
        # directory and the session directory, and resolves the node's DNS;
        # setup_pools() adopts a pool on first sight, marker file and
        # adoption registry both. None of that belongs in a command that
        # reports on a node. The settings themselves are complete without
        # setup(): every path these verbs read is derived when the settings
        # object is built.
        storage_pools.setup_pools(read_only=True)
    else:
        settings.setup()
        storage_pools.setup_pools()
        if not database.exists():
            logger.info("Creating the agent database at %s", database)
    # Read-only included: the registry cannot be read out of a database
    # whose schema predates the code, and the migration writes only to the
    # database file that is already there.
    initialise_database()

    registry = asyncio.run(_load_registry())
    return run(args, registry, sys.stdout, sys.stderr)


def main(argv: list[str]) -> int:
    return run_parsed(parse_args(argv))
