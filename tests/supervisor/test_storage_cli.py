from __future__ import annotations

import io
import json
import logging
import os
import re
import socket
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

import aleph.vm.agent.cli as agent_cli
import aleph.vm.agent.storage_cli as cli
import aleph.vm.agent.vm.reconciler as reconciler_module
from aleph.vm import storage_pools
from aleph.vm.agent.vm.reclaimable import (
    ReclaimableMarker,
    clear_marker,
    mark_reclaimable,
    write_marker,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings

LIVE = "dead" * 16
NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)
# Captured before the autouse fixture below replaces it, for the tests that
# are about the probe itself rather than about what a verb does with it.
REAL_PROBE_AGENT = cli._probe_agent


@pytest.fixture
def registry():
    reg = AgentVmRegistry()
    content = MagicMock(volumes=[], rootfs=None)
    reg.record(ItemHash(LIVE), message=content, original=content, persistent=True)
    return reg


@pytest.fixture(autouse=True)
def _no_backups(mocker):
    mocker.patch("aleph.vm.agent.vm.reconciler.sweep_expired_backups", return_value=0)


@pytest.fixture(autouse=True)
def _no_device_mapper(tmp_path, monkeypatch):
    """Never let a test read the host's real /dev/mapper: the reconcile the
    CLI runs tears down the devices of every namespace nothing owns."""
    empty = tmp_path / "empty-mapper"
    empty.mkdir()
    monkeypatch.setattr(reconciler_module, "DEVICE_MAPPER_DIRECTORY", str(empty))


def _fake_mapper(monkeypatch, tmp_path, *names: str) -> Path:
    mapper = tmp_path / "mapper"
    mapper.mkdir(exist_ok=True)
    for name in names:
        (mapper / name).touch()
    monkeypatch.setattr(reconciler_module, "DEVICE_MAPPER_DIRECTORY", str(mapper))
    return mapper


def _fake_supervisor(*vm_ids: str, fails: bool = False, error: Exception | None = None):
    """A supervisor handle that lists ``vm_ids``, or cannot be asked at all
    (an unreachable daemon: a connection error, a timeout, any of it).

    ``fails`` raises a generic error, which the CLI then classifies by
    probing the socket itself (absent under the tests, so: verified down).
    ``error`` raises exactly what the caller passes, for the classes the CLI
    reads off the exception alone.
    """
    if error is not None:
        return SimpleNamespace(list_vms=AsyncMock(side_effect=error))
    if fails:
        return SimpleNamespace(list_vms=AsyncMock(side_effect=RuntimeError("no answer")))
    return SimpleNamespace(list_vms=AsyncMock(return_value=[SimpleNamespace(vm_id=vm_id) for vm_id in vm_ids]))


@pytest.fixture(autouse=True)
def _agent_stopped(monkeypatch):
    """By default the aleph-vm agent is down, which is the node this command
    is for: the tests that care about a live agent say so themselves."""
    monkeypatch.setattr(
        cli,
        "_probe_agent",
        lambda: cli.AgentProbe(cli.AgentReach.STOPPED, "nothing accepts a connection on 127.0.0.1:4020"),
    )


def _agent_up(reach=None):
    """A probe that says the agent is running, or that it cannot be ruled
    out as running (which counts as running)."""
    reach = reach or cli.AgentReach.RUNNING
    if reach is cli.AgentReach.RUNNING:
        return lambda: cli.AgentProbe(reach, "something is listening on 127.0.0.1:4020")
    return lambda: cli.AgentProbe(reach, "127.0.0.1:4020 could not be probed (PermissionError: denied)")


@pytest.fixture(autouse=True)
def _supervisor_reachable(monkeypatch):
    """By default the supervisor is reachable and lists nothing running: the
    tests that care about a different answer override ``_open_supervisor``
    themselves."""
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor())


def _run(argv: list[str], registry) -> tuple[int, str, str]:
    """(exit code, stdout, stderr). The verbs write to the streams they are
    handed, so a test reads the two apart without capsys."""
    out, err = io.StringIO(), io.StringIO()
    code = cli.run(cli.parse_args(argv), registry, out, err)
    return code, out.getvalue(), err.getvalue()


def test_status_lists_pools_and_caches(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    volume(pools["pool0"], LIVE, "rootfs.qcow2", size=4096)
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    code, out, err = _run(["status"], registry)

    assert code == 0
    assert "POOL" in out and str(pools["pool0"]) in out and str(pools["pool1"]) in out
    assert "CACHE" in out and str(pools["runtime"]) in out


def test_list_shows_every_vm_dir_and_reclaimable_filters(pools, registry):  # noqa: F811
    volume(pools["pool0"], LIVE, "rootfs.qcow2")
    volume(pools["pool1"], VM_HASH, "rootfs.qcow2")
    volume(pools["pool1"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "orphan", now=NOW - timedelta(days=3))

    code, out, err = _run(["list"], registry)
    assert code == 0
    rows = {line.split("\t")[0]: line.split("\t")[3] for line in out.splitlines()[1:]}
    # An unmarked directory is "live" only on the registry's word; an
    # unmarked orphan no pass has reached yet must not read as a live VM.
    assert rows == {LIVE: "live", VM_HASH: "orphan", OTHER_HASH: "unmarked"}

    code, out, err = _run(["list", "--reclaimable"], registry)
    assert LIVE not in out and VM_HASH in out and "orphan" in out


def test_reclaim_purges_a_reclaimable_dir_only(pools, registry):  # noqa: F811
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    unmarked = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    code, out, err = _run(["reclaim", VM_HASH], registry)
    assert code == 0 and "Purged" in out
    assert not gone.exists()

    # OTHER_HASH is on disk, unmarked, unknown to the registry and to the
    # (fake, reachable) supervisor: reclaim refuses it for lack of a marker,
    # not because anything claims to own it.
    code, out, err = _run(["reclaim", OTHER_HASH], registry)
    assert code == 1 and "not reclaimable" in err
    assert out == ""  # a refusal achieved nothing, so stdout stays empty
    assert unmarked.exists()


def test_reclaim_checks_the_marker_before_dialing_the_supervisor(pools, registry, monkeypatch):  # noqa: F811, ARG001
    """A typo'd or unrelated hash is refused by the purely local marker check
    alone: nothing here should wait out a supervisor dial first."""
    dialed = []

    def open_supervisor():
        dialed.append(True)
        return _fake_supervisor()

    monkeypatch.setattr(cli, "_open_supervisor", open_supervisor)

    code, out, err = _run(["reclaim", "not-a-real-hash"], registry)
    assert code == 1 and "not a VM hash" in err

    code, out, err = _run(["reclaim", "f" * 64], registry)
    assert code == 1 and "not reclaimable" in err

    assert dialed == []


def test_reclaim_refuses_a_marked_directory_not_named_after_a_vm(pools, registry):  # noqa: F811
    """A hand-made marker under a directory nobody named after a VM: the
    daemon's walk drops such names, and reclaim must refuse them cleanly
    rather than trip over purge_vm_storage's own hash guard."""
    kept = volume(pools["pool0"], "backup_old", "rootfs.qcow2")
    write_marker(kept.parent, ReclaimableMarker(reclaimable_since=NOW, reason="gone", size_bytes=0))

    code, out, err = _run(["reclaim", "backup_old"], registry)

    assert code == 1 and "not a VM hash" in err
    assert kept.exists()


def test_reclaim_refuses_an_unmarked_live_directory(pools, registry):  # noqa: F811
    """A live VM's directory ordinarily carries no marker, so the marker
    check alone already refuses it."""
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")

    code, out, err = _run(["reclaim", LIVE], registry)

    assert code == 1 and "not reclaimable" in err
    assert live.exists()


def test_reclaim_refuses_a_marked_but_still_live_registry_hash(pools, registry):  # noqa: F811
    """A stale marker on a directory the registry still calls live (not yet
    cleared by a reconcile pass): the registry check catches it once the
    marker check has passed."""
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")
    mark_reclaimable(LIVE, "orphan", now=NOW)

    code, out, err = _run(["reclaim", LIVE], registry)

    assert code == 1 and "live VM in the agent registry" in err
    assert live.exists()


def test_reclaim_refuses_a_hash_the_supervisor_lists_as_running(pools, registry, monkeypatch):  # noqa: F811
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(VM_HASH))

    code, out, err = _run(["reclaim", VM_HASH], registry)

    assert code == 1 and "running" in err
    assert gone.exists()


def test_reclaim_refuses_unless_trust_registry_when_supervisor_unreachable(pools, registry, monkeypatch):  # noqa: F811
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out, err = _run(["reclaim", VM_HASH], registry)
    assert code == 1 and "unreachable" in err
    assert gone.exists()

    code, out, err = _run(["reclaim", "--trust-registry", VM_HASH], registry)
    assert code == 0 and "Purged" in out
    assert not gone.exists()


def test_reclaim_does_not_advise_the_registry_when_the_daemon_may_be_up(pools, registry, monkeypatch):  # noqa: F811
    """A dial that failed for a reason other than a stopped daemon must not
    end in an invitation to purge on the registry alone."""
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    denied = PermissionError(13, "Permission denied")
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(error=denied))

    code, out, err = _run(["reclaim", VM_HASH], registry)

    assert code == 1
    assert "PermissionError" in err and "Permission denied" in err
    assert "--trust-registry" not in err
    assert gone.exists()


def test_reclaim_refuses_an_empty_registry_the_supervisor_contradicts(pools, monkeypatch):  # noqa: F811
    """A lost agent DB makes every marker on the node look purgeable, and
    the supervisor's list is no second opinion on a VM it has not started
    yet."""
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(LIVE))

    code, out, err = _run(["reclaim", VM_HASH], AgentVmRegistry())

    assert code == cli.DEGRADED_EXIT_CODE and "registry is empty" in err
    assert gone.exists()


def test_reclaim_refuses_a_marker_that_vanished_during_the_dial(pools, registry, monkeypatch):  # noqa: F811
    """A re-create adopts its retained directory by clearing the marker. If
    that happens while the supervisor is being asked, the hash is not yet in
    any answer, and a purge on the checks made before the dial would delete
    the disks of a VM the daemon is at that moment building on them."""
    adopted = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    def open_supervisor():
        clear_marker(adopted.parent)
        return _fake_supervisor()

    monkeypatch.setattr(cli, "_open_supervisor", open_supervisor)

    code, out, err = _run(["reclaim", VM_HASH], registry)

    assert code == 1 and "no longer marked reclaimable" in err
    assert adopted.exists()


def test_reclaim_refuses_when_the_purge_leaves_a_dm_held_directory(pools, registry, monkeypatch):  # noqa: F811
    held = volume(pools["pool0"], VM_HASH, "data.btrfs")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    dm_path = Path("/dev/mapper") / f"{VM_HASH}_data"
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self == dm_path or real_is_block_device(self))

    code, out, err = _run(["reclaim", VM_HASH], registry)

    assert code == 1
    assert "device-mapper" in err
    assert held.exists()


def test_reconcile_dry_run_reports_without_changing(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))

    code, out, err = _run(["reconcile", "--dry-run"], registry)

    assert code == 0 and "Dry run" in out and "purged=1" in out
    assert orphan.exists()

    # The agent is down (the autouse fixture) and the supervisor is
    # reachable and lists nothing running, so a real pass may purge.
    code, out, err = _run(["reconcile"], registry)
    assert code == 0 and not orphan.exists()


@pytest.mark.parametrize("reach", [None, "unknown"])
def test_reconcile_refuses_a_real_pass_while_the_agent_may_be_running(pools, registry, monkeypatch, reach):  # noqa: F811
    """The agent holds the one thing this process cannot see: the set of
    creates it has in flight. A long import outlives VOLUME_CREATE_GUARD
    before its DB record exists, and a CLI pass would purge it as an orphan.
    A probe that could not answer counts as a running agent: the cost of
    being wrong is one refused command against a deleted disk."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_probe_agent", _agent_up(cli.AgentReach.UNKNOWN if reach else None))

    code, out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert orphan.exists()
    assert out == ""  # nothing was reconciled, so there is no report to print
    assert "Refusing to reconcile" in err and "--dry-run" in err
    assert ("cannot be ruled out" in err) is bool(reach)

    # The preview is still available, still sees the orphan, and says what
    # the running agent does to its reading.
    code, out, err = _run(["reconcile", "--dry-run"], registry)
    assert code == 0 and "purged=1" in out
    assert orphan.exists()
    assert "creating" in err


def test_a_refused_pass_never_dials_the_supervisor(pools, registry, monkeypatch):  # noqa: F811, ARG001
    """The agent probe answers at once and can refuse the whole pass; the
    dial can take the full three second deadline and would be discarded."""
    dialed: list[bool] = []
    monkeypatch.setattr(cli, "_probe_agent", _agent_up())

    def open_supervisor():
        dialed.append(True)
        return _fake_supervisor()

    monkeypatch.setattr(cli, "_open_supervisor", open_supervisor)

    code, _out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert "Refusing to reconcile" in err
    assert dialed == []


def test_reclaim_refuses_while_the_agent_may_be_running(pools, registry, monkeypatch):  # noqa: F811
    """Same rule, no --dry-run to fall back on: a marked directory is not
    safe to purge merely because it is marked, since a create adopts one by
    clearing its marker."""
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    monkeypatch.setattr(cli, "_probe_agent", _agent_up())

    code, out, err = _run(["reclaim", VM_HASH], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert "the agent is running" in err
    assert out == ""
    assert gone.exists()


def test_reconcile_refuses_an_empty_registry_the_supervisor_contradicts(pools, monkeypatch):  # noqa: F811, ARG001
    """The daemon's own startup refusal, applied here: an empty registry
    while the supervisor runs VMs means the agent DB was lost, and every
    directory on the node then reads as an orphan."""
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(LIVE))

    code, out, err = _run(["reconcile"], AgentVmRegistry())

    assert code == cli.DEGRADED_EXIT_CODE
    assert out == ""
    assert "registry is empty" in err and "1 VM(s)" in err


def test_reconcile_leaves_a_supervisor_known_vm_the_registry_does_not(pools, registry, monkeypatch):  # noqa: F811
    """The agent is down but the supervisor still runs VMs: the case this
    command exists for. OTHER_HASH is not in the registry, so only the union
    with list_vms keeps its disks."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    unknown = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(unknown.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(OTHER_HASH))

    code, out, err = _run(["reconcile"], registry)

    assert code == 0
    assert unknown.exists()


def test_reconcile_unreachable_exits_nonzero_and_warns_on_stderr(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert "Dry run" in out
    assert "unreachable" not in out  # the warning must not land in the parseable report
    assert "unreachable" in err and "registry-only" in err
    assert orphan.exists()


def test_reconcile_explicit_dry_run_stays_exit_zero_when_unreachable(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out, err = _run(["reconcile", "--dry-run"], registry)

    assert code == 0
    assert "Dry run" in out
    assert orphan.exists()
    # Nothing was downgraded: the operator asked for a preview and got one,
    # so advising the flag that turns a pass into a purge is noise.
    assert "registry-only" in err and "--trust-registry" not in err


def test_a_dial_that_is_no_proof_the_daemon_is_down_advises_no_purge(pools, registry, monkeypatch):  # noqa: F811
    """A socket this user may not open, a deadline, a reply that does not
    parse: none of them says the daemon is stopped, and purging on the
    registry alone while it runs is the very thing the union prevents. The
    error itself has to reach the operator, named."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    denied = PermissionError(13, "Permission denied")
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(error=denied))

    code, out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert orphan.exists()
    assert "PermissionError" in err and "Permission denied" in err
    assert "--trust-registry" not in err


def test_a_timeout_is_never_reported_as_a_stopped_daemon(pools, registry, monkeypatch):  # noqa: F811
    """asyncio.wait_for gives up on a daemon that is up but wedged."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(error=TimeoutError("timed out")))

    code, _out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert "TimeoutError" in err
    assert "--trust-registry" not in err


def test_the_agent_probe_reads_a_listening_socket_as_running(monkeypatch):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        monkeypatch.setattr(settings, "SUPERVISOR_HOST", "127.0.0.1")
        monkeypatch.setattr(settings, "SUPERVISOR_PORT", server.getsockname()[1])

        probe = REAL_PROBE_AGENT()

    assert probe.reach is cli.AgentReach.RUNNING
    assert probe.may_be_running


@pytest.fixture
def ipv6_loopback():
    """A listening socket on ::1 alone, or a skip on a host without one."""
    server = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        server.bind(("::1", 0))
    except OSError as error:  # no IPv6 loopback on this host
        server.close()
        pytest.skip(f"no IPv6 loopback: {error}")
    server.listen(1)
    try:
        yield server.getsockname()[1]
    finally:
        server.close()


def test_the_agent_probe_finds_a_wildcard_agent_on_the_ipv6_loopback(monkeypatch, ipv6_loopback):
    """asyncio's server sets IPV6_V6ONLY, so an agent bound to "::" refuses
    on 127.0.0.1 and accepts on ::1 alone. A probe that asked only the IPv4
    loopback would call it stopped and purge behind a running agent."""
    monkeypatch.setattr(settings, "SUPERVISOR_HOST", "::")
    monkeypatch.setattr(settings, "SUPERVISOR_PORT", ipv6_loopback)

    probe = REAL_PROBE_AGENT()

    assert probe.reach is cli.AgentReach.RUNNING
    assert "[::1]" in probe.detail


def test_a_wildcard_bind_is_stopped_only_when_every_loopback_refuses(monkeypatch):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bound:
        bound.bind(("127.0.0.1", 0))
        port = bound.getsockname()[1]
    monkeypatch.setattr(settings, "SUPERVISOR_HOST", "0.0.0.0")  # noqa: S104
    monkeypatch.setattr(settings, "SUPERVISOR_PORT", port)

    probe = REAL_PROBE_AGENT()

    assert probe.reach is cli.AgentReach.STOPPED
    assert "127.0.0.1" in probe.detail and "::1" in probe.detail


def test_the_agent_probe_reads_a_refused_port_as_stopped(monkeypatch):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as bound:
        bound.bind(("127.0.0.1", 0))
        port = bound.getsockname()[1]
    monkeypatch.setattr(settings, "SUPERVISOR_HOST", "127.0.0.1")
    monkeypatch.setattr(settings, "SUPERVISOR_PORT", port)

    probe = REAL_PROBE_AGENT()

    assert probe.reach is cli.AgentReach.STOPPED
    assert not probe.may_be_running


def test_an_agent_probe_that_cannot_answer_counts_as_running(monkeypatch):
    """Fail closed: being wrong the other way purges the disks of a VM the
    agent is at that moment creating."""

    def denied(*_args, **_kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(socket, "create_connection", denied)

    probe = REAL_PROBE_AGENT()

    assert probe.reach is cli.AgentReach.UNKNOWN
    assert probe.may_be_running
    assert "PermissionError" in probe.detail


def test_a_missing_file_that_is_not_the_socket_is_no_proof_the_daemon_is_down(pools, registry, monkeypatch, tmp_path):  # noqa: F811, ARG001
    """The gRPC client opens more than its socket. A FileNotFoundError from
    somewhere else in the dial must not end in the advice to purge on the
    registry alone while the daemon is answering on a socket that is there."""
    path = tmp_path / "sup.sock"
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(path))
    server.listen(1)
    monkeypatch.setattr(settings, "SUPERVISOR_GRPC_SOCKET", path)
    missing = FileNotFoundError(2, "No such file or directory: '/etc/aleph-vm/credentials'")
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(error=missing))
    try:
        code, _out, err = _run(["reconcile"], registry)
    finally:
        server.close()

    assert code == cli.DEGRADED_EXIT_CODE
    assert "FileNotFoundError" in err
    assert "--trust-registry" not in err


def test_a_socket_that_accepts_is_never_read_as_a_stopped_daemon(tmp_path):
    """The fallback classification, on its own: a daemon that is listening
    but would not answer must never end in the advice to purge without it."""
    path = tmp_path / "sup.sock"
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(path))
        server.listen(1)

        assert cli._socket_reach(path) is not cli.SupervisorReach.DOWN


def test_a_missing_socket_is_read_as_a_stopped_daemon(tmp_path):
    assert cli._socket_reach(tmp_path / "nothing.sock") is cli.SupervisorReach.DOWN


def test_an_unset_socket_path_says_nothing_about_the_daemon():
    assert cli._socket_reach(None) is cli.SupervisorReach.UNKNOWN


def test_a_refusal_behind_a_permission_error_is_still_proof_of_down():
    """The chain is walked front to back; a PermissionError closer to the
    head must not hide a ConnectionRefusedError deeper in the same chain."""
    refused = ConnectionRefusedError(111, "Connection refused")
    denied = PermissionError(13, "Permission denied")
    denied.__cause__ = refused

    assert cli._reach_from_failure(denied) is cli.SupervisorReach.DOWN


def test_a_refused_socket_is_reported_as_a_stopped_daemon(pools, registry, monkeypatch):  # noqa: F811
    refused = ConnectionRefusedError(111, "Connection refused")
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(error=refused))

    code, _out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert "unreachable" in err and "ConnectionRefusedError" in err
    assert "--trust-registry" in err


def test_reconcile_trust_registry_purges_when_supervisor_unreachable(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out, err = _run(["reconcile", "--trust-registry"], registry)

    assert code == 0 and not orphan.exists()

    # --dry-run still wins even with --trust-registry.
    other = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    os.utime(other.parent, (time.time() - 10_000, time.time() - 10_000))
    code, out, err = _run(["reconcile", "--dry-run", "--trust-registry"], registry)
    assert code == 0 and "Dry run" in out
    assert other.exists()


def test_reconcile_passes_live_known_false_when_supervisor_unreachable(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))
    fake_report = reconciler_module.ReconcileReport()
    spy = MagicMock(return_value=fake_report)
    monkeypatch.setattr(cli, "reconcile_storage", spy)

    code, out, err = _run(["reconcile", "--trust-registry"], registry)

    assert code == 0
    assert spy.call_args.kwargs["live_known"] is False


def test_reconcile_passes_live_known_true_when_supervisor_reachable(pools, registry, monkeypatch):  # noqa: F811
    # The autouse fixtures already install a reachable fake supervisor and a
    # stopped agent.
    fake_report = reconciler_module.ReconcileReport()
    spy = MagicMock(return_value=fake_report)
    monkeypatch.setattr(cli, "reconcile_storage", spy)

    code, out, err = _run(["reconcile"], registry)

    assert code == 0
    assert spy.call_args.kwargs["live_known"] is True


def test_reconcile_tears_down_devices_of_evicted_cache_parents(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)
    removed: list[str] = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    code, out, err = _run(["reconcile"], registry)

    assert code == 0
    assert not stale.exists()
    assert removed == ["stale"]


def test_reconcile_touches_no_cache_entry_while_the_agent_is_running(pools, registry, monkeypatch):  # noqa: F811
    """The cache pass runs inside the pass a live agent refuses."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    monkeypatch.setattr(cli, "_probe_agent", _agent_up())
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)
    removed: list[str] = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    code, out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert stale.exists()
    assert removed == []


def test_reconcile_dry_run_never_touches_cache_parent_devices(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)
    removed: list[str] = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    code, out, err = _run(["reconcile", "--dry-run"], registry)

    assert code == 0
    assert stale.exists()
    assert removed == []


def test_cli_main_dispatches_storage_subcommand(mocker):
    run_parsed = mocker.patch("aleph.vm.agent.storage_cli.run_parsed", return_value=7)
    mocker.patch("sys.argv", ["aleph-vm", "-vv", "storage", "status"])
    with pytest.raises(SystemExit) as exit_info:
        agent_cli.main()
    assert exit_info.value.code == 7
    args = run_parsed.call_args.args[0]
    assert args.command == "storage"
    assert args.storage_command == "status"
    # A global flag placed before the verb reaches the storage command.
    assert args.loglevel == logging.DEBUG


def test_reconcile_tears_down_the_devices_of_an_orphan_namespace(pools, registry, monkeypatch, tmp_path):  # noqa: F811
    """Same parity as the cache devices: without this the CLI keeps refusing
    the dm-held directories the agent's own pass reclaims. The live set is a
    known one here (the agent is down, the supervisor answered), which is
    what makes a teardown safe."""
    _fake_mapper(monkeypatch, tmp_path, f"{VM_HASH}_rootfs", f"{LIVE}_rootfs")
    torn: list[str] = []
    monkeypatch.setattr(reconciler_module, "teardown_namespace_devices", AsyncMock(side_effect=torn.append))

    code, _out, err = _run(["reconcile"], registry)

    assert code == 0
    assert torn == [VM_HASH]


def test_no_device_is_torn_down_while_the_agent_is_running(pools, registry, monkeypatch, tmp_path):  # noqa: F811
    _fake_mapper(monkeypatch, tmp_path, f"{VM_HASH}_rootfs")
    monkeypatch.setattr(cli, "_probe_agent", _agent_up())
    torn: list[str] = []
    monkeypatch.setattr(reconciler_module, "teardown_namespace_devices", AsyncMock(side_effect=torn.append))

    code, _out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert torn == []


def test_reconcile_dry_run_never_touches_orphan_devices(pools, registry, monkeypatch, tmp_path):  # noqa: F811
    _fake_mapper(monkeypatch, tmp_path, f"{VM_HASH}_rootfs")
    torn: list[str] = []
    monkeypatch.setattr(reconciler_module, "teardown_namespace_devices", AsyncMock(side_effect=torn.append))

    code, _out, err = _run(["reconcile", "--dry-run"], registry)

    assert code == 0
    assert torn == []


def test_reconcile_leaves_orphan_devices_when_the_supervisor_is_unreachable(pools, registry, monkeypatch, tmp_path):  # noqa: F811
    """--trust-registry buys a purge on the registry's word, not a teardown:
    a VM the registry has forgotten but the daemon still runs would lose its
    disk with its device."""
    _fake_mapper(monkeypatch, tmp_path, f"{VM_HASH}_rootfs")
    torn: list[str] = []
    monkeypatch.setattr(reconciler_module, "teardown_namespace_devices", AsyncMock(side_effect=torn.append))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, _out, err = _run(["reconcile", "--trust-registry"], registry)

    assert code == 0
    assert torn == []


def test_a_degraded_reconcile_leaves_orphan_devices_too(pools, registry, monkeypatch, tmp_path):  # noqa: F811
    """Without --trust-registry an unreachable supervisor downgrades the pass
    to a dry run, and a dry run tears nothing down: the device skip holds on
    both counts, not only through the --trust-registry branch."""
    _fake_mapper(monkeypatch, tmp_path, f"{VM_HASH}_rootfs")
    torn: list[str] = []
    monkeypatch.setattr(reconciler_module, "teardown_namespace_devices", AsyncMock(side_effect=torn.append))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, _out, err = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert torn == []


# --- process-level plumbing: env file, logging, database migrations ---------


@pytest.fixture(autouse=True)
def _restore_root_logger():
    """``main()`` configures the root logger, and pytest's own logging plugin
    lives on that same logger: put back what was there when the test ends."""
    root = logging.getLogger()
    handlers = list(root.handlers)
    level = root.level
    yield
    root.handlers[:] = handlers
    root.setLevel(level)


@pytest.fixture
def isolated_environ(monkeypatch):
    """A private copy of ``os.environ``: loading an environment file writes
    into it, and a leak would change the settings of every later test."""
    environ = dict(os.environ)
    monkeypatch.setattr(os, "environ", environ)
    return environ


@pytest.fixture
def plumbing(tmp_path, monkeypatch, registry):
    """Drive ``main()`` end to end with the parts a test cannot provide
    stubbed out: the pool setup the ``pools`` fixture already did by hand,
    and the registry the agent DB would rehydrate. Returns the database path
    the CLI will find, already present so the missing-DB refusal stays out of
    the way of the tests that are about something else."""
    monkeypatch.setattr(cli, "DEFAULT_ENV_FILE", tmp_path / "no-such-file.env")
    monkeypatch.setattr(type(settings), "setup", lambda _self: None)
    monkeypatch.setattr(storage_pools, "setup_pools", lambda **_: None)
    monkeypatch.setattr(cli, "initialise_database", lambda: None)
    monkeypatch.setattr(cli, "_load_registry", AsyncMock(return_value=registry))
    database = tmp_path / "executions.sqlite3"
    database.touch()
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", database)
    # An env file the CLI loads rebuilds every field of the settings
    # singleton, not only the ones a test monkeypatched, so the whole
    # namespace is put back rather than trusting the two patches to cover it.
    snapshot = dict(settings.__dict__)
    yield database
    settings.__dict__.clear()
    settings.__dict__.update(snapshot)


def test_the_env_file_reaches_the_settings(tmp_path, monkeypatch, isolated_environ, plumbing):
    """Only the systemd units inject /etc/aleph-vm/supervisor.env. Without
    reading it here, a hand-run pass on a node configured to keep retained
    volumes runs with the reap default and evicts every retained directory."""
    env_file = tmp_path / "supervisor.env"
    env_file.write_text(f"ALEPH_VM_VOLUME_RETENTION=keep\nALEPH_VM_EXECUTION_DATABASE={plumbing}\n")
    isolated_environ.pop("ALEPH_VM_VOLUME_RETENTION", None)
    # This test's assertion is what the loaded file set, not what the
    # process environment happened to already hold.
    isolated_environ.pop("ALEPH_VM_EXECUTION_DATABASE", None)
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    seen: list[str] = []

    def record_retention(*_args: object) -> int:
        seen.append(settings.VOLUME_RETENTION)
        return 0

    monkeypatch.setattr(cli, "run", record_retention)

    code = cli.main(["--env-file", str(env_file), "status"])

    assert code == 0
    assert seen == ["keep"]


def test_a_named_env_file_that_is_missing_is_an_error(tmp_path, monkeypatch, plumbing, capsys):
    """Silently ignoring the file the operator named would run the command
    with exactly the defaults they were trying to override."""
    monkeypatch.setattr(cli, "run", lambda *_: 0)

    code = cli.main(["--env-file", str(tmp_path / "typo.env"), "status"])

    assert code == 1
    assert "typo.env" in capsys.readouterr().err


def test_an_env_file_named_by_the_environment_variable_that_is_missing_is_an_error(
    tmp_path, monkeypatch, isolated_environ, plumbing, capsys
):
    """$ALEPH_VM_ENV_FILE is just as explicit as --env-file: a typo there
    used to fall through to the built-in defaults with only an INFO line,
    exactly the hazard the fail-closed --env-file behaviour exists for."""
    monkeypatch.setattr(cli, "run", lambda *_: 0)
    isolated_environ[cli.ENV_FILE_VARIABLE] = str(tmp_path / "typo.env")

    code = cli.main(["status"])

    assert code == 1
    assert "typo.env" in capsys.readouterr().err


def test_an_invalid_value_in_the_env_file_is_a_clean_usage_error(
    tmp_path, monkeypatch, isolated_environ, plumbing, capsys
):
    """A typo'd value in the node's env file used to surface as a raw
    pydantic ValidationError traceback; the operator should see which field
    is wrong instead."""
    env_file = tmp_path / "supervisor.env"
    env_file.write_text("ALEPH_VM_VOLUME_RETENTION=sometimes\n")
    isolated_environ.pop("ALEPH_VM_VOLUME_RETENTION", None)
    monkeypatch.setattr(cli, "run", lambda *_: 0)

    code = cli.main(["--env-file", str(env_file), "status"])

    assert code == 2
    assert "VOLUME_RETENTION" in capsys.readouterr().err


def test_status_refuses_a_missing_database_without_creating_one(tmp_path, monkeypatch, plumbing, capsys):
    """A read-only command must not bring an agent DB into existence: an
    operator who mistyped EXECUTION_ROOT has to see a refusal, not an empty
    listing backed by a file this process just made."""
    database = tmp_path / "gone.sqlite3"
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", database)
    initialised: list[str] = []
    monkeypatch.setattr(cli, "initialise_database", lambda: initialised.append("yes"))

    code = cli.main(["status"])

    assert code == 1
    assert not database.exists()
    assert initialised == []
    assert str(database) in capsys.readouterr().err


def test_the_database_is_migrated_before_the_registry_is_read(monkeypatch, plumbing, registry):
    order: list[str] = []
    monkeypatch.setattr(cli, "initialise_database", lambda: order.append("migrate"))

    async def load() -> AgentVmRegistry:
        order.append("load")
        return registry

    monkeypatch.setattr(cli, "_load_registry", load)
    monkeypatch.setattr(cli, "run", lambda *_: 0)

    assert cli.main(["status"]) == 0
    assert order == ["migrate", "load"]


def test_an_unmigrated_database_is_brought_up_to_date(pools, tmp_path, monkeypatch):  # noqa: F811
    """An empty sqlite file (a fresh install, or a DB predating a migration)
    used to reach rehydrate_registry with no ``executions`` table and crash
    with a raw OperationalError. This runs the real migrations."""
    database = tmp_path / "executions.sqlite3"
    database.touch()
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", database)
    monkeypatch.setattr(cli, "DEFAULT_ENV_FILE", tmp_path / "no-such-file.env")
    monkeypatch.setattr(type(settings), "setup", lambda _self: None)
    monkeypatch.setattr(storage_pools, "setup_pools", lambda **_: None)

    assert cli.main(["list"]) == 0


def test_reconcile_reports_its_purges_on_stderr(pools, monkeypatch, plumbing, capsys):  # noqa: F811
    """The purge logs what it removed; with no handler configured those INFO
    lines went nowhere and an operator watching a purge saw nothing."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))

    code = cli.main(["reconcile"])

    assert code == 0
    assert not orphan.exists()
    assert "Deleted volume" in capsys.readouterr().err


def test_global_flags_before_the_verb_parse():
    """`aleph-vm --loglevel DEBUG storage status` used to be a usage error:
    the dispatch sniffed sys.argv[1] before the agent parser ran."""
    args = agent_cli.parse_args(["--loglevel", "debug", "storage", "list", "--reclaimable"])

    assert args.command == "storage"
    assert args.storage_command == "list"
    assert args.reclaimable
    # The subparser must not clobber the level the parent flag set.
    assert args.loglevel == "DEBUG"


def test_the_storage_subparser_keeps_its_own_loglevel_flag():
    args = cli.parse_args(["--loglevel", "warning", "status"])

    assert args.storage_command == "status"
    assert args.loglevel == "WARNING"


def test_an_unknown_loglevel_is_a_usage_error_not_a_traceback(capsys):
    """`--loglevel verbos` used to reach logging.Logger.setLevel and die with
    a raw ValueError traceback instead of a clean argparse usage error."""
    with pytest.raises(SystemExit) as exit_info:
        cli.parse_args(["--loglevel", "verbos", "status"])

    assert exit_info.value.code == 2
    assert "--loglevel" in capsys.readouterr().err


def test_the_agent_level_loglevel_is_validated_the_same_way(capsys):
    """The flag exists on the agent parser too, ahead of the subcommand, and
    `aleph-vm --loglevel verbos storage status` reached the same setLevel
    traceback after the storage parser's own flag had been fixed."""
    with pytest.raises(SystemExit) as exit_info:
        agent_cli.parse_args(["--loglevel", "verbos", "storage", "status"])

    assert exit_info.value.code == 2
    assert "--loglevel" in capsys.readouterr().err


def test_a_write_verb_creates_a_missing_database(pools, tmp_path, monkeypatch, caplog):  # noqa: F811
    """status and list refuse a missing database; reconcile creates it, since
    a fresh node has no file at all and the pass has to record what it
    does. This runs the real table creation and migrations."""
    database = tmp_path / "executions.sqlite3"
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", database)
    monkeypatch.setattr(cli, "DEFAULT_ENV_FILE", tmp_path / "no-such-file.env")
    monkeypatch.setattr(type(settings), "setup", lambda _self: None)
    monkeypatch.setattr(storage_pools, "setup_pools", lambda: None)

    with caplog.at_level(logging.INFO, logger=cli.logger.name):
        assert cli.main(["reconcile", "--dry-run"]) == 0

    assert database.exists()
    assert any("Creating the agent database" in record.message for record in caplog.records)


def _corrupt_marker(pool: Path, namespace: str) -> Path:
    volume(pool, namespace, "rootfs.qcow2")
    marker = pool / namespace / ".reclaimable"
    marker.write_text("{not json")
    return marker


def test_list_keeps_a_corrupt_marker_and_lists_the_other_rows(pools, registry):  # noqa: F811
    """status and list are documented read-only. Reading a marker that does
    not parse used to unlink it, which is a write on a listing, and one an
    operator running without the agent's privileges cannot even make: the
    PermissionError aborted the whole command."""
    corrupt = _corrupt_marker(pools["pool0"], OTHER_HASH)
    volume(pools["pool1"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    code, out, _err = _run(["list"], registry)

    assert code == 0
    rows = {line.split("\t")[0]: line.split("\t")[3] for line in out.splitlines()[1:]}
    assert rows == {VM_HASH: "gone", OTHER_HASH: "unmarked"}
    assert corrupt.exists(), "a read-only listing must not remove anything"


def test_status_keeps_a_corrupt_marker(pools, registry):  # noqa: F811
    """The reclaimable byte sum walks every marker too, so status removed
    the file just as list did."""
    corrupt = _corrupt_marker(pools["pool0"], OTHER_HASH)

    code, _out, _err = _run(["status"], registry)

    assert code == 0
    assert corrupt.exists()


def test_a_marker_without_an_offset_shows_an_age(pools, registry):  # noqa: F811
    """A hand-edited marker whose timestamp carries no offset parsed naive,
    and subtracting it from the aware clock raised TypeError, which aborted
    the whole listing instead of costing that one row its age."""
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    naive = (datetime.now(tz=timezone.utc) - timedelta(days=3)).replace(tzinfo=None)
    (pools["pool0"] / VM_HASH / ".reclaimable").write_text(
        json.dumps(
            {
                "version": 1,
                "reclaimable_since": naive.isoformat(),
                "reason": "gone",
                "size_bytes": 1,
                "depends_on": [],
            }
        )
    )

    code, out, _err = _run(["list"], registry)

    assert code == 0
    age = [line.split("\t")[4] for line in out.splitlines()[1:] if line.startswith(VM_HASH)]
    assert age == ["3d 0h"]


def test_a_future_dated_marker_never_shows_a_negative_age(pools, registry):  # noqa: F811
    """A node whose clock ran backwards, or a marker copied from elsewhere:
    an age of "-1d 23h" reads as a parsing bug to whoever sees it."""
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=datetime.now(tz=timezone.utc) + timedelta(days=2))

    code, out, _err = _run(["list"], registry)

    assert code == 0
    age = [line.split("\t")[4] for line in out.splitlines()[1:] if line.startswith(VM_HASH)]
    assert age == ["0d 0h"]


def test_reclaim_names_the_error_that_kept_a_directory(pools, registry, monkeypatch):  # noqa: F811
    """The purge leaves a directory behind on any failure to remove it (a
    read-only filesystem, an immutable file, a directory this user may not
    write), not only on a device-mapper hold. Sending the operator to
    'storage reconcile' for those is advice that cannot work."""
    import errno
    import shutil as shutil_module

    import aleph.vm.agent.vm.purge as purge_module

    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    volume(pools["pool1"], VM_HASH, "data.ext4")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    real_rmtree = shutil_module.rmtree

    def refuse(path, *args, **kwargs):
        if Path(path).parent == pools["pool0"]:
            raise OSError(errno.EROFS, "Read-only file system")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(purge_module.shutil, "rmtree", refuse)

    code, out, err = _run(["reclaim", VM_HASH], registry)

    assert code == 1
    assert out == "", "a purge that did not finish leaves stdout empty"
    assert "Read-only file system" in err
    assert "No device-mapper target is holding these" in err
    assert "storage reconcile" not in err, "a teardown cannot fix a removal that failed"
    assert re.search(r"Deleted \d+ volume file\(s\)", err), "the partial count belongs in the report"


def test_status_adopts_no_pool_and_writes_no_pool_file(pools, tmp_path, monkeypatch, registry):  # noqa: F811
    """A read-only verb ran the agent's own pool setup, which adopts a pool
    on first sight: it writes the in-pool marker and the adoption registry.
    On a node whose second disk is not mounted, that adoption is exactly the
    write the guard exists to prevent."""
    monkeypatch.setattr(settings, "VOLUME_POOLS", [f"{pools['pool1']}=ssd"])
    monkeypatch.setattr(cli, "DEFAULT_ENV_FILE", tmp_path / "no-such-file.env")
    monkeypatch.setattr(cli, "initialise_database", lambda: None)
    monkeypatch.setattr(cli, "_load_registry", AsyncMock(return_value=registry))
    database = pools["execution_root"] / "executions.sqlite3"
    database.touch()
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", database)

    assert cli.main(["status"]) == 0

    assert not (pools["pool1"] / ".aleph-vm-pool").exists()
    assert not (pools["execution_root"] / "volume-pools.json").exists()


def test_status_creates_no_directory_before_refusing_a_missing_database(tmp_path, monkeypatch, capsys):
    """The refusal came after settings.setup(), which makes every configured
    directory. An operator who mistyped the execution root got the refusal
    and a tree of empty directories at the typo."""
    execution_root = tmp_path / "typo"
    monkeypatch.setattr(settings, "EXECUTION_ROOT", execution_root)
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", execution_root / "volumes" / "persistent")
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", execution_root / "executions.sqlite3")
    monkeypatch.setattr(cli, "DEFAULT_ENV_FILE", tmp_path / "no-such-file.env")

    code = cli.main(["status"])

    assert code == 1
    assert not execution_root.exists(), "nothing may be created under the root it refused"
    assert str(execution_root / "executions.sqlite3") in capsys.readouterr().err


def test_the_env_file_is_not_interpolated(tmp_path, monkeypatch, isolated_environ, plumbing):
    """systemd's EnvironmentFile= does no ${} expansion, so a node's file is
    written with literal values. Expanding them here silently truncates any
    secret containing a dollar sign to the empty string."""
    env_file = tmp_path / "supervisor.env"
    env_file.write_text(
        f"ALEPH_VM_EXECUTION_DATABASE={plumbing}\nALEPH_VM_SENTRY_DSN=https://key:pa${{sswd}}@sentry.example/1\n"
    )
    isolated_environ["sswd"] = "leaked"
    monkeypatch.setattr(cli, "run", lambda *_: 0)

    assert cli.main(["--env-file", str(env_file), "status"]) == 0

    assert isolated_environ["ALEPH_VM_SENTRY_DSN"] == "https://key:pa${sswd}@sentry.example/1"


def test_the_env_file_path_prefers_the_flag_then_the_variable_then_the_default(monkeypatch, tmp_path):
    """The second element says whether the path was named (by --env-file or
    $ALEPH_VM_ENV_FILE) rather than defaulted to: both namings are equally
    explicit operator intent, so a missing file is a refusal either way."""
    monkeypatch.setattr(cli, "DEFAULT_ENV_FILE", tmp_path / "packaged.env")
    monkeypatch.delenv(cli.ENV_FILE_VARIABLE, raising=False)

    assert cli._env_file_path(None) == (tmp_path / "packaged.env", False)

    monkeypatch.setenv(cli.ENV_FILE_VARIABLE, str(tmp_path / "from-variable.env"))
    assert cli._env_file_path(None) == (tmp_path / "from-variable.env", True)
    assert cli._env_file_path(str(tmp_path / "explicit.env")) == (tmp_path / "explicit.env", True)
