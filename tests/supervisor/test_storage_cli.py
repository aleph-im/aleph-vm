from __future__ import annotations

import io
import logging
import os
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
    mark_reclaimable,
    write_marker,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings

LIVE = "dead" * 16
NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)


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


def _fake_supervisor(*vm_ids: str, fails: bool = False):
    """A supervisor handle that lists ``vm_ids``, or cannot be asked at all
    (an unreachable daemon: a connection error, a timeout, any of it)."""
    if fails:
        return SimpleNamespace(list_vms=AsyncMock(side_effect=RuntimeError("no answer")))
    return SimpleNamespace(list_vms=AsyncMock(return_value=[SimpleNamespace(vm_id=vm_id) for vm_id in vm_ids]))


@pytest.fixture(autouse=True)
def _supervisor_reachable(monkeypatch):
    """By default the supervisor is reachable and lists nothing running: the
    tests that care about a different answer override ``_open_supervisor``
    themselves."""
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor())


def _run(argv: list[str], registry) -> tuple[int, str]:
    out = io.StringIO()
    code = cli.run(cli.parse_args(argv), registry, out)
    return code, out.getvalue()


def test_status_lists_pools_and_caches(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    volume(pools["pool0"], LIVE, "rootfs.qcow2", size=4096)
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    code, out = _run(["status"], registry)

    assert code == 0
    assert "POOL" in out and str(pools["pool0"]) in out and str(pools["pool1"]) in out
    assert "CACHE" in out and str(pools["runtime"]) in out


def test_list_shows_every_vm_dir_and_reclaimable_filters(pools, registry):  # noqa: F811
    volume(pools["pool0"], LIVE, "rootfs.qcow2")
    volume(pools["pool1"], VM_HASH, "rootfs.qcow2")
    volume(pools["pool1"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "orphan", now=NOW - timedelta(days=3))

    code, out = _run(["list"], registry)
    assert code == 0
    rows = {line.split("\t")[0]: line.split("\t")[3] for line in out.splitlines()[1:]}
    # An unmarked directory is "live" only on the registry's word; an
    # unmarked orphan no pass has reached yet must not read as a live VM.
    assert rows == {LIVE: "live", VM_HASH: "orphan", OTHER_HASH: "unmarked"}

    code, out = _run(["list", "--reclaimable"], registry)
    assert LIVE not in out and VM_HASH in out and "orphan" in out


def test_reclaim_purges_a_reclaimable_dir_only(pools, registry):  # noqa: F811
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    unmarked = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    code, out = _run(["reclaim", VM_HASH], registry)
    assert code == 0 and "Purged" in out
    assert not gone.exists()

    # OTHER_HASH is on disk, unmarked, unknown to the registry and to the
    # (fake, reachable) supervisor: reclaim refuses it for lack of a marker,
    # not because anything claims to own it.
    code, out = _run(["reclaim", OTHER_HASH], registry)
    assert code == 1 and "not reclaimable" in out
    assert unmarked.exists()


def test_reclaim_checks_the_marker_before_dialing_the_supervisor(pools, registry, monkeypatch):  # noqa: F811, ARG001
    """A typo'd or unrelated hash is refused by the purely local marker check
    alone: nothing here should wait out a supervisor dial first."""
    dialed = []

    def open_supervisor():
        dialed.append(True)
        return _fake_supervisor()

    monkeypatch.setattr(cli, "_open_supervisor", open_supervisor)

    code, out = _run(["reclaim", "not-a-real-hash"], registry)
    assert code == 1 and "not a VM hash" in out

    code, out = _run(["reclaim", "f" * 64], registry)
    assert code == 1 and "not reclaimable" in out

    assert dialed == []


def test_reclaim_refuses_a_marked_directory_not_named_after_a_vm(pools, registry):  # noqa: F811
    """A hand-made marker under a directory nobody named after a VM: the
    daemon's walk drops such names, and reclaim must refuse them cleanly
    rather than trip over purge_vm_storage's own hash guard."""
    kept = volume(pools["pool0"], "backup_old", "rootfs.qcow2")
    write_marker(kept.parent, ReclaimableMarker(reclaimable_since=NOW, reason="gone", size_bytes=0))

    code, out = _run(["reclaim", "backup_old"], registry)

    assert code == 1 and "not a VM hash" in out
    assert kept.exists()


def test_reclaim_refuses_an_unmarked_live_directory(pools, registry):  # noqa: F811
    """A live VM's directory ordinarily carries no marker, so the marker
    check alone already refuses it."""
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")

    code, out = _run(["reclaim", LIVE], registry)

    assert code == 1 and "not reclaimable" in out
    assert live.exists()


def test_reclaim_refuses_a_marked_but_still_live_registry_hash(pools, registry):  # noqa: F811
    """A stale marker on a directory the registry still calls live (not yet
    cleared by a reconcile pass): the registry check catches it once the
    marker check has passed."""
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")
    mark_reclaimable(LIVE, "orphan", now=NOW)

    code, out = _run(["reclaim", LIVE], registry)

    assert code == 1 and "live VM in the agent registry" in out
    assert live.exists()


def test_reclaim_refuses_a_hash_the_supervisor_lists_as_running(pools, registry, monkeypatch):  # noqa: F811
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(VM_HASH))

    code, out = _run(["reclaim", VM_HASH], registry)

    assert code == 1 and "running" in out
    assert gone.exists()


def test_reclaim_refuses_unless_trust_registry_when_supervisor_unreachable(pools, registry, monkeypatch):  # noqa: F811
    gone = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out = _run(["reclaim", VM_HASH], registry)
    assert code == 1 and "unreachable" in out
    assert gone.exists()

    code, out = _run(["reclaim", "--trust-registry", VM_HASH], registry)
    assert code == 0 and "Purged" in out
    assert not gone.exists()


def test_reclaim_refuses_when_the_purge_leaves_a_dm_held_directory(pools, registry, monkeypatch):  # noqa: F811
    held = volume(pools["pool0"], VM_HASH, "data.btrfs")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    dm_path = Path("/dev/mapper") / f"{VM_HASH}_data"
    real_is_block_device = Path.is_block_device
    monkeypatch.setattr(Path, "is_block_device", lambda self: self == dm_path or real_is_block_device(self))

    code, out = _run(["reclaim", VM_HASH], registry)

    assert code == 1
    assert "device-mapper" in out
    assert held.exists()


def test_reconcile_dry_run_reports_without_changing(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))

    code, out = _run(["reconcile", "--dry-run"], registry)

    assert code == 0 and "Dry run" in out and "purged=1" in out
    assert orphan.exists()

    # The fake supervisor (installed by the autouse fixture) is reachable and
    # lists nothing running, so a real pass is allowed to purge.
    code, out = _run(["reconcile"], registry)
    assert code == 0 and not orphan.exists()


def test_reconcile_leaves_a_supervisor_known_vm_the_registry_does_not(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    unknown = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(unknown.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(OTHER_HASH))

    code, out = _run(["reconcile"], registry)

    assert code == 0
    assert unknown.exists()


def test_reconcile_unreachable_exits_nonzero_and_warns_on_stderr(pools, registry, monkeypatch, capsys):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out = _run(["reconcile"], registry)

    assert code == cli.DEGRADED_EXIT_CODE
    assert "Dry run" in out
    assert "unreachable" not in out  # the warning must not land in the parseable report
    err = capsys.readouterr().err
    assert "unreachable" in err and "registry-only" in err
    assert orphan.exists()


def test_reconcile_explicit_dry_run_stays_exit_zero_when_unreachable(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out = _run(["reconcile", "--dry-run"], registry)

    assert code == 0
    assert "Dry run" in out
    assert orphan.exists()


def test_reconcile_trust_registry_purges_when_supervisor_unreachable(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    orphan = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    stamp = time.time() - 10_000
    os.utime(orphan.parent, (stamp, stamp))
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))

    code, out = _run(["reconcile", "--trust-registry"], registry)

    assert code == 0 and not orphan.exists()

    # --dry-run still wins even with --trust-registry.
    other = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    os.utime(other.parent, (time.time() - 10_000, time.time() - 10_000))
    code, out = _run(["reconcile", "--dry-run", "--trust-registry"], registry)
    assert code == 0 and "Dry run" in out
    assert other.exists()


def test_reconcile_passes_live_known_false_when_supervisor_unreachable(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(cli, "_open_supervisor", lambda: _fake_supervisor(fails=True))
    fake_report = reconciler_module.ReconcileReport()
    spy = MagicMock(return_value=fake_report)
    monkeypatch.setattr(cli, "reconcile_storage", spy)

    code, out = _run(["reconcile", "--trust-registry"], registry)

    assert code == 0
    assert spy.call_args.kwargs["live_known"] is False


def test_reconcile_passes_live_known_true_when_supervisor_reachable(pools, registry, monkeypatch):  # noqa: F811
    # The autouse fixture already installs a reachable fake supervisor.
    fake_report = reconciler_module.ReconcileReport()
    spy = MagicMock(return_value=fake_report)
    monkeypatch.setattr(cli, "reconcile_storage", spy)

    code, out = _run(["reconcile"], registry)

    assert code == 0
    assert spy.call_args.kwargs["live_known"] is True


def test_reconcile_tears_down_devices_of_evicted_cache_parents(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)
    removed: list[str] = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    code, out = _run(["reconcile"], registry)

    assert code == 0
    assert not stale.exists()
    assert removed == ["stale"]


def test_reconcile_dry_run_never_touches_cache_parent_devices(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)
    removed: list[str] = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    code, out = _run(["reconcile", "--dry-run"], registry)

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
    the dm-held directories the daemon's own pass now reclaims."""
    _fake_mapper(monkeypatch, tmp_path, f"{VM_HASH}_rootfs", f"{LIVE}_rootfs")
    torn: list[str] = []
    monkeypatch.setattr(reconciler_module, "teardown_namespace_devices", AsyncMock(side_effect=torn.append))

    code, _out = _run(["reconcile"], registry)

    assert code == 0
    assert torn == [VM_HASH]


def test_reconcile_dry_run_never_touches_orphan_devices(pools, registry, monkeypatch, tmp_path):  # noqa: F811
    _fake_mapper(monkeypatch, tmp_path, f"{VM_HASH}_rootfs")
    torn: list[str] = []
    monkeypatch.setattr(reconciler_module, "teardown_namespace_devices", AsyncMock(side_effect=torn.append))

    code, _out = _run(["reconcile", "--dry-run"], registry)

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

    code, _out = _run(["reconcile", "--trust-registry"], registry)

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

    code, _out = _run(["reconcile"], registry)

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
    monkeypatch.setattr(storage_pools, "setup_pools", lambda: None)
    monkeypatch.setattr(cli, "initialise_database", lambda: None)
    monkeypatch.setattr(cli, "_load_registry", AsyncMock(return_value=registry))
    database = tmp_path / "executions.sqlite3"
    database.touch()
    monkeypatch.setattr(settings, "EXECUTION_DATABASE", database)
    return database


def test_the_env_file_reaches_the_settings(tmp_path, monkeypatch, isolated_environ, plumbing):
    """Only the systemd units inject /etc/aleph-vm/supervisor.env. Without
    reading it here, a hand-run pass on a node configured to keep retained
    volumes runs with the reap default and evicts every retained directory."""
    env_file = tmp_path / "supervisor.env"
    env_file.write_text(f"ALEPH_VM_VOLUME_RETENTION=keep\nALEPH_VM_EXECUTION_DATABASE={plumbing}\n")
    isolated_environ.pop("ALEPH_VM_VOLUME_RETENTION", None)
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
    monkeypatch.setattr(storage_pools, "setup_pools", lambda: None)

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
