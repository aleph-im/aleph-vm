from __future__ import annotations

import io
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

import aleph.vm.agent.storage_cli as cli
import aleph.vm.agent.vm.reconciler as reconciler_module
from aleph.vm.agent.vm.reclaimable import mark_reclaimable
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
    mark_reclaimable(VM_HASH, "orphan", now=NOW - timedelta(days=3))

    code, out = _run(["list"], registry)
    assert code == 0
    assert LIVE in out and VM_HASH in out

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
    monkeypatch.setattr(cli, "_open_supervisor", lambda: dialed.append(True) or _fake_supervisor())

    code, out = _run(["reclaim", "not-a-real-hash"], registry)

    assert code == 1 and "not reclaimable" in out
    assert dialed == []


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
    removed = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    code, out = _run(["reconcile"], registry)

    assert code == 0
    assert not stale.exists()
    assert removed == ["stale"]


def test_reconcile_dry_run_never_touches_cache_parent_devices(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)
    removed = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    code, out = _run(["reconcile", "--dry-run"], registry)

    assert code == 0
    assert stale.exists()
    assert removed == []


def test_cli_main_dispatches_storage_subcommand(mocker):
    from aleph.vm.agent import cli as agent_cli

    storage_main = mocker.patch("aleph.vm.agent.storage_cli.main", return_value=7)
    mocker.patch("sys.argv", ["aleph-vm", "storage", "status"])
    with pytest.raises(SystemExit) as exit_info:
        agent_cli.main()
    assert exit_info.value.code == 7
    storage_main.assert_called_once_with(["status"])
