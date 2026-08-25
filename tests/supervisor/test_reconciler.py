from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

import aleph.vm.agent.vm.reconciler as reconciler_module
from aleph.vm.agent.vm.reclaimable import mark_reclaimable, read_marker
from aleph.vm.agent.vm.reconciler import (
    creating,
    is_creating,
    make_room,
    reconcile_storage,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.storage_pools import get_pools

LIVE = "dead" * 16
NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def _age(path, seconds: int) -> None:
    """Set the mtime ``seconds`` before NOW: the reconciler threads one ``now``
    through the whole pass, so ages are relative to it and not to the clock."""
    stamp = NOW.timestamp() - seconds
    os.utime(path, (stamp, stamp))


@pytest.fixture
def registry():
    reg = AgentVmRegistry()
    content = MagicMock(volumes=[], rootfs=None)
    reg.record(ItemHash(LIVE), message=content, original=content, persistent=True)
    return reg


@pytest.fixture(autouse=True)
def _no_backups(mocker):
    mocker.patch.object(reconciler_module, "sweep_expired_backups", return_value=0)


@pytest.fixture(autouse=True)
def _mount_root(tmp_path, monkeypatch):
    """Never let a test walk the host's real /mnt."""
    monkeypatch.setattr(reconciler_module, "MOUNT_ROOT", tmp_path / "unused-mnt")


def test_live_dirs_are_left_alone(pools, registry):  # noqa: F811
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")
    _age(live.parent, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert live.exists()
    assert report.purged_orphans == [] and report.marked_orphans == []


def test_young_orphan_is_inside_the_create_guard(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    young = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(young.parent, 10)

    reconcile_storage(registry, now=NOW)

    assert young.exists()


def test_in_flight_create_is_never_an_orphan(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    with creating(VM_HASH):
        assert is_creating(VM_HASH)
        reconcile_storage(registry, now=NOW)
        assert old.exists()
    assert not is_creating(VM_HASH)


def test_creating_adopts_retained_dirs(pools, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    with creating(VM_HASH):
        assert read_marker(pools["pool0"] / VM_HASH) is None


def test_old_orphan_is_purged_under_reap(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert not old.parent.exists()
    assert report.purged_orphans == [VM_HASH]


def test_old_orphan_is_marked_under_keep(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert old.exists()
    assert read_marker(old.parent).reason == "orphan"
    assert report.marked_orphans == [VM_HASH]


def test_marked_dir_whose_vm_is_live_again_is_adopted(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    volume(pools["pool0"], LIVE, "rootfs.qcow2")
    mark_reclaimable(LIVE, "gone", now=NOW)

    reconcile_storage(registry, now=NOW)

    assert read_marker(pools["pool0"] / LIVE) is None


def test_implausible_dir_names_are_skipped(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    weird = pools["pool0"] / "lost+found"
    weird.mkdir()
    _age(weird, 10_000)

    reconcile_storage(registry, now=NOW)

    assert weird.exists()


def test_dry_run_changes_nothing(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    report = reconcile_storage(registry, now=NOW, dry_run=True)

    assert old.exists()
    assert report.purged_orphans == [VM_HASH]


def test_old_part_files_are_removed_young_ones_kept(pools, registry):  # noqa: F811
    old_part = pools["runtime"] / "abc.part"
    old_part.write_bytes(b"x")
    _age(old_part, 10_000)
    young_part = pools["code"] / "def.part"
    young_part.write_bytes(b"x")
    _age(young_part, 10)
    pool_part = volume(pools["pool0"], LIVE, "rootfs.qcow2.part")
    _age(pool_part, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert not old_part.exists()
    assert young_part.exists()
    assert not pool_part.exists()
    assert report.parts_removed == 2


def test_side_dirs_of_unknown_hashes_are_removed(pools, registry):  # noqa: F811
    stale_session = pools["sessions"] / VM_HASH
    stale_session.mkdir()
    live_session = pools["sessions"] / LIVE
    live_session.mkdir()
    stale_staging = pools["execution_root"] / "snp-instance" / VM_HASH
    stale_staging.mkdir(parents=True)
    stale_mount = pools["execution_root"] / "mnt" / f"{VM_HASH}_data"
    stale_mount.mkdir(parents=True)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reconciler_module, "MOUNT_ROOT", pools["execution_root"] / "mnt")
        report = reconcile_storage(registry, now=NOW)

    assert not stale_session.exists()
    assert live_session.exists()
    assert not stale_staging.exists()
    assert not stale_mount.exists()
    assert report.side_dirs_removed == 3


def test_budget_evicts_oldest_first(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    monkeypatch.setattr(settings, "VOLUME_RETENTION_BUDGET", "8192")
    oldest = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    newest = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW - timedelta(days=2))
    mark_reclaimable(OTHER_HASH, "gone", now=NOW - timedelta(days=1))

    report = reconcile_storage(registry, now=NOW)

    assert not oldest.exists()
    assert newest.exists()
    assert report.evicted == [VM_HASH]


def test_switching_to_reap_evicts_everything_marked(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    kept = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)

    reconcile_storage(registry, now=NOW)

    assert not kept.exists()


def test_make_room_frees_only_what_is_needed(pools, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    oldest = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    newest = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW - timedelta(days=2))
    mark_reclaimable(OTHER_HASH, "gone", now=NOW - timedelta(days=1))

    freed = make_room(get_pools()[0], needed_bytes=4096)

    assert freed >= 4096
    assert not oldest.exists()
    assert newest.exists()
