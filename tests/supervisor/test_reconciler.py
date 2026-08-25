from __future__ import annotations

import asyncio
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

import aleph.vm.agent.vm.cache as cache_module
import aleph.vm.agent.vm.reconciler as reconciler_module
from aleph.vm.agent.vm.reclaimable import mark_reclaimable, read_marker
from aleph.vm.agent.vm.reconciler import (
    creating,
    is_creating,
    make_room,
    reconcile_at_startup,
    reconcile_now,
    reconcile_storage,
    start_storage_reconcile_task,
    stop_storage_reconcile_task,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.storage_pools import get_pools
from aleph.vm.supervisor_interface.errors import SupervisorError

LIVE = "dead" * 16
NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)
GIB = 1024**3


def _fake_disk_usage(monkeypatch, free_bytes):
    """Pin the free space every pool reports. ``free_bytes`` is either a
    number or a callable, so a test can let evictions give space back."""

    def usage(path):
        free = free_bytes(Path(path)) if callable(free_bytes) else free_bytes
        return SimpleNamespace(total=10 * GIB, used=10 * GIB - free, free=free)

    monkeypatch.setattr(reconciler_module.shutil, "disk_usage", usage)


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


def _supervisor(*vm_ids: str, fails: bool = False):
    """A supervisor handle that lists ``vm_ids``, or refuses to answer."""
    if fails:
        return SimpleNamespace(list_vms=AsyncMock(side_effect=SupervisorError("no answer")))
    return SimpleNamespace(list_vms=AsyncMock(return_value=[SimpleNamespace(vm_id=vm_id) for vm_id in vm_ids]))


def _app(registry, supervisor=None):
    return {"vm_registry": registry, "supervisor": supervisor if supervisor is not None else _supervisor()}


@pytest.fixture(autouse=True)
def _no_live_snapshot(monkeypatch):
    """The live-set snapshot the admission hook reads is module state."""
    monkeypatch.setattr(cache_module, "_live_snapshot", None)


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
    for stale in (stale_session, stale_staging, stale_mount):
        _age(stale, 10_000)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reconciler_module, "MOUNT_ROOT", pools["execution_root"] / "mnt")
        report = reconcile_storage(registry, now=NOW)

    assert not stale_session.exists()
    assert live_session.exists()
    assert not stale_staging.exists()
    assert not stale_mount.exists()
    assert report.side_dirs_removed == 3


def test_a_non_empty_mnt_directory_is_never_removed(pools, registry):  # noqa: F811
    """/mnt is the operator's directory. An agent mount point there is empty
    once unmounted (create_devmapper only mkdirs it), so anything with content
    under a name that merely matches the pattern is somebody else's disk."""
    mnt = pools["execution_root"] / "mnt"
    operator_disk = mnt / f"{VM_HASH}_1"
    operator_disk.mkdir(parents=True)
    (operator_disk / "customer-data.img").write_bytes(b"x")
    stale_mount = mnt / f"{OTHER_HASH}_data"
    stale_mount.mkdir()
    for path in (operator_disk, stale_mount):
        _age(path, 10_000)

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(reconciler_module, "MOUNT_ROOT", mnt)
        report = reconcile_storage(registry, now=NOW)

    assert (operator_disk / "customer-data.img").exists()
    assert not stale_mount.exists()
    assert report.side_dirs_removed == 1


def test_a_hash_claimed_mid_pass_is_not_purged(pools, registry, monkeypatch):  # noqa: F811
    """The live set is snapshotted on the loop and the walk runs in a thread:
    a create that commits in between must not be purged. The directory's mtime
    is no help, it does not move while a file inside it grows."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    content = MagicMock(volumes=[], rootfs=None)
    for namespace in (VM_HASH, OTHER_HASH):
        _age(volume(pools["pool0"], namespace, "rootfs.qcow2").parent, 10_000)
    real_purge = reconciler_module.purge_vm_storage

    def purge_and_commit_the_other(namespace):
        # The create for the namespace this pass has not reached yet commits
        # while the pass is busy with the first one.
        other = OTHER_HASH if namespace == VM_HASH else VM_HASH
        registry.record(ItemHash(other), message=content, original=content, persistent=True)
        return real_purge(namespace)

    monkeypatch.setattr(reconciler_module, "purge_vm_storage", purge_and_commit_the_other)
    live = reconciler_module.live_hashes(registry)

    report = reconcile_storage(registry, now=NOW, live=live, is_live=reconciler_module.registry_is_live(registry, live))

    assert len(report.purged_orphans) == 1
    survivor = OTHER_HASH if report.purged_orphans == [VM_HASH] else VM_HASH
    assert (pools["pool0"] / survivor).is_dir()


def test_young_side_dirs_are_inside_the_create_guard(pools, registry):  # noqa: F811
    young = pools["sessions"] / VM_HASH
    young.mkdir()
    _age(young, 10)
    old = pools["sessions"] / OTHER_HASH
    old.mkdir()
    _age(old, 10_000)

    report = reconcile_storage(registry, now=NOW)

    assert young.exists()
    assert not old.exists()
    assert report.side_dirs_removed == 1


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


def test_make_room_evicts_oldest_first_until_the_create_fits(pools, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    oldest = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    newest = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW - timedelta(days=2))
    mark_reclaimable(OTHER_HASH, "gone", now=NOW - timedelta(days=1))
    # A full pool that gets 8 KiB back for every evicted VM.
    _fake_disk_usage(monkeypatch, lambda path: 8192 * sum(not (path / h).exists() for h in (VM_HASH, OTHER_HASH)))

    freed = make_room(get_pools()[0], needed_bytes=8192)

    assert freed == 8192
    assert not oldest.exists()
    assert newest.exists()


def test_make_room_evicts_nothing_when_the_pool_already_fits(pools, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    retained = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW - timedelta(days=2))
    _fake_disk_usage(monkeypatch, 90 * GIB)

    freed = make_room(get_pools()[0], needed_bytes=8192)

    assert freed == 0
    assert retained.exists()


def test_make_room_counts_only_the_bytes_it_frees_on_that_pool(pools, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    on_pool0 = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    on_pool1 = volume(pools["pool1"], VM_HASH, "data.ext4", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW - timedelta(days=2))
    _fake_disk_usage(monkeypatch, 0)

    freed = make_room(get_pools()[0], needed_bytes=1024**2)

    # The VM is purged whole, but only pool 0's 8 KiB help a pool 0 create.
    assert freed == 8192
    assert not on_pool0.exists() and not on_pool1.exists()


def test_make_room_never_evicts_a_live_namespace(pools, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    running = volume(pools["pool0"], LIVE, "rootfs.qcow2", size=8192)
    mark_reclaimable(LIVE, "gone", now=NOW - timedelta(days=2))
    _fake_disk_usage(monkeypatch, 0)

    freed = make_room(get_pools()[0], needed_bytes=8192, live={LIVE})

    assert freed == 0
    assert running.exists()


@pytest.mark.asyncio
async def test_a_vm_the_supervisor_runs_is_live_even_without_a_record(pools, registry, monkeypatch):  # noqa: F811
    """The registry is refilled at boot from the agent DB alone, and that
    rehydration skips records with an empty or unparseable message. A VM the
    supervisor is still running is live whatever the registry remembers."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    running = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(running.parent, 10_000)

    report = await reconcile_now(_app(registry, _supervisor(VM_HASH)))

    assert running.exists()
    assert report.purged_orphans == []


@pytest.mark.asyncio
async def test_startup_purges_nothing_when_the_supervisor_cannot_be_listed(pools, registry, monkeypatch, caplog):  # noqa: F811
    """No answer from the supervisor is not "it runs nothing": without the
    second opinion the live set is unknown, so the startup pass runs dry."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    with caplog.at_level("WARNING"):
        await reconcile_at_startup(_app(registry, _supervisor(fails=True)))

    assert old.exists()
    assert "running dry" in caplog.text


@pytest.mark.asyncio
async def test_startup_purges_nothing_when_the_registry_is_empty_but_vms_run(pools, monkeypatch, caplog):  # noqa: F811
    """A fresh or lost agent DB rehydrates zero records while the supervisor
    still runs VMs: every directory would look like an orphan."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)
    other = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    _age(other.parent, 10_000)

    with caplog.at_level("WARNING"):
        await reconcile_at_startup(_app(AgentVmRegistry(), _supervisor(LIVE)))

    assert old.exists() and other.exists()
    assert "registry is empty" in caplog.text


@pytest.mark.asyncio
async def test_a_refusing_startup_never_promises_a_purge(pools, registry, monkeypatch, caplog):  # noqa: F811
    """The preview and the pass behind it share one live set and one refusal
    decision, so the log cannot read "will purge N" above "purging nothing",
    and the supervisor is asked once."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)
    supervisor = _supervisor(fails=True)

    with caplog.at_level("WARNING"):
        await reconcile_at_startup(_app(registry, supervisor))

    assert "will purge 1 orphan" not in caplog.text
    assert "would have purged 1" in caplog.text
    assert supervisor.list_vms.await_count == 1
    assert old.exists()


@pytest.mark.asyncio
async def test_startup_hook_logs_a_preview_then_reconciles(pools, registry, monkeypatch, caplog):  # noqa: F811
    """The one-shot cleanup on an upgraded node is announced before it runs:
    an operator reading the log must be able to explain why free space jumped
    (spec section 6, migration)."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    old = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    _age(old.parent, 10_000)

    with caplog.at_level("WARNING"):
        await reconcile_at_startup(_app(registry))

    assert "will purge 1 orphan" in caplog.text
    # A line per pool, so the operator sees which disk gives the space back.
    assert f"pool 0 ({pools['pool0']})" in caplog.text
    assert not old.parent.exists()


@pytest.mark.asyncio
async def test_startup_hook_is_quiet_when_there_is_nothing_to_reclaim(pools, registry, caplog):  # noqa: F811
    live = volume(pools["pool0"], LIVE, "rootfs.qcow2")
    _age(live.parent, 10_000)

    with caplog.at_level("WARNING"):
        await reconcile_at_startup(_app(registry))

    assert "Startup storage reconcile" not in caplog.text
    assert live.exists()


@pytest.mark.asyncio
async def test_the_periodic_task_starts_and_is_cancelled_on_shutdown(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "VOLUME_RECONCILE_INTERVAL", 3600)
    app = _app(registry)

    await start_storage_reconcile_task(app)
    task = app["storage_reconcile"]
    await asyncio.sleep(0)  # let the task reach its first (long) sleep
    assert not task.done()
    await stop_storage_reconcile_task(app)

    assert task.done()


def test_a_create_in_flight_keeps_its_directory_and_its_part_files(pools, registry, monkeypatch):  # noqa: F811
    """A migration import streams multi-GB disks into a namespace no registry
    record covers yet, for far longer than VOLUME_CREATE_GUARD, and the
    directory's own mtime does not advance while a file inside it grows. Only
    ``creating()`` stands between that transfer and the reaper."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "reap")
    staged = volume(pools["pool0"], VM_HASH, "rootfs.qcow2.part")
    _age(staged, 10_000)
    _age(staged.parent, 10_000)

    with creating(VM_HASH):
        report = reconcile_storage(registry, now=NOW)

    assert staged.exists()
    assert report.purged_orphans == [] and report.parts_removed == 0


def test_evicting_a_directory_that_already_vanished_counts_nothing(pools, monkeypatch):  # noqa: F811
    """Passes can overlap (a GONE-triggered pass, the periodic one, make_room),
    so a directory can disappear between being listed and being acted on. That
    is not an error, and it is not freed space this pass may claim."""
    report = reconciler_module.ReconcileReport()

    freed = reconciler_module._evict(VM_HASH, report, dry_run=False)

    assert freed == 0
    assert report.evicted == [] and report.bytes_freed == 0


def test_a_refused_purge_is_not_counted_as_an_eviction(pools, monkeypatch):  # noqa: F811
    """purge_vm_storage refuses a directory a device-mapper target still
    holds. make_room must not then report room it did not make."""
    monkeypatch.setattr(settings, "VOLUME_RETENTION", "keep")
    retained = volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    monkeypatch.setattr(reconciler_module, "purge_vm_storage", lambda _namespace: 0)
    _fake_disk_usage(monkeypatch, 0)

    freed = make_room(get_pools()[0], needed_bytes=8192)

    assert freed == 0
    assert retained.exists()


@pytest.mark.asyncio
async def test_two_reconcile_passes_do_not_overlap(pools, registry, monkeypatch):  # noqa: F811
    """A GONE fires a pass while the periodic one may be running: without a
    lock the two threads evict the same directories and double-count."""
    order = []

    def slow_pass(_registry, **_kwargs):
        order.append("enter")
        time.sleep(0.05)
        order.append("exit")
        return reconciler_module.ReconcileReport()

    monkeypatch.setattr(reconciler_module, "reconcile_storage", slow_pass)
    app = _app(registry)

    await asyncio.gather(reconcile_now(app), reconcile_now(app))

    assert order == ["enter", "exit", "enter", "exit"]


def test_reconcile_runs_the_cache_pass(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)

    report = reconcile_storage(registry, now=NOW)

    assert report.cache_evicted == [stale]
    assert not stale.exists()


def test_the_cache_pass_is_skipped_when_a_live_vm_has_no_record(pools, registry, monkeypatch, caplog):  # noqa: F811
    """Cache references are read from the registry's messages alone, so a VM
    the supervisor runs but the registry does not know makes the referenced
    set incomplete. Fail closed rather than evict a running VM's runtime."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)

    report = reconcile_storage(registry, now=NOW, live={LIVE, VM_HASH})

    assert report.cache_evicted == []
    assert stale.exists()
    assert any(record.levelname == "ERROR" and "cache pass" in record.message for record in caplog.records)


@pytest.mark.asyncio
async def test_reconcile_now_removes_the_devices_of_evicted_parents(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    (pools["runtime"] / "stale").write_bytes(b"x" * 4096)
    removed = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))

    report = await reconcile_now(_app(registry))

    assert [path.name for path in report.cache_evicted] == ["stale"]
    assert removed == ["stale"]


def test_old_tmp_files_are_removed_alongside_the_parts(pools, registry):  # noqa: F811
    """get_message writes <ref>.json.tmp before renaming, create_ext4 and the
    marker writer do the same: an interrupted one leaks exactly like a .part."""
    old_tmp = pools["message"] / "abc.json.tmp"
    old_tmp.write_bytes(b"x")
    _age(old_tmp, 10_000)
    young_tmp = pools["code"] / "def.tmp"
    young_tmp.write_bytes(b"x")
    _age(young_tmp, 10)

    report = reconcile_storage(registry, now=NOW)

    assert not old_tmp.exists()
    assert young_tmp.exists()
    assert report.parts_removed == 1


@pytest.mark.asyncio
async def test_the_pass_records_the_live_set_for_the_admission_hook(pools, registry):  # noqa: F811
    await reconcile_now(_app(registry, _supervisor(VM_HASH)))

    assert cache_module.live_snapshot() == frozenset({LIVE, VM_HASH})


@pytest.mark.asyncio
async def test_a_half_known_live_set_is_never_published(pools, registry):  # noqa: F811
    """Admission evicts against this set; a set missing whatever the
    supervisor would have listed is not one it may use."""
    await reconcile_now(_app(registry, _supervisor(fails=True)))

    assert cache_module.live_snapshot() is None


@pytest.mark.asyncio
async def test_a_dry_run_never_touches_a_device(pools, registry, monkeypatch):  # noqa: F811
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    stale = pools["runtime"] / "stale"
    stale.write_bytes(b"x" * 4096)
    removed = []
    monkeypatch.setattr(reconciler_module, "remove_parent_device", AsyncMock(side_effect=removed.append))
    swept = AsyncMock(return_value=[])
    monkeypatch.setattr(reconciler_module, "sweep_leaked_cache_loops", swept)

    report = await reconcile_now(_app(registry), dry_run=True)

    assert [path.name for path in report.cache_evicted] == ["stale"]
    assert stale.exists()
    assert removed == []
    swept.assert_not_awaited()
