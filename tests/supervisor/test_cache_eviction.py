from __future__ import annotations

import json
import logging
import os
import shutil
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

import aleph.vm.agent.vm.cache as cache_module
import aleph.vm.agent.vm.reconciler as reconciler_module
import aleph.vm.storage as storage_module
from aleph.vm.agent.vm.cache import (
    admit_download,
    cache_entries,
    evict_caches,
    parent_refs_of,
    referenced_hashes,
)
from aleph.vm.agent.vm.reclaimable import mark_reclaimable
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.storage import DownloadReservation

NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)
OLDER = datetime(2026, 8, 23, tzinfo=timezone.utc)


def _unreadable_disk(path):
    """``shutil.disk_usage`` on a cache root whose filesystem will not answer."""
    raise OSError(13, "Permission denied", str(path))


@pytest.fixture(autouse=True)
def _no_live_snapshot(monkeypatch):
    """The reconciler's live-set snapshot is module state: no test inherits
    another's."""
    monkeypatch.setattr(cache_module, "_live_snapshot", None)


@pytest.fixture(autouse=True)
def _no_reserved_downloads(monkeypatch):
    """So is the set of downloads admission has already charged for."""
    monkeypatch.setattr(storage_module, "_reserved_downloads", {})


def _entry(root, name, size=4096, age=0):
    path = root / name
    path.write_bytes(b"x" * size)
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))
    return path


def _program_record(registry, vm_hash, *, runtime="rt", code="code", data=None):
    content = MagicMock()
    content.runtime = MagicMock(ref=runtime)
    content.code = MagicMock(ref=code)
    content.data = MagicMock(ref=data) if data else None
    content.rootfs = None
    content.volumes = []
    content.workload = None
    content.environment = None
    registry.record(ItemHash(vm_hash), message=content, original=content)
    return content


def test_referenced_hashes_cover_records_and_markers(pools):
    registry = AgentVmRegistry()
    vm_hash = "ab" * 32
    _program_record(registry, vm_hash, runtime="rt1", code="c1", data="d1")
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent1",), now=NOW)

    # The VM's own message entry is a reference too: the message cache holds
    # it as <vm_hash>.json.
    assert referenced_hashes(registry) == {"rt1", "c1", "d1", "parent1", vm_hash}


def test_referenced_hashes_cover_instance_parents_and_immutable_volumes(pools):
    registry = AgentVmRegistry()
    content = MagicMock()
    content.runtime = None
    content.code = None
    content.data = None
    # ``parent`` is a Mock constructor argument, so it has to be assigned.
    content.rootfs = MagicMock()
    content.rootfs.parent = MagicMock(ref="base")
    parent_backed = MagicMock(ref=None)
    parent_backed.parent = MagicMock(ref="vparent")
    immutable = MagicMock(ref="immutable")
    immutable.parent = None
    content.volumes = [parent_backed, immutable]
    content.workload = None
    content.environment = None
    vm_hash = "ab" * 32
    registry.record(ItemHash(vm_hash), message=content, original=content)

    assert referenced_hashes(registry) == {"base", "vparent", "immutable", vm_hash}


def _vprogram_record(registry, vm_hash, **fields):
    content = MagicMock()
    content.runtime = MagicMock(ref=fields.get("runtime", "manifest"))
    content.code = None
    content.data = None
    content.rootfs = None
    content.volumes = []
    content.workload = MagicMock(ref=fields.get("workload", "workload"), hash_tree=fields.get("hash_tree", "hashtree"))
    content.environment = MagicMock()
    content.environment.trusted_execution = fields.get("trusted_execution")
    registry.record(ItemHash(vm_hash), message=content, original=content)
    return content


def test_a_live_vprograms_workload_disks_are_never_evicted(pools, monkeypatch):
    """Both are attached as the VM's disks straight out of DATA_CACHE."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    _vprogram_record(registry, "ab" * 32)
    workload = _entry(pools["data"], "workload", size=4096)
    hash_tree = _entry(pools["data"], "hashtree", size=4096)

    assert evict_caches(registry) == []
    assert workload.exists() and hash_tree.exists()


def test_a_confidential_instances_firmware_and_runtime_are_never_evicted(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    _vprogram_record(registry, "ab" * 32, trusted_execution=MagicMock(firmware="fw", runtime="tee-rt"))
    firmware = _entry(pools["data"], "fw", size=4096)
    runtime = _entry(pools["data"], "tee-rt", size=4096)

    assert evict_caches(registry) == []
    assert firmware.exists() and runtime.exists()


def test_the_bundle_a_locally_cached_manifest_names_is_kept(pools, monkeypatch):
    """The tarball ref is only knowable from the manifest, so it is protected
    whenever the manifest itself is in the cache."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    _vprogram_record(registry, "ab" * 32, workload="w", hash_tree="h")
    (pools["data"] / "manifest").write_text(json.dumps({"bundle": {"ref": "tarball"}}))
    tarball = _entry(pools["data"], "tarball", size=4096)

    assert evict_caches(registry) == []
    assert tarball.exists()


def test_a_live_vms_own_message_entry_is_kept(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    vm_hash = "ab" * 32
    _program_record(registry, vm_hash)
    message = _entry(pools["message"], f"{vm_hash}.json", size=4096)

    assert evict_caches(registry) == []
    assert message.exists()


def test_cache_entries_skip_parts_and_sort_oldest_first(pools):
    new = _entry(pools["runtime"], "new", age=10)
    old = _entry(pools["runtime"], "old", age=1000)
    _entry(pools["runtime"], "x.part")

    assert [e.path for e in cache_entries(pools["runtime"])] == [old, new]


def test_evicts_unreferenced_lru_until_under_budget(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    _program_record(registry, "ab" * 32, runtime="live")
    live = _entry(pools["runtime"], "live", age=5000)
    oldest = _entry(pools["runtime"], "oldest", age=3000)
    newer = _entry(pools["runtime"], "newer", age=100)

    evicted = evict_caches(registry)

    assert evicted == [oldest]
    assert live.exists() and newer.exists()


def test_never_evicts_a_live_reference_even_over_budget(pools, monkeypatch, caplog):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    _program_record(registry, "ab" * 32, runtime="live")
    live = _entry(pools["runtime"], "live", size=4096)

    assert evict_caches(registry) == []
    assert live.exists()
    assert "live references" in caplog.text


def test_a_message_cache_entry_of_a_live_vm_is_kept(pools, monkeypatch):
    """The message cache keys entries ``<ref>.json``, so the referenced set
    has to be matched against the stem too."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    _program_record(registry, "ab" * 32, runtime="live")
    kept = _entry(pools["message"], "live.json", size=4096)

    assert evict_caches(registry) == []
    assert kept.exists()


def test_reclaimable_dependents_go_before_their_parent(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    retained = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=NOW)

    evicted = evict_caches(registry)

    assert evicted == [parent]
    assert not retained.exists()
    assert parent_refs_of(evicted) == ["parent"]


def test_a_parent_a_vm_that_is_live_again_needs_is_kept(pools, monkeypatch):
    """Reclaiming one dependent does not free a parent a second directory
    still names, and a stale marker on a live VM is never reclaimed for it."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    reclaimable = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    live = volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=OLDER)
    mark_reclaimable(OTHER_HASH, "gone", ("parent",), now=NOW)
    _program_record(registry, OTHER_HASH)

    assert evict_caches(registry) == []
    assert parent.exists() and live.exists()
    assert not reclaimable.exists()


def test_every_dependent_goes_before_the_parent_they_share(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=OLDER)
    mark_reclaimable(OTHER_HASH, "gone", ("parent",), now=NOW)

    assert evict_caches(registry) == [parent]
    assert not (pools["pool0"] / VM_HASH).exists()
    assert not (pools["pool0"] / OTHER_HASH).exists()


def test_a_parent_is_kept_when_its_dependents_purge_leaves_disks_behind(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    retained = volume(pools["pool0"], VM_HASH, "rootfs.btrfs")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=NOW)
    # What purge_vm_storage does when a device-mapper target still holds the
    # volume: it logs and leaves the directory in place.
    monkeypatch.setattr(cache_module, "purge_vm_storage", lambda namespace: 0)

    assert evict_caches(registry) == []
    assert parent.exists() and retained.exists()


def test_needed_bytes_are_counted_against_the_budget(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    a = _entry(pools["code"], "a", size=4096, age=100)

    assert evict_caches(registry, needed={pools["code"]: 8000}) == [a]


def test_dry_run_reports_without_deleting(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    a = _entry(pools["data"], "a", size=4096)

    assert evict_caches(registry, dry_run=True) == [a]
    assert a.exists()


def test_dry_run_does_not_purge_a_reclaimable_dependent(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    retained = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=NOW)

    assert evict_caches(registry, dry_run=True) == [parent]
    assert parent.exists() and retained.exists()


def test_a_parent_whose_device_is_still_held_is_not_evicted(pools, monkeypatch, caplog):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    monkeypatch.setattr(cache_module, "parent_device_is_free", lambda ref: False)

    assert evict_caches(registry) == []
    assert parent.exists()
    assert "device" in caplog.text


def test_parent_refs_of_only_names_runtime_entries(pools):
    assert parent_refs_of([pools["runtime"] / "a", pools["code"] / "b"]) == ["a"]


def test_admit_download_evicts_to_make_room(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["code"], "old", size=4096, age=1000)

    admit_download(registry, pools["code"] / "new.part", 8000)

    assert not old.exists()


def test_admit_download_never_reclaims_retained_disks(pools, monkeypatch):
    """Phase 2 purges VM directories, which on the admission path would mean
    an rmtree on the event loop: admission evicts cache files or refuses."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    parent = _entry(pools["runtime"], "parent", size=4096)
    retained = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=NOW)

    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["runtime"] / "new.part", 512)

    assert parent.exists() and retained.exists()


def test_admit_download_evicts_nothing_when_a_live_vm_has_no_record(pools, monkeypatch, caplog):
    """The same fail-closed rule the pass applies: without every live VM's
    message, what the caches hold for them is unknown."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot({VM_HASH})
    old = _entry(pools["code"], "old", size=4096, age=1000)

    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["code"] / "new.part", 8000)

    assert old.exists()
    assert "no registry record" in caplog.text


def test_admit_download_evicts_nothing_before_the_first_pass(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    old = _entry(pools["code"], "old", size=4096, age=1000)

    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["code"] / "new.part", 8000)

    assert old.exists()


def test_admit_download_refuses_what_the_budget_cannot_hold(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()

    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["code"] / "a.part", 9000)


def test_two_concurrent_downloads_cannot_both_fit_in_room_for_one(pools, monkeypatch):
    """Admission used to see only what was already on disk, and a ``.part`` is
    not a cache entry: two creates arriving together were both told there was
    room for a download only one of them could have."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    first = pools["code"] / "a.part"
    first.touch()

    admit_download(registry, first, 8000)

    second = pools["code"] / "b.part"
    second.touch()
    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, second, 8000)


def test_a_finished_download_releases_the_room_it_held(pools, monkeypatch):
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    first = pools["code"] / "a.part"
    first.touch()
    admit_download(registry, first, 8000)

    storage_module.release_download(first)
    first.unlink()

    admit_download(registry, pools["code"] / "b.part", 8000)


def test_the_bytes_of_an_unadmitted_part_file_are_counted_too(pools, monkeypatch):
    """A ``.part`` from a crashed download holds real blocks until the
    reconciler's guard expires; admission may not hand the same blocks out."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    orphan = pools["code"] / "crashed.part"
    orphan.write_bytes(b"x" * 8000)

    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["code"] / "b.part", 4096)


def test_a_reservation_is_not_counted_twice_while_its_part_grows(pools, monkeypatch):
    """The reservation and the bytes already written are the same room."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "16384")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    part = pools["code"] / "a.part"
    part.touch()
    admit_download(registry, part, 8192)
    part.write_bytes(b"x" * 8192)

    # 8 KiB reserved, 8 KiB of it written: 8 KiB of the 16 KiB budget is left.
    admit_download(registry, pools["code"] / "b.part", 4096)


def test_admit_download_ignores_a_directory_that_is_not_a_cache(pools, monkeypatch, caplog):
    """The downloader streams per-VM volumes in place; those are admitted by
    the capacity checks and the pool budget, not by CACHE_BUDGET."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    directory = pools["pool0"] / VM_HASH
    directory.mkdir()

    admit_download(registry, directory / "rootfs.qcow2.part", 10 * 1024**3)

    assert str(directory) in caplog.text


def _record_calls(monkeypatch, *, loop_of=None):
    """Record the commands remove_parent_device runs, with a fake sysfs whose
    only loop device is backed by ``loop_of`` (already unlinked)."""
    commands: list[list[str]] = []

    async def fake_run(command, **kwargs):
        commands.append(command)
        return b""

    monkeypatch.setattr(cache_module, "run_in_subprocess", fake_run)
    if loop_of is not None:
        sys_block = loop_of.parent / "sys-block"
        backing_file = sys_block / "loop7" / "loop" / "backing_file"
        backing_file.parent.mkdir(parents=True)
        backing_file.write_text(f"{loop_of} (deleted)\n")
        (sys_block / "loop8" / "loop").mkdir(parents=True)
        (sys_block / "loop8" / "loop" / "backing_file").write_text("/some/other/file\n")
        monkeypatch.setattr(cache_module, "SYS_BLOCK", sys_block)
    return commands


@pytest.mark.asyncio
async def test_remove_parent_device_removes_the_device_and_its_loop(pools, monkeypatch):
    """The eviction unlinks the image before this runs, so `losetup -j` can no
    longer find the loop device that pins its blocks: sysfs still can."""
    commands = _record_calls(monkeypatch, loop_of=pools["runtime"] / "parent")
    monkeypatch.setattr(cache_module, "_is_block_device", lambda path: True)

    await cache_module.remove_parent_device("parent")

    assert commands == [["dmsetup", "remove", "--retry", "parent"], ["losetup", "-d", "/dev/loop7"]]


@pytest.mark.asyncio
async def test_remove_parent_device_detaches_the_loop_of_a_ref_with_no_device(pools, monkeypatch):
    """An interrupted create can leave a read-only loop device with no dm
    target on top: the evicted file's blocks stay pinned until it is detached."""
    commands = _record_calls(monkeypatch, loop_of=pools["runtime"] / "parent")
    monkeypatch.setattr(cache_module, "_is_block_device", lambda path: False)

    await cache_module.remove_parent_device("parent")

    assert commands == [["losetup", "-d", "/dev/loop7"]]


@pytest.mark.asyncio
async def test_remove_parent_device_leaves_an_image_that_came_back_alone(pools, monkeypatch):
    """Downloaded again between the eviction and this teardown: the devices
    belong to the create that fetched it, not to the eviction."""
    commands = _record_calls(monkeypatch, loop_of=pools["runtime"] / "parent")
    (pools["runtime"] / "parent").write_bytes(b"image")
    monkeypatch.setattr(cache_module, "_is_block_device", lambda path: True)

    await cache_module.remove_parent_device("parent")

    assert commands == []


@pytest.mark.asyncio
async def test_remove_parent_device_refuses_an_implausible_ref(pools, monkeypatch):
    commands = _record_calls(monkeypatch)

    await cache_module.remove_parent_device("../escape")

    assert commands == []


@pytest.mark.asyncio
async def test_the_sweep_detaches_a_loop_left_over_a_deleted_cache_entry(pools, monkeypatch):
    """The recovery path for a teardown that failed: the entry is gone, so
    only the kernel still knows which loop pins its blocks."""
    commands = _record_calls(monkeypatch, loop_of=pools["runtime"] / "gone")
    monkeypatch.setattr(cache_module, "_is_block_device", lambda path: True)
    monkeypatch.setattr(cache_module, "parent_device_is_free", lambda ref: True)

    assert await cache_module.sweep_leaked_cache_loops() == ["/dev/loop7"]
    assert commands == [["dmsetup", "remove", "--retry", "gone"], ["losetup", "-d", "/dev/loop7"]]


@pytest.mark.asyncio
async def test_the_sweep_leaves_a_loop_whose_device_is_still_held(pools, monkeypatch):
    commands = _record_calls(monkeypatch, loop_of=pools["runtime"] / "gone")
    monkeypatch.setattr(cache_module, "_is_block_device", lambda path: True)
    monkeypatch.setattr(cache_module, "parent_device_is_free", lambda ref: False)

    assert await cache_module.sweep_leaked_cache_loops() == []
    assert commands == []


@pytest.mark.asyncio
async def test_the_sweep_ignores_deleted_files_outside_the_caches(pools, monkeypatch):
    """A VM volume's loop device is remove_devmapper's business, not this
    sweep's."""
    commands = _record_calls(monkeypatch, loop_of=pools["pool0"] / "rootfs.btrfs")
    monkeypatch.setattr(cache_module, "_is_block_device", lambda path: True)

    assert await cache_module.sweep_leaked_cache_loops() == []
    assert commands == []


def test_a_retained_dir_a_create_is_using_is_not_reclaimed_for_its_parent(pools, monkeypatch):
    """Same race as the retention budget's: the markers were listed before the
    create adopted the directory, and the VM has no registry record yet."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    parent = _entry(pools["runtime"], "parent", size=4096)
    adopted = volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), now=NOW)
    monkeypatch.setattr(reconciler_module, "_creating", {VM_HASH: reconciler_module._CreateState(creates=1)})

    assert evict_caches(registry) == []
    assert parent.exists() and adopted.exists()


def _fake_device(monkeypatch, tmp_path, ref="parent", *, present=True):
    """A /dev/mapper and a /sys/dev/block the test owns.

    ``_is_block_device`` answers on existence: a regular file stands in for a
    device node, which no test can create, and a path that is not there is
    still not there.
    """
    mapper = tmp_path / "mapper"
    mapper.mkdir(exist_ok=True)
    sysfs = tmp_path / "sys-dev-block"
    sysfs.mkdir(exist_ok=True)
    monkeypatch.setattr(cache_module, "DEVICE_MAPPER_DIRECTORY", str(mapper))
    monkeypatch.setattr(cache_module, "SYS_DEV_BLOCK", sysfs)
    monkeypatch.setattr(cache_module, "_is_block_device", lambda path: path.exists())
    device = mapper / ref
    if present:
        device.write_bytes(b"")
    return device, sysfs


def _holders_of(sysfs, device):
    """Where the kernel would list what is stacked on ``device``."""
    rdev = device.stat().st_rdev
    return sysfs / f"{os.major(rdev)}:{os.minor(rdev)}" / "holders"


def test_a_parent_device_with_no_holders_is_free(monkeypatch, tmp_path):
    device, sysfs = _fake_device(monkeypatch, tmp_path)
    _holders_of(sysfs, device).mkdir(parents=True)

    assert cache_module.parent_device_is_free("parent") is True


def test_a_parent_device_a_vm_is_stacked_on_is_not_free(monkeypatch, tmp_path, caplog):
    """create_devmapper stacks one <namespace>_base per VM on the image."""
    caplog.set_level(logging.INFO)
    device, sysfs = _fake_device(monkeypatch, tmp_path)
    holders = _holders_of(sysfs, device)
    holders.mkdir(parents=True)
    (holders / "dm-3").mkdir()

    assert cache_module.parent_device_is_free("parent") is False
    assert "dm-3" in caplog.text


def test_a_ref_with_no_device_at_all_is_free(monkeypatch, tmp_path):
    """Nothing is stacked on a device that does not exist."""
    _fake_device(monkeypatch, tmp_path, present=False)

    assert cache_module.parent_device_is_free("parent") is True


def test_a_device_sysfs_does_not_know_is_not_free(monkeypatch, tmp_path, caplog):
    """Fail closed: the question could not be answered, and the cost of
    guessing wrong is a running VM's disk."""
    _fake_device(monkeypatch, tmp_path)

    assert cache_module.parent_device_is_free("parent") is False
    assert "still in use" in caplog.text


def test_an_unreadable_holders_directory_is_not_free(monkeypatch, tmp_path):
    device, sysfs = _fake_device(monkeypatch, tmp_path)
    holders = _holders_of(sysfs, device)
    holders.parent.mkdir(parents=True)
    holders.write_bytes(b"not a directory")

    assert cache_module.parent_device_is_free("parent") is False


def test_an_implausible_ref_is_never_free(monkeypatch, tmp_path):
    _fake_device(monkeypatch, tmp_path, present=False)

    assert cache_module.parent_device_is_free("../escape") is False
    assert cache_module.parent_device_is_free("-o") is False


def test_an_unknown_length_download_evicts_nothing(pools, monkeypatch):
    """A cap is not a measurement. MAX_RUNTIME_ARCHIVE_SIZE is 100 GiB, and
    charging that for a chunked response wiped every unreferenced entry in the
    root before refusing the download anyway."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    # Named so the 8192 below is the budget capping a larger reserve, not a
    # coincidence of whatever the default reserve happens to be.
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "16384")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["runtime"], "old", size=4096, age=1000)

    admit_download(registry, pools["runtime"] / "new.part", None, 100 * 1024**3)

    assert old.exists()
    assert storage_module.reserved_downloads() == {
        pools["runtime"] / "new.part": DownloadReservation(8192, measured=False)
    }


def test_an_unknown_length_download_is_refused_on_a_root_over_budget(pools, monkeypatch):
    """The one thing it still refuses, and it evicts nothing on the way out."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "1024")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["runtime"], "old", size=4096, age=1000)

    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["runtime"] / "new.part", None, 999)

    assert old.exists()
    assert storage_module.reserved_downloads() == {}


def test_two_unknown_length_downloads_are_both_charged_the_capped_figure(pools, monkeypatch):
    """Bounded, so a stream of them still runs the root over its budget and
    the next one is refused, but never charged more than the budget itself."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    # A reserve above the budget, so what caps each charge below is named here:
    # the download's own 4096 for the first, the budget for the second.
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "16384")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    first = pools["runtime"] / "a.part"
    second = pools["runtime"] / "b.part"

    admit_download(registry, first, None, 4096)
    admit_download(registry, second, None, 100 * 1024**3)

    assert storage_module.reserved_downloads() == {
        first: DownloadReservation(4096, measured=False),
        second: DownloadReservation(8192, measured=False),
    }
    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["runtime"] / "c.part", None, 4096)


def test_an_unreadable_cache_disk_admits_a_measured_download(pools, monkeypatch, caplog):
    """The disk is read once, and a read that fails ends the admission there:
    the download goes through on its own figure, and nothing on the root is
    evicted for a budget nobody could compute."""
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["runtime"], "old", size=4096, age=1000)
    part = pools["runtime"] / "new.part"

    monkeypatch.setattr(cache_module.shutil, "disk_usage", _unreadable_disk)

    with caplog.at_level(logging.WARNING):
        admit_download(registry, part, 4096)

    assert old.exists()
    assert storage_module.reserved_downloads() == {part: DownloadReservation(4096, measured=True)}
    assert "not accessible" in caplog.text


def test_an_unreadable_cache_disk_holds_nothing_for_an_unmeasured_download(pools, monkeypatch):
    """The whole budget must not come back through the back door: the budget
    is a share of a disk size nobody could read, so there is no figure to
    hold, and one chunked response does not get the root to itself."""
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())

    monkeypatch.setattr(cache_module.shutil, "disk_usage", _unreadable_disk)

    admit_download(registry, pools["runtime"] / "new.part", None, 100 * 1024**3)

    assert storage_module.reserved_downloads() == {}


def test_the_reserve_is_a_share_of_the_total_the_caller_read(pools, monkeypatch):
    """A percentage reserve is resolved against the disk size the admission
    already measured, not against a reading of its own."""
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "10%")

    assert cache_module._unknown_length_charge(80_000, 1024**3, None) == 8000


def test_a_measured_download_still_evicts_to_make_room(pools, monkeypatch):
    """The Content-Length path is unchanged: that figure is this download's
    size, so the budget may be made to fit it."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["code"], "old", size=4096, age=1000)

    admit_download(registry, pools["code"] / "new.part", 8000)

    assert not old.exists()


def test_a_body_bigger_than_its_reserve_is_recovered_by_the_next_pass(pools, monkeypatch):
    """The reserve is a guess, so a chunked body can outgrow it. The root is
    over its budget while the extra bytes land, and nothing may unlink the
    .part under the download writing it; what the pass does instead is count
    those bytes (they are a measurement, unlike the reserve) and evict least
    recently used for them, and once the download finishes its own entry is
    evictable like any other."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "4096")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    root = pools["code"]
    old = _entry(root, "old", size=4096, age=1000)
    chunked = root / "chunked.part"

    admit_download(registry, chunked, None, 100 * 1024**3)
    chunked.write_bytes(b"x" * 8192)

    assert cache_module._root_usage(root, cache_entries(root)) > 8192
    assert evict_caches(registry) == [old]

    storage_module.release_download(chunked)
    chunked.rename(root / "chunked")

    assert cache_module._root_usage(root, cache_entries(root)) <= 8192


def test_the_cache_disk_is_read_once_per_admission(pools, monkeypatch):
    """Both the budget and the reserve held for an unmeasured body are shares
    of the cache disk's size. Reading it twice gave the second read its own
    failure path, which could not be reached (the first had just succeeded)
    and held the entire budget when it was."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "50%")
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "10%")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    root = pools["runtime"]
    reads: list[str] = []
    real_usage = shutil.disk_usage

    def counting_usage(path):
        reads.append(str(path))
        return real_usage(path)

    monkeypatch.setattr(cache_module.shutil, "disk_usage", counting_usage)

    admit_download(registry, root / "chunked.part", None, 100 * 1024**3)

    assert reads.count(str(root)) == 1
    total = real_usage(root).total
    assert storage_module.reserved_downloads()[root / "chunked.part"] == DownloadReservation(
        total // 10, measured=False
    )


def test_a_refused_download_evicts_nothing(pools, monkeypatch):
    """Admission evicted against one measure and refused against another: it
    stopped evicting once the bytes really on disk fitted, then refused on a
    total that counts the room an unmeasured download is holding. The entry
    was gone and the download failed anyway, which is the worst of both."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "8192")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["code"], "old", size=8192, age=1000)
    admit_download(registry, pools["code"] / "chunked.part", None, 100 * 1024**3)

    with pytest.raises(InsufficientResourcesError):
        admit_download(registry, pools["code"] / "measured.part", 4096)

    assert old.exists()


def test_a_measured_download_fits_beside_an_unknown_length_one(pools, monkeypatch):
    """The whole budget used to go to the chunked response, so the next
    measured download found the root at its cap: it evicted every unreferenced
    entry trying to make room that a guess was holding, and was refused
    anyway."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "16384")
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "4096")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    root = pools["code"]
    old = _entry(root, "old", size=4096, age=1000)
    chunked = root / "chunked.part"

    admit_download(registry, chunked, None, 100 * 1024**3)
    admit_download(registry, root / "measured.part", 4096)

    assert old.exists()
    assert storage_module.reserved_downloads()[chunked] == DownloadReservation(4096, measured=False)


def test_a_ceiling_reservation_never_drives_the_pass_to_evict(pools, monkeypatch):
    """A guess may make a later download wait, never make an entry go: until
    the chunked body writes bytes, the room it holds is hypothetical and the
    eviction target leaves it out."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "4096")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["code"], "old", size=8192, age=1000)

    admit_download(registry, pools["code"] / "chunked.part", None, 100 * 1024**3)

    assert evict_caches(registry) == []
    assert old.exists()


def test_the_bytes_a_ceiling_download_writes_are_counted_as_they_land(pools, monkeypatch):
    """The reconciliation of the guess: what the ``.part`` actually holds is a
    measurement, so it counts against the budget like any other blocks."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "8192")
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "4096")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    old = _entry(pools["code"], "old", size=8192, age=1000)
    chunked = pools["code"] / "chunked.part"

    admit_download(registry, chunked, None, 100 * 1024**3)
    chunked.write_bytes(b"x" * 4096)

    assert evict_caches(registry) == [old]


def test_both_downloads_together_stay_inside_the_budget(pools, monkeypatch):
    """The guess is a placeholder, not a licence: what the two downloads leave
    behind once they land is still under the cap."""
    monkeypatch.setattr(settings, "CACHE_BUDGET", "16384")
    monkeypatch.setattr(settings, "UNKNOWN_LENGTH_RESERVE", "4096")
    registry = AgentVmRegistry()
    cache_module.record_live_snapshot(set())
    root = pools["code"]
    _entry(root, "old", size=4096, age=1000)
    chunked = root / "chunked.part"
    measured = root / "measured.part"

    admit_download(registry, chunked, None, 100 * 1024**3)
    admit_download(registry, measured, 4096)
    for part in (chunked, measured):
        part.write_bytes(b"x" * 4096)
        storage_module.release_download(part)
        part.rename(part.with_suffix(""))

    assert cache_module._root_usage(root, cache_entries(root)) <= 16384
