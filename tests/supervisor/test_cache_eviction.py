from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from unittest.mock import MagicMock

import pytest
from aleph_message.models import ItemHash
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

import aleph.vm.agent.vm.cache as cache_module
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

NOW = datetime(2026, 8, 24, tzinfo=timezone.utc)
OLDER = datetime(2026, 8, 23, tzinfo=timezone.utc)


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
