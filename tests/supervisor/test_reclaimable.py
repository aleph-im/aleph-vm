from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest
from aleph_message.models import (
    InstanceContent,
    ProgramContent,
    VerifiableProgramContent,
)
from reclaim_fixtures import OTHER_HASH, VM_HASH, pools, volume  # noqa: F401

from aleph.vm.agent.vm.reclaimable import (
    MARKER_NAME,
    ReclaimableMarker,
    adopt,
    clear_marker,
    depends_on_from_content,
    directory_size_bytes,
    iter_reclaimable,
    mark_reclaimable,
    read_marker,
    reclaimable_bytes,
    refs_from_content,
    write_marker,
)
from aleph.vm.storage import get_message

NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


def test_marker_round_trips_through_json():
    marker = ReclaimableMarker(
        reclaimable_since=NOW, reason="gone", size_bytes=42, depends_on=("abc", "def"), owner="0xOWNER"
    )
    text = marker.to_json()
    assert json.loads(text) == {
        "version": 1,
        "reclaimable_since": "2026-08-24T12:00:00+00:00",
        "reason": "gone",
        "size_bytes": 42,
        "depends_on": ["abc", "def"],
        "owner": "0xOWNER",
    }
    assert ReclaimableMarker.from_json(text) == marker


def test_a_marker_written_before_the_owner_field_still_parses():
    """Markers on disk predate the owner field; version stays 1 and they must
    keep parsing (they are simply markers nobody can be authorized against)."""
    text = json.dumps(
        {
            "version": 1,
            "reclaimable_since": "2026-08-24T12:00:00+00:00",
            "reason": "orphan",
            "size_bytes": 7,
            "depends_on": [],
        }
    )

    marker = ReclaimableMarker.from_json(text)

    assert marker.owner is None
    assert marker.reason == "orphan" and marker.size_bytes == 7


def test_read_marker_is_none_without_file(pools):  # noqa: F811
    directory = pools["pool0"] / VM_HASH
    directory.mkdir()
    assert read_marker(directory) is None


def test_read_marker_tolerates_a_corrupt_file(pools, caplog):  # noqa: F811
    directory = pools["pool0"] / VM_HASH
    directory.mkdir()
    (directory / MARKER_NAME).write_text("{not json")
    assert read_marker(directory) is None
    assert "corrupt" in caplog.text.lower()


def test_write_and_clear_marker(pools):  # noqa: F811
    directory = pools["pool0"] / VM_HASH
    directory.mkdir()
    write_marker(directory, ReclaimableMarker(reclaimable_since=NOW, reason="orphan", size_bytes=0))
    assert read_marker(directory).reason == "orphan"
    assert clear_marker(directory) is True
    assert clear_marker(directory) is False
    assert read_marker(directory) is None


def test_mark_reclaimable_writes_one_marker_per_pool_dir(pools):  # noqa: F811
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    volume(pools["pool1"], VM_HASH, "data.ext4", size=8192)

    written = mark_reclaimable(VM_HASH, "gone", ("parent-ref",), now=NOW)

    assert sorted(written) == sorted([pools["pool0"] / VM_HASH / MARKER_NAME, pools["pool1"] / VM_HASH / MARKER_NAME])
    marker0 = read_marker(pools["pool0"] / VM_HASH)
    marker1 = read_marker(pools["pool1"] / VM_HASH)
    assert marker0.reclaimable_since == NOW
    assert marker0.depends_on == ("parent-ref",)
    # size_bytes is per directory, so each pool's budget is local
    assert marker0.size_bytes == directory_size_bytes(pools["pool0"] / VM_HASH)
    assert marker1.size_bytes == directory_size_bytes(pools["pool1"] / VM_HASH)
    assert marker1.size_bytes >= 8192


def test_mark_reclaimable_refuses_an_implausible_namespace(pools):  # noqa: F811, ARG001
    with pytest.raises(ValueError):
        mark_reclaimable("../etc", "gone")


def test_directory_size_counts_only_regular_files_directly_inside(pools):  # noqa: F811
    directory = pools["pool0"] / VM_HASH
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    (directory / "sub").mkdir()
    (directory / "sub" / "big").write_bytes(b"x" * 100_000)
    assert 4096 <= directory_size_bytes(directory) < 100_000


def test_adopt_clears_every_marker_of_the_namespace(pools):  # noqa: F811
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    volume(pools["pool1"], VM_HASH, "data.ext4")
    volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    mark_reclaimable(OTHER_HASH, "gone", now=NOW)

    assert adopt(VM_HASH) == 2

    assert read_marker(pools["pool0"] / VM_HASH) is None
    assert read_marker(pools["pool1"] / VM_HASH) is None
    assert read_marker(pools["pool0"] / OTHER_HASH) is not None
    assert adopt(VM_HASH) == 0


def test_iter_reclaimable_and_reclaimable_bytes(pools):  # noqa: F811
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    volume(pools["pool1"], OTHER_HASH, "rootfs.qcow2", size=4096)
    volume(pools["pool1"], "dead" * 16, "rootfs.qcow2")  # live, unmarked
    mark_reclaimable(VM_HASH, "gone", now=NOW)
    mark_reclaimable(OTHER_HASH, "orphan", now=NOW + timedelta(hours=1))

    found = {path.name: marker for path, marker in iter_reclaimable()}
    assert set(found) == {VM_HASH, OTHER_HASH}
    assert reclaimable_bytes() == found[VM_HASH].size_bytes + found[OTHER_HASH].size_bytes
    assert reclaimable_bytes(pools["pool0"]) == found[VM_HASH].size_bytes


@pytest.mark.asyncio
async def test_depends_on_from_instance_content_lists_parent_refs():
    from aleph.vm.conf import settings

    message = await get_message(ref=settings.FAKE_INSTANCE_ID)
    content = message.content
    assert isinstance(content, InstanceContent)
    depends = depends_on_from_content(content)
    assert content.rootfs.parent.ref in depends
    for vol in content.volumes:
        parent = getattr(vol, "parent", None)
        if parent is not None:
            assert parent.ref in depends


def test_depends_on_from_program_content_has_no_parents(mocker):
    """A program's rootfs is the shared runtime cache entry, not a per-VM
    volume, so nothing here depends on a parent image."""
    content = mocker.MagicMock(spec=ProgramContent)
    vol_without_parent = mocker.MagicMock()
    vol_without_parent.parent = None
    content.volumes = [vol_without_parent, mocker.MagicMock(spec=[])]
    assert depends_on_from_content(content) == ()


def test_depends_on_deduplicates_parent_refs(mocker):
    content = mocker.MagicMock(spec=InstanceContent)
    content.rootfs = mocker.MagicMock()
    content.rootfs.parent = mocker.MagicMock(ref="same")
    volume_same = mocker.MagicMock()
    volume_same.parent = mocker.MagicMock(ref="same")
    volume_other = mocker.MagicMock()
    volume_other.parent = mocker.MagicMock(ref="other")
    content.volumes = [volume_same, volume_other]
    assert depends_on_from_content(content) == ("same", "other")


def test_refs_from_content_covers_a_vprogram_workload(mocker):
    """A V-PROGRAM's workload image and hash tree are attached as the VM's
    disks straight from DATA_CACHE, so they are refs like any other."""
    content = mocker.MagicMock(spec=VerifiableProgramContent)
    content.runtime = mocker.MagicMock(ref="manifest")
    content.volumes = []
    content.workload = mocker.MagicMock(ref="workload", hash_tree="hashtree")
    content.environment = mocker.MagicMock(trusted_execution=None)

    assert refs_from_content(content, vm_hash="vmhash") == {"manifest", "workload", "hashtree", "vmhash"}


def test_refs_from_content_covers_trusted_execution(mocker):
    content = mocker.MagicMock(spec=InstanceContent)
    content.rootfs = mocker.MagicMock()
    content.rootfs.parent = mocker.MagicMock(ref="base")
    content.volumes = []
    content.environment = mocker.MagicMock()
    content.environment.trusted_execution = mocker.MagicMock(firmware="firmware", runtime="tee-runtime")

    assert refs_from_content(content) == {"base", "firmware", "tee-runtime"}


def test_depends_on_is_the_parent_subset_of_the_same_enumeration(mocker):
    """One traversal, two questions: the marker pins the parent images its
    volumes are built on, not everything the message names."""
    content = mocker.MagicMock(spec=VerifiableProgramContent)
    content.runtime = mocker.MagicMock(ref="manifest")
    parent_backed = mocker.MagicMock(ref=None)
    parent_backed.parent = mocker.MagicMock(ref="parent")
    content.volumes = [parent_backed]
    content.workload = mocker.MagicMock(ref="workload", hash_tree="hashtree")
    content.environment = mocker.MagicMock(trusted_execution=None)

    assert depends_on_from_content(content) == ("parent",)
    assert set(depends_on_from_content(content)) <= refs_from_content(content)
