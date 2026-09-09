from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

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


def test_a_failed_marker_write_leaves_no_temp_file(pools, monkeypatch, caplog):  # noqa: F811
    """A replace that fails (ENOSPC, EACCES) must not strand the temp file:
    nothing else would ever collect it from the VM directory. Nor may it
    raise: a GONE retire and the namespace pass both call this, and at
    startup the pass runs inside the on_startup hook, where a raise on a
    full pool would stop the agent from booting."""
    import aleph.vm.agent.vm.reclaimable as reclaimable_module

    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")

    def refuse(src, dst):
        raise OSError("no space left on device")

    monkeypatch.setattr(reclaimable_module.os, "replace", refuse)

    assert mark_reclaimable(VM_HASH, "gone") == []

    assert read_marker(pools["pool0"] / VM_HASH) is None
    assert list((pools["pool0"] / VM_HASH).glob("*.tmp")) == []
    assert "Could not write the reclaimable marker" in caplog.text


@pytest.mark.parametrize("content", ["[]", '"x"', "null", "42", "{not json", '{"reason": "gone"}'])
def test_a_corrupt_marker_is_removed_and_reads_as_none(pools, content):  # noqa: F811
    """Valid JSON that is not an object used to escape read_marker as an
    AttributeError, which iter_reclaimable() fed straight into every
    admission check. Every corrupt shape now reads as no marker, and the file
    goes, so the directory is not wedged forever (the exclusive orphan write
    backs off from any existing file)."""
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    marker_path = pools["pool0"] / VM_HASH / MARKER_NAME
    marker_path.write_text(content)

    assert read_marker(pools["pool0"] / VM_HASH) is None
    assert not marker_path.exists()
    assert reclaimable_bytes() == 0


def test_clearing_a_marker_that_vanished_first_is_quiet(pools, monkeypatch):  # noqa: F811
    """Two adopters, or a pass clearing a stale marker while a create adopts:
    the loser must not raise out of adopt() and fail the create."""
    directory = pools["pool0"] / VM_HASH
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone")
    real_unlink = Path.unlink

    def vanish_then_unlink(self, *args, **kwargs):
        if self.name == MARKER_NAME:
            real_unlink(self)
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", vanish_then_unlink)

    assert clear_marker(directory) is False
    assert read_marker(directory) is None


def test_a_failed_marker_write_of_the_temp_file_leaves_nothing_behind(pools, monkeypatch):  # noqa: F811
    """ENOSPC can hit the temp file write itself, not only the publish."""
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    real_write_text = Path.write_text

    def refuse(self, *args, **kwargs):
        if self.name.endswith(".tmp"):
            (self.parent / self.name).touch()
            raise OSError("no space left on device")
        return real_write_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", refuse)

    assert mark_reclaimable(VM_HASH, "gone") == []

    assert list((pools["pool0"] / VM_HASH).glob("*.tmp")) == []


def test_an_exclusive_write_that_the_filesystem_refuses_is_not_a_marker(pools, monkeypatch, caplog):  # noqa: F811
    """No hardlinks (or no space): the directory stays unmarked and the pass
    goes on, rather than aborting on this one directory."""
    import aleph.vm.agent.vm.reclaimable as reclaimable_module

    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")

    def refuse(src, dst):
        raise PermissionError("hard links not supported")

    monkeypatch.setattr(reclaimable_module.os, "link", refuse)

    assert mark_reclaimable(VM_HASH, "orphan") == []
    assert read_marker(pools["pool0"] / VM_HASH) is None
    assert list((pools["pool0"] / VM_HASH).glob("*.tmp")) == []
    assert "Could not write the reclaimable marker" in caplog.text


def test_reclaimable_bytes_is_cached_between_marker_changes(pools, monkeypatch):  # noqa: F811
    """Admission asks on every request; the walk must not happen every time,
    and must not be stale after a marker is written, cleared, or its whole
    directory removed."""
    import shutil

    import aleph.vm.agent.vm.reclaimable as reclaimable_module

    walks = []
    real_iter = reclaimable_module.iter_reclaimable

    def counting_iter(**kwargs):
        walks.append(1)
        return real_iter(**kwargs)

    monkeypatch.setattr(reclaimable_module, "iter_reclaimable", counting_iter)
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=8192)
    volume(pools["pool0"], OTHER_HASH, "rootfs.qcow2", size=8192)
    mark_reclaimable(VM_HASH, "gone")
    mark_reclaimable(OTHER_HASH, "gone")

    assert reclaimable_bytes() == 16384
    assert reclaimable_bytes() == 16384
    assert len(walks) == 1, "the second call must be served from the cache"

    clear_marker(pools["pool0"] / VM_HASH)
    assert reclaimable_bytes() == 8192, "an in-process marker change invalidates at once"

    shutil.rmtree(pools["pool0"] / OTHER_HASH)
    assert reclaimable_bytes() == 0, "a directory that went away changes the pool's mtime"


def test_an_orphan_marker_never_overwrites_an_existing_marker(pools):  # noqa: F811
    """The periodic pass can decide "orphan" in the window where a GONE
    retire is writing the real marker; the gone marker carries the owner and
    the parent-image pins, so the orphan write must lose that race, not win
    it."""
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    mark_reclaimable(VM_HASH, "gone", ("parent",), owner="0xOWNER")

    written = mark_reclaimable(VM_HASH, "orphan")

    marker = read_marker(pools["pool0"] / VM_HASH)
    assert written == []
    assert marker is not None
    assert marker.reason == "gone" and marker.owner == "0xOWNER" and marker.depends_on == ("parent",)


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


def test_the_cache_is_invalidated_after_the_publish_too(pools, monkeypatch):  # noqa: F811
    """A reader that computes between the pre-write invalidation and the
    os.replace caches the pre-change sum; the pool directory's mtime does not
    move on a marker write, so the fingerprint would keep that stale value
    for the whole TTL. Invalidating after the publish closes the window."""
    import aleph.vm.agent.vm.reclaimable as reclaimable_module

    volume(pools["pool0"], VM_HASH, "rootfs.qcow2", size=4096)
    real_replace = reclaimable_module.os.replace
    seen_mid_write = []

    def read_then_replace(src, dst):
        seen_mid_write.append(reclaimable_bytes())
        return real_replace(src, dst)

    monkeypatch.setattr(reclaimable_module.os, "replace", read_then_replace)

    mark_reclaimable(VM_HASH, "gone")

    assert seen_mid_write == [0]
    assert reclaimable_bytes() == 4096


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


def test_a_reader_that_may_not_repair_keeps_a_corrupt_marker(pools):  # noqa: F811
    """The repair is the reconciler's, not every reader's. A read-only caller
    (the storage CLI's status and list) must leave the file where it is: it
    may be running as a user who cannot unlink it at all, and an operator
    inspecting a node has not asked for anything on disk to change."""
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    marker_path = pools["pool0"] / VM_HASH / MARKER_NAME
    marker_path.write_text("{not json")

    assert read_marker(pools["pool0"] / VM_HASH, repair=False) is None
    assert marker_path.exists()
    assert reclaimable_bytes(repair=False) == 0
    assert marker_path.exists()


def test_a_corrupt_marker_that_cannot_be_removed_still_reads_as_none(pools, monkeypatch, caplog):  # noqa: F811
    """Removing the corrupt marker is best effort: a read-only filesystem or
    a marker this user does not own must not raise out of a pass that was
    only reading."""
    volume(pools["pool0"], VM_HASH, "rootfs.qcow2")
    marker_path = pools["pool0"] / VM_HASH / MARKER_NAME
    marker_path.write_text("{not json")
    real_unlink = Path.unlink

    def refuse(self, *args, **kwargs):
        if self.name == MARKER_NAME:
            raise PermissionError("not yours to remove")
        return real_unlink(self, *args, **kwargs)

    monkeypatch.setattr(Path, "unlink", refuse)

    assert read_marker(pools["pool0"] / VM_HASH) is None
    assert "Could not remove" in caplog.text


def test_a_timestamp_without_an_offset_reads_as_utc():
    """A hand-edited marker (an operator restoring one, an older writer) can
    carry a naive timestamp. Parsed naive it mixes with the aware clock
    everything else uses, and every subtraction raises TypeError."""
    text = json.dumps(
        {
            "version": 1,
            "reclaimable_since": "2026-08-24T12:00:00",
            "reason": "gone",
            "size_bytes": 7,
            "depends_on": [],
        }
    )

    marker = ReclaimableMarker.from_json(text)

    assert marker.reclaimable_since == NOW
    assert marker.reclaimable_since.tzinfo is not None
    assert (datetime.now(tz=timezone.utc) - marker.reclaimable_since).total_seconds() > 0
