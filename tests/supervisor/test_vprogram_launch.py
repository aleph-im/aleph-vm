"""Tests for the V-PROGRAM SEV-SNP launch path (agent side).

Everything runs offline: get_existing_file is monkeypatched to serve a
manifest JSON and a locally built bundle tarball from tmp_path, mirroring
the real layout (#1050: members under an ``image/`` prefix, dm-verity
sidecars adjacent to rootfs.ext4).
"""

import copy
import gzip
import hashlib
import io
import json
import shutil
import tarfile
from pathlib import Path
from typing import IO, Any, cast

import pytest
from aleph_message.models import VerifiableProgramMessage, parse_message

from aleph.vm.agent.vprogram_launch import (
    build_vprogram_spec,
    fetch_runtime_manifest,
    vprogram_staging_dir,
)
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    Backend,
    DiskFormat,
    DiskRole,
    TeeBackend,
)
from aleph.vm.vprogram.manifest import RuntimeManifest

FIXTURE = Path(__file__).parent / "fixtures" / "vprogram_message.json"

MANIFEST_REF = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"
BUNDLE_REF = "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977"
PLATFORM_ROOTHASH = "cb121a317be7dc7969dd633ca9b6c3718ffe9ea6715b64e0e35a871d484b56b8"

# Matches content.workload in tests/supervisor/fixtures/vprogram_message.json:
# the fixture message always carries a workload block (the field is required
# on VerifiableProgramContent), so every test that runs build_vprogram_spec
# to completion needs get_existing_file to resolve these two refs too.
WORKLOAD_REF = "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
WORKLOAD_HASH_TREE_REF = "feedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeedfeed"
WORKLOAD_ROOTHASH = "cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"

# The reference manifest shape (tests/vprogram/test_manifest.py), with the
# bundle digest/size patched per-test to match the locally built tarball.
MANIFEST_TEMPLATE: dict[str, Any] = {
    "format": "aleph-vprogram-runtime",
    "format_version": 1,
    "name": "aleph-snp-attest",
    "version": "2026.07.08",
    "platform": "sev_snp",
    "bundle": {
        "ref": BUNDLE_REF,
        "sha256": "0" * 64,
        "size": 1,
        "members": {
            "ovmf": "image/OVMF.fd",
            "kernel": "image/bzImage",
            "initrd": "image/initrd",
            "platform_rootfs": "image/rootfs.ext4",
            "platform_hash_tree": "image/rootfs.ext4.verity",
        },
    },
    "boot": {
        "method": "qemu-direct-kernel",
        "kernel_hashes": True,
        "cpu_models": ["EPYC-v4"],
        "platform_roothash": PLATFORM_ROOTHASH,
        "cmdline_template": "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}",
    },
    "attestation": [{"protocol": "aleph.ra-tls", "version": "1", "transport": {"type": "tcp", "port": 8443}}],
    "workload": {"contract": "aleph.builtin/1", "upstream_port": 8080},
    "source": {
        "repo": "https://github.com/aleph-im/aleph-vm",
        "rev": "4d90abaf",
        "build": 'nix build "git+file://$REPO?dir=nix#image"',
    },
}

BUNDLE_FILES: dict[str, bytes] = {
    "OVMF.fd": b"ovmf firmware blob",
    "bzImage": b"kernel image",
    "initrd": b"initial ramdisk",
    "rootfs.ext4": b"platform rootfs",
    "rootfs.ext4.verity": b"dm-verity hash tree",
    "rootfs.ext4.roothash": PLATFORM_ROOTHASH.encode() + b"\n",
}


def load_vprogram_message() -> VerifiableProgramMessage:
    message = parse_message(json.loads(FIXTURE.read_text()))
    assert isinstance(message, VerifiableProgramMessage)
    return message


def make_bundle(out_dir: Path, files: dict[str, bytes] | None = None) -> Path:
    """Build a tar.gz shaped like the #1050 bundle: members under image/."""
    files = BUNDLE_FILES if files is None else files
    tar_path = out_dir / "snp-image.tar.gz"
    with tar_path.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=cast(IO[bytes], gz), mode="w") as tar:
                directory = tarfile.TarInfo("image")
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                tar.addfile(directory)
                for name, data in sorted(files.items()):
                    member = tarfile.TarInfo(f"image/{name}")
                    member.size = len(data)
                    member.mode = 0o644
                    tar.addfile(member, io.BytesIO(data))
    return tar_path


def make_manifest(tar_path: Path, out_dir: Path, **overrides: Any) -> Path:
    """Write a manifest JSON whose bundle digest/size match tar_path."""
    data = copy.deepcopy(MANIFEST_TEMPLATE)
    raw = tar_path.read_bytes()
    data["bundle"]["sha256"] = hashlib.sha256(raw).hexdigest()
    data["bundle"]["size"] = len(raw)
    for dotted, value in overrides.items():
        target = data
        *parents, leaf = dotted.split(".")
        for key in parents:
            target = target[key]
        target[leaf] = value
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(data))
    return manifest_path


@pytest.fixture
def storage_files(tmp_path, monkeypatch) -> dict[str, Path]:
    """Serve get_existing_file from a local ref -> path map: no network."""
    files: dict[str, Path] = {}

    async def fake_get_existing_file(ref: str) -> Path:
        return files[str(ref)]

    monkeypatch.setattr("aleph.vm.agent.vprogram_launch.get_existing_file", fake_get_existing_file)
    return files


def stage_workload(storage_files: dict[str, Path], tmp_path: Path) -> dict[str, Path]:
    """Register the fixture message's workload ref + hash_tree with
    get_existing_file, mirroring how the runtime bundle members are staged."""
    data_path = tmp_path / "workload_data.img"
    data_path.write_bytes(b"workload data volume")
    hashtree_path = tmp_path / "workload_hashtree.img"
    hashtree_path.write_bytes(b"workload hash tree")
    storage_files[WORKLOAD_REF] = data_path
    storage_files[WORKLOAD_HASH_TREE_REF] = hashtree_path
    return {"data": data_path, "hashtree": hashtree_path}


@pytest.fixture
def staged_bundle(tmp_path, storage_files) -> dict[str, Path]:
    tar_path = make_bundle(tmp_path)
    manifest_path = make_manifest(tar_path, tmp_path)
    storage_files[MANIFEST_REF] = manifest_path
    storage_files[BUNDLE_REF] = tar_path
    workload = stage_workload(storage_files, tmp_path)
    return {"tar": tar_path, "manifest": manifest_path, **workload}


@pytest.mark.asyncio
async def test_fetch_runtime_manifest_parses(staged_bundle):
    manifest = await fetch_runtime_manifest(MANIFEST_REF)
    assert isinstance(manifest, RuntimeManifest)
    assert manifest.platform == "sev_snp"
    assert manifest.bundle.members.platform_rootfs == "image/rootfs.ext4"
    assert manifest.boot.platform_roothash == PLATFORM_ROOTHASH


@pytest.mark.asyncio
async def test_fetch_runtime_manifest_rejects_garbage(tmp_path, storage_files):
    bad = tmp_path / "manifest.json"
    bad.write_text('{"format": "not-a-runtime"}')
    storage_files[MANIFEST_REF] = bad
    with pytest.raises(VmSetupError, match="invalid"):
        await fetch_runtime_manifest(MANIFEST_REF)


@pytest.mark.asyncio
async def test_bundle_sha256_mismatch_fails_closed(tmp_path, storage_files):
    """The manifest's sha256 is the integrity gate: a tarball with different
    bytes must never be extracted or launched."""
    tar_path = make_bundle(tmp_path)
    manifest_path = make_manifest(tar_path, tmp_path, **{"bundle.sha256": "f" * 64})
    storage_files[MANIFEST_REF] = manifest_path
    storage_files[BUNDLE_REF] = tar_path

    message = load_vprogram_message()
    staging = vprogram_staging_dir(message.item_hash)
    if staging.exists():  # leftover from a previous pytest run: EXECUTION_ROOT persists
        shutil.rmtree(staging)
    with pytest.raises(VmSetupError, match="sha256 mismatch"):
        await build_vprogram_spec(message.item_hash, message.content)
    # Fail closed means nothing was staged.
    assert not staging.exists()


@pytest.mark.asyncio
async def test_bundle_size_mismatch_fails_closed(tmp_path, storage_files):
    tar_path = make_bundle(tmp_path)
    manifest_path = make_manifest(tar_path, tmp_path, **{"bundle.size": 7})
    storage_files[MANIFEST_REF] = manifest_path
    storage_files[BUNDLE_REF] = tar_path

    message = load_vprogram_message()
    staging = vprogram_staging_dir(message.item_hash)
    if staging.exists():  # leftover from a previous pytest run: EXECUTION_ROOT persists
        shutil.rmtree(staging)
    with pytest.raises(VmSetupError, match="size mismatch"):
        await build_vprogram_spec(message.item_hash, message.content)
    # The size gate runs before extraction, so nothing is staged (symmetric
    # with the sha256 mismatch test).
    assert not staging.exists()


@pytest.mark.asyncio
async def test_build_vprogram_spec(staged_bundle):
    """The spec mirrors the on-host SNP launch template: QEMU + SEV_SNP tee,
    direct-kernel boot from the extracted members, and a disk order that IS
    the guest contract: platform rootfs (/dev/vda), platform hash tree
    (/dev/vdb), workload data (/dev/vdc), workload hash tree (/dev/vdd);
    persistent."""
    message = load_vprogram_message()
    content = message.content
    spec = await build_vprogram_spec(message.item_hash, content)

    staging = vprogram_staging_dir(message.item_hash)
    assert spec.vm_id == str(message.item_hash)
    assert spec.backend is Backend.QEMU
    assert spec.kernel_path == staging / "image/bzImage"
    assert spec.initrd_path == staging / "image/initrd"
    assert spec.kernel_path.read_bytes() == b"kernel image"

    # The platform hash tree is NOT a spec disk: the daemon force-inserts
    # {rootfs}.verity as the first SNP host volume (/dev/vdb). The spec carries
    # only the rootfs + the workload data/hash tree (/dev/vdc, /dev/vdd).
    assert [d.path for d in spec.disks] == [
        staging / "image/rootfs.ext4",
        staged_bundle["data"],
        staged_bundle["hashtree"],
    ]
    assert [d.role for d in spec.disks] == [
        DiskRole.ROOTFS,
        DiskRole.EXTRA,
        DiskRole.EXTRA,
    ]
    assert all(d.readonly for d in spec.disks)
    assert all(d.format is DiskFormat.RAW for d in spec.disks)
    # The platform verity sidecar still exists on disk for the daemon.
    assert (staging / "image/rootfs.ext4.verity").is_file()

    assert spec.vcpus == content.resources.vcpus == 2
    assert spec.memory_mib == content.resources.memory == 2048

    assert spec.tee is not None
    assert spec.tee.backend is TeeBackend.SEV_SNP
    assert spec.tee.policy == str(content.verification.policy) == "196608"
    assert spec.tee.firmware_path == staging / "image/OVMF.fd"

    assert spec.network.internet_access is True
    assert spec.network.requested_ipv6 == ""
    assert spec.network.ipv6_prefix_len == 0
    assert spec.persistent is True
    assert spec.gpus == []
    assert spec.ssh_authorized_keys == []


@pytest.mark.asyncio
async def test_roothash_sidecar_present_after_staging(staged_bundle):
    """The daemon derives the measured cmdline from <rootfs>.roothash and the
    hash tree from <rootfs>.verity next to the rootfs disk: both must be in
    place after staging, with the manifest's platform roothash."""
    message = load_vprogram_message()
    spec = await build_vprogram_spec(message.item_hash, message.content)

    rootfs = spec.rootfs.path
    roothash_sidecar = rootfs.with_name(rootfs.name + ".roothash")
    verity_sidecar = rootfs.with_name(rootfs.name + ".verity")
    assert roothash_sidecar.is_file()
    assert roothash_sidecar.read_text().strip() == PLATFORM_ROOTHASH
    assert verity_sidecar.is_file()


@pytest.mark.asyncio
async def test_roothash_sidecar_written_when_bundle_lacks_it(tmp_path, storage_files):
    """A bundle without the roothash sidecar (only the 5 declared members)
    still stages one, sourced from manifest.boot.platform_roothash."""
    files = {name: data for name, data in BUNDLE_FILES.items() if name != "rootfs.ext4.roothash"}
    tar_path = make_bundle(tmp_path, files)
    storage_files[MANIFEST_REF] = make_manifest(tar_path, tmp_path)
    storage_files[BUNDLE_REF] = tar_path
    stage_workload(storage_files, tmp_path)

    message = load_vprogram_message()
    spec = await build_vprogram_spec(message.item_hash, message.content)
    rootfs = spec.rootfs.path
    assert rootfs.with_name(rootfs.name + ".roothash").read_text().strip() == PLATFORM_ROOTHASH


@pytest.mark.asyncio
async def test_roothash_sidecar_disagreeing_with_manifest_fails_closed(tmp_path, storage_files):
    """A tarball sidecar that contradicts the manifest's platform_roothash is
    a mispackaged or tampered bundle: never boot a mismeasured VM."""
    files = dict(BUNDLE_FILES)
    files["rootfs.ext4.roothash"] = b"a" * 64 + b"\n"
    tar_path = make_bundle(tmp_path, files)
    storage_files[MANIFEST_REF] = make_manifest(tar_path, tmp_path)
    storage_files[BUNDLE_REF] = tar_path

    message = load_vprogram_message()
    with pytest.raises(VmSetupError, match="disagrees with the manifest"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_missing_member_fails_closed(tmp_path, storage_files):
    """A verified tarball that still lacks a declared member must fail before
    any spec is produced."""
    files = {name: data for name, data in BUNDLE_FILES.items() if name != "bzImage"}
    tar_path = make_bundle(tmp_path, files)
    storage_files[MANIFEST_REF] = make_manifest(tar_path, tmp_path)
    storage_files[BUNDLE_REF] = tar_path

    message = load_vprogram_message()
    with pytest.raises(VmSetupError, match="kernel missing"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_corrupt_tarball_fails_closed_on_extract(tmp_path, storage_files):
    """A blob that passes the sha256+size gate but is not a valid gzip/tar
    stream must surface as VmSetupError from the extract step (fail closed),
    not an opaque tarfile/OS error, and stage no members."""
    blob = tmp_path / "snp-image.tar.gz"
    blob.write_bytes(b"not a gzip stream, but of the right length" * 4)
    # Digest and size are computed from the blob, so integrity passes and the
    # failure is forced into _extract_bundle rather than the sha256/size gate.
    storage_files[MANIFEST_REF] = make_manifest(blob, tmp_path)
    storage_files[BUNDLE_REF] = blob

    message = load_vprogram_message()
    staging = vprogram_staging_dir(message.item_hash)
    if staging.exists():  # leftover from a previous pytest run: EXECUTION_ROOT persists
        shutil.rmtree(staging)
    with pytest.raises(VmSetupError, match="cannot extract runtime bundle"):
        await build_vprogram_spec(message.item_hash, message.content)
    # Fail closed leaves no partial staging behind: the except branch removes it.
    assert not staging.exists()


@pytest.mark.asyncio
async def test_workload_attached_and_sidecar_written(staged_bundle):
    """content.workload is attached as two EXTRA disks (data, then hash tree)
    after the rootfs, and its roothash is staged in a sidecar next to the
    rootfs: the daemon has no cmdline field on the proto, so this sidecar is
    the only way it learns 'workload_roothash=<hex>'. The platform hash tree
    is NOT a spec disk (the daemon force-inserts it as /dev/vdb), so the
    workload data/hash tree land at /dev/vdc, /dev/vdd."""
    message = load_vprogram_message()
    content = message.content
    assert content.workload.roothash == WORKLOAD_ROOTHASH
    spec = await build_vprogram_spec(message.item_hash, content)

    assert len(spec.disks) == 3
    assert [d.role for d in spec.disks] == [
        DiskRole.ROOTFS,
        DiskRole.EXTRA,
        DiskRole.EXTRA,
    ]
    assert spec.disks[1].path == staged_bundle["data"]
    assert spec.disks[2].path == staged_bundle["hashtree"]
    assert all(d.readonly for d in spec.disks[1:])
    assert all(d.format is DiskFormat.RAW for d in spec.disks[2:])

    rootfs = spec.rootfs.path
    sidecar = rootfs.with_name(rootfs.name + ".workload_roothash")
    assert sidecar.is_file()
    assert sidecar.read_text() == content.workload.roothash


@pytest.mark.asyncio
async def test_workload_roothash_non_hex_fails_closed(staged_bundle):
    """A workload roothash that is not bare hex must never be staged or
    attached: the daemon trusts the sidecar content verbatim, appending it to
    the measured cmdline unquoted."""
    message = load_vprogram_message()
    bad_workload = message.content.workload.model_copy(update={"roothash": "not-bare-hex!!"})
    content = message.content.model_copy(update={"workload": bad_workload})

    with pytest.raises(VmSetupError, match="not bare hex"):
        await build_vprogram_spec(message.item_hash, content)

    staging = vprogram_staging_dir(message.item_hash)
    rootfs = staging / "image" / "rootfs.ext4"
    assert not rootfs.with_name(rootfs.name + ".workload_roothash").is_file()
