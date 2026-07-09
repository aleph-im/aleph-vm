"""Tests for deterministic bundle packaging and manifest construction."""

import hashlib
import tarfile
from pathlib import Path

import pytest

from aleph.vm.vprogram.bundle import BUNDLE_INFO_NAME, BUNDLE_NAME, BundleInfo, build_bundle
from aleph.vm.vprogram.manifest import SourceInfo

ROOTHASH = "cb121a317be7dc7969dd633ca9b6c3718ffe9ea6715b64e0e35a871d484b56b8"
MEASUREMENT = "de" * 48
EPOCH = 1700000000

SOURCE = SourceInfo(
    repo="https://github.com/aleph-im/aleph-vm",
    rev="abc1234",
    build='nix build "git+file://$REPO?dir=nix#image"',
)


@pytest.fixture()
def image_dir(tmp_path: Path) -> Path:
    d = tmp_path / "image"
    d.mkdir()
    (d / "OVMF.fd").write_bytes(b"ovmf firmware")
    (d / "bzImage").write_bytes(b"kernel")
    (d / "initrd").write_bytes(b"initrd contents")
    (d / "rootfs.ext4").write_bytes(b"rootfs")
    (d / "rootfs.ext4.verity").write_bytes(b"hash tree")
    (d / "rootfs.ext4.roothash").write_text(ROOTHASH + "\n")
    (d / "measurement.hex").write_text(MEASUREMENT + "\n")
    return d


def _out(tmp_path: Path, name: str) -> Path:
    out = tmp_path / name
    out.mkdir()
    return out


def test_build_bundle_is_deterministic(image_dir: Path, tmp_path: Path) -> None:
    out1, out2 = _out(tmp_path, "out1"), _out(tmp_path, "out2")
    info1 = build_bundle(image_dir=image_dir, out_dir=out1, source_epoch=EPOCH, source=SOURCE)
    info2 = build_bundle(image_dir=image_dir, out_dir=out2, source_epoch=EPOCH, source=SOURCE)
    assert (out1 / BUNDLE_NAME).read_bytes() == (out2 / BUNDLE_NAME).read_bytes()
    assert info1 == info2


def test_bundle_info_matches_tarball(image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE)
    data = (out / BUNDLE_NAME).read_bytes()
    assert info.sha256 == hashlib.sha256(data).hexdigest()
    assert info.size == len(data)
    assert info.platform_roothash == ROOTHASH
    assert info.measurement == MEASUREMENT
    assert info.members.ovmf == "image/OVMF.fd"
    assert info.members.platform_hash_tree == "image/rootfs.ext4.verity"
    # The sidecar file round-trips to the same model.
    on_disk = BundleInfo.model_validate_json((out / BUNDLE_INFO_NAME).read_text())
    assert on_disk == info


def test_tarball_layout_and_metadata(image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    build_bundle(image_dir=image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE)
    with tarfile.open(out / BUNDLE_NAME, "r:gz") as tar:
        names = tar.getnames()
        members = tar.getmembers()
    assert names == [
        "image",
        "image/OVMF.fd",
        "image/bzImage",
        "image/initrd",
        "image/measurement.hex",
        "image/rootfs.ext4",
        "image/rootfs.ext4.roothash",
        "image/rootfs.ext4.verity",
    ]
    for member in members:
        assert member.uid == 0
        assert member.gid == 0
        assert member.uname == ""
        assert member.gname == ""
        assert member.mtime == EPOCH


def test_missing_image_file_is_an_error(image_dir: Path, tmp_path: Path) -> None:
    (image_dir / "initrd").unlink()
    with pytest.raises(FileNotFoundError):
        build_bundle(image_dir=image_dir, out_dir=_out(tmp_path, "out"), source_epoch=EPOCH, source=SOURCE)


def test_malformed_roothash_is_an_error(image_dir: Path, tmp_path: Path) -> None:
    (image_dir / "rootfs.ext4.roothash").write_text("not a hash\n")
    with pytest.raises(ValueError, match="roothash"):
        build_bundle(image_dir=image_dir, out_dir=_out(tmp_path, "out"), source_epoch=EPOCH, source=SOURCE)
