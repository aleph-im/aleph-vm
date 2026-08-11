"""Tests for deterministic bundle packaging and manifest construction."""

import hashlib
import tarfile
from pathlib import Path

import pytest
from pydantic import ValidationError

from aleph.vm.vprogram.bundle import (
    BUNDLE_INFO_NAME,
    BUNDLE_NAME,
    CMDLINE_TEMPLATE_EXEC_V1,
    BundleInfo,
    build_bundle,
    make_manifest,
    verify_bundle_info,
)
from aleph.vm.vprogram.manifest import RuntimeManifest, SourceInfo

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
        extracted_kernel = tar.extractfile("image/bzImage")
        assert extracted_kernel is not None
        assert extracted_kernel.read() == b"kernel"
        extracted_roothash = tar.extractfile("image/rootfs.ext4.roothash")
        assert extracted_roothash is not None
        assert extracted_roothash.read() == (ROOTHASH + "\n").encode()
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


BUNDLE_REF = "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977"


def test_make_manifest_from_bundle_info(image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE)
    manifest = make_manifest(info=info, bundle_ref=BUNDLE_REF, name="aleph-snp-attest", runtime_version="2026.07.08")
    # The result re-validates from its own canonical JSON.
    reparsed = RuntimeManifest.model_validate_json(manifest.to_canonical_json())
    assert reparsed == manifest
    assert manifest.bundle.ref == BUNDLE_REF
    assert manifest.bundle.sha256 == info.sha256
    assert manifest.bundle.size == info.size
    assert manifest.bundle.members == info.members
    assert manifest.boot.platform_roothash == info.platform_roothash
    expected_cmdline = "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}"
    assert manifest.boot.cmdline_template == expected_cmdline
    assert manifest.boot.cpu_models == ["EPYC-v4"]
    assert manifest.attestation[0].protocol == "aleph.ra-tls"
    assert manifest.attestation[0].transport.port == 8443
    assert manifest.workload.contract == "aleph.builtin/1"
    assert manifest.workload.upstream_port == 8080
    assert manifest.source == SOURCE


def test_make_manifest_does_not_alias_module_defaults(image_dir: Path, tmp_path: Path) -> None:
    info = build_bundle(image_dir=image_dir, out_dir=_out(tmp_path, "out"), source_epoch=EPOCH, source=SOURCE)
    first = make_manifest(info=info, bundle_ref=BUNDLE_REF, name="x", runtime_version="1")
    second = make_manifest(info=info, bundle_ref=BUNDLE_REF, name="x", runtime_version="1")
    assert first.workload == second.workload
    assert first.workload is not second.workload
    assert first.attestation[0] == second.attestation[0]
    assert first.attestation[0] is not second.attestation[0]


def test_exec_manifest_uses_workload_template(image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE)
    manifest = make_manifest(
        info=info, bundle_ref=BUNDLE_REF, name="aleph-exec", runtime_version="2026.07.08", exec_runtime=True
    )
    RuntimeManifest.model_validate(manifest.model_dump(mode="json"))
    assert manifest.boot.cmdline_template == CMDLINE_TEMPLATE_EXEC_V1
    assert manifest.workload.contract == "aleph.exec/1"
    assert manifest.workload.upstream_port == 8080


def test_make_manifest_rejects_bad_ref(image_dir: Path, tmp_path: Path) -> None:
    info = build_bundle(image_dir=image_dir, out_dir=_out(tmp_path, "out"), source_epoch=EPOCH, source=SOURCE)
    with pytest.raises(ValidationError):
        make_manifest(info=info, bundle_ref="not-a-hash", name="x", runtime_version="1")


def test_verify_bundle_info_accepts_untampered(image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE)
    verify_bundle_info(info, out / BUNDLE_NAME)  # must not raise


def test_verify_bundle_info_rejects_tampered(image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE)
    tar_path = out / BUNDLE_NAME
    tar_path.write_bytes(tar_path.read_bytes() + b"x")
    with pytest.raises(ValueError, match="does not match"):
        verify_bundle_info(info, tar_path)
