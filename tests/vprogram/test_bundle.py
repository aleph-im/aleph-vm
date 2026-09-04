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
    CMDLINE_TEMPLATE_GPU_V1,
    CMDLINE_TEMPLATE_LUKS_V1,
    BundleInfo,
    InstanceBundleInfo,
    build_bundle,
    make_instance_manifest,
    make_manifest,
    verify_bundle_info,
)
from aleph.vm.vprogram.manifest import (
    InstanceRuntimeManifest,
    RuntimeManifest,
    SourceInfo,
)

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


@pytest.fixture()
def gpu_image_dir(image_dir: Path) -> Path:
    """The nix gpuImage output: same layout as image_dir, plus the gpu.json
    facts sidecar the gpu flavor reads."""
    (image_dir / "gpu.json").write_text(
        '{"vendor":"nvidia","arch":"blackwell","driver_version":"595.71.05",'
        '"accepted_models":["NVIDIA RTX PRO 6000 Blackwell Server Edition"],'
        '"library_path":"/opt/nvidia/lib"}'
    )
    return image_dir


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


def test_compose_manifest_uses_workload_template(image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE)
    manifest = make_manifest(
        info=info, bundle_ref=BUNDLE_REF, name="aleph-compose", runtime_version="2026.08.20", compose_runtime=True
    )
    RuntimeManifest.model_validate(manifest.model_dump(mode="json"))
    assert manifest.boot.cmdline_template == CMDLINE_TEMPLATE_EXEC_V1
    assert manifest.workload.contract == "aleph.compose/1"
    assert manifest.workload.upstream_port == 8080


def test_make_manifest_rejects_exec_and_compose_together(image_dir: Path, tmp_path: Path) -> None:
    # The CLI cannot express this combination (--exec is rejected with
    # --flavor compose before cmd_manifest runs), so this guards direct
    # library callers of make_manifest.
    info = build_bundle(image_dir=image_dir, out_dir=_out(tmp_path, "out"), source_epoch=EPOCH, source=SOURCE)
    with pytest.raises(ValueError, match="mutually exclusive"):
        make_manifest(
            info=info, bundle_ref=BUNDLE_REF, name="x", runtime_version="1", exec_runtime=True, compose_runtime=True
        )


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


@pytest.fixture()
def instance_image_dir(tmp_path: Path) -> Path:
    """The nix instanceImage output: OVMF/kernel/initrd only, no verity sidecars."""
    d = tmp_path / "instance-image"
    d.mkdir()
    (d / "OVMF.fd").write_bytes(b"ovmf firmware")
    (d / "bzImage").write_bytes(b"kernel")
    (d / "initrd").write_bytes(b"initrd contents")
    return d


def test_build_bundle_instance_flavor(instance_image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=instance_image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE, flavor="instance")
    data = (out / BUNDLE_NAME).read_bytes()
    assert isinstance(info, InstanceBundleInfo)
    assert info.sha256 == hashlib.sha256(data).hexdigest()
    assert info.size == len(data)
    assert info.members.ovmf == "image/OVMF.fd"
    assert info.members.kernel == "image/bzImage"
    assert info.members.initrd == "image/initrd"
    assert not hasattr(info, "platform_roothash")
    assert not hasattr(info, "measurement")
    with tarfile.open(out / BUNDLE_NAME, "r:gz") as tar:
        assert tar.getnames() == ["image", "image/OVMF.fd", "image/bzImage", "image/initrd"]
    on_disk = InstanceBundleInfo.model_validate_json((out / BUNDLE_INFO_NAME).read_text())
    assert on_disk == info


def test_build_bundle_instance_flavor_ignores_verity_sidecars(instance_image_dir: Path, tmp_path: Path) -> None:
    """The instance image dir never has roothash/measurement sidecars; a
    vprogram-flavor build against the same dir would fail, proving the
    instance flavor does not read them."""
    with pytest.raises(FileNotFoundError):
        build_bundle(image_dir=instance_image_dir, out_dir=_out(tmp_path, "out"), source_epoch=EPOCH, source=SOURCE)
    # But the instance flavor succeeds against the very same directory.
    build_bundle(
        image_dir=instance_image_dir,
        out_dir=_out(tmp_path, "out2"),
        source_epoch=EPOCH,
        source=SOURCE,
        flavor="instance",
    )


def test_build_bundle_instance_flavor_missing_file_is_an_error(instance_image_dir: Path, tmp_path: Path) -> None:
    (instance_image_dir / "bzImage").unlink()
    with pytest.raises(FileNotFoundError):
        build_bundle(
            image_dir=instance_image_dir,
            out_dir=_out(tmp_path, "out"),
            source_epoch=EPOCH,
            source=SOURCE,
            flavor="instance",
        )


INSTANCE_BUNDLE_REF = "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977"


def test_make_instance_manifest_from_bundle_info(instance_image_dir: Path, tmp_path: Path) -> None:
    out = _out(tmp_path, "out")
    info = build_bundle(image_dir=instance_image_dir, out_dir=out, source_epoch=EPOCH, source=SOURCE, flavor="instance")
    manifest = make_instance_manifest(info, bundle_ref=INSTANCE_BUNDLE_REF, name="aleph-snp-luks", version="2026.08.18")
    reparsed = InstanceRuntimeManifest.model_validate_json(manifest.to_canonical_json())
    assert reparsed == manifest
    assert manifest.format == "aleph-instance-runtime"
    assert manifest.bundle.ref == INSTANCE_BUNDLE_REF
    assert manifest.bundle.sha256 == info.sha256
    assert manifest.bundle.size == info.size
    assert manifest.bundle.members == info.members
    assert manifest.boot.cmdline_template == CMDLINE_TEMPLATE_LUKS_V1
    assert "{owner}" in manifest.boot.cmdline_template
    assert manifest.source == SOURCE


def test_exec_and_compose_templates_carry_the_verified_volumes_slot():
    """Both workload-bearing templates must end with the verified_volumes
    token: the CLI refuses --volume against a slot-less runtime (fail
    closed), so a template without the slot means no volumes, ever, on that
    runtime. The builtin no-workload template stays slot-less (volumes
    require a workload)."""
    from aleph.vm.vprogram.bundle import CMDLINE_TEMPLATE_EXEC_V1, CMDLINE_TEMPLATE_V1

    assert CMDLINE_TEMPLATE_EXEC_V1 == (
        "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}"
        " workload_roothash={workload_roothash}"
        " verified_volumes={verified_volumes}"
    )
    assert "verified_volumes" not in CMDLINE_TEMPLATE_V1


def test_gpu_flavor_records_the_gpu_block(gpu_image_dir: Path, tmp_path: Path) -> None:
    info = build_bundle(gpu_image_dir, tmp_path, source_epoch=0, source=SOURCE, flavor="gpu")
    assert info.gpu.vendor == "nvidia"
    manifest = make_manifest(
        info=info, bundle_ref=BUNDLE_REF, name="aleph-snp-gpu", runtime_version="1", gpu_runtime=True
    )
    assert manifest.gpu == info.gpu
    assert manifest.boot.cmdline_template == CMDLINE_TEMPLATE_GPU_V1


def test_gpu_flavor_requires_gpu_json(image_dir: Path, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        build_bundle(image_dir, tmp_path, source_epoch=0, source=SOURCE, flavor="gpu")


def test_make_manifest_refuses_gpu_runtime_without_gpu_facts(image_dir: Path, tmp_path: Path) -> None:
    info = build_bundle(image_dir, tmp_path, source_epoch=0, source=SOURCE)
    with pytest.raises(ValueError, match="gpu"):
        make_manifest(info=info, bundle_ref=BUNDLE_REF, name="x", runtime_version="1", gpu_runtime=True)
