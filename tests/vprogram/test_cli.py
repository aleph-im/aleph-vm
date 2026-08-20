"""End-to-end CLI tests (subprocess; no nix, no network — --image-dir is the seam)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aleph.vm.vprogram.manifest import InstanceRuntimeManifest, RuntimeManifest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "vprogram_bundle.py"
ROOTHASH = "cb121a317be7dc7969dd633ca9b6c3718ffe9ea6715b64e0e35a871d484b56b8"
BUNDLE_REF = "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977"


@pytest.fixture()
def instance_image_dir(tmp_path: Path) -> Path:
    d = tmp_path / "instance-image"
    d.mkdir()
    (d / "OVMF.fd").write_bytes(b"ovmf firmware")
    (d / "bzImage").write_bytes(b"kernel")
    (d / "initrd").write_bytes(b"initrd contents")
    return d


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
    (d / "measurement.hex").write_text("de" * 48 + "\n")
    return d


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "SOURCE_DATE_EPOCH": "1700000000"}
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],  # noqa: S603
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def test_build_then_manifest(image_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = _run("build", "--image-dir", str(image_dir), "--out", str(out))
    assert result.returncode == 0, result.stderr
    assert "aleph file upload" in result.stdout
    assert (out / "snp-image.tar.gz").is_file()
    info = json.loads((out / "bundle-info.json").read_text())
    assert info["platform_roothash"] == ROOTHASH

    result = _run(
        "manifest",
        "--bundle-info",
        str(out / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "aleph-snp-attest",
        "--runtime-version",
        "2026.07.08",
    )
    assert result.returncode == 0, result.stderr
    assert "aleph file upload" in result.stdout
    manifest = RuntimeManifest.model_validate_json((out / "manifest.json").read_text())
    assert manifest.bundle.ref == BUNDLE_REF
    assert manifest.boot.platform_roothash == ROOTHASH
    # Without --exec the default stays the builtin no-workload runtime.
    assert manifest.workload.contract == "aleph.builtin/1"
    assert "{workload_roothash}" not in manifest.boot.cmdline_template


def test_manifest_exec_runtime(image_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _run("build", "--image-dir", str(image_dir), "--out", str(out)).returncode == 0
    result = _run(
        "manifest",
        "--bundle-info",
        str(out / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "aleph-snp-attest",
        "--runtime-version",
        "2026.08.18",
        "--exec",
    )
    assert result.returncode == 0, result.stderr
    manifest = RuntimeManifest.model_validate_json((out / "manifest.json").read_text())
    assert manifest.workload.contract == "aleph.exec/1"
    assert "{workload_roothash}" in manifest.boot.cmdline_template


def test_manifest_compose_runtime(image_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _run("build", "--image-dir", str(image_dir), "--out", str(out)).returncode == 0
    result = _run(
        "manifest",
        "--bundle-info",
        str(out / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "aleph-snp-attest",
        "--runtime-version",
        "2026.08.19",
        "--flavor",
        "compose",
    )
    assert result.returncode == 0, result.stderr
    manifest = RuntimeManifest.model_validate_json((out / "manifest.json").read_text())
    assert manifest.workload.contract == "aleph.compose/1"
    assert "{workload_roothash}" in manifest.boot.cmdline_template


def test_manifest_exec_and_compose_are_mutually_exclusive(image_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _run("build", "--image-dir", str(image_dir), "--out", str(out)).returncode == 0
    result = _run(
        "manifest",
        "--bundle-info",
        str(out / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "aleph-snp-attest",
        "--runtime-version",
        "2026.08.19",
        "--exec",
        "--flavor",
        "compose",
    )
    assert result.returncode != 0
    assert "--exec is incompatible with --flavor compose" in result.stderr


def test_manifest_rejects_tampered_bundle(image_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    assert _run("build", "--image-dir", str(image_dir), "--out", str(out)).returncode == 0
    tar_path = out / "snp-image.tar.gz"
    tar_path.write_bytes(tar_path.read_bytes() + b"x")
    result = _run(
        "manifest",
        "--bundle-info",
        str(out / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "x",
        "--runtime-version",
        "1",
    )
    assert result.returncode != 0
    assert "does not match" in result.stderr


def test_build_missing_image_file_fails(image_dir: Path, tmp_path: Path) -> None:
    (image_dir / "bzImage").unlink()
    result = _run("build", "--image-dir", str(image_dir), "--out", str(tmp_path / "out"))
    assert result.returncode != 0


def test_build_then_manifest_instance_flavor(instance_image_dir: Path, tmp_path: Path) -> None:
    out = tmp_path / "out"
    result = _run("build", "--image-dir", str(instance_image_dir), "--out", str(out), "--flavor", "instance")
    assert result.returncode == 0, result.stderr
    assert (out / "snp-image.tar.gz").is_file()
    info = json.loads((out / "bundle-info.json").read_text())
    assert "platform_roothash" not in info
    assert info["members"] == {"ovmf": "image/OVMF.fd", "kernel": "image/bzImage", "initrd": "image/initrd"}

    result = _run(
        "manifest",
        "--bundle-info",
        str(out / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "aleph-snp-luks",
        "--runtime-version",
        "2026.08.18",
        "--flavor",
        "instance",
    )
    assert result.returncode == 0, result.stderr
    manifest = InstanceRuntimeManifest.model_validate_json((out / "manifest.json").read_text())
    assert manifest.format == "aleph-instance-runtime"
    assert manifest.bundle.ref == BUNDLE_REF
    assert manifest.boot.cmdline_template == "console=ttyS0 luks=1 owner={owner}"


def test_build_then_manifest_compose_flavor(image_dir: Path, tmp_path: Path) -> None:
    # Unlike test_manifest_compose_runtime above (which pins that a compose
    # manifest can be cut from a default-flavor build), this exercises the
    # fully flavored path: build --flavor compose shares the vprogram byte
    # layout but must record the composeImage nix target as provenance.
    out = tmp_path / "out"
    result = _run("build", "--image-dir", str(image_dir), "--out", str(out), "--flavor", "compose")
    assert result.returncode == 0, result.stderr
    assert (out / "snp-image.tar.gz").is_file()
    info = json.loads((out / "bundle-info.json").read_text())
    assert info["platform_roothash"] == ROOTHASH
    assert info["source"]["build"] == 'nix build "git+file://$REPO?dir=nix#composeImage"'

    result = _run(
        "manifest",
        "--bundle-info",
        str(out / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "aleph-compose-runtime",
        "--runtime-version",
        "2026.08.20",
        "--flavor",
        "compose",
    )
    assert result.returncode == 0, result.stderr
    manifest = RuntimeManifest.model_validate_json((out / "manifest.json").read_text())
    assert manifest.workload.contract == "aleph.compose/1"
    assert "{workload_roothash}" in manifest.boot.cmdline_template
    assert manifest.source.build == 'nix build "git+file://$REPO?dir=nix#composeImage"'


def test_manifest_rejects_exec_with_instance_flavor(tmp_path: Path) -> None:
    # The combination is rejected before the subcommand runs, so the
    # bundle-info path is never read.
    result = _run(
        "manifest",
        "--bundle-info",
        str(tmp_path / "bundle-info.json"),
        "--bundle-ref",
        BUNDLE_REF,
        "--name",
        "aleph-snp-luks",
        "--runtime-version",
        "2026.08.18",
        "--flavor",
        "instance",
        "--exec",
    )
    assert result.returncode == 2
    assert "--exec is incompatible with --flavor instance" in result.stderr
