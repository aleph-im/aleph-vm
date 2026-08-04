"""End-to-end CLI tests (subprocess; no nix, no network — --image-dir is the seam)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aleph.vm.vprogram.manifest import RuntimeManifest

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT = REPO_ROOT / "scripts" / "vprogram_bundle.py"
ROOTHASH = "cb121a317be7dc7969dd633ca9b6c3718ffe9ea6715b64e0e35a871d484b56b8"
BUNDLE_REF = "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977"


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
