"""Deterministic packaging of the Nix measured-image output into a runtime
bundle, plus manifest construction from the recorded build facts.

The bundle is ONE tar.gz pinned by ONE STORE message. Determinism matters:
independently rebuilding the same image must yield the same tarball bytes,
so entries are sorted, ownership is zeroed, mtimes are pinned to the source
commit timestamp and the gzip header carries no name or timestamp.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import re
import tarfile
from pathlib import Path

from pydantic import Field

from aleph.vm.vprogram.manifest import (
    SHA256_HEX_PATTERN,
    BundleMembers,
    SourceInfo,
    StrictModel,
)

BUNDLE_NAME = "snp-image.tar.gz"
BUNDLE_INFO_NAME = "bundle-info.json"
MANIFEST_NAME = "manifest.json"
TAR_PREFIX = "image"

# Role -> file name inside the nix `image` output directory.
MEMBER_FILES = {
    "ovmf": "OVMF.fd",
    "kernel": "bzImage",
    "initrd": "initrd",
    "platform_rootfs": "rootfs.ext4",
    "platform_hash_tree": "rootfs.ext4.verity",
}
ROOTHASH_FILE = "rootfs.ext4.roothash"
MEASUREMENT_FILE = "measurement.hex"


class BundleInfo(StrictModel):
    """Sidecar record of a `build` run: everything `manifest` needs except
    the STORE item hash, which only exists after the manual upload."""

    sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    size: int = Field(gt=0)
    members: BundleMembers
    platform_roothash: str = Field(pattern=SHA256_HEX_PATTERN)
    # The measurement baked by the nix build (fixed CI shape); informational.
    measurement: str = Field(min_length=1)
    source: SourceInfo


def _read_sidecar(image_dir: Path, name: str, pattern: str | None) -> str:
    value = (image_dir / name).read_text().strip()
    if pattern is not None and not re.fullmatch(pattern, value):
        msg = f"{name} does not look like a dm-verity roothash: {value!r}"
        raise ValueError(msg)
    return value


def build_bundle(image_dir: Path, out_dir: Path, source_epoch: int, source: SourceInfo) -> BundleInfo:
    """Package a nix image output directory as a deterministic tar.gz and
    write the bundle-info sidecar. Returns the recorded facts."""
    file_names = sorted({*MEMBER_FILES.values(), ROOTHASH_FILE, MEASUREMENT_FILE})
    for name in file_names:
        if not (image_dir / name).is_file():
            msg = f"expected image file missing: {image_dir / name}"
            raise FileNotFoundError(msg)

    platform_roothash = _read_sidecar(image_dir, ROOTHASH_FILE, SHA256_HEX_PATTERN)
    measurement = _read_sidecar(image_dir, MEASUREMENT_FILE, None)

    tar_path = out_dir / BUNDLE_NAME
    with tar_path.open("wb") as raw:
        # filename="" keeps the output path out of the gzip header (FNAME);
        # mtime=0 pins the gzip timestamp. Both are required for determinism.
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=gz, mode="w", format=tarfile.USTAR_FORMAT) as tar:  # type: ignore[arg-type]
                directory = tarfile.TarInfo(TAR_PREFIX)
                directory.type = tarfile.DIRTYPE
                directory.mode = 0o755
                directory.mtime = source_epoch
                tar.addfile(directory)
                for name in file_names:
                    path = image_dir / name
                    member = tarfile.TarInfo(f"{TAR_PREFIX}/{name}")
                    member.size = path.stat().st_size
                    member.mode = 0o644
                    member.mtime = source_epoch
                    with path.open("rb") as fileobj:
                        tar.addfile(member, fileobj)

    data = tar_path.read_bytes()
    info = BundleInfo(
        sha256=hashlib.sha256(data).hexdigest(),
        size=len(data),
        members=BundleMembers(**{role: f"{TAR_PREFIX}/{name}" for role, name in MEMBER_FILES.items()}),
        platform_roothash=platform_roothash,
        measurement=measurement,
        source=source,
    )
    info_path = out_dir / BUNDLE_INFO_NAME
    info_path.write_text(json.dumps(info.model_dump(mode="json"), indent=2, sort_keys=True) + "\n")
    return info
