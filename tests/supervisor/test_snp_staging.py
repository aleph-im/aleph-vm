"""Tests for the shared SEV-SNP bundle-staging helpers.

Everything runs offline: get_existing_file is monkeypatched to serve a
locally built bundle tarball from tmp_path, mirroring the pattern in
tests/supervisor/test_vprogram_launch.py.
"""

import gzip
import hashlib
import io
import tarfile
from pathlib import Path
from typing import IO, cast

import pytest

from aleph.vm.agent.snp_staging import fetch_and_stage_bundle, staging_dir
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import VmSetupError

VM_HASH = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafec"
BUNDLE_REF = "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b97"

BUNDLE_FILES: dict[str, bytes] = {
    "hello.txt": b"hello from the bundle",
    "nested/inner.bin": b"nested member data",
}


def make_bundle(out_dir: Path, files: dict[str, bytes] | None = None) -> Path:
    """Build a small tar.gz with a nested member, like the runtime bundle."""
    files = BUNDLE_FILES if files is None else files
    tar_path = out_dir / "bundle.tar.gz"
    with tar_path.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=cast(IO[bytes], gz), mode="w") as tar:
                for name, data in sorted(files.items()):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    member.mode = 0o644
                    tar.addfile(member, io.BytesIO(data))
    return tar_path


@pytest.fixture
def storage_files(tmp_path, monkeypatch) -> dict[str, Path]:
    """Serve get_existing_file from a local ref -> path map: no network."""
    files: dict[str, Path] = {}

    async def fake_get_existing_file(ref: str) -> Path:
        return files[str(ref)]

    monkeypatch.setattr("aleph.vm.agent.snp_staging.get_existing_file", fake_get_existing_file)
    monkeypatch.setattr(settings, "EXECUTION_ROOT", str(tmp_path))
    return files


@pytest.mark.asyncio
async def test_fetch_and_stage_bundle_stages_members(tmp_path, storage_files):
    """The happy path: a verified tarball is fetched and extracted, and the
    returned directory is exactly staging_dir(kind, vm_hash)."""
    tar_path = make_bundle(tmp_path)
    raw = tar_path.read_bytes()
    storage_files[BUNDLE_REF] = tar_path

    dest = await fetch_and_stage_bundle(
        VM_HASH,
        kind="snp-instance",
        ref=BUNDLE_REF,
        sha256=hashlib.sha256(raw).hexdigest(),
        size=len(raw),
    )

    assert dest == staging_dir("snp-instance", VM_HASH)
    assert (dest / "hello.txt").read_bytes() == b"hello from the bundle"
    assert (dest / "nested" / "inner.bin").read_bytes() == b"nested member data"


@pytest.mark.asyncio
async def test_fetch_and_stage_bundle_sha256_mismatch_fails_closed(tmp_path, storage_files):
    """A tarball whose bytes do not match the pinned sha256 must never be
    extracted: fail closed and leave no staging directory behind."""
    tar_path = make_bundle(tmp_path)
    raw = tar_path.read_bytes()
    storage_files[BUNDLE_REF] = tar_path

    dest = staging_dir("snp-instance", VM_HASH)

    with pytest.raises(VmSetupError, match="sha256 mismatch"):
        await fetch_and_stage_bundle(
            VM_HASH,
            kind="snp-instance",
            ref=BUNDLE_REF,
            sha256="f" * 64,
            size=len(raw),
        )
    assert not dest.exists()
