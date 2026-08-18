"""Shared SEV-SNP bundle-staging helpers.

Both the V-PROGRAM launch path (vprogram_launch.py: one runtime bundle per
VM) and the SNP confidential-instance launch path stage a tar.gz bundle into
a per-VM directory under EXECUTION_ROOT, verifying it against a pinned
sha256 + size before extraction. This module holds that shared machinery so
neither launch path reimplements the integrity gate or the tarfile-safety
extraction.

Every check fails closed with VmSetupError: a mismeasured or tampered bundle
must never reach create_vm.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import shutil
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING

from aleph.vm.conf import settings
from aleph.vm.storage import get_existing_file
from aleph.vm.supervisor_interface.errors import VmSetupError

if TYPE_CHECKING:
    from aleph_message.models import ItemHash

logger = logging.getLogger(__name__)

_SHA256_CHUNK_SIZE = 1024 * 1024


def staging_dir(kind: str, vm_hash: ItemHash) -> Path:
    """The per-VM directory a runtime bundle is extracted into."""
    return Path(settings.EXECUTION_ROOT) / kind / str(vm_hash)


def remove_staging(kind: str, vm_hash: ItemHash) -> None:
    """Delete a VM's staging directory once its VM is gone for good.

    The extracted bundle lives at EXECUTION_ROOT/<kind>/<vm_hash>; the launch
    path only clears it on re-extraction, so a churned VM would otherwise
    leak it on disk. Idempotent and safe for any VM type: a VM with no such
    directory is a no-op. Call it from the teardown paths, after the
    supervisor delete and registry.forget.
    """
    staging = staging_dir(kind, vm_hash)
    if staging.exists():
        logger.debug("Removing %s %s staging directory %s", kind, vm_hash, staging)
        shutil.rmtree(staging, ignore_errors=True)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fileobj:
        while chunk := fileobj.read(_SHA256_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def verify_bundle(tar_path: Path, *, ref: str, sha256: str, size: int) -> None:
    """The integrity gate: the downloaded tarball must be byte-identical to
    the one pinned by ref/sha256/size (sha256 + size), or nothing gets extracted."""
    actual_size = tar_path.stat().st_size
    if actual_size != size:
        msg = f"runtime bundle {ref} size mismatch: expected {size}, got {actual_size}"
        raise VmSetupError(msg)
    actual_sha256 = _sha256_file(tar_path)
    # Constant-time compare: defense-in-depth for the hash gate, even though the
    # manifest is content-addressed and the timing surface here is negligible.
    if not hmac.compare_digest(actual_sha256, sha256):
        msg = f"runtime bundle {ref} sha256 mismatch: expected {sha256}, got {actual_sha256}"
        raise VmSetupError(msg)


def extract_bundle(tar_path: Path, dest: Path) -> None:
    """Extract the verified tarball into a clean staging directory.

    ``filter="data"`` is the tarfile safety filter: it rejects absolute
    member names, upward traversal, links pointing outside the destination,
    and strips setuid/devices, so a hostile tarball cannot escape ``dest``.
    """
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    try:
        with tarfile.open(tar_path, mode="r:gz") as tar:
            # filter="data" (PEP 706) needs CPython >= 3.12 / 3.11.4 / 3.10.12.
            # On an older patch release the keyword is absent and extractall
            # raises TypeError; catch it so we fail closed as VmSetupError
            # rather than an opaque error (never extract without the filter).
            tar.extractall(dest, filter="data")
    except (tarfile.TarError, OSError, TypeError) as error:
        # Never leave a partially-populated staging dir behind on failure.
        shutil.rmtree(dest, ignore_errors=True)
        msg = f"cannot extract runtime bundle {tar_path} into {dest}: {error}"
        raise VmSetupError(msg) from error


async def fetch_and_stage_bundle(vm_hash: ItemHash, *, kind: str, ref: str, sha256: str, size: int) -> Path:
    """Download the bundle by ref, verify it against sha256/size, and extract
    it into a clean per-VM staging directory. Returns the staging directory.

    Every failure (download, integrity mismatch, extraction) is a
    VmSetupError: a mismeasured or tampered bundle must never reach
    create_vm.
    """
    tar_path = await get_existing_file(ref)
    verify_bundle(tar_path, ref=ref, sha256=sha256, size=size)
    dest = staging_dir(kind, vm_hash)
    extract_bundle(tar_path, dest)
    return dest


def member_path(bundle_dir: Path, relative: str, role: str) -> Path:
    """Resolve a manifest member (already validated relative + no-upward by
    the model) inside the extracted bundle, failing closed if it is missing
    or somehow escapes the staging directory."""
    path = bundle_dir / relative
    if not path.resolve().is_relative_to(bundle_dir.resolve()):
        msg = f"bundle member {role} escapes the staging directory: {relative}"
        raise VmSetupError(msg)
    if not path.is_file():
        msg = f"bundle member {role} missing after extraction: {path}"
        raise VmSetupError(msg)
    return path
