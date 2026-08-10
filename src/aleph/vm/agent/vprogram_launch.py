"""SEV-SNP launch path for V-PROGRAM messages: runtime bundle staging and
CreateVmSpec construction.

A V-PROGRAM pins its measured platform through a runtime manifest (a STORE
message holding JSON parsed by ``aleph.vm.vprogram.manifest.RuntimeManifest``).
The manifest pins the runtime bundle: ONE tar.gz holding the measured OVMF,
kernel, initrd and the dm-verity platform rootfs plus its hash tree.

This module is the agent half of the launch: fetch the manifest, fetch and
integrity-check the bundle (sha256 pinned by the manifest), extract it into a
per-VM staging directory, make sure the dm-verity sidecars sit where the
supervisor daemon looks for them, and build the SNP CreateVmSpec. The daemon
derives the measured kernel cmdline itself from the ``<rootfs>.roothash``
sidecar next to the rootfs disk and reads the hash tree at ``<rootfs>.verity``
(see rust/crates/supervisor-daemon/src/lifecycle.rs, snp_config_slice, and
docs/plans/rust-port-divergences.md entry 68c): the proto deliberately has no
cmdline field, so nothing here passes one.

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

from pydantic import ValidationError

from aleph.vm.conf import settings
from aleph.vm.storage import get_existing_file
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    TeeBackend,
    TeeConfig,
    VmId,
)
from aleph.vm.utils import get_hostname_from_hash
from aleph.vm.vprogram.manifest import RuntimeManifest

if TYPE_CHECKING:
    from aleph_message.models import ItemHash
    from aleph_message.models.execution.vprogram import VerifiableProgramContent

logger = logging.getLogger(__name__)

_SHA256_CHUNK_SIZE = 1024 * 1024


def vprogram_staging_dir(vm_hash: ItemHash) -> Path:
    """The per-VM directory the runtime bundle is extracted into."""
    return Path(settings.EXECUTION_ROOT) / "vprogram" / str(vm_hash)


async def fetch_runtime_manifest(runtime_ref: str) -> RuntimeManifest:
    """Download and parse the runtime manifest pinned by ``runtime.ref``.

    The ref is the item hash of a STORE message whose file is the manifest
    JSON. Parsing is strict (extra keys, malformed templates and traversing
    member paths are all rejected by the model); any failure is a
    VmSetupError so update_allocations reports it per-VM.
    """
    manifest_path = await get_existing_file(runtime_ref)
    try:
        return RuntimeManifest.model_validate_json(manifest_path.read_bytes())
    except (ValidationError, ValueError, OSError) as error:
        msg = f"runtime manifest {runtime_ref} is invalid: {error}"
        raise VmSetupError(msg) from error


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fileobj:
        while chunk := fileobj.read(_SHA256_CHUNK_SIZE):
            digest.update(chunk)
    return digest.hexdigest()


def _verify_bundle(tar_path: Path, manifest: RuntimeManifest) -> None:
    """The integrity gate: the downloaded tarball must be byte-identical to
    the one the manifest measured (sha256 + size), or nothing gets extracted."""
    actual_size = tar_path.stat().st_size
    if actual_size != manifest.bundle.size:
        msg = f"runtime bundle {manifest.bundle.ref} size mismatch: expected {manifest.bundle.size}, got {actual_size}"
        raise VmSetupError(msg)
    actual_sha256 = _sha256_file(tar_path)
    # Constant-time compare: defense-in-depth for the hash gate, even though the
    # manifest is content-addressed and the timing surface here is negligible.
    if not hmac.compare_digest(actual_sha256, manifest.bundle.sha256):
        msg = (
            f"runtime bundle {manifest.bundle.ref} sha256 mismatch: "
            f"expected {manifest.bundle.sha256}, got {actual_sha256}"
        )
        raise VmSetupError(msg)


def _extract_bundle(tar_path: Path, dest: Path) -> None:
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


def _member_path(bundle_dir: Path, relative: str, role: str) -> Path:
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


def _ensure_verity_sidecars(rootfs_path: Path, hash_tree_path: Path, platform_roothash: str) -> None:
    """Place the dm-verity sidecars where the daemon looks for them.

    snp_config_slice reads ``<rootfs>.roothash`` (measured cmdline input) and
    ``<rootfs>.verity`` (the hash tree it wires as /dev/vdb) NEXT TO the
    rootfs disk path in the spec. The #1050 bundle already ships both
    adjacent to rootfs.ext4; this guards against a layout where they are not.

    A roothash sidecar that disagrees with the manifest's platform_roothash
    is a tampered or mispackaged bundle: fail closed rather than boot a VM
    whose measured cmdline does not match what the manifest declared.
    """
    roothash_path = rootfs_path.with_name(rootfs_path.name + ".roothash")
    if roothash_path.is_file():
        found = roothash_path.read_text().strip()
        if found != platform_roothash:
            msg = (
                f"bundle roothash sidecar {roothash_path} disagrees with the manifest: "
                f"expected {platform_roothash}, got {found}"
            )
            raise VmSetupError(msg)
    else:
        roothash_path.write_text(platform_roothash + "\n")

    verity_path = rootfs_path.with_name(rootfs_path.name + ".verity")
    if not verity_path.is_file():
        # The manifest may name the hash tree member differently; the daemon
        # only ever reads <rootfs>.verity, so link the member there.
        try:
            verity_path.hardlink_to(hash_tree_path)
        except OSError:
            shutil.copyfile(hash_tree_path, verity_path)


async def build_vprogram_spec(vm_hash: ItemHash, content: VerifiableProgramContent) -> CreateVmSpec:
    """Fetch, verify and stage the runtime bundle, then build the SNP spec.

    Mirrors the on-host launch template (aleph-testnets test_vm_snp.py): QEMU
    backend, direct-kernel boot from the measured bundle members, and a disk
    order that IS the contract: the guest init reads the platform rootfs from
    /dev/vda and the dm-verity hash tree from /dev/vdb.
    """
    manifest = await fetch_runtime_manifest(str(content.runtime.ref))

    tar_path = await get_existing_file(manifest.bundle.ref)
    _verify_bundle(tar_path, manifest)

    bundle_dir = vprogram_staging_dir(vm_hash)
    _extract_bundle(tar_path, bundle_dir)
    logger.debug("Staged V-PROGRAM %s runtime bundle at %s", vm_hash, bundle_dir)

    members = manifest.bundle.members
    ovmf_path = _member_path(bundle_dir, members.ovmf, "ovmf")
    kernel_path = _member_path(bundle_dir, members.kernel, "kernel")
    initrd_path = _member_path(bundle_dir, members.initrd, "initrd")
    rootfs_path = _member_path(bundle_dir, members.platform_rootfs, "platform_rootfs")
    hash_tree_path = _member_path(bundle_dir, members.platform_hash_tree, "platform_hash_tree")

    _ensure_verity_sidecars(rootfs_path, hash_tree_path, manifest.boot.platform_roothash)

    session_base = settings.CONFIDENTIAL_SESSION_DIRECTORY or (Path(settings.EXECUTION_ROOT) / "sessions")

    return CreateVmSpec(
        vm_id=VmId(str(vm_hash)),
        backend=Backend.QEMU,
        kernel_path=kernel_path,
        initrd_path=initrd_path,
        # Disk ORDER is load-bearing: the guest init reads the rootfs from the
        # first virtio disk (/dev/vda) and the dm-verity hash tree from /dev/vdb.
        disks=[
            DiskSpec(path=rootfs_path, readonly=True, format=DiskFormat.RAW, role=DiskRole.ROOTFS),
            DiskSpec(path=hash_tree_path, readonly=True, format=DiskFormat.RAW, role=DiskRole.EXTRA),
        ],
        vcpus=content.resources.vcpus,
        memory_mib=content.resources.memory,
        tee=TeeConfig(
            backend=TeeBackend.SEV_SNP,
            policy=str(content.verification.policy),
            # The daemon derives its own CONFIDENTIAL_SESSION_DIRECTORY/<vm_id>
            # for SNP (lifecycle.rs): required-but-ignored placeholder.
            session_dir=DirectoryPath(Path(session_base) / str(vm_hash)),
            firmware_path=ovmf_path,
        ),
        network=NetworkConfig(
            internet_access=bool(content.environment.internet),
            requested_ipv6="",
            ipv6_prefix_len=0,
        ),
        gpus=[],
        numa_node=None,
        # QEMU instances start under systemd only; the daemon rejects a
        # non-persistent QEMU VM.
        persistent=True,
        hostname=get_hostname_from_hash(vm_hash),
    )
