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

import logging
import re
import shutil
from pathlib import Path
from typing import TYPE_CHECKING

from aleph_message.models.execution.vprogram import VERITY_ROOTHASH_PATTERN
from pydantic import ValidationError

from aleph.vm.agent import snp_staging
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


def vprogram_staging_dir(vm_hash: ItemHash) -> Path:
    """The per-VM directory the runtime bundle is extracted into."""
    return snp_staging.staging_dir("vprogram", vm_hash)


def remove_vprogram_staging(vm_hash: ItemHash) -> None:
    """Delete a V-PROGRAM's staging directory once its VM is gone for good.

    The extracted runtime bundle lives at EXECUTION_ROOT/vprogram/<vm_hash>;
    the launch path only clears it on re-extraction, so a churned V-PROGRAM
    would otherwise leak it on disk. Idempotent and safe for any VM type: a
    non-V-PROGRAM has no such directory, so this is a no-op. Call it from the
    teardown paths, after the supervisor delete and registry.forget.
    """
    snp_staging.remove_staging("vprogram", vm_hash)


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

    # The tarball is fetched here (not via snp_staging.fetch_and_stage_bundle)
    # so it goes through this module's own get_existing_file: run.py and the
    # launch-path tests patch aleph.vm.agent.vprogram_launch.get_existing_file
    # and expect every ref (manifest, bundle, workload) to resolve through it.
    tar_path = await get_existing_file(manifest.bundle.ref)
    snp_staging._verify_bundle(
        tar_path, ref=manifest.bundle.ref, sha256=manifest.bundle.sha256, size=manifest.bundle.size
    )

    bundle_dir = vprogram_staging_dir(vm_hash)
    snp_staging._extract_bundle(tar_path, bundle_dir)
    logger.debug("Staged V-PROGRAM %s runtime bundle at %s", vm_hash, bundle_dir)

    members = manifest.bundle.members
    ovmf_path = snp_staging.member_path(bundle_dir, members.ovmf, "ovmf")
    kernel_path = snp_staging.member_path(bundle_dir, members.kernel, "kernel")
    initrd_path = snp_staging.member_path(bundle_dir, members.initrd, "initrd")
    rootfs_path = snp_staging.member_path(bundle_dir, members.platform_rootfs, "platform_rootfs")
    hash_tree_path = snp_staging.member_path(bundle_dir, members.platform_hash_tree, "platform_hash_tree")

    _ensure_verity_sidecars(rootfs_path, hash_tree_path, manifest.boot.platform_roothash)

    # Disk ORDER is load-bearing: the guest init reads the rootfs from the
    # first virtio disk (/dev/vda), the platform dm-verity hash tree from
    # /dev/vdb, the workload data from /dev/vdc and its hash tree from
    # /dev/vdd.
    #
    # The platform hash tree is NOT attached here: the daemon force-inserts
    # `{rootfs}.verity` (written by _ensure_verity_sidecars above) as the
    # first SNP host volume (-> /dev/vdb). Attaching it here too would
    # duplicate it and shift the workload disks to vdd/vde, breaking the
    # guest's vdc/vdd workload-verity assumption.
    disks = [
        DiskSpec(path=rootfs_path, readonly=True, format=DiskFormat.RAW, role=DiskRole.ROOTFS),
    ]

    # The daemon trusts the sidecar content verbatim (snp_config_slice appends
    # it to the measured cmdline unquoted). The schema already pins the field
    # to this pattern on message validation; re-checking it here fails closed
    # on the unvalidated construction routes (model_copy/model_construct).
    wl_roothash = content.workload.roothash
    if not re.fullmatch(VERITY_ROOTHASH_PATTERN, wl_roothash):
        msg = f"V-PROGRAM {vm_hash} workload roothash is not a bare sha256 hex string"
        raise VmSetupError(msg)
    workload_data = await get_existing_file(str(content.workload.ref))
    workload_hashtree = await get_existing_file(str(content.workload.hash_tree))
    # The daemon derives ' workload_roothash=' from this sidecar next to the
    # rootfs (proto has no cmdline field).
    (rootfs_path.parent / f"{rootfs_path.name}.workload_roothash").write_text(wl_roothash + "\n")
    disks.append(DiskSpec(path=workload_data, readonly=True, format=DiskFormat.RAW, role=DiskRole.EXTRA))
    disks.append(DiskSpec(path=workload_hashtree, readonly=True, format=DiskFormat.RAW, role=DiskRole.EXTRA))

    session_base = settings.CONFIDENTIAL_SESSION_DIRECTORY or (Path(settings.EXECUTION_ROOT) / "sessions")

    return CreateVmSpec(
        vm_id=VmId(str(vm_hash)),
        backend=Backend.QEMU,
        kernel_path=kernel_path,
        initrd_path=initrd_path,
        disks=disks,
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
