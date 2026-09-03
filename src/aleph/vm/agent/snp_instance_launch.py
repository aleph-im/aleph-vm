"""SEV-SNP launch path for confidential INSTANCE messages: runtime manifest
fetch, bundle staging and CreateVmSpec construction for the LUKS
(opaque-cmdline) SNP instance flavor (``environment.trusted_execution.mode ==
"sev_snp"``).

Unlike a V-PROGRAM (vprogram_launch.py: measured dm-verity platform rootfs,
no client-supplied disk image), a confidential instance supplies its OWN
LUKS2-encrypted rootfs as a writable qcow2 volume: the runtime bundle here
only pins the measured platform (OVMF, kernel, initrd) and the guest-init
kernel cmdline template. There is no dm-verity platform rootfs and no
workload block: the guest owns everything past LUKS unlock.

Every check fails closed with VmSetupError: an unmeasured host input, an
unsupported host, or a malformed manifest must never reach create_vm.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import TYPE_CHECKING

from aleph_message.models.execution.instance import InstanceContent
from pydantic import ValidationError

from aleph.vm.agent import snp_staging
from aleph.vm.agent.guest_ipv6 import compute_requested_ipv6
from aleph.vm.agent.vcpu_probe import get_supported_snp_vcpu_types
from aleph.vm.agent.vcpu_select import requested_vcpu_types, select_snp_vcpu_type
from aleph.vm.agent.vm.downloader import QemuDownloader
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
from aleph.vm.utils import check_amd_sev_snp_supported, get_hostname_from_hash
from aleph.vm.vm_type import VmType
from aleph.vm.vprogram.manifest import InstanceRuntimeManifest

if TYPE_CHECKING:
    from aleph_message.models import ItemHash

logger = logging.getLogger(__name__)

# A lowercased 0x-prefixed 20-byte hex address: v1 confidential instances are
# EVM-keyed only (owner-auth is EIP-191; see build_snp_instance_spec).
_EVM_ADDRESS_PATTERN = re.compile(r"0x[0-9a-f]{40}")


def snp_instance_staging_dir(vm_hash: ItemHash) -> Path:
    """The per-VM directory the instance runtime bundle is extracted into."""
    return snp_staging.staging_dir("snp-instance", vm_hash)


def remove_snp_instance_staging(vm_hash: ItemHash) -> None:
    """Delete a confidential instance's staging directory once its VM is gone
    for good.

    The extracted runtime bundle lives at EXECUTION_ROOT/snp-instance/<vm_hash>;
    the launch path only clears it on re-extraction, so a churned instance
    would otherwise leak it on disk. Idempotent and safe for any VM type: a
    non-SNP-instance VM has no such directory, so this is a no-op. Call it
    from the teardown paths, after the supervisor delete and registry.forget.
    """
    snp_staging.remove_staging("snp-instance", vm_hash)


def is_snp_instance(content) -> bool:
    """True for an InstanceContent whose trusted_execution runs the SEV-SNP
    (mode="sev_snp") flavor, as opposed to legacy SEV or no TEE at all."""
    return (
        isinstance(content, InstanceContent)
        and content.environment.trusted_execution is not None
        and getattr(content.environment.trusted_execution, "is_snp", False)
    )


async def fetch_instance_runtime_manifest(runtime_ref: str) -> InstanceRuntimeManifest:
    """Download and parse the instance runtime manifest pinned by
    ``trusted_execution.runtime``.

    Mirrors vprogram_launch.fetch_runtime_manifest but validates against the
    aleph-instance-runtime format; a manifest of another format (e.g. a
    v-program's aleph-vprogram-runtime) fails its ``format`` literal, and the
    resulting VmSetupError names the expected format.
    """
    manifest_path = await get_existing_file(runtime_ref)
    try:
        return InstanceRuntimeManifest.model_validate_json(manifest_path.read_bytes())
    except (ValidationError, ValueError, OSError) as error:
        msg = f"instance runtime manifest {runtime_ref} is invalid: {error}"
        raise VmSetupError(msg) from error


def select_attestation_port(manifest: InstanceRuntimeManifest) -> int:
    """The guest attestation port, ordered by preference over
    ``manifest.attestation``: the ``aleph.ra-tls`` descriptor's port, falling
    back to the first descriptor for a runtime that only implements another
    protocol.

    Deliberately NOT the same contract as the V-PROGRAM's
    ``_select_attestation_port`` (vprogram_launch.py), which returns None
    when no ``aleph.ra-tls`` tcp descriptor exists: instance manifests pin
    ``attestation`` to at least one entry with a tcp transport, so this
    selector always has a port to return. Do not "harmonize" the two."""
    for descriptor in manifest.attestation:
        if descriptor.protocol == "aleph.ra-tls":
            return descriptor.transport.port
    return manifest.attestation[0].transport.port


async def resolve_instance_attestation_port(content: InstanceContent) -> int:
    """Re-derive the RA-TLS attestation port from the runtime manifest alone.

    The port-forward reconcilers (the aggregate watcher and the re-adoption
    healing path) need the port to keep the host DNAT mapping in their
    desired set, but must not pay for ``build_snp_instance_spec``: that
    stages the whole runtime bundle, which the running VM already booted
    from. The manifest is a small STORE file: one message-metadata lookup,
    with the file itself coming from the local download cache after the
    first create. Raises VmSetupError when the manifest cannot be fetched or
    parsed; the caller decides whether that is fatal.
    """
    manifest = await fetch_instance_runtime_manifest(str(content.environment.trusted_execution.runtime))
    return select_attestation_port(manifest)


async def build_snp_instance_spec(vm_hash: ItemHash, content: InstanceContent, sender: str) -> tuple[CreateVmSpec, int]:
    """Validate, fetch/stage the runtime bundle, and build the SNP CreateVmSpec
    for a confidential instance with its own LUKS-encrypted rootfs. Returns
    the spec and the guest attestation port.

    ``sender`` is the address that signed the INSTANCE message, and it is what
    fills the measured cmdline's unlock-authority slot: the guest accepts a
    secret injection only from the key that signed the deployment. For a
    directly-signed message sender == content.address, so nothing changes; for
    an on-behalf-of deployment the delegate (whose authorization from the
    owner the CCN already enforced) is the one that holds the passphrase and
    unlocks. content.address stays the billing/ownership identity and may be
    non-EVM; the sender must be EVM-keyed (owner-auth is EIP-191).

    Rejections fire in this order, all before any staging I/O: an
    attestation_port override, a host without SNP support, a policy above 32
    bits, and a non-EVM sender. Because every rejection runs before
    fetch_instance_runtime_manifest/fetch_and_stage_bundle are ever called, a
    rejection never leaves a staging directory behind.
    """
    trusted_execution = content.environment.trusted_execution
    if trusted_execution.attestation_port is not None:
        msg = (
            "attestation_port overrides are not supported yet; leave it unset "
            "(the runtime manifest declares the port)"
        )
        raise VmSetupError(msg)
    if not check_amd_sev_snp_supported():
        msg = "this host does not support SEV-SNP"
        raise VmSetupError(msg)
    if int(trusted_execution.policy) >= 2**32:
        msg = "SNP guest policy above 32 bits is not supported yet"
        raise VmSetupError(msg)
    unlock_address = str(sender).lower()
    if not _EVM_ADDRESS_PATTERN.fullmatch(unlock_address):
        msg = "SNP confidential instances require an EVM-keyed sender in v1 (owner-auth is EIP-191)"
        raise VmSetupError(msg)

    if content.authorized_keys or content.variables:
        logger.warning(
            "SNP instance %s: authorized_keys/variables are unmeasured host inputs and are "
            "ignored; provision inside the encrypted rootfs",
            vm_hash,
        )

    manifest = await fetch_instance_runtime_manifest(str(trusted_execution.runtime))
    bundle_dir = await snp_staging.fetch_and_stage_bundle(
        vm_hash,
        kind="snp-instance",
        ref=manifest.bundle.ref,
        sha256=manifest.bundle.sha256,
        size=manifest.bundle.size,
    )
    logger.debug("Staged SNP instance %s runtime bundle at %s", vm_hash, bundle_dir)

    members = manifest.bundle.members
    ovmf_path = snp_staging.member_path(bundle_dir, members.ovmf, "ovmf")
    kernel_path = snp_staging.member_path(bundle_dir, members.kernel, "kernel")
    initrd_path = snp_staging.member_path(bundle_dir, members.initrd, "initrd")
    # The template's slot is named {owner} (a frozen runtime-manifest
    # contract); the value it binds is the unlock authority above.
    kernel_cmdline = manifest.boot.cmdline_template.format(owner=unlock_address)

    attest_port = select_attestation_port(manifest)

    resources = QemuDownloader(content, namespace=str(vm_hash))
    await resources.download_all()
    disks = [
        DiskSpec(path=resources.rootfs_path, readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS),
    ] + [
        DiskSpec(path=v.path_on_host, readonly=v.read_only, format=DiskFormat.RAW, role=DiskRole.EXTRA)
        for v in resources.volumes
    ]

    session_base = settings.CONFIDENTIAL_SESSION_DIRECTORY or (Path(settings.EXECUTION_ROOT) / "sessions")

    # A confidential instance's static IPv6 depends only on the type and item
    # hash, so the agent computes it upfront (empty under the dynamic policy).
    requested_ipv6, ipv6_prefix_len = compute_requested_ipv6(vm_hash, VmType.instance)

    # Same rule as a V-PROGRAM: the launched CPU model must be one the
    # instance's launch measurements were computed for. trusted_execution
    # .measurements is Optional on the model but required non-empty in
    # sev_snp mode, so None fails closed here.
    cpu_model = select_snp_vcpu_type(
        requested_vcpu_types(trusted_execution.measurements),
        await get_supported_snp_vcpu_types(),
    )

    spec = CreateVmSpec(
        vm_id=VmId(str(vm_hash)),
        backend=Backend.QEMU,
        kernel_path=kernel_path,
        initrd_path=initrd_path,
        disks=disks,
        vcpus=content.resources.vcpus,
        memory_mib=content.resources.memory,
        tee=TeeConfig(
            backend=TeeBackend.SEV_SNP,
            policy=str(trusted_execution.policy),
            # The daemon derives its own CONFIDENTIAL_SESSION_DIRECTORY/<vm_id>
            # for SNP (lifecycle.rs): required-but-ignored placeholder.
            session_dir=DirectoryPath(Path(session_base) / str(vm_hash)),
            firmware_path=ovmf_path,
            kernel_cmdline=kernel_cmdline,
            cpu_model=cpu_model,
        ),
        network=NetworkConfig(
            internet_access=bool(content.environment.internet),
            requested_ipv6=requested_ipv6,
            ipv6_prefix_len=ipv6_prefix_len,
        ),
        gpus=[],
        numa_node=None,
        # QEMU instances start under systemd only; the daemon rejects a
        # non-persistent QEMU VM.
        persistent=True,
        # authorized_keys are ignored above; the SSH keys live inside the
        # owner's LUKS-encrypted rootfs.
        ssh_authorized_keys=[],
        hostname=get_hostname_from_hash(vm_hash),
    )
    return spec, attest_port
