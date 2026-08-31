"""Deterministic packaging of the Nix measured-image output into a runtime
bundle, plus manifest construction from the recorded build facts.

The bundle is ONE tar.gz pinned by ONE STORE message. Determinism matters:
independently rebuilding the same image must yield the same tarball bytes,
so entries are sorted, ownership is zeroed, mtimes are pinned to the source
commit timestamp and the gzip header carries no name or timestamp. The tar
layer is fully deterministic; the compressed bytes are deterministic for a
given Python/zlib build (zlib-ng emits different bytes at the same level).
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
    AttestationProtocol,
    AttestationTransport,
    BootSpec,
    BundleMembers,
    InstanceBootSpec,
    InstanceBundleMembers,
    InstanceRuntimeBundle,
    InstanceRuntimeManifest,
    RuntimeBundle,
    RuntimeManifest,
    SourceInfo,
    StrictModel,
    WorkloadSpec,
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

# Role -> file name inside the nix `instanceImage` output directory: OVMF,
# kernel, initrd only. No rootfs, no hash tree, no verity sidecars: the
# instance init has no verity branch (the guest supplies its own LUKS rootfs
# at runtime).
INSTANCE_MEMBER_FILES = {
    "ovmf": "OVMF.fd",
    "kernel": "bzImage",
    "initrd": "initrd",
}


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


class InstanceBundleInfo(StrictModel):
    """Sidecar record of an instance-flavor `build` run: no platform_roothash,
    no measurement (the instance image has no verity branch to measure)."""

    sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    size: int = Field(gt=0)
    members: InstanceBundleMembers
    source: SourceInfo


def _read_sidecar(image_dir: Path, name: str, pattern: str | None) -> str:
    value = (image_dir / name).read_text().strip()
    if pattern is not None and not re.fullmatch(pattern, value):
        msg = f"{name} does not look like a dm-verity roothash: {value!r}"
        raise ValueError(msg)
    return value


def _write_tar(image_dir: Path, tar_path: Path, source_epoch: int, file_names: list[str]) -> None:
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


def build_bundle(
    image_dir: Path,
    out_dir: Path,
    source_epoch: int,
    source: SourceInfo,
    flavor: str = "vprogram",
) -> BundleInfo | InstanceBundleInfo:
    """Package a nix image output directory as a deterministic tar.gz and
    write the bundle-info sidecar. Returns the recorded facts.

    `flavor="vprogram"` (default) expects the platform rootfs, its dm-verity
    hash tree, and the roothash/measurement sidecars, matching today's byte
    layout exactly. `flavor="compose"` packages the nix `composeImage`
    output, which has the exact same byte layout (the flavors differ only in
    which derivations fill the member slots), so it shares the vprogram
    path below. `flavor="instance"` expects only OVMF/kernel/initrd (the
    nix `instanceImage` output) and never reads a verity sidecar.
    """
    if flavor not in ("vprogram", "instance", "compose"):
        msg = f"unknown bundle flavor: {flavor!r}"
        raise ValueError(msg)

    if flavor == "instance":
        file_names = sorted(INSTANCE_MEMBER_FILES.values())
        for name in file_names:
            if not (image_dir / name).is_file():
                msg = f"expected image file missing: {image_dir / name}"
                raise FileNotFoundError(msg)

        tar_path = out_dir / BUNDLE_NAME
        _write_tar(image_dir, tar_path, source_epoch, file_names)

        data = tar_path.read_bytes()
        instance_info = InstanceBundleInfo(
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            members=InstanceBundleMembers(
                **{role: f"{TAR_PREFIX}/{name}" for role, name in INSTANCE_MEMBER_FILES.items()}
            ),
            source=source,
        )
        info_path = out_dir / BUNDLE_INFO_NAME
        info_path.write_text(json.dumps(instance_info.model_dump(mode="json"), indent=2, sort_keys=True) + "\n")
        return instance_info

    file_names = sorted({*MEMBER_FILES.values(), ROOTHASH_FILE, MEASUREMENT_FILE})
    for name in file_names:
        if not (image_dir / name).is_file():
            msg = f"expected image file missing: {image_dir / name}"
            raise FileNotFoundError(msg)

    platform_roothash = _read_sidecar(image_dir, ROOTHASH_FILE, SHA256_HEX_PATTERN)
    measurement = _read_sidecar(image_dir, MEASUREMENT_FILE, None)

    tar_path = out_dir / BUNDLE_NAME
    _write_tar(image_dir, tar_path, source_epoch, file_names)

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


# Fixed format-version-1 values describing what the current image implements
# (nix/init.sh hardcodes the agent on tcp/8443 proxying 127.0.0.1:8080, and
# its init parses roothash= plus the optional workload_roothash=). Changing
# these is a runtime/format evolution, not a CLI flag.
CMDLINE_TEMPLATE_V1 = "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}"
# Exec-runtime flavor: the daemon measures a workload rootfs alongside the
# platform rootfs and folds its dm-verity roothash into the cmdline (the daemon
# emits exactly this string once the CLI drops or fills the verified_volumes
# token; snp_config_slice appends ' verified_volumes=h1,h2' only when the
# launcher staged the sidecar). Client-side launch-measurement computation
# depends on byte-identity with what the daemon emits, so this constant must
# not be reformatted independently of that emitter.
CMDLINE_TEMPLATE_EXEC_V1 = (
    "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}"
    " workload_roothash={workload_roothash}"
    " verified_volumes={verified_volumes}"
)
DEFAULT_CPU_MODELS = ["EPYC-v4"]
DEFAULT_ATTESTATION = [
    AttestationProtocol(protocol="aleph.ra-tls", version="1", transport=AttestationTransport(type="tcp", port=8443))
]
DEFAULT_WORKLOAD = WorkloadSpec(contract="aleph.builtin/1", upstream_port=8080)
# Exec-runtime workload contract: a plain executable/command workload rather
# than the builtin no-workload runtime.
EXEC_WORKLOAD = WorkloadSpec(contract="aleph.exec/1", upstream_port=8080)
# Compose-runtime workload contract: a multi-service workload defined by a
# compose file rather than a single command; it boots a measured workload
# rootfs just like exec, so it shares CMDLINE_TEMPLATE_EXEC_V1 above.
COMPOSE_WORKLOAD = WorkloadSpec(contract="aleph.compose/1", upstream_port=8080)
# Instance-runtime luks-mode cmdline template (format version 1): the
# instance init parses `luks=` and `owner=` off /proc/cmdline (design section
# 4.1). No platform_roothash slot: the instance image has no verity rootfs.
CMDLINE_TEMPLATE_LUKS_V1 = "console=ttyS0 luks=1 owner={owner}"


def make_manifest(
    info: BundleInfo,
    bundle_ref: str,
    name: str,
    runtime_version: str,
    *,
    exec_runtime: bool = False,
    compose_runtime: bool = False,
) -> RuntimeManifest:
    """Build the manifest for an uploaded bundle. Validation is the
    constructor: any inconsistency raises pydantic ValidationError.

    By default builds the platform-only, no-workload manifest (builtin
    contract, `{platform_roothash}`-only cmdline template). Pass
    `exec_runtime=True` to select the `aleph.exec/1` workload contract, or
    `compose_runtime=True` to select the `aleph.compose/1` workload
    contract; both use the same `{platform_roothash}`/`{workload_roothash}`
    cmdline template, since both boot a separate measured workload rootfs.
    The two are mutually exclusive.
    """
    if exec_runtime and compose_runtime:
        msg = "exec_runtime and compose_runtime are mutually exclusive"
        raise ValueError(msg)
    workload_runtime = exec_runtime or compose_runtime
    cmdline_template = CMDLINE_TEMPLATE_EXEC_V1 if workload_runtime else CMDLINE_TEMPLATE_V1
    if exec_runtime:
        workload = EXEC_WORKLOAD
    elif compose_runtime:
        workload = COMPOSE_WORKLOAD
    else:
        workload = DEFAULT_WORKLOAD
    return RuntimeManifest(
        format="aleph-vprogram-runtime",
        format_version=1,
        name=name,
        version=runtime_version,
        platform="sev_snp",
        bundle=RuntimeBundle(ref=bundle_ref, sha256=info.sha256, size=info.size, members=info.members),
        boot=BootSpec(
            method="qemu-direct-kernel",
            kernel_hashes=True,
            cpu_models=list(DEFAULT_CPU_MODELS),
            platform_roothash=info.platform_roothash,
            cmdline_template=cmdline_template,
        ),
        attestation=[protocol.model_copy(deep=True) for protocol in DEFAULT_ATTESTATION],
        workload=workload.model_copy(deep=True),
        source=info.source,
    )


def make_instance_manifest(
    info: InstanceBundleInfo, bundle_ref: str, name: str, version: str
) -> InstanceRuntimeManifest:
    """Build the aleph-instance-runtime manifest for an uploaded instance
    bundle. Validation is the constructor: any inconsistency raises pydantic
    ValidationError.

    Fixed to the luks-mode boot recipe (`{owner}`-only cmdline template); no
    workload contract, no platform_roothash (the instance image has no
    verity rootfs to measure).
    """
    return InstanceRuntimeManifest(
        format="aleph-instance-runtime",
        format_version=1,
        name=name,
        version=version,
        platform="sev_snp",
        bundle=InstanceRuntimeBundle(ref=bundle_ref, sha256=info.sha256, size=info.size, members=info.members),
        boot=InstanceBootSpec(
            method="qemu-direct-kernel",
            kernel_hashes=True,
            cpu_models=list(DEFAULT_CPU_MODELS),
            cmdline_template=CMDLINE_TEMPLATE_LUKS_V1,
        ),
        attestation=[protocol.model_copy(deep=True) for protocol in DEFAULT_ATTESTATION],
        source=info.source,
    )


def verify_bundle_info(info: BundleInfo | InstanceBundleInfo, tar_path: Path) -> None:
    """Cross-check a bundle-info sidecar against the tarball on disk."""
    data = tar_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != info.sha256 or len(data) != info.size:
        msg = (
            f"bundle {tar_path} does not match bundle-info: "
            f"sha256 {digest} != {info.sha256} or size {len(data)} != {info.size}"
        )
        raise ValueError(msg)
