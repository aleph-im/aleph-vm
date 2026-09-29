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
from typing import Literal

from pydantic import Field, model_validator

from aleph.vm.vprogram.manifest import (
    CMDLINE_TDX_DESCRIPTOR_SWITCH_V1,
    SHA256_HEX_PATTERN,
    AttestationProtocol,
    AttestationTransport,
    BootSpec,
    BundleMembers,
    GpuRuntimeSpec,
    InstanceBootSpec,
    InstanceBundleMembers,
    InstanceGpuRuntimeSpec,
    InstanceRuntimeBundle,
    InstanceRuntimeManifest,
    RuntimeBundle,
    RuntimeManifest,
    SourceInfo,
    StrictModel,
    TdxBootSpec,
    TdxMeasurements,
    WorkloadSpec,
)

BUNDLE_NAME = "snp-image.tar.gz"
BUNDLE_INFO_NAME = "bundle-info.json"
MANIFEST_NAME = "manifest.json"
TAR_PREFIX = "image"

# Role -> file name inside the nix `image` output directory. The tdx flavor
# (nix `tdxImage`) has the same layout with TDVF in the OVMF.fd slot.
MEMBER_FILES = {
    "ovmf": "OVMF.fd",
    "kernel": "bzImage",
    "initrd": "initrd",
    "platform_rootfs": "rootfs.ext4",
    "platform_hash_tree": "rootfs.ext4.verity",
}
ROOTHASH_FILE = "rootfs.ext4.roothash"
MEASUREMENT_FILE = "measurement.hex"
# The tdx flavor's {mrtd, rtmr1, rtmr2} triple, in place of measurement.hex.
TDX_MEASUREMENTS_FILE = "measurements.json"

# The nix `gpuImage` output directory has the identical byte layout to the
# vprogram `image` output (the gpu flavor differs only in the extra gpu.json
# facts sidecar read below), so it packages from MEMBER_FILES too.
#
# The gpu flavor's build-time facts about the confidential GPU this runtime
# drives, written by the nix build alongside the usual image members. The
# instance-gpu flavor's `instanceGpuImage` output carries the same sidecar,
# minus library_path (the instance owner supplies the driver userland).
GPU_JSON_FILE = "gpu.json"

# Role -> file name inside the nix `instanceImage` (and `instanceGpuImage`)
# output directory: OVMF, kernel, initrd only. No rootfs, no hash tree, no
# verity sidecars: the instance init has no verity branch (the guest
# supplies its own LUKS rootfs at runtime).
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
    # The SNP measurement baked by the nix build (fixed CI shape); informational.
    measurement: str | None = Field(default=None, min_length=1)
    # The tdx flavor's register triple, published as the manifest's `measurements`.
    tdx_measurements: TdxMeasurements | None = None
    # Recorded only by a `flavor="gpu"` build, from the image's gpu.json.
    gpu: GpuRuntimeSpec | None = None
    source: SourceInfo

    @model_validator(mode="after")
    def check_one_measurement(self) -> BundleInfo:
        if (self.measurement is None) == (self.tdx_measurements is None):
            msg = "bundle-info records exactly one of measurement (sev_snp) or tdx_measurements (tdx)"
            raise ValueError(msg)
        return self


class InstanceBundleInfo(StrictModel):
    """Sidecar record of an instance-flavor `build` run: no platform_roothash,
    no measurement (the instance image has no verity branch to measure)."""

    sha256: str = Field(pattern=SHA256_HEX_PATTERN)
    size: int = Field(gt=0)
    members: InstanceBundleMembers
    # Recorded only by a `flavor="instance-gpu"` build, from the image's gpu.json.
    instance_gpu: InstanceGpuRuntimeSpec | None = None
    source: SourceInfo


def _read_sidecar(image_dir: Path, name: str, pattern: str | None) -> str:
    value = (image_dir / name).read_text().strip()
    if pattern is not None and not re.fullmatch(pattern, value):
        msg = f"{name} does not look like a dm-verity roothash: {value!r}"
        raise ValueError(msg)
    return value


def _check_image_files(image_dir: Path, file_names: list[str]) -> None:
    for name in file_names:
        if not (image_dir / name).is_file():
            msg = f"expected image file missing: {image_dir / name}"
            raise FileNotFoundError(msg)


def _read_gpu_facts_json(image_dir: Path) -> str:
    gpu_path = image_dir / GPU_JSON_FILE
    if not gpu_path.is_file():
        msg = f"expected gpu facts file missing: {gpu_path}"
        raise FileNotFoundError(msg)
    return gpu_path.read_text()


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
    path below. `flavor="gpu"` packages the nix `gpuImage` output, same byte
    layout again, plus an extra `gpu.json` facts sidecar (read into
    `BundleInfo.gpu`, never added to the tarball). `flavor="instance"`
    expects only OVMF/kernel/initrd (the nix `instanceImage` output) and
    never reads a verity sidecar. `flavor="instance-gpu"` packages the nix
    `instanceGpuImage` output, same byte layout as `instance`, plus the
    `gpu.json` facts sidecar (read into `InstanceBundleInfo.instance_gpu`).
    `flavor="tdx"` packages the nix `tdxImage` output: the vprogram layout
    with TDVF in the OVMF.fd slot and `measurements.json` (read into
    `BundleInfo.tdx_measurements`) in place of `measurement.hex`.
    """
    if flavor not in ("vprogram", "instance", "compose", "gpu", "instance-gpu", "tdx"):
        msg = f"unknown bundle flavor: {flavor!r}"
        raise ValueError(msg)

    if flavor in ("instance", "instance-gpu"):
        file_names = sorted(INSTANCE_MEMBER_FILES.values())
        _check_image_files(image_dir, file_names)

        instance_gpu_spec = (
            InstanceGpuRuntimeSpec.model_validate_json(_read_gpu_facts_json(image_dir))
            if flavor == "instance-gpu"
            else None
        )

        tar_path = out_dir / BUNDLE_NAME
        _write_tar(image_dir, tar_path, source_epoch, file_names)

        data = tar_path.read_bytes()
        instance_info = InstanceBundleInfo(
            sha256=hashlib.sha256(data).hexdigest(),
            size=len(data),
            members=InstanceBundleMembers(
                **{role: f"{TAR_PREFIX}/{name}" for role, name in INSTANCE_MEMBER_FILES.items()}
            ),
            instance_gpu=instance_gpu_spec,
            source=source,
        )
        info_path = out_dir / BUNDLE_INFO_NAME
        info_path.write_text(json.dumps(instance_info.model_dump(mode="json"), indent=2, sort_keys=True) + "\n")
        return instance_info

    measurement_file = TDX_MEASUREMENTS_FILE if flavor == "tdx" else MEASUREMENT_FILE
    file_names = sorted({*MEMBER_FILES.values(), ROOTHASH_FILE, measurement_file})
    _check_image_files(image_dir, file_names)

    gpu_spec = GpuRuntimeSpec.model_validate_json(_read_gpu_facts_json(image_dir)) if flavor == "gpu" else None

    platform_roothash = _read_sidecar(image_dir, ROOTHASH_FILE, SHA256_HEX_PATTERN)
    measurement: str | None = None
    tdx_measurements: TdxMeasurements | None = None
    if flavor == "tdx":
        tdx_measurements = TdxMeasurements.model_validate_json((image_dir / TDX_MEASUREMENTS_FILE).read_text())
    else:
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
        tdx_measurements=tdx_measurements,
        gpu=gpu_spec,
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
# Gpu-runtime flavor: same placeholder order and the same
# verified_volumes={verified_volumes} spelling as CMDLINE_TEMPLATE_EXEC_V1
# (the aleph-rs CLI renders {verified_volumes} as the joined roothashes and
# drops the whole verified_volumes= token when there are none; a bare
# {verified_volumes} slot would render an unmeasurable cmdline), with a
# fixed swiotlb=262144 token inserted before it to size the IOMMU bounce
# buffer for the passed-through confidential GPU. Byte-identity with what
# the daemon emits matters the same way CMDLINE_TEMPLATE_EXEC_V1's does.
#
# The three trailing slots carry the GPU requirement the guest enforces;
# gpu_models is dropped whole when the message names no model, like
# verified_volumes above it.
CMDLINE_TEMPLATE_GPU_V1 = (
    "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}"
    " workload_roothash={workload_roothash}"
    " swiotlb=262144"
    " verified_volumes={verified_volumes}"
    " gpu_arch={gpu_arch} gpu_count={gpu_count} gpu_models={gpu_models}"
)
# TDX runtime: the fixed per-runtime cmdline the daemon derives on its own
# (tdx_config_slice, lifecycle.rs) and RTMR2 is predicted from. No
# per-deployment slot: workload_roothash and friends travel on the
# MRCONFIGID-bound descriptor drive the last token switches the guest to.
CMDLINE_TEMPLATE_TDX_V1 = (
    f"console=ttyS0 root=/dev/mapper/verity-root ro roothash={{platform_roothash}} {CMDLINE_TDX_DESCRIPTOR_SWITCH_V1}"
)
# QEMU CPU models the published runtimes are measured for, in preference
# order: the CRN launches the first one its QEMU can run. Despite the name,
# "EPYC-v4" is QEMU's Naples model (family 23, model 1): no AVX-512, so
# vector-heavy workloads such as llama.cpp fall back to AVX2 and run several
# times slower than on the host silicon. "EPYC-Genoa" (family 25, model 17)
# exposes AVX-512 and is what every SEV-SNP CRN on the network advertises;
# "EPYC-v4" stays as the fallback so a Milan or Rome host is never stranded.
# Each entry costs one client-side measurement per launch; keep the list short.
DEFAULT_CPU_MODELS = ["EPYC-Genoa", "EPYC-v4"]
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
# Instance-gpu flavor: the luks template plus the fixed swiotlb=262144 token
# and the three gpu requirement slots, same spelling and order as
# CMDLINE_TEMPLATE_GPU_V1's. Byte-identity with what the daemon emits
# matters the same way that constant's does.
CMDLINE_TEMPLATE_INSTANCE_GPU_V1 = (
    "console=ttyS0 luks=1 swiotlb=262144 owner={owner}"
    " gpu_arch={gpu_arch} gpu_count={gpu_count} gpu_models={gpu_models}"
)


def _check_platform_facts(
    info: BundleInfo, platform: Literal["sev_snp", "tdx"], *, compose_runtime: bool, gpu_runtime: bool
) -> None:
    """A tdx manifest needs a tdx flavor build (and no compose/gpu image
    exists for tdx); a tdx flavor build cannot be published as anything else."""
    if platform == "tdx":
        if info.tdx_measurements is None:
            msg = "platform tdx needs the measurements recorded by the tdx flavor build"
            raise ValueError(msg)
        if compose_runtime or gpu_runtime:
            msg = "the compose and gpu runtimes have no tdx image"
            raise ValueError(msg)
    elif info.tdx_measurements is not None:
        msg = f"a tdx flavor build cannot be published as a {platform} runtime"
        raise ValueError(msg)


def _boot_spec(
    info: BundleInfo, platform: Literal["sev_snp", "tdx"], *, gpu_runtime: bool, workload_runtime: bool
) -> BootSpec | TdxBootSpec:
    if platform == "tdx":
        # The fixed TDX cmdline whatever the workload contract: the workload
        # tokens travel on the descriptor drive.
        return TdxBootSpec(
            method="qemu-direct-kernel",
            platform_roothash=info.platform_roothash,
            cmdline_template=CMDLINE_TEMPLATE_TDX_V1,
        )
    if gpu_runtime:
        cmdline_template = CMDLINE_TEMPLATE_GPU_V1
    elif workload_runtime:
        cmdline_template = CMDLINE_TEMPLATE_EXEC_V1
    else:
        cmdline_template = CMDLINE_TEMPLATE_V1
    return BootSpec(
        method="qemu-direct-kernel",
        kernel_hashes=True,
        cpu_models=list(DEFAULT_CPU_MODELS),
        platform_roothash=info.platform_roothash,
        cmdline_template=cmdline_template,
    )


def make_manifest(  # noqa: PLR0913 -- one flag per mutually exclusive workload flavor, kept explicit over a mode enum
    info: BundleInfo,
    bundle_ref: str,
    name: str,
    runtime_version: str,
    *,
    exec_runtime: bool = False,
    compose_runtime: bool = False,
    gpu_runtime: bool = False,
    platform: Literal["sev_snp", "tdx"] = "sev_snp",
) -> RuntimeManifest:
    """Build the manifest for an uploaded bundle. Validation is the
    constructor: any inconsistency raises pydantic ValidationError.

    By default builds the platform-only, no-workload manifest (builtin
    contract, `{platform_roothash}`-only cmdline template). Pass
    `exec_runtime=True` to select the `aleph.exec/1` workload contract, or
    `compose_runtime=True` to select the `aleph.compose/1` workload
    contract; both use the same `{platform_roothash}`/`{workload_roothash}`
    cmdline template, since both boot a separate measured workload rootfs.
    Pass `gpu_runtime=True` to select the `aleph.exec/1` workload contract
    with the gpu cmdline template (adds the fixed swiotlb=262144 token) and
    to carry `info.gpu` onto the manifest; it requires `info.gpu` to be set,
    i.e. `info` must come from a `flavor="gpu"` build. The three are
    mutually exclusive.

    `platform="tdx"` needs `info` from a `flavor="tdx"` build: the fixed TDX
    cmdline template replaces the SNP one whatever the workload contract
    (the workload tokens travel on the descriptor drive, not the cmdline),
    `info.tdx_measurements` becomes the manifest's `measurements`, and the
    compose and gpu runtimes are refused (no TDX image exists for either).
    """
    if sum((exec_runtime, compose_runtime, gpu_runtime)) > 1:
        msg = "exec_runtime, compose_runtime and gpu_runtime are mutually exclusive"
        raise ValueError(msg)
    _check_platform_facts(info, platform, compose_runtime=compose_runtime, gpu_runtime=gpu_runtime)
    if gpu_runtime and info.gpu is None:
        msg = "gpu_runtime needs the gpu facts recorded by the gpu flavor build"
        raise ValueError(msg)
    if exec_runtime or gpu_runtime:
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
        platform=platform,
        bundle=RuntimeBundle(ref=bundle_ref, sha256=info.sha256, size=info.size, members=info.members),
        boot=_boot_spec(info, platform, gpu_runtime=gpu_runtime, workload_runtime=exec_runtime or compose_runtime),
        attestation=[protocol.model_copy(deep=True) for protocol in DEFAULT_ATTESTATION],
        workload=workload.model_copy(deep=True),
        gpu=info.gpu.model_copy(deep=True) if gpu_runtime and info.gpu is not None else None,
        measurements=info.tdx_measurements.model_copy(deep=True) if info.tdx_measurements is not None else None,
        source=info.source,
    )


def make_instance_manifest(
    info: InstanceBundleInfo, bundle_ref: str, name: str, version: str, *, gpu_runtime: bool = False
) -> InstanceRuntimeManifest:
    """Build the aleph-instance-runtime manifest for an uploaded instance
    bundle. Validation is the constructor: any inconsistency raises pydantic
    ValidationError.

    Fixed to the luks-mode boot recipe (`{owner}`-only cmdline template); no
    workload contract, no platform_roothash (the instance image has no
    verity rootfs to measure). Pass `gpu_runtime=True` to select the
    instance-gpu cmdline template (adds the fixed swiotlb=262144 token and
    the three gpu requirement slots) and to carry `info.instance_gpu` onto
    the manifest; it requires `info.instance_gpu` to be set, i.e. `info`
    must come from a `flavor="instance-gpu"` build.
    """
    if gpu_runtime and info.instance_gpu is None:
        msg = "gpu_runtime needs the gpu facts recorded by the instance-gpu flavor build"
        raise ValueError(msg)
    cmdline_template = CMDLINE_TEMPLATE_INSTANCE_GPU_V1 if gpu_runtime else CMDLINE_TEMPLATE_LUKS_V1
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
            cmdline_template=cmdline_template,
        ),
        attestation=[protocol.model_copy(deep=True) for protocol in DEFAULT_ATTESTATION],
        gpu=info.instance_gpu.model_copy(deep=True) if gpu_runtime and info.instance_gpu is not None else None,
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
