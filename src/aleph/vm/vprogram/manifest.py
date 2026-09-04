"""Typed model of the aleph-vprogram-runtime manifest format (version 1).

A runtime manifest is a small JSON document, published as a STORE message,
that a V-PROGRAM message pins via runtime.ref. It points at the runtime
bundle (ONE tar.gz holding OVMF, kernel, initrd and the dm-verity platform
rootfs plus its hash tree) and declares everything the tarball cannot say
about itself: the boot recipe, the normative kernel cmdline template, the
attestation protocols the runtime implements, and the workload contract.

Design: docs/plans/2026-07-09-vprogram-runtime-bundle-design.md
"""

from __future__ import annotations

import json
import re
import string
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SHA256_HEX_PATTERN = r"^[0-9a-f]{64}$"
# Namespaced identifier such as "aleph.ra-tls": at least two dot-separated
# labels, so bare names cannot collide with future namespaces.
PROTOCOL_PATTERN = r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+$"
# Namespaced contract with a required version suffix, e.g. "aleph.builtin/1".
CONTRACT_PATTERN = r"^[a-z0-9][a-z0-9_-]*(\.[a-z0-9][a-z0-9_-]*)+/[0-9]+$"

# The closed set of placeholders a format-version-1 cmdline template may use.
# The template is the normative cmdline recipe: restricting its slots is what
# prevents a malicious manifest from smuggling arbitrary kernel parameters.
CMDLINE_PLACEHOLDERS_V1 = frozenset({"platform_roothash", "workload_roothash", "verified_volumes"})
# The closed placeholder set for the aleph-instance-runtime luks cmdline
# template (format version 1): the instance init parses only `owner=` off
# /proc/cmdline, so that is the only slot a manifest may fill.
CMDLINE_PLACEHOLDERS_LUKS_V1 = frozenset({"owner"})

# The closed set of purely-literal (non-placeholder) tokens a format-version-1
# v-program cmdline template may carry, beyond `key={placeholder}` pairs
# (whose placeholder name is already restricted by CMDLINE_PLACEHOLDERS_V1).
# swiotlb=262144 is the gpu runtime's fixed IOMMU bounce-buffer size; nothing
# else may ride along (e.g. init=/bin/sh), same rationale as the placeholder
# allowlist above.
CMDLINE_FIXED_TOKENS_V1 = frozenset({"console=ttyS0", "root=/dev/mapper/verity-root", "ro", "swiotlb=262144"})
# The closed set of purely-literal tokens for the aleph-instance-runtime luks
# cmdline template.
CMDLINE_FIXED_TOKENS_LUKS_V1 = frozenset({"console=ttyS0", "luks=1"})

# The one legal spelling of each closed-set placeholder inside a cmdline
# token: `<key>={<placeholder>}`, nothing glued before or after it, and no
# other key. Without this, a placeholder-bearing token was only checked for
# its placeholder *name* being allowed, so `evil{platform_roothash}`,
# `roothash={platform_roothash}evil`, or `rdinit={platform_roothash}` all
# validated: the placeholder name alone said nothing about what surrounds
# it in the actual booted cmdline.
CMDLINE_PLACEHOLDER_KEYS = {
    "platform_roothash": "roothash",
    "workload_roothash": "workload_roothash",
    "verified_volumes": "verified_volumes",
    "owner": "owner",
}
_CMDLINE_KV_TOKEN = re.compile(r"^([a-z_]+)=\{([a-z_]+)\}$")

DRIVER_VERSION_PATTERN = r"^\d+\.\d+(\.\d+)?$"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _validate_member_path(value: str) -> str:
    if not value:
        msg = "member path must not be empty"
        raise ValueError(msg)
    if value.startswith("/"):
        msg = f"member path must be relative: {value}"
        raise ValueError(msg)
    if ".." in value.split("/"):
        msg = f"member path must not traverse upward: {value}"
        raise ValueError(msg)
    return value


def _parse_cmdline_placeholders(value: str) -> set[str]:
    """Parse `value` as a str.format template and return its placeholder
    names, rejecting positional/format-spec/conversion placeholders."""
    placeholders: set[str] = set()
    try:
        parsed = list(string.Formatter().parse(value))
    except ValueError as exc:
        msg = f"malformed cmdline template: {exc}"
        raise ValueError(msg) from exc
    for _literal, field_name, format_spec, conversion in parsed:
        if field_name is None:
            continue
        if field_name == "":
            msg = "cmdline template must not use positional placeholders"
            raise ValueError(msg)
        if format_spec or conversion:
            msg = f"cmdline placeholder must be plain (no format spec / conversion): {field_name}"
            raise ValueError(msg)
        placeholders.add(field_name)
    return placeholders


def _check_cmdline_tokens(value: str, fixed_tokens: frozenset[str]) -> None:
    """Check every whitespace-separated token in `value`: a token with no
    placeholder must be one of `fixed_tokens` (closed set); a token that
    carries a placeholder must be exactly `key={placeholder}`, with the key
    pinned per placeholder by CMDLINE_PLACEHOLDER_KEYS, and nothing glued
    onto either side."""
    for token in value.split():
        if "{" not in token and "}" not in token:
            if token not in fixed_tokens:
                msg = f"unknown fixed cmdline token {token!r}; allowed: {sorted(fixed_tokens)}"
                raise ValueError(msg)
            continue
        match = _CMDLINE_KV_TOKEN.fullmatch(token)
        if match is None:
            msg = f"cmdline token must be exactly key={{placeholder}}, with nothing else glued onto it: {token!r}"
            raise ValueError(msg)
        key, placeholder = match.groups()
        if CMDLINE_PLACEHOLDER_KEYS.get(placeholder) != key:
            msg = f"cmdline token {token!r} must pair {{{placeholder}}} with its pinned key, not {key!r}"
            raise ValueError(msg)


def _validate_cmdline_template(value: str, allowed: frozenset[str], required: str, fixed_tokens: frozenset[str]) -> str:
    """Shared cmdline-template validator: checks the template's placeholder
    set against `allowed` (closed set) with `required` mandatory, and checks
    every token (see `_check_cmdline_tokens`) so a manifest cannot smuggle an
    arbitrary kernel parameter such as `init=/bin/sh`, or arbitrary text
    glued onto a legitimate placeholder such as `rdinit={platform_roothash}`.
    Used by both BootSpec (v-program) and InstanceBootSpec so the two
    formats cannot drift apart."""
    placeholders = _parse_cmdline_placeholders(value)
    unknown = placeholders - allowed
    if unknown:
        msg = f"unknown cmdline placeholders {sorted(unknown)}; allowed: {sorted(allowed)}"
        raise ValueError(msg)
    if required not in placeholders:
        msg = f"cmdline template must contain {{{required}}}"
        raise ValueError(msg)
    _check_cmdline_tokens(value, fixed_tokens)
    return value


class BundleMembers(StrictModel):
    """Role -> path map inside the bundle tarball, so consumers never
    hardcode the layout."""

    ovmf: str
    kernel: str
    initrd: str
    platform_rootfs: str
    platform_hash_tree: str

    @field_validator("ovmf", "kernel", "initrd", "platform_rootfs", "platform_hash_tree")
    @classmethod
    def check_member_path(cls, value: str) -> str:
        return _validate_member_path(value)


class InstanceBundleMembers(StrictModel):
    """Role -> path map inside the instance bundle tarball: OVMF, kernel,
    initrd only (no rootfs, no hash tree; the instance image has no verity
    branch)."""

    ovmf: str
    kernel: str
    initrd: str

    @field_validator("ovmf", "kernel", "initrd")
    @classmethod
    def check_member_path(cls, value: str) -> str:
        return _validate_member_path(value)


class RuntimeBundle(StrictModel):
    ref: str = Field(pattern=SHA256_HEX_PATTERN, description="Item hash of the bundle STORE message")
    sha256: str = Field(pattern=SHA256_HEX_PATTERN, description="sha256 of the bundle tarball file")
    size: int = Field(gt=0, description="Size of the bundle tarball in bytes")
    members: BundleMembers


class BootSpec(StrictModel):
    method: Literal["qemu-direct-kernel"]
    kernel_hashes: Literal[True]
    cpu_models: list[str] = Field(min_length=1)
    platform_roothash: str = Field(
        pattern=SHA256_HEX_PATTERN,
        description="dm-verity root hash of the platform rootfs; measured via the cmdline",
    )
    cmdline_template: str

    @field_validator("cmdline_template")
    @classmethod
    def check_cmdline_template(cls, value: str) -> str:
        return _validate_cmdline_template(value, CMDLINE_PLACEHOLDERS_V1, "platform_roothash", CMDLINE_FIXED_TOKENS_V1)


class AttestationTransport(StrictModel):
    type: Literal["tcp"]
    port: int = Field(ge=1, le=65535)


class AttestationProtocol(StrictModel):
    protocol: str = Field(pattern=PROTOCOL_PATTERN, description='Protocol identifier, e.g. "aleph.ra-tls"')
    version: str = Field(min_length=1)
    transport: AttestationTransport


class WorkloadSpec(StrictModel):
    contract: str = Field(pattern=CONTRACT_PATTERN, description='Workload contract, e.g. "aleph.builtin/1"')
    upstream_port: int = Field(ge=1, le=65535)


class SourceInfo(StrictModel):
    """How to rebuild and audit the bundle. Informational but required."""

    repo: str = Field(min_length=1)
    rev: str = Field(min_length=1)
    build: str = Field(min_length=1)


class GpuRuntimeSpec(StrictModel):
    """What a client pins about the confidential GPU this runtime drives.
    Properties of the measured runtime (the driver is inside the image), so
    they live here, pinned through runtime.ref, and never in the message."""

    vendor: Literal["nvidia"]
    arch: Literal["blackwell", "hopper"]
    driver_version: str = Field(pattern=DRIVER_VERSION_PATTERN)
    accepted_models: list[str] = Field(
        min_length=1, description="Hardware model strings NVIDIA device certificates carry"
    )
    library_path: str = Field(
        pattern=r"^/[a-z0-9/_-]+$", description="Where the driver userland is mounted in the workload chroot"
    )


class RuntimeManifest(StrictModel):
    format: Literal["aleph-vprogram-runtime"]
    format_version: Literal[1]
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    platform: Literal["sev_snp"]
    bundle: RuntimeBundle
    boot: BootSpec
    # Ordered by preference; protocol identity lives ONLY here, never in
    # V-PROGRAM messages (rejected as denormalization in the protocol design).
    attestation: list[AttestationProtocol] = Field(min_length=1)
    workload: WorkloadSpec
    gpu: GpuRuntimeSpec | None = None
    source: SourceInfo

    def to_canonical_json(self) -> str:
        """The exact bytes to publish: compact separators, sorted keys, so
        independently regenerated manifests hash identically. `gpu` is
        omitted entirely (not published as null) when the runtime has no
        gpu facts, so a non-gpu manifest hashes exactly as it did before
        the field existed."""
        return json.dumps(self.model_dump(mode="json", exclude_none=True), separators=(",", ":"), sort_keys=True)


class InstanceRuntimeBundle(StrictModel):
    ref: str = Field(pattern=SHA256_HEX_PATTERN, description="Item hash of the bundle STORE message")
    sha256: str = Field(pattern=SHA256_HEX_PATTERN, description="sha256 of the bundle tarball file")
    size: int = Field(gt=0, description="Size of the bundle tarball in bytes")
    members: InstanceBundleMembers


class InstanceBootSpec(StrictModel):
    """Boot recipe for the aleph-instance-runtime format. TEE-agnostic name;
    no platform_roothash (the instance image has no verity rootfs to
    measure), no workload block (the guest owns its own rootfs via LUKS)."""

    method: Literal["qemu-direct-kernel"]
    kernel_hashes: Literal[True]
    cpu_models: list[str] = Field(min_length=1)
    cmdline_template: str

    @field_validator("cmdline_template")
    @classmethod
    def check_cmdline_template(cls, value: str) -> str:
        return _validate_cmdline_template(value, CMDLINE_PLACEHOLDERS_LUKS_V1, "owner", CMDLINE_FIXED_TOKENS_LUKS_V1)


class InstanceRuntimeManifest(StrictModel):
    """Typed model of the aleph-instance-runtime manifest format (version 1).

    Points at the instance bundle (OVMF, kernel, initrd; no rootfs, no hash
    tree: the guest supplies its own LUKS-encrypted rootfs at runtime) and
    declares the luks-mode cmdline template, the attestation protocols the
    runtime implements, and its build provenance. Platform is a field (not
    baked into the format name) so a future TEE backend reuses this format.

    Design: docs/plans/2026-08-18-snp-confidential-instances-design.md section 5.1
    """

    format: Literal["aleph-instance-runtime"]
    format_version: Literal[1]
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    platform: Literal["sev_snp"]
    bundle: InstanceRuntimeBundle
    boot: InstanceBootSpec
    attestation: list[AttestationProtocol] = Field(min_length=1)
    source: SourceInfo

    def to_canonical_json(self) -> str:
        """The exact bytes to publish: compact separators, sorted keys, so
        independently regenerated manifests hash identically."""
        return json.dumps(self.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)
