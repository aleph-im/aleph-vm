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


def _validate_cmdline_template(value: str, allowed: frozenset[str], required: str) -> str:
    """Shared cmdline-template validator: parses `value` as a str.format
    template, rejects positional/format-spec/conversion placeholders, and
    checks the placeholder set against `allowed` (closed set) with `required`
    mandatory. Used by both BootSpec (v-program) and InstanceBootSpec so the
    two formats cannot drift apart."""
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
    unknown = placeholders - allowed
    if unknown:
        msg = f"unknown cmdline placeholders for format version 1: {sorted(unknown)}"
        raise ValueError(msg)
    if required not in placeholders:
        msg = f"cmdline template must contain {{{required}}}"
        raise ValueError(msg)
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
        return _validate_cmdline_template(value, CMDLINE_PLACEHOLDERS_V1, "platform_roothash")


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
    source: SourceInfo

    def to_canonical_json(self) -> str:
        """The exact bytes to publish: compact separators, sorted keys, so
        independently regenerated manifests hash identically."""
        return json.dumps(self.model_dump(mode="json"), separators=(",", ":"), sort_keys=True)


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
        return _validate_cmdline_template(value, CMDLINE_PLACEHOLDERS_LUKS_V1, "owner")


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
