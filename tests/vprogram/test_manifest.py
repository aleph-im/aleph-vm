"""Tests for the aleph-vprogram-runtime manifest model."""

import copy
import json
import re
from collections.abc import Callable
from copy import deepcopy
from typing import Any

import pytest
from pydantic import ValidationError

from aleph.vm.vprogram.bundle import COMPOSE_WORKLOAD
from aleph.vm.vprogram.manifest import (
    CONTRACT_PATTERN,
    InstanceRuntimeManifest,
    RuntimeManifest,
)

# The reference manifest from the design doc, with the real mainnet bundle values.
REFERENCE_MANIFEST: dict[str, Any] = {
    "format": "aleph-vprogram-runtime",
    "format_version": 1,
    "name": "aleph-snp-attest",
    "version": "2026.07.08",
    "platform": "sev_snp",
    "bundle": {
        "ref": "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977",
        "sha256": "1db0d69c96dc7ed6c8a6cbb8c63f8de516ef4ed668e95c468cc216e4c44d911b",
        "size": 57522386,
        "members": {
            "ovmf": "image/OVMF.fd",
            "kernel": "image/bzImage",
            "initrd": "image/initrd",
            "platform_rootfs": "image/rootfs.ext4",
            "platform_hash_tree": "image/rootfs.ext4.verity",
        },
    },
    "boot": {
        "method": "qemu-direct-kernel",
        "kernel_hashes": True,
        "cpu_models": ["EPYC-v4"],
        "platform_roothash": "cb121a317be7dc7969dd633ca9b6c3718ffe9ea6715b64e0e35a871d484b56b8",
        "cmdline_template": "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}",
    },
    "attestation": [{"protocol": "aleph.ra-tls", "version": "1", "transport": {"type": "tcp", "port": 8443}}],
    "workload": {"contract": "aleph.builtin/1", "upstream_port": 8080},
    "source": {
        "repo": "https://github.com/aleph-im/aleph-vm",
        "rev": "4d90abaf",
        "build": 'nix build "git+file://$REPO?dir=nix#image"',
    },
}


def test_reference_manifest_validates_and_roundtrips() -> None:
    manifest = RuntimeManifest.model_validate(REFERENCE_MANIFEST)
    canonical = manifest.to_canonical_json()
    assert RuntimeManifest.model_validate_json(canonical) == manifest
    # Canonical form is compact, key-sorted, and loses no data.
    assert json.loads(canonical) == REFERENCE_MANIFEST
    assert ": " not in canonical
    assert canonical == json.dumps(json.loads(canonical), separators=(",", ":"), sort_keys=True)


def test_compose_workload_constant() -> None:
    assert COMPOSE_WORKLOAD.contract == "aleph.compose/1"
    assert COMPOSE_WORKLOAD.upstream_port == 8080
    assert re.fullmatch(CONTRACT_PATTERN, COMPOSE_WORKLOAD.contract)


def test_workload_roothash_and_verified_volumes_slots_are_legal() -> None:
    data = copy.deepcopy(REFERENCE_MANIFEST)
    data["boot"]["cmdline_template"] = (
        "console=ttyS0 root=/dev/mapper/verity-root ro roothash={platform_roothash}"
        " workload_roothash={workload_roothash} verified_volumes={verified_volumes}"
    )
    RuntimeManifest.model_validate(data)  # must not raise


REJECTION_CASES: list[tuple[str, Callable[[dict[str, Any]], None]]] = [
    ("roothash too short", lambda d: d["boot"].update(platform_roothash="cb12")),
    ("roothash uppercase", lambda d: d["boot"].update(platform_roothash="CB" * 32)),
    ("bundle ref not hex", lambda d: d["bundle"].update(ref="z" * 64)),
    (
        "unknown cmdline placeholder",
        lambda d: d["boot"].update(cmdline_template="roothash={platform_roothash} x={foo}"),
    ),
    ("template missing platform_roothash", lambda d: d["boot"].update(cmdline_template="console=ttyS0 ro")),
    ("positional placeholder", lambda d: d["boot"].update(cmdline_template="roothash={platform_roothash} {}")),
    ("format spec in placeholder", lambda d: d["boot"].update(cmdline_template="roothash={platform_roothash:>10}")),
    ("conversion in placeholder", lambda d: d["boot"].update(cmdline_template="roothash={platform_roothash!r}")),
    ("unbalanced brace", lambda d: d["boot"].update(cmdline_template="roothash={platform_roothash} {oops")),
    ("port zero", lambda d: d["attestation"][0]["transport"].update(port=0)),
    ("port too large", lambda d: d["attestation"][0]["transport"].update(port=65536)),
    ("empty attestation list", lambda d: d.update(attestation=[])),
    ("bad protocol identifier", lambda d: d["attestation"][0].update(protocol="RA-TLS")),
    ("unnamespaced protocol", lambda d: d["attestation"][0].update(protocol="aleph")),
    ("empty protocol version", lambda d: d["attestation"][0].update(version="")),
    ("absolute member path", lambda d: d["bundle"]["members"].update(ovmf="/etc/passwd")),
    ("traversing member path", lambda d: d["bundle"]["members"].update(kernel="image/../../x")),
    ("empty member path", lambda d: d["bundle"]["members"].update(initrd="")),
    ("contract without version", lambda d: d["workload"].update(contract="aleph.builtin")),
    ("unnamespaced contract", lambda d: d["workload"].update(contract="builtin/1")),
    ("unknown format", lambda d: d.update(format="aleph-runtime")),
    ("unknown format_version", lambda d: d.update(format_version=2)),
    ("unknown platform", lambda d: d.update(platform="tdx")),
    ("kernel_hashes false", lambda d: d["boot"].update(kernel_hashes=False)),
    ("empty cpu_models", lambda d: d["boot"].update(cpu_models=[])),
    ("bundle size zero", lambda d: d["bundle"].update(size=0)),
    ("empty name", lambda d: d.update(name="")),
    ("empty source rev", lambda d: d["source"].update(rev="")),
    ("extra top-level field", lambda d: d.update(comment="hi")),
    ("extra bundle field", lambda d: d["bundle"].update(mirror="x")),
    ("extra boot field", lambda d: d["boot"].update(ip="dhcp")),
    ("extra transport field", lambda d: d["attestation"][0]["transport"].update(host="x")),
]


@pytest.mark.parametrize(("description", "mutate"), REJECTION_CASES, ids=[c[0] for c in REJECTION_CASES])
def test_rejections(description: str, mutate: Callable[[dict[str, Any]], None]) -> None:  # noqa: ARG001
    data = copy.deepcopy(REFERENCE_MANIFEST)
    mutate(data)
    with pytest.raises(ValidationError):
        RuntimeManifest.model_validate(data)


def test_vprogram_manifest_rejects_instance_format() -> None:
    """Symmetry guard: the two formats must not accept each other's literal."""
    bad = copy.deepcopy(REFERENCE_MANIFEST)
    bad["format"] = "aleph-instance-runtime"
    with pytest.raises(ValidationError):
        RuntimeManifest.model_validate(bad)


# The reference manifest for the aleph-instance-runtime format: TEE-agnostic
# in format name, no platform_roothash, no workload block, bundle members
# limited to ovmf/kernel/initrd (no rootfs, no hash tree).
MINIMAL_INSTANCE_MANIFEST: dict[str, Any] = {
    "format": "aleph-instance-runtime",
    "format_version": 1,
    "name": "aleph-snp-luks",
    "version": "2026.08.18",
    "platform": "sev_snp",
    "bundle": {
        "ref": "87287e4a5c8d7554a50f982cd681b64b2600c0bbb1c0b1e618465e022e01b977",
        "sha256": "1db0d69c96dc7ed6c8a6cbb8c63f8de516ef4ed668e95c468cc216e4c44d911b",
        "size": 57522386,
        "members": {
            "ovmf": "image/OVMF.fd",
            "kernel": "image/bzImage",
            "initrd": "image/initrd",
        },
    },
    "boot": {
        "method": "qemu-direct-kernel",
        "kernel_hashes": True,
        "cpu_models": ["EPYC-v4"],
        "cmdline_template": "console=ttyS0 luks=1 owner={owner}",
    },
    "attestation": [{"protocol": "aleph.ra-tls", "version": "1", "transport": {"type": "tcp", "port": 8443}}],
    "source": {
        "repo": "https://github.com/aleph-im/aleph-vm",
        "rev": "4d90abaf",
        "build": 'nix build "git+file://$REPO?dir=nix#image"',
    },
}


@pytest.fixture()
def minimal_instance_manifest_dict() -> dict[str, Any]:
    return copy.deepcopy(MINIMAL_INSTANCE_MANIFEST)


def test_instance_manifest_roundtrip(minimal_instance_manifest_dict: dict[str, Any]) -> None:
    manifest = InstanceRuntimeManifest.model_validate(minimal_instance_manifest_dict)
    assert manifest.platform == "sev_snp"
    assert "{owner}" in manifest.boot.cmdline_template
    assert InstanceRuntimeManifest.model_validate_json(manifest.to_canonical_json()) == manifest


def test_instance_manifest_rejects_vprogram_format(minimal_instance_manifest_dict: dict[str, Any]) -> None:
    bad = {**minimal_instance_manifest_dict, "format": "aleph-vprogram-runtime"}
    with pytest.raises(ValidationError):
        InstanceRuntimeManifest.model_validate(bad)


def test_instance_template_rejects_roothash_placeholder(minimal_instance_manifest_dict: dict[str, Any]) -> None:
    bad = deepcopy(minimal_instance_manifest_dict)
    bad["boot"]["cmdline_template"] = "console=ttyS0 luks=1 owner={owner} roothash={platform_roothash}"
    with pytest.raises(ValidationError, match="unknown cmdline placeholder"):
        InstanceRuntimeManifest.model_validate(bad)


def test_instance_template_requires_owner(minimal_instance_manifest_dict: dict[str, Any]) -> None:
    bad = deepcopy(minimal_instance_manifest_dict)
    bad["boot"]["cmdline_template"] = "console=ttyS0 luks=1"
    with pytest.raises(ValidationError, match="owner"):
        InstanceRuntimeManifest.model_validate(bad)


def test_instance_manifest_rejects_workload_field(minimal_instance_manifest_dict: dict[str, Any]) -> None:
    bad = {**minimal_instance_manifest_dict, "workload": {"contract": "aleph.builtin/1", "upstream_port": 8080}}
    with pytest.raises(ValidationError):
        InstanceRuntimeManifest.model_validate(bad)


def test_instance_manifest_rejects_platform_roothash_field(minimal_instance_manifest_dict: dict[str, Any]) -> None:
    bad = deepcopy(minimal_instance_manifest_dict)
    bad["boot"]["platform_roothash"] = "cb121a317be7dc7969dd633ca9b6c3718ffe9ea6715b64e0e35a871d484b56b8"
    with pytest.raises(ValidationError):
        InstanceRuntimeManifest.model_validate(bad)


def test_instance_manifest_rejects_extra_bundle_member(minimal_instance_manifest_dict: dict[str, Any]) -> None:
    bad = deepcopy(minimal_instance_manifest_dict)
    bad["bundle"]["members"]["platform_rootfs"] = "image/rootfs.ext4"
    with pytest.raises(ValidationError):
        InstanceRuntimeManifest.model_validate(bad)
