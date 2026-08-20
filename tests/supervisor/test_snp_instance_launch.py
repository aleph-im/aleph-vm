"""Tests for the confidential-INSTANCE SEV-SNP launch path (agent side).

Everything runs offline: get_existing_file is monkeypatched (both in this
module's namespace, for the manifest fetch, and in aleph.vm.agent.snp_staging's
namespace, for the bundle fetch) to serve a manifest JSON and a locally built
bundle tarball from tmp_path, mirroring tests/supervisor/test_vprogram_launch.py.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import io
import json
import tarfile
from pathlib import Path
from typing import IO, Any, cast

import pytest
from aleph_message.models import ItemHash
from aleph_message.models.execution.base import Payment, PaymentType
from aleph_message.models.execution.environment import (
    DEFAULT_SNP_POLICY,
    HypervisorType,
    InstanceEnvironment,
    LaunchMeasurement,
    MachineResources,
    TeePlatform,
    TrustedExecutionEnvironment,
)
from aleph_message.models.execution.instance import InstanceContent, RootfsVolume
from aleph_message.models.execution.volume import ParentVolume, VolumePersistence
from aleph_message.utils import Mebibytes

from aleph.vm.agent.snp_instance_launch import (
    build_snp_instance_spec,
    fetch_instance_runtime_manifest,
    is_snp_instance,
    remove_snp_instance_staging,
    snp_instance_staging_dir,
)
from aleph.vm.agent.vm.downloader import QemuDownloader
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import DiskFormat, TeeBackend
from aleph.vm.vprogram.manifest import InstanceRuntimeManifest

VM_HASH = ItemHash("deadbeef" * 8)
_FAKE_HASH = ItemHash("cafecafe" * 8)
MANIFEST_REF = "d00dd00d" * 8
BUNDLE_REF = "b1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1eeb1ee"

OWNER_LOWER = "0x1234567890abcdef1234567890abcdef12345678"
NON_EVM_ADDRESS = "5FHwkrdxDCvSXWvBaHf3Aq6X8AfUY5vLwLLpAt7dQxCg"

# The reference instance manifest shape (tests/vprogram/test_manifest.py), with
# the bundle digest/size patched per-test to match the locally built tarball.
MANIFEST_TEMPLATE: dict[str, Any] = {
    "format": "aleph-instance-runtime",
    "format_version": 1,
    "name": "aleph-snp-instance",
    "version": "2026.08.18",
    "platform": "sev_snp",
    "bundle": {
        "ref": BUNDLE_REF,
        "sha256": "0" * 64,
        "size": 1,
        "members": {
            "ovmf": "OVMF.fd",
            "kernel": "bzImage",
            "initrd": "initrd",
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
        "build": 'nix build "git+file://$REPO?dir=nix#instance-image"',
    },
}

# A v-program-shaped manifest (wrong format): used to prove
# fetch_instance_runtime_manifest rejects it by name.
VPROGRAM_MANIFEST: dict[str, Any] = {
    "format": "aleph-vprogram-runtime",
    "format_version": 1,
    "name": "aleph-snp-attest",
    "version": "2026.07.08",
    "platform": "sev_snp",
    "bundle": {
        "ref": BUNDLE_REF,
        "sha256": "0" * 64,
        "size": 1,
        "members": {
            "ovmf": "OVMF.fd",
            "kernel": "bzImage",
            "initrd": "initrd",
            "platform_rootfs": "rootfs.ext4",
            "platform_hash_tree": "rootfs.ext4.verity",
        },
    },
    "boot": {
        "method": "qemu-direct-kernel",
        "kernel_hashes": True,
        "cpu_models": ["EPYC-v4"],
        "platform_roothash": "a" * 64,
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

BUNDLE_FILES: dict[str, bytes] = {
    "OVMF.fd": b"ovmf firmware blob",
    "bzImage": b"kernel image",
    "initrd": b"initial ramdisk",
}


def make_bundle(out_dir: Path, files: dict[str, bytes] | None = None) -> Path:
    """Build a tar.gz shaped like the instance bundle: OVMF, kernel, initrd only."""
    files = BUNDLE_FILES if files is None else files
    tar_path = out_dir / "snp-instance-image.tar.gz"
    with tar_path.open("wb") as raw:
        with gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=0) as gz:
            with tarfile.open(fileobj=cast(IO[bytes], gz), mode="w") as tar:
                for name, data in sorted(files.items()):
                    member = tarfile.TarInfo(name)
                    member.size = len(data)
                    member.mode = 0o644
                    tar.addfile(member, io.BytesIO(data))
    return tar_path


def make_manifest(
    tar_path: Path, out_dir: Path, template: dict[str, Any] = MANIFEST_TEMPLATE, **overrides: Any
) -> Path:
    """Write a manifest JSON whose bundle digest/size match tar_path."""
    data = copy.deepcopy(template)
    raw = tar_path.read_bytes()
    data["bundle"]["sha256"] = hashlib.sha256(raw).hexdigest()
    data["bundle"]["size"] = len(raw)
    for dotted, value in overrides.items():
        target = data
        *parents, leaf = dotted.split(".")
        for key in parents:
            target = target[key]
        target[leaf] = value
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(data))
    return manifest_path


def snp_instance_content(
    *,
    address: str = OWNER_LOWER,
    authorized_keys: list[str] | None = None,
    variables: dict[str, str] | None = None,
    trusted_execution_overrides: dict[str, Any] | None = None,
) -> InstanceContent:
    trusted_execution_kwargs: dict[str, Any] = {
        "mode": "sev_snp",
        "policy": DEFAULT_SNP_POLICY,
        "runtime": ItemHash(MANIFEST_REF),
        "measurements": [LaunchMeasurement(platform=TeePlatform.sev_snp, digest="a" * 96, vcpu_type="EPYC-v4")],
    }
    trusted_execution_kwargs.update(trusted_execution_overrides or {})
    return InstanceContent(
        address=address,
        time=1.0,
        allow_amend=False,
        authorized_keys=authorized_keys,
        variables=variables,
        # SEV-SNP confidential instances are credit-only (schema-enforced).
        payment=Payment(type=PaymentType.credit),
        environment=InstanceEnvironment(
            internet=True,
            aleph_api=False,
            hypervisor=HypervisorType.qemu,
            trusted_execution=TrustedExecutionEnvironment(**trusted_execution_kwargs),
        ),
        resources=MachineResources(vcpus=2, memory=Mebibytes(2048), seconds=300),
        volumes=[],
        rootfs=RootfsVolume(
            parent=ParentVolume(ref=_FAKE_HASH, use_latest=False),
            persistence=VolumePersistence.host,
            size_mib=10000,
        ),
    )


@pytest.fixture
def storage_files(tmp_path, monkeypatch) -> dict[str, Path]:
    """Serve get_existing_file from a local ref -> path map: no network.

    Patches BOTH namespaces the launch path resolves refs through: this
    module's own get_existing_file (the manifest fetch) and
    aleph.vm.agent.snp_staging's (the bundle fetch, via fetch_and_stage_bundle).
    """
    files: dict[str, Path] = {}

    async def fake_get_existing_file(ref: str) -> Path:
        return files[str(ref)]

    monkeypatch.setattr("aleph.vm.agent.snp_instance_launch.get_existing_file", fake_get_existing_file)
    monkeypatch.setattr("aleph.vm.agent.snp_staging.get_existing_file", fake_get_existing_file)
    monkeypatch.setattr(settings, "EXECUTION_ROOT", str(tmp_path))
    return files


@pytest.fixture
def snp_supported(monkeypatch):
    monkeypatch.setattr("aleph.vm.agent.snp_instance_launch.check_amd_sev_snp_supported", lambda: True)


@pytest.fixture
def staged_instance_bundle(tmp_path, storage_files, snp_supported, monkeypatch) -> dict[str, Path]:
    tar_path = make_bundle(tmp_path)
    manifest_path = make_manifest(tar_path, tmp_path)
    storage_files[MANIFEST_REF] = manifest_path
    storage_files[BUNDLE_REF] = tar_path

    async def fake_download_all(self) -> None:
        self.rootfs_path = tmp_path / "instance-rootfs.qcow2"
        self.rootfs_path.write_bytes(b"writable luks rootfs")
        self.volumes = []

    monkeypatch.setattr(QemuDownloader, "download_all", fake_download_all)

    return {"tar": tar_path, "manifest": manifest_path}


@pytest.mark.asyncio
async def test_build_snp_instance_spec_happy_path(staged_instance_bundle):
    spec, attest_port = await build_snp_instance_spec(VM_HASH, snp_instance_content())

    assert spec.tee is not None
    assert spec.tee.backend is TeeBackend.SEV_SNP
    assert spec.tee.kernel_cmdline == f"console=ttyS0 luks=1 owner={OWNER_LOWER}"
    assert spec.tee.policy == str(DEFAULT_SNP_POLICY)
    rootfs = spec.rootfs
    assert rootfs is not None
    assert rootfs.format is DiskFormat.QCOW2
    assert rootfs.readonly is False
    assert spec.kernel_path.name == "bzImage"
    assert spec.initrd_path.name == "initrd"
    assert spec.tee.firmware_path is not None
    assert spec.tee.firmware_path.name == "OVMF.fd"
    assert spec.ssh_authorized_keys == []
    assert spec.persistent is True
    assert spec.hostname
    assert attest_port == 8443


@pytest.mark.asyncio
async def test_rejects_attestation_port_set(staged_instance_bundle):
    content = snp_instance_content(trusted_execution_overrides={"attestation_port": 9000})
    with pytest.raises(VmSetupError, match="attestation_port"):
        await build_snp_instance_spec(VM_HASH, content)


@pytest.mark.asyncio
async def test_rejects_non_evm_sender(snp_supported):
    content = snp_instance_content(address=NON_EVM_ADDRESS)
    with pytest.raises(VmSetupError, match="EVM"):
        await build_snp_instance_spec(VM_HASH, content)


@pytest.mark.asyncio
async def test_rejects_vprogram_manifest(tmp_path, storage_files, snp_supported):
    """A runtime ref that resolves to an aleph-vprogram-runtime manifest must
    be rejected by name: fetch_instance_runtime_manifest validates strictly
    against InstanceRuntimeManifest's format literal."""
    tar_path = make_bundle(tmp_path)
    manifest_path = make_manifest(tar_path, tmp_path, template=VPROGRAM_MANIFEST)
    storage_files[MANIFEST_REF] = manifest_path
    storage_files[BUNDLE_REF] = tar_path

    content = snp_instance_content()
    with pytest.raises(VmSetupError, match="aleph-instance-runtime"):
        await build_snp_instance_spec(VM_HASH, content)


@pytest.mark.asyncio
async def test_rejects_policy_above_u32(snp_supported):
    # Bit 17 (reserved, must be set) stays set so the message schema itself
    # accepts the policy; only the launch-path 32-bit cap rejects it.
    over_u32_policy = (1 << 32) | (1 << 17)
    content = snp_instance_content(trusted_execution_overrides={"policy": over_u32_policy})
    with pytest.raises(VmSetupError, match="policy"):
        await build_snp_instance_spec(VM_HASH, content)


@pytest.mark.asyncio
async def test_rejects_host_without_snp(monkeypatch):
    monkeypatch.setattr("aleph.vm.agent.snp_instance_launch.check_amd_sev_snp_supported", lambda: False)
    content = snp_instance_content()
    with pytest.raises(VmSetupError, match="SEV-SNP"):
        await build_snp_instance_spec(VM_HASH, content)


@pytest.mark.asyncio
async def test_warns_and_ignores_authorized_keys(caplog, staged_instance_bundle):
    content = snp_instance_content(authorized_keys=["ssh-ed25519 AAAAB3NzaC1lZDI1NTE5AAAAIAbc owner@example.com"])
    with caplog.at_level("WARNING"):
        spec, _ = await build_snp_instance_spec(VM_HASH, content)

    assert spec.ssh_authorized_keys == []
    assert any("authorized_keys" in record.message for record in caplog.records)


def test_is_snp_instance_true_for_sev_snp_mode():
    assert is_snp_instance(snp_instance_content()) is True


def test_is_snp_instance_false_for_non_instance_content():
    assert is_snp_instance(object()) is False


def test_is_snp_instance_false_for_no_trusted_execution():
    content = snp_instance_content()
    plain = content.model_copy(
        update={"environment": content.environment.model_copy(update={"trusted_execution": None})}
    )
    assert is_snp_instance(plain) is False


@pytest.mark.asyncio
async def test_fetch_instance_runtime_manifest_parses(tmp_path, storage_files):
    tar_path = make_bundle(tmp_path)
    manifest_path = make_manifest(tar_path, tmp_path)
    storage_files[MANIFEST_REF] = manifest_path

    manifest = await fetch_instance_runtime_manifest(MANIFEST_REF)
    assert isinstance(manifest, InstanceRuntimeManifest)
    assert manifest.platform == "sev_snp"
    assert manifest.bundle.members.kernel == "bzImage"


def test_remove_snp_instance_staging_is_idempotent(tmp_path, monkeypatch):
    """The teardown paths call remove_snp_instance_staging so a churned
    confidential instance does not leak its extracted bundle. It must remove
    a populated staging dir and be a no-op (never raise) when there is
    nothing to remove."""
    monkeypatch.setattr(settings, "EXECUTION_ROOT", str(tmp_path))
    staging = snp_instance_staging_dir(VM_HASH)
    staging.mkdir(parents=True)
    (staging / "OVMF.fd").write_bytes(b"ovmf firmware blob")
    assert staging.exists()

    remove_snp_instance_staging(VM_HASH)
    assert not staging.exists()

    # Already gone (second teardown, or a non-SNP-instance VM with no staging dir).
    remove_snp_instance_staging(VM_HASH)
    assert not staging.exists()
