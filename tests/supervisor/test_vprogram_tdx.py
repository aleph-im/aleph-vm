"""Tests for the V-PROGRAM Intel TDX launch path (agent side).

Mirrors test_vprogram_launch.py: get_existing_file serves a tdx runtime
manifest and a locally built bundle (TDVF in the OVMF.fd slot, the
measurements.json triple beside the members) from tmp_path, no network.

The tdx messages are the fixture message with a validated tdx verification
block (aleph-message 1.7.0); the launch path must still refuse a sev_snp
message that names a tdx runtime, and the reverse.
"""

from __future__ import annotations

import copy
import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from aleph_message.models import VerifiableProgramMessage
from aleph_message.models.execution.environment import (
    LaunchMeasurement,
    TdxRegisters,
    TeePlatform,
)
from aleph_message.models.execution.vprogram import (
    ConfidentialGpuRequirement,
    TeeVerification,
)
from test_vprogram_launch import (
    BUNDLE_FILES,
    BUNDLE_REF,
    FIXTURE_VOLUME_HASH_TREE_REF,
    FIXTURE_VOLUME_REF,
    MANIFEST_REF,
    MANIFEST_TEMPLATE,
    VOLUME_HASH_TREE_REFS,
    VOLUME_REFS,
    VOLUME_ROOTHASHES,
    load_vprogram_message,
    make_bundle,
    make_manifest,
    stage_volumes,
    stage_workload,
    vprogram_staging_dir,
)

from aleph.vm.agent import vprogram_launch
from aleph.vm.agent.vprogram_launch import TDX_MIN_MEMORY_MIB, build_vprogram_spec
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    Backend,
    DiskFormat,
    DiskRole,
    TeeBackend,
)
from aleph.vm.vprogram.bundle import CMDLINE_TEMPLATE_TDX_V1, TDX_MEASUREMENTS_FILE

TDX_MEASUREMENTS: dict[str, str] = {"mrtd": "ab" * 48, "rtmr1": "cd" * 48, "rtmr2": "ef" * 48}

# The tdx runtime: the SNP manifest shape with TDVF in the ovmf slot, the
# fixed descriptor cmdline, no kernel-hashes switch, no vCPU models, and
# the register triple a client pins.
TDX_MANIFEST_OVERRIDES: dict[str, Any] = {
    "name": "aleph-tdx-attest",
    "platform": "tdx",
    "boot": {
        "method": "qemu-direct-kernel",
        "kernel_hashes": False,
        "cpu_models": [],
        "platform_roothash": MANIFEST_TEMPLATE["boot"]["platform_roothash"],
        "cmdline_template": CMDLINE_TEMPLATE_TDX_V1,
    },
    "measurements": dict(TDX_MEASUREMENTS),
}

TDX_BUNDLE_FILES: dict[str, bytes] = {
    **BUNDLE_FILES,
    "OVMF.fd": b"tdvf firmware blob",
    TDX_MEASUREMENTS_FILE: json.dumps(TDX_MEASUREMENTS).encode(),
}


def stage_tdx_bundle(
    tmp_path: Path,
    storage_files: dict[str, Path],
    files: dict[str, bytes] | None = None,
    **manifest_overrides: Any,
) -> dict[str, Path]:
    tar_path = make_bundle(tmp_path, TDX_BUNDLE_FILES if files is None else files)
    overrides = {**copy.deepcopy(TDX_MANIFEST_OVERRIDES), **manifest_overrides}
    manifest_path = make_manifest(tar_path, tmp_path, **overrides)
    storage_files[MANIFEST_REF] = manifest_path
    storage_files[BUNDLE_REF] = tar_path
    workload = stage_workload(storage_files, tmp_path)
    fixture_volume_data = tmp_path / "fixture_volume_data.img"
    fixture_volume_data.write_bytes(b"fixture volume data")
    fixture_volume_tree = tmp_path / "fixture_volume_tree.img"
    fixture_volume_tree.write_bytes(b"fixture volume hash tree")
    storage_files[FIXTURE_VOLUME_REF] = fixture_volume_data
    storage_files[FIXTURE_VOLUME_HASH_TREE_REF] = fixture_volume_tree
    return {"tar": tar_path, "manifest": manifest_path, **workload}


@pytest.fixture
def storage_files(monkeypatch) -> dict[str, Path]:
    """Serve get_existing_file from a local ref -> path map: no network."""
    files: dict[str, Path] = {}

    async def fake_get_existing_file(ref: str) -> Path:
        return files[str(ref)]

    monkeypatch.setattr(vprogram_launch, "get_existing_file", fake_get_existing_file)
    return files


@pytest.fixture
def staged_tdx_bundle(tmp_path, storage_files) -> dict[str, Path]:
    return stage_tdx_bundle(tmp_path, storage_files)


@pytest.fixture
def tdx_host(mocker):
    """The host probe, answering True unless a test says otherwise."""

    def _set(*, supported: bool) -> None:
        mocker.patch.object(vprogram_launch, "check_intel_tdx_supported", return_value=supported)

    _set(supported=True)
    return _set


@pytest.fixture
def no_snp_probe(mocker):
    """The SNP vCPU probe must never run for a tdx launch; make it explode."""

    async def fail_probe() -> list[str]:
        raise AssertionError("the SNP vCPU probe must not run for a TDX launch")

    mocker.patch.object(vprogram_launch, "get_supported_snp_vcpu_types", fail_probe)


def tdx_message(*, memory: int | None = None, **content_updates: Any) -> VerifiableProgramMessage:
    """The fixture message re-pointed at a tdx backend, through the schema:
    no policy, one measurement with the runtime's triple."""
    message = load_vprogram_message()
    verification = TeeVerification(
        backend="tdx",
        measurements=[
            LaunchMeasurement(
                platform=TeePlatform.tdx,
                registers=TdxRegisters(
                    mrtd=TDX_MEASUREMENTS["mrtd"],
                    rtmr1=TDX_MEASUREMENTS["rtmr1"],
                    rtmr2=TDX_MEASUREMENTS["rtmr2"],
                    mrconfigid="44" * 48,
                ),
            )
        ],
    )
    updates: dict[str, Any] = {"verification": verification, **content_updates}
    if memory is not None:
        updates["resources"] = message.content.resources.model_copy(update={"memory": memory})
    content = message.content.model_copy(update=updates)
    return message.model_copy(update={"content": content})


@pytest.mark.asyncio
async def test_tdx_spec_takes_the_tdx_launch_path(staged_tdx_bundle, tdx_host, no_snp_probe):
    """A tdx manifest builds a TDX TeeConfig: TDVF as the firmware, no
    cmdline (the daemon derives the fixed one), no SEV policy, no vCPU
    model, and the same disk contract as SNP (rootfs, then the workload
    pair; the daemon inserts the hash tree and appends the descriptor)."""
    message = tdx_message(volumes=[])
    spec, attest_port = await build_vprogram_spec(message.item_hash, message.content)
    assert attest_port == 8443

    staging = vprogram_staging_dir(message.item_hash)
    assert spec.backend is Backend.QEMU
    assert spec.kernel_path == staging / "image/bzImage"
    assert spec.initrd_path == staging / "image/initrd"
    assert spec.memory_mib == 2048

    assert spec.tee is not None
    assert spec.tee.backend is TeeBackend.TDX
    assert spec.tee.firmware_path == staging / "image/OVMF.fd"
    assert spec.tee.firmware_path.read_bytes() == b"tdvf firmware blob"
    assert spec.tee.kernel_cmdline == ""
    assert spec.tee.cpu_model == ""
    assert spec.tee.policy == ""

    assert [d.path for d in spec.disks] == [
        staging / "image/rootfs.ext4",
        staged_tdx_bundle["data"],
        staged_tdx_bundle["hashtree"],
    ]
    assert [d.role for d in spec.disks] == [DiskRole.ROOTFS, DiskRole.EXTRA, DiskRole.EXTRA]
    assert all(d.readonly and d.format is DiskFormat.RAW for d in spec.disks)
    assert spec.gpus == []
    assert spec.persistent is True


@pytest.mark.asyncio
async def test_tdx_sidecars_are_staged_like_snp(staged_tdx_bundle, tdx_host, no_snp_probe):
    """The daemon builds the descriptor from the same sidecars the SNP
    verity arm splices into the cmdline: roothash, hash tree and workload
    roothash present; no volumes, no extra token, no GPU, so no such file."""
    message = tdx_message(volumes=[])
    spec, _ = await build_vprogram_spec(message.item_hash, message.content)
    rootfs = spec.rootfs.path
    platform_roothash = MANIFEST_TEMPLATE["boot"]["platform_roothash"]
    assert rootfs.with_name(rootfs.name + ".roothash").read_text().strip() == platform_roothash
    assert rootfs.with_name(rootfs.name + ".verity").is_file()
    assert rootfs.with_name(rootfs.name + ".workload_roothash").read_text().strip() == message.content.workload.roothash
    for sidecar in (".verified_volumes", ".cmdline_extra", ".gpu_requirement"):
        assert not rootfs.with_name(rootfs.name + sidecar).exists()


@pytest.mark.asyncio
async def test_tdx_accepts_verified_volumes_without_a_template_slot(
    staged_tdx_bundle, storage_files, tmp_path, tdx_host, no_snp_probe
):
    """The TDX template has no {verified_volumes} slot by design (the token
    rides the descriptor), so the SNP slot check must not fire: the volumes
    are attached as (data, hash tree) pairs and their sidecar staged."""
    volumes = stage_volumes(storage_files, tmp_path, 2)
    message = tdx_message(volumes=volumes)
    spec, _ = await build_vprogram_spec(message.item_hash, message.content)

    assert len(spec.disks) == 7
    assert spec.disks[3].path == storage_files[VOLUME_REFS[0]]
    assert spec.disks[4].path == storage_files[VOLUME_HASH_TREE_REFS[0]]
    assert spec.disks[5].path == storage_files[VOLUME_REFS[1]]
    assert spec.disks[6].path == storage_files[VOLUME_HASH_TREE_REFS[1]]
    rootfs = spec.rootfs.path
    assert rootfs.with_name(rootfs.name + ".verified_volumes").read_text() == ",".join(VOLUME_ROOTHASHES) + "\n"


@pytest.mark.asyncio
async def test_tdx_refuses_a_confidential_gpu(staged_tdx_bundle, tdx_host, no_snp_probe):
    message = tdx_message(
        memory=4096,
        gpu=ConfidentialGpuRequirement(vendor="nvidia", arch="blackwell", count=1, models=None, mode="cc"),
    )
    with pytest.raises(VmSetupError, match="TDX guests do not support"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_tdx_refuses_memory_below_the_floor(staged_tdx_bundle, tdx_host, no_snp_probe):
    message = tdx_message(memory=TDX_MIN_MEMORY_MIB - 1)
    with pytest.raises(VmSetupError, match=f"at least {TDX_MIN_MEMORY_MIB} MiB"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_tdx_refuses_a_host_without_tdx(staged_tdx_bundle, tdx_host, no_snp_probe):
    tdx_host(supported=False)
    message = tdx_message()
    with pytest.raises(VmSetupError, match="does not support"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_tdx_refusals_stage_nothing(staged_tdx_bundle, tdx_host, no_snp_probe, tmp_path):
    """Every TDX gate runs before the bundle is fetched: a refused message
    leaves no staging directory behind."""
    staging = vprogram_staging_dir(load_vprogram_message().item_hash)
    if staging.exists():  # leftover from a previous pytest run: EXECUTION_ROOT persists
        shutil.rmtree(staging)
    tdx_host(supported=False)
    message = tdx_message()
    with pytest.raises(VmSetupError):
        await build_vprogram_spec(message.item_hash, message.content)
    assert not staging.exists()


@pytest.mark.asyncio
async def test_sev_snp_message_refuses_a_tdx_runtime(staged_tdx_bundle, tdx_host, no_snp_probe):
    """The fixture message (backend sev_snp) pointing at a tdx runtime is a
    mismatch: an SNP-measured message must never boot a TD."""
    message = load_vprogram_message()
    assert message.content.verification.backend == "sev_snp"
    with pytest.raises(VmSetupError, match="declares TEE backend 'sev_snp' but runtime .* is a tdx runtime"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_tdx_message_refuses_a_sev_snp_runtime(tmp_path, storage_files, tdx_host, no_snp_probe):
    """Mirror image: a tdx-measured message on an SNP runtime."""
    tar_path = make_bundle(tmp_path)
    storage_files[MANIFEST_REF] = make_manifest(tar_path, tmp_path)
    storage_files[BUNDLE_REF] = tar_path
    message = tdx_message()
    with pytest.raises(VmSetupError, match="declares TEE backend 'tdx' but runtime .* is a sev_snp runtime"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_tdx_bundle_measurements_disagreeing_with_the_manifest_fail_closed(
    tmp_path, storage_files, tdx_host, no_snp_probe
):
    """The bundle records the triple its build predicted; the manifest's is
    what clients pin. A disagreement is a mispackaged or tampered bundle."""
    files = dict(TDX_BUNDLE_FILES)
    files[TDX_MEASUREMENTS_FILE] = json.dumps({**TDX_MEASUREMENTS, "rtmr2": "00" * 48}).encode()
    stage_tdx_bundle(tmp_path, storage_files, files)
    message = tdx_message(volumes=[])
    with pytest.raises(VmSetupError, match="disagree with the manifest"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_tdx_bundle_measurements_malformed_fail_closed(tmp_path, storage_files, tdx_host, no_snp_probe):
    files = dict(TDX_BUNDLE_FILES)
    files[TDX_MEASUREMENTS_FILE] = b'{"mrtd": "nope"}'
    stage_tdx_bundle(tmp_path, storage_files, files)
    message = tdx_message(volumes=[])
    with pytest.raises(VmSetupError, match="measurements .* are invalid"):
        await build_vprogram_spec(message.item_hash, message.content)


@pytest.mark.asyncio
async def test_tdx_bundle_without_measurements_file_launches(tmp_path, storage_files, tdx_host, no_snp_probe):
    """The manifest is the authority clients pin against; the recorded
    triple is a cross-check only when the bundle ships one."""
    files = {name: data for name, data in TDX_BUNDLE_FILES.items() if name != TDX_MEASUREMENTS_FILE}
    stage_tdx_bundle(tmp_path, storage_files, files)
    message = tdx_message(volumes=[])
    spec, _ = await build_vprogram_spec(message.item_hash, message.content)
    assert spec.tee is not None and spec.tee.backend is TeeBackend.TDX


def test_remove_vprogram_staging_takes_the_daemon_descriptor_with_it(tmp_path, monkeypatch):
    """The daemon writes {rootfs}.tdx_descriptor beside the staged rootfs;
    the per-VM teardown removes the whole staging directory, descriptor and
    sidecars included."""
    monkeypatch.setattr(settings, "EXECUTION_ROOT", str(tmp_path))
    vm_hash = load_vprogram_message().item_hash
    staging = vprogram_staging_dir(vm_hash)
    (staging / "image").mkdir(parents=True)
    for name in ("rootfs.ext4", "rootfs.ext4.roothash", "rootfs.ext4.verity", "rootfs.ext4.tdx_descriptor"):
        (staging / "image" / name).write_bytes(b"x")

    vprogram_launch.remove_vprogram_staging(vm_hash)
    assert not staging.exists()
