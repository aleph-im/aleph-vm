"""run.create_vm_execution routes mode=sev_snp confidential instances through
the SNP launch path (build_snp_instance_spec), not the legacy SEV translate.py
path. Mirrors tests/supervisor/test_supervisor_run_routing.py and
tests/supervisor/test_vprogram.py's create-path tests, using
test_snp_instance_launch.snp_instance_content for a schema-valid SNP fixture
and test_supervisor_translate._make_qemu_instance_message for the legacy SEV
regression check.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models.execution.environment import (
    GpuProperties,
    HostRequirements,
    TrustedExecutionEnvironment,
)
from test_snp_instance_launch import VM_HASH, snp_instance_content
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent import run as run_module
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    IpAssignment,
    NetworkConfig,
    TeeBackend,
    TeeConfig,
    VmId,
    VmInfo,
    VmStatus,
)

_ATTEST_PORT = 8443
_SENDER = "0x1234567890abcdef1234567890abcdef12345678"


def _snp_spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(str(VM_HASH)),
        backend=Backend.QEMU,
        kernel_path=Path("bzImage"),
        initrd_path=Path("initrd"),
        disks=[
            DiskSpec(
                path=Path("/data/instance-rootfs.qcow2"),
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        ],
        vcpus=2,
        memory_mib=2048,
        tee=TeeConfig(
            backend=TeeBackend.SEV_SNP,
            policy="196608",
            session_dir=DirectoryPath(Path("/sessions") / str(VM_HASH)),
            firmware_path=Path("OVMF.fd"),
            kernel_cmdline="console=ttyS0 luks=1 owner=0x1234567890abcdef1234567890abcdef12345678",
        ),
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _info(status: VmStatus = VmStatus.RUNNING, *, awaiting_confidential_init: bool = False) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(VM_HASH)),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        awaiting_confidential_init=awaiting_confidential_init,
    )


def _fake_capacity():
    return MagicMock(check_capacity=MagicMock(), resolve_gpus=AsyncMock())


def _fake_supervisor(*, create_status: VmStatus = VmStatus.RUNNING, get_status: VmStatus = VmStatus.RUNNING):
    return MagicMock(
        create_vm=AsyncMock(return_value=_info(create_status)),
        get_vm=AsyncMock(return_value=_info(get_status)),
        add_port_forward=AsyncMock(),
        delete_vm=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_snp_instance_create_uses_snp_builder(monkeypatch):
    """The SNP builder is used (not build_create_vm_spec), and after RUNNING
    the recorded port forwards include SSH (22) and the attestation port
    (8443, from build_snp_instance_spec's returned attest_port)."""
    content = snp_instance_content()
    message = MagicMock(content=content, sender=_SENDER)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    spec = _snp_spec()
    build_snp = AsyncMock(return_value=(spec, _ATTEST_PORT))
    monkeypatch.setattr(run_module, "build_snp_instance_spec", build_snp)
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", AsyncMock(return_value=_ATTEST_PORT))
    build_sev = AsyncMock()
    monkeypatch.setattr(run_module, "build_create_vm_spec", build_sev)
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())
    # The attest-gate itself is unit-tested in test_vprogram_launch.py; here
    # only the spec-build/create/port-forward wiring is under test. Keep a
    # reference so we can still assert the create path actually wires the
    # gate in: a refactor that drops the call site must not leave this suite
    # green.
    mock_gate = AsyncMock()
    monkeypatch.setattr(run_module, "_wait_until_attest_endpoint_listens", mock_gate)

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    execution = await run_module.create_vm_execution(
        VM_HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
    )

    build_snp.assert_awaited_once_with(VM_HASH, content, _SENDER)
    build_sev.assert_not_awaited()
    sent_spec = supervisor.create_vm.await_args.args[0]
    assert sent_spec.tee is not None
    assert sent_spec.tee.kernel_cmdline

    forwarded_ports = {int(call.args[0].vm_port) for call in supervisor.add_port_forward.await_args_list}
    assert 22 in forwarded_ports
    assert _ATTEST_PORT in forwarded_ports
    assert execution is None
    mock_gate.assert_awaited_once_with(supervisor, VmId(str(VM_HASH)), _ATTEST_PORT)


@pytest.mark.asyncio
async def test_snp_instance_never_awaits_confidential_init(monkeypatch):
    """SNP VMs auto-boot: create_vm never reports awaiting_confidential_init,
    so the path must fall straight through to finish_instance_create / the
    port-forward stage rather than the SEV await branch."""
    content = snp_instance_content()
    message = MagicMock(content=content, sender=_SENDER)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    spec = _snp_spec()
    monkeypatch.setattr(run_module, "build_snp_instance_spec", AsyncMock(return_value=(spec, _ATTEST_PORT)))
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", AsyncMock(return_value=_ATTEST_PORT))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    persist = AsyncMock()
    monkeypatch.setattr(run_module, "persist_record", persist)
    # The attest-gate itself is unit-tested in test_vprogram_launch.py; here
    # only the fall-through past the SEV await branch is under test.
    monkeypatch.setattr(run_module, "_wait_until_attest_endpoint_listens", AsyncMock())

    info = _info(VmStatus.RUNNING, awaiting_confidential_init=False)
    supervisor = _fake_supervisor()
    supervisor.create_vm = AsyncMock(return_value=info)
    registry = AgentVmRegistry()

    await run_module.create_vm_execution(
        VM_HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
    )

    # Reached the port-forward stage: add_port_forward was actually called.
    assert supervisor.add_port_forward.await_count >= 2
    persist.assert_awaited_once()


@pytest.mark.asyncio
async def test_snp_instance_with_gpus_rejected(monkeypatch):
    """A GPU-requesting SNP instance is rejected with a clean VmSetupError
    BEFORE build_snp_instance_spec or create_vm ever run."""
    content = snp_instance_content().model_copy(
        update={
            "requirements": HostRequirements(
                gpu=[
                    GpuProperties(
                        vendor="NVIDIA",
                        device_name="RTX",
                        device_class="0300",
                        device_id="10de:1234",
                    )
                ]
            )
        }
    )
    message = MagicMock(content=content, sender=_SENDER)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    build_snp = AsyncMock()
    monkeypatch.setattr(run_module, "build_snp_instance_spec", build_snp)
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", AsyncMock(return_value=_ATTEST_PORT))

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    with pytest.raises(VmSetupError, match="GPU passthrough is not supported on SEV-SNP"):
        await run_module.create_vm_execution(
            VM_HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    build_snp.assert_not_awaited()
    supervisor.create_vm.assert_not_awaited()
    assert registry.get(VM_HASH) is None


@pytest.mark.asyncio
async def test_legacy_sev_instance_path_untouched(monkeypatch):
    """A plain/legacy SEV (or non-confidential) instance still routes through
    build_create_vm_spec, never build_snp_instance_spec; its spec carries no
    kernel_cmdline (build_create_vm_spec never sets one)."""
    content = _make_qemu_instance_message(trusted_execution=TrustedExecutionEnvironment())
    message = MagicMock(content=content, sender=_SENDER)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    sev_spec = CreateVmSpec(
        vm_id=VmId(str(VM_HASH)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(path=Path("/data/rootfs.qcow2"), readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)
        ],
        vcpus=2,
        memory_mib=2048,
        tee=TeeConfig(
            backend=TeeBackend.SEV,
            policy="0x1",
            session_dir=DirectoryPath(Path("/sessions") / str(VM_HASH)),
            firmware_path=Path("OVMF_SEV.fd"),
        ),
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )
    build_sev = AsyncMock(return_value=sev_spec)
    monkeypatch.setattr(run_module, "build_create_vm_spec", build_sev)
    build_snp = AsyncMock()
    monkeypatch.setattr(run_module, "build_snp_instance_spec", build_snp)
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", AsyncMock(return_value=_ATTEST_PORT))
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())

    awaiting = _info(VmStatus.BOOTING, awaiting_confidential_init=True)
    supervisor = _fake_supervisor()
    supervisor.create_vm = AsyncMock(return_value=awaiting)
    registry = AgentVmRegistry()

    execution = await run_module.create_vm_execution(
        VM_HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
    )

    build_sev.assert_awaited_once_with(VM_HASH, content)
    build_snp.assert_not_awaited()
    assert supervisor.create_vm.await_args is not None
    sent_spec = supervisor.create_vm.await_args.args[0]
    assert sent_spec.tee.kernel_cmdline == ""
    assert execution is None


@pytest.mark.asyncio
async def test_snp_instance_failure_cleans_staging(monkeypatch):
    """supervisor.create_vm raises: the failure path must call
    remove_snp_instance_staging and forget the registry record, mirroring the
    V-PROGRAM build/create failure branch."""
    content = snp_instance_content()
    message = MagicMock(content=content, sender=_SENDER)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    spec = _snp_spec()
    monkeypatch.setattr(run_module, "build_snp_instance_spec", AsyncMock(return_value=(spec, _ATTEST_PORT)))
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", AsyncMock(return_value=_ATTEST_PORT))
    remove_staging = MagicMock()
    monkeypatch.setattr(run_module, "remove_snp_instance_staging", remove_staging)

    supervisor = _fake_supervisor()
    supervisor.create_vm = AsyncMock(side_effect=RuntimeError("qemu spawn failed"))
    registry = AgentVmRegistry()

    with pytest.raises(RuntimeError, match="qemu spawn failed"):
        await run_module.create_vm_execution(
            VM_HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    remove_staging.assert_called_once_with(VM_HASH)
    assert registry.get(VM_HASH) is None


@pytest.mark.asyncio
async def test_snp_instance_port_forward_failure_cleans_staging(monkeypatch):
    """The second teardown path: create_vm succeeds but the port-forward
    application inside finish_instance_create fails. The half-started VM must
    be deleted and its staging removed, mirroring the create-failure branch
    (run.py's finish_instance_create/attest-gate except block)."""
    content = snp_instance_content()
    message = MagicMock(content=content, sender=_SENDER)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    spec = _snp_spec()
    monkeypatch.setattr(run_module, "build_snp_instance_spec", AsyncMock(return_value=(spec, _ATTEST_PORT)))
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", AsyncMock(return_value=_ATTEST_PORT))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "_wait_until_attest_endpoint_listens", AsyncMock())
    remove_staging = MagicMock()
    monkeypatch.setattr(run_module, "remove_snp_instance_staging", remove_staging)

    supervisor = _fake_supervisor()  # create_vm returns RUNNING, not awaiting init
    supervisor.add_port_forward = AsyncMock(side_effect=RuntimeError("nftables rule failed"))
    registry = AgentVmRegistry()

    with pytest.raises(RuntimeError, match="nftables rule failed"):
        await run_module.create_vm_execution(
            VM_HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    remove_staging.assert_called_once_with(VM_HASH)
    supervisor.delete_vm.assert_awaited_once()
    assert registry.get(VM_HASH) is None
