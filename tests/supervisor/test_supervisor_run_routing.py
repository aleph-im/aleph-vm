"""run.create_vm_execution routes eligible QEMU instances through the Supervisor."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash, ProgramContent
from aleph_message.models.execution.environment import (
    GpuProperties,
    HostRequirements,
    HypervisorType,
    TrustedExecutionEnvironment,
)
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.models import MessageSpec
from aleph.vm.orchestrator import run as run_module
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
    VmInfo,
    VmStatus,
)

_HASH = ItemHash("deadbeef" * 8)


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(str(_HASH)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(
                path=Path("/data/rootfs.qcow2"),
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        ],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _info(status: VmStatus = VmStatus.RUNNING) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(_HASH)),
        status=status,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


def _fake_supervisor(*, create_status: VmStatus = VmStatus.RUNNING, get_status: VmStatus = VmStatus.RUNNING):
    return SimpleNamespace(
        create_vm=AsyncMock(return_value=_info(create_status)),
        get_vm=AsyncMock(return_value=_info(get_status)),
        add_port_forward=AsyncMock(),
        delete_vm=AsyncMock(),
    )


@pytest.mark.asyncio
async def test_eligible_instance_routed_through_supervisor(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    original_content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    original_message = MagicMock(content=original_content)
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    spec = _spec()
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=spec))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()
    created = SimpleNamespace(save=AsyncMock())
    pool = SimpleNamespace(executions={_HASH: created}, create_a_vm=AsyncMock())

    execution = await run_module.create_vm_execution(
        _HASH, pool, supervisor=supervisor, registry=registry, persistent=True
    )

    supervisor.create_vm.assert_awaited_once_with(spec)
    pool.create_a_vm.assert_not_awaited()
    # The message is recorded in the agent registry, not on the execution.
    assert registry.get(_HASH).message is content
    assert registry.get(_HASH).original is original_content
    assert registry.get(_HASH).persistent is True
    # The spec create path must persist the execution record after re-sourcing.
    created.save.assert_awaited_once()
    # SSH port-forward applied through the abstraction.
    assert supervisor.add_port_forward.await_count >= 1
    # The execution is read back from the pool once for start_persistent_vm.
    assert execution is created
    # PR 1 boundary: the message-free execution is re-sourced as message-driven
    # so the operator API (owner-auth, billing) keeps reading execution.message
    # until those consumers move to the registry.
    assert execution.spec == MessageSpec(message=content, original=original_content)
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_eligible_instance_timeout_tears_down(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "_START_POLL_TIMEOUT_SECONDS", 0)

    supervisor = _fake_supervisor(get_status=VmStatus.BOOTING)  # never RUNNING
    registry = AgentVmRegistry()
    pool = SimpleNamespace(executions={}, create_a_vm=AsyncMock())

    with pytest.raises(asyncio.TimeoutError):
        await run_module.create_vm_execution(_HASH, pool, supervisor=supervisor, registry=registry, persistent=True)

    supervisor.delete_vm.assert_awaited_once_with(VmId(str(_HASH)))
    assert registry.get(_HASH) is None  # forgotten on failure


@pytest.mark.asyncio
async def test_eligible_instance_port_forward_failure_tears_down(monkeypatch):
    # Readiness succeeds but applying a port forward fails: the other failure
    # source in the same try block must trigger the same teardown.
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    supervisor = _fake_supervisor()  # get_vm reports RUNNING immediately
    supervisor.add_port_forward = AsyncMock(side_effect=RuntimeError("nftables boom"))
    registry = AgentVmRegistry()
    pool = SimpleNamespace(executions={}, create_a_vm=AsyncMock())

    with pytest.raises(RuntimeError, match="nftables boom"):
        await run_module.create_vm_execution(_HASH, pool, supervisor=supervisor, registry=registry, persistent=True)

    supervisor.delete_vm.assert_awaited_once_with(VmId(str(_HASH)))
    assert registry.get(_HASH) is None  # forgotten on failure


async def _assert_routed_to_legacy(monkeypatch, content) -> None:
    """An ineligible message takes create_a_vm, never touches the spec path, and is still recorded."""
    message = MagicMock(content=content)
    original_message = MagicMock(content=_make_qemu_instance_message())
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()
    legacy = SimpleNamespace()
    pool = SimpleNamespace(executions={}, create_a_vm=AsyncMock(return_value=legacy))

    execution = await run_module.create_vm_execution(
        _HASH, pool, supervisor=supervisor, registry=registry, persistent=False
    )

    pool.create_a_vm.assert_awaited_once()
    supervisor.create_vm.assert_not_awaited()
    run_module.build_create_vm_spec.assert_not_awaited()
    assert execution is legacy
    assert registry.get(_HASH) is not None  # legacy path records the message too


@pytest.mark.asyncio
async def test_non_instance_falls_back_to_legacy(monkeypatch):
    await _assert_routed_to_legacy(monkeypatch, MagicMock(spec=ProgramContent))


@pytest.mark.asyncio
async def test_confidential_instance_falls_back_to_legacy(monkeypatch):
    content = _make_qemu_instance_message(trusted_execution=TrustedExecutionEnvironment())
    await _assert_routed_to_legacy(monkeypatch, content)


@pytest.mark.asyncio
async def test_gpu_instance_falls_back_to_legacy(monkeypatch):
    content = _make_qemu_instance_message().model_copy(
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
    await _assert_routed_to_legacy(monkeypatch, content)
