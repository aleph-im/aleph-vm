"""run.create_vm_execution routes eligible QEMU instances through the spec."""

from __future__ import annotations

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

from aleph.vm.orchestrator import run as run_module
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
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


@pytest.mark.asyncio
async def test_eligible_instance_routed_through_spec(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    original_content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    original_message = MagicMock(content=original_content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, original_message))
    )

    spec = _spec()
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=spec))

    created = SimpleNamespace(message=None, original=None, is_instance=True)
    created.fetch_port_redirect_config_and_setup = AsyncMock()
    pool = SimpleNamespace(
        message_cache={},
        create_vm_from_spec=AsyncMock(return_value=created),
        create_a_vm=AsyncMock(),
    )

    execution = await run_module.create_vm_execution(_HASH, pool, persistent=True)

    run_module.build_create_vm_spec.assert_awaited_once()
    pool.create_vm_from_spec.assert_awaited_once_with(spec)
    pool.create_a_vm.assert_not_awaited()
    # Agent re-attached the message for its own consumers.
    assert execution.message is content
    assert execution.original is original_content
    created.fetch_port_redirect_config_and_setup.assert_awaited_once()


@pytest.mark.asyncio
async def test_ineligible_firecracker_falls_back_to_legacy(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.firecracker)
    message = MagicMock(content=content)
    original_message = MagicMock(content=_make_qemu_instance_message())
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, original_message))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())

    legacy = SimpleNamespace()
    pool = SimpleNamespace(
        message_cache={},
        create_vm_from_spec=AsyncMock(),
        create_a_vm=AsyncMock(return_value=legacy),
    )

    execution = await run_module.create_vm_execution(_HASH, pool, persistent=False)

    pool.create_a_vm.assert_awaited_once()
    pool.create_vm_from_spec.assert_not_awaited()
    run_module.build_create_vm_spec.assert_not_awaited()
    assert execution is legacy


async def _assert_routed_to_legacy(monkeypatch, content) -> None:
    """Assert an ineligible message takes create_a_vm and never touches the spec path."""
    message = MagicMock(content=content)
    original_message = MagicMock(content=_make_qemu_instance_message())
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())

    legacy = SimpleNamespace()
    pool = SimpleNamespace(
        message_cache={},
        create_vm_from_spec=AsyncMock(),
        create_a_vm=AsyncMock(return_value=legacy),
    )

    execution = await run_module.create_vm_execution(_HASH, pool, persistent=False)

    pool.create_a_vm.assert_awaited_once()
    pool.create_vm_from_spec.assert_not_awaited()
    run_module.build_create_vm_spec.assert_not_awaited()
    assert execution is legacy


@pytest.mark.asyncio
async def test_non_instance_falls_back_to_legacy(monkeypatch):
    # A program (non-instance) message is never spec-eligible.
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
