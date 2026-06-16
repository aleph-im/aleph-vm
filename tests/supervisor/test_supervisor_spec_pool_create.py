"""pool.create_vm_from_spec — message-free, no-download create wiring."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor.errors import TeeUnavailableError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DirectoryPath,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    TeeBackend,
    TeeConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec(backend: Backend = Backend.QEMU, tee: TeeConfig | None = None) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
        backend=backend,
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
        tee=tee,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _bare_pool() -> VmPool:
    import asyncio

    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.reservations = {}
    pool.network = None  # exercise the no-network branch
    pool.snapshot_manager = None
    pool.creation_lock = asyncio.Lock()
    systemd = MagicMock()
    systemd.enable_and_start = AsyncMock()
    pool.systemd_manager = systemd
    return pool


@pytest.mark.asyncio
async def test_create_vm_from_spec_wires_into_pool(monkeypatch):
    pool = _bare_pool()

    build_cfg = AsyncMock(return_value="fake-config")
    save_cfg = MagicMock()
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", build_cfg)
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", save_cfg)
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))
    # Controller reports active immediately.
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )

    execution = await pool.create_vm_from_spec(_spec())

    assert pool.executions[execution.vm_hash] is execution
    assert execution.message is None
    assert execution.vm is not None
    build_cfg.assert_awaited_once()
    save_cfg.assert_called_once_with(_HASH, "fake-config")
    pool.systemd_manager.enable_and_start.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_vm_from_spec_preloads_persisted_port_mappings(monkeypatch):
    """create_vm_from_spec loads persisted port mappings and recreates nft rules."""
    pool = _bare_pool()

    persisted = {22: {"host": 24022, "tcp": True, "udp": False}}
    get_pm = AsyncMock(return_value=persisted)
    monkeypatch.setattr("aleph.vm.pool.build_qemu_configuration", AsyncMock(return_value="cfg"))
    monkeypatch.setattr("aleph.vm.pool.save_controller_configuration", MagicMock())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", get_pm)
    monkeypatch.setattr(
        "aleph.vm.models.VmExecution.non_blocking_wait_for_boot",
        AsyncMock(return_value=True),
    )
    recreate = AsyncMock()
    monkeypatch.setattr("aleph.vm.models.VmExecution.recreate_port_redirect_rules", recreate)

    execution = await pool.create_vm_from_spec(_spec())

    get_pm.assert_awaited_once_with(_HASH)
    assert execution.mapped_ports == persisted
    recreate.assert_awaited_once()


@pytest.mark.asyncio
async def test_create_vm_from_spec_rejects_tee():
    """A confidential spec must fail loudly: the spec path would otherwise
    boot the VM without memory encryption."""
    pool = _bare_pool()
    tee = TeeConfig(backend=TeeBackend.SEV, policy="", session_dir=DirectoryPath(Path("/tmp/session")))
    with pytest.raises(TeeUnavailableError):
        await pool.create_vm_from_spec(_spec(tee=tee))
    assert pool.executions == {}


@pytest.mark.asyncio
async def test_create_vm_from_spec_same_spec_returns_live_vm():
    """CreateVm idempotency: a retry with the identical spec is a no-op read."""
    from types import SimpleNamespace

    pool = _bare_pool()
    spec = _spec()
    live = SimpleNamespace(is_running=True, is_stopping=False, vm_spec=spec)
    from aleph_message.models import ItemHash

    pool.executions[ItemHash(_HASH)] = live

    assert await pool.create_vm_from_spec(spec) is live


@pytest.mark.asyncio
async def test_create_vm_from_spec_conflicting_spec_raises_already_exists():
    """A different spec for a live vm_id is a conflict, not a silent reuse."""
    from dataclasses import replace
    from types import SimpleNamespace

    from aleph_message.models import ItemHash

    from aleph.vm.supervisor.errors import VmAlreadyExistsError

    pool = _bare_pool()
    spec = _spec()
    live = SimpleNamespace(is_running=True, is_stopping=False, vm_spec=spec)
    pool.executions[ItemHash(_HASH)] = live

    with pytest.raises(VmAlreadyExistsError):
        await pool.create_vm_from_spec(replace(spec, memory_mib=4096))


@pytest.mark.asyncio
async def test_create_vm_from_spec_collision_with_message_built_vm_raises():
    """A live message-built execution (vm_spec=None) for the same hash is a
    conflict too: the pool cannot prove the spec matches."""
    from types import SimpleNamespace

    from aleph_message.models import ItemHash

    from aleph.vm.supervisor.errors import VmAlreadyExistsError

    pool = _bare_pool()
    live = SimpleNamespace(is_running=True, is_stopping=False, vm_spec=None)
    pool.executions[ItemHash(_HASH)] = live

    with pytest.raises(VmAlreadyExistsError):
        await pool.create_vm_from_spec(_spec())
