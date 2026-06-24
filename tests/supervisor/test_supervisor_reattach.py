"""Config-driven, message-free reattach helpers."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.vm.pool import VmPool
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
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
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _bare_pool() -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.systemd_manager = MagicMock()
    return pool


@pytest.mark.asyncio
async def test_handle_dead_controller_stops_service():
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH)

    await pool._handle_dead_controller(config)

    pool.systemd_manager.stop_and_disable.assert_called_once_with(f"aleph-vm-controller@{_HASH}.service")


@pytest.mark.asyncio
async def test_failed_reattach_does_not_abort_the_rest(tmp_path):
    """A single VM whose restore raises (e.g. an unsupported confidential
    config) must not stop the other active VMs from reattaching."""
    hash_ok = "a" * 64
    hash_bad = "b" * 64
    pool = _bare_pool()
    pool.systemd_manager.get_services_active_states = MagicMock(
        return_value={
            f"aleph-vm-controller@{hash_ok}.service": True,
            f"aleph-vm-controller@{hash_bad}.service": True,
        }
    )
    for h in (hash_ok, hash_bad):
        (tmp_path / f"{h}-controller.json").write_text("{}")
    configs = {hash_ok: SimpleNamespace(vm_hash=hash_ok, vm_id=1), hash_bad: SimpleNamespace(vm_hash=hash_bad, vm_id=2)}

    async def fake_restore(config, vm_index, vm_id):
        if str(config.vm_hash) == hash_bad:
            msg = "reattach supports QemuVMConfiguration only"
            raise RuntimeError(msg)
        pool.executions[vm_id] = SimpleNamespace(vm_index=vm_index)

    with (
        patch("aleph.vm.pool.settings", SimpleNamespace(EXECUTION_ROOT=tmp_path)),
        patch("aleph.vm.pool.load_controller_configuration", side_effect=lambda h: configs[h]),
        patch.object(pool, "_restore_running_execution_from_config", side_effect=fake_restore),
        patch.object(pool, "_handle_dead_controller", new_callable=AsyncMock) as dead,
        patch.object(pool, "_cleanup_orphan_resources") as cleanup,
    ):
        await pool.load_persistent_executions()

    # The healthy VM reattached despite the other one failing.
    assert VmId(hash_ok) in pool.executions
    # The failed VM's live controller is left running, not killed as "dead".
    dead.assert_not_called()
    # And it is protected from the orphan sweep so cleanup cannot delete its
    # config or tear down its networking while the VM is still running.
    _, kwargs = cleanup.call_args
    assert kwargs["protected_vm_ids"] == {2}
    assert kwargs["protected_vm_hashes"] == {hash_bad}


@pytest.mark.asyncio
async def test_cleanup_orphan_resources_treats_protected_as_active(monkeypatch):
    """A protected (failed-reattach) VM must not be swept: its vm_index and
    hash are unioned into the active sets the cleanup helpers receive."""
    pool = _bare_pool()
    seen: dict[str, object] = {}
    monkeypatch.setattr("aleph.vm.pool.get_existing_nftables_ruleset", lambda: [])
    monkeypatch.setattr(pool, "_cleanup_orphan_port_redirects", lambda _ruleset: None)
    monkeypatch.setattr(pool, "_cleanup_orphan_nft_chains", lambda ids, _ruleset: seen.update(ids=ids))
    monkeypatch.setattr(pool, "_cleanup_orphan_tap_interfaces", lambda _ids: None)
    monkeypatch.setattr(pool, "_cleanup_orphan_controller_configs", lambda hashes: seen.update(hashes=hashes))

    pool._cleanup_orphan_resources(protected_vm_ids={5}, protected_vm_hashes={"c" * 64})

    assert seen["ids"] == {5}
    assert seen["hashes"] == {"c" * 64}


@pytest.mark.asyncio
async def test_restore_running_execution_from_config_registers_execution(monkeypatch):
    pool = _bare_pool()
    config = SimpleNamespace(vm_hash=_HASH, vm_id=7)

    monkeypatch.setattr("aleph.vm.pool.spec_from_controller_configuration", lambda _c: _spec())
    monkeypatch.setattr("aleph.vm.pool.get_port_mappings", AsyncMock(return_value={}))

    from aleph.vm.models import VmExecution

    monkeypatch.setattr(VmExecution, "prepare", AsyncMock())
    fake_vm = SimpleNamespace(support_snapshot=False, start_guest_api=AsyncMock())
    monkeypatch.setattr(VmExecution, "create", MagicMock(return_value=fake_vm))

    await pool._restore_running_execution_from_config(config, vm_index=7, vm_id=_HASH)

    assert _HASH in pool.executions
    execution = pool.executions[_HASH]
    assert execution.spec is not None
    assert execution.vm_spec is execution.spec
    fake_vm.start_guest_api.assert_awaited_once()
    assert execution.ready_event.is_set()
