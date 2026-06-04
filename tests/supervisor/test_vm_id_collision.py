"""Tests for vm_id collision between persistent instances on reboot-recovery.

After a reboot the supervisor reattaches VMs from on-disk controller configs.
Two configs that claim the same vm_id (a stale config left behind) must not
both restore -- they would share a tap interface and clobber each other's
networking. Only the first active one is restored; the rest are treated as
dead controllers.
"""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aleph.vm.pool import VmPool

HASH_A = "a" * 64
HASH_B = "b" * 64


def _make_pool() -> VmPool:
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.systemd_manager = MagicMock()
    pool.systemd_manager.get_services_active_states = MagicMock(return_value={})
    return pool


def _write_configs(tmp_path: Path, *vm_hashes: str) -> None:
    for vm_hash in vm_hashes:
        (tmp_path / f"{vm_hash}-controller.json").write_text("{}")


def _config_for(vm_hash: str, vm_id: int) -> SimpleNamespace:
    return SimpleNamespace(vm_hash=vm_hash, vm_id=vm_id)


@pytest.mark.asyncio
class TestDuplicateVmIdLoading:
    async def _run(self, pool, tmp_path, configs, active):
        def fake_load(vm_hash):
            return configs[vm_hash]

        with (
            patch("aleph.vm.pool.settings", SimpleNamespace(EXECUTION_ROOT=tmp_path)),
            patch("aleph.vm.pool.load_controller_configuration", side_effect=fake_load),
            patch.object(pool, "_restore_running_execution_from_config", new_callable=AsyncMock) as restore,
            patch.object(pool, "_handle_dead_controller", new_callable=AsyncMock) as dead,
            patch.object(pool, "_cleanup_orphan_resources"),
            patch.object(pool, "update_domain_mapping", new_callable=AsyncMock),
        ):
            pool.systemd_manager.get_services_active_states.return_value = active
            await pool.load_persistent_executions()
        return restore, dead

    async def test_duplicate_vm_id_only_first_active_restored(self, tmp_path):
        pool = _make_pool()
        _write_configs(tmp_path, HASH_A, HASH_B)
        configs = {HASH_A: _config_for(HASH_A, 7), HASH_B: _config_for(HASH_B, 7)}
        active = {
            f"aleph-vm-controller@{HASH_A}.service": True,
            f"aleph-vm-controller@{HASH_B}.service": True,
        }
        restore, dead = await self._run(pool, tmp_path, configs, active)
        assert restore.call_count == 1
        assert dead.call_count == 1

    async def test_duplicate_vm_id_dead_both_cleaned(self, tmp_path):
        pool = _make_pool()
        _write_configs(tmp_path, HASH_A, HASH_B)
        configs = {HASH_A: _config_for(HASH_A, 7), HASH_B: _config_for(HASH_B, 7)}
        restore, dead = await self._run(pool, tmp_path, configs, active={})
        assert restore.call_count == 0
        assert dead.call_count == 2

    async def test_unique_vm_ids_all_restored(self, tmp_path):
        pool = _make_pool()
        _write_configs(tmp_path, HASH_A, HASH_B)
        configs = {HASH_A: _config_for(HASH_A, 7), HASH_B: _config_for(HASH_B, 8)}
        active = {
            f"aleph-vm-controller@{HASH_A}.service": True,
            f"aleph-vm-controller@{HASH_B}.service": True,
        }
        restore, dead = await self._run(pool, tmp_path, configs, active)
        assert restore.call_count == 2
        assert dead.call_count == 0
