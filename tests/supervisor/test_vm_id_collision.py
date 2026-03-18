"""Tests for vm_id collision between persistent instances.

Reproduces the bug where two persistent instances share the same vm_id
in the database. When both are loaded on supervisor restart, they share
the same tap interface. When one is stopped/cleaned up, it deletes the
tap interface used by the other — destroying its network connectivity.

Real-world scenario from production logs:
- Instance A (7a7e0c79) has vm_id=7, running with vmtap7
- Instance B (41dd6224) also has vm_id=7 in DB (stale record)
- Supervisor restarts, loads both, both restore vmtap7
- Instance B is detected as dead, cleaned up — deletes vmtap7
- Instance A loses network while still running
"""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator.metrics import ExecutionRecord
from aleph.vm.pool import VmPool


def _make_message_json(address: str = "0xtest") -> str:
    """Create minimal valid message JSON for an instance."""
    return json.dumps(
        {
            "address": address,
            "time": 1700000000,
            "allow_amend": False,
            "metadata": None,
            "authorized_keys": [],
            "variables": None,
            "environment": {
                "reproducible": False,
                "internet": True,
                "aleph_api": True,
                "shared_cache": False,
            },
            "resources": {"vcpus": 1, "memory": 2048, "seconds": 30},
            "payment": {"chain": "ETH", "type": "hold"},
            "requirements": None,
            "volumes": [],
            "rootfs": {
                "parent": {
                    "ref": "b6ff5c3a8205d1ca4c7c3369300eeafff498b558f71b851aa2114afd0a532717",
                    "use_latest": True,
                },
                "persistence": "host",
                "size_mib": 20480,
            },
        }
    )


def _make_db_record(
    vm_hash: str,
    vm_id: int,
    persistent: bool = True,
    uuid: str = "test-uuid",
) -> ExecutionRecord:
    """Create an ExecutionRecord matching the DB schema."""
    msg = _make_message_json()
    record = ExecutionRecord(
        uuid=uuid,
        vm_hash=vm_hash,
        vm_id=vm_id,
        persistent=persistent,
        message=msg,
        original_message=msg,
        gpus="[]",
        mapped_ports={},
    )
    return record


def _make_pool() -> VmPool:
    """Create a minimal VmPool with mocked dependencies."""
    pool = VmPool.__new__(VmPool)
    pool.executions = {}
    pool.network = None
    pool.snapshot_manager = None
    pool.systemd_manager = MagicMock()
    pool.systemd_manager.get_services_active_states = MagicMock(return_value={})
    pool.systemd_manager.get_services_enabled_states = MagicMock(return_value={})
    return pool


@pytest.mark.asyncio
class TestDuplicateVmIdLoading:
    """Test that load_persistent_executions handles duplicate vm_ids."""

    @patch("aleph.vm.pool.get_execution_records")
    @patch("aleph.vm.pool.get_port_mappings", new_callable=AsyncMock, return_value={})
    async def test_duplicate_vm_id_only_first_active_restored(self, mock_ports, mock_get_records):
        """When two persistent records share vm_id=7 and both are active,
        only the first should be restored. The second should be skipped."""
        pool = _make_pool()

        hash_a = "a" * 64
        hash_b = "b" * 64

        mock_get_records.return_value = [
            _make_db_record(hash_a, vm_id=7, uuid="uuid-a"),
            _make_db_record(hash_b, vm_id=7, uuid="uuid-b"),
        ]

        # Both services are active
        pool.systemd_manager.get_services_active_states.return_value = {
            f"aleph-vm-controller@{hash_a}.service": True,
            f"aleph-vm-controller@{hash_b}.service": True,
        }

        # Mock _restore_running_execution to avoid actual VM creation
        with patch.object(pool, "_restore_running_execution", new_callable=AsyncMock) as mock_restore:
            with patch.object(pool, "_handle_dead_execution", new_callable=AsyncMock) as mock_dead:
                with patch.object(pool, "_cleanup_orphan_resources"):
                    with patch.object(pool, "update_domain_mapping", new_callable=AsyncMock):
                        await pool.load_persistent_executions()

            # First instance restored, second treated as dead
            assert mock_restore.call_count == 1
            restored_hash = (
                mock_restore.call_args[1]["vm_hash"] if mock_restore.call_args[1] else mock_restore.call_args[0][3]
            )
            assert str(restored_hash) == hash_a

            assert mock_dead.call_count == 1

    @patch("aleph.vm.pool.get_execution_records")
    @patch("aleph.vm.pool.get_port_mappings", new_callable=AsyncMock, return_value={})
    async def test_duplicate_vm_id_dead_records_both_cleaned(self, mock_ports, mock_get_records):
        """When two persistent records share vm_id=7 and neither is active,
        both should be handled as dead (no collision since neither restores)."""
        pool = _make_pool()

        hash_a = "a" * 64
        hash_b = "b" * 64

        mock_get_records.return_value = [
            _make_db_record(hash_a, vm_id=7, uuid="uuid-a"),
            _make_db_record(hash_b, vm_id=7, uuid="uuid-b"),
        ]

        # Neither service is active
        pool.systemd_manager.get_services_active_states.return_value = {}
        pool.systemd_manager.get_services_enabled_states.return_value = {}

        with patch.object(pool, "_restore_running_execution", new_callable=AsyncMock) as mock_restore:
            with patch.object(pool, "_handle_dead_execution", new_callable=AsyncMock) as mock_dead:
                with patch.object(pool, "_cleanup_orphan_resources"):
                    await pool.load_persistent_executions()

            # Neither restored, both cleaned up
            assert mock_restore.call_count == 0
            assert mock_dead.call_count == 2

    @patch("aleph.vm.pool.get_execution_records")
    @patch("aleph.vm.pool.get_port_mappings", new_callable=AsyncMock, return_value={})
    async def test_unique_vm_ids_all_restored(self, mock_ports, mock_get_records):
        """When persistent records have unique vm_ids and are active,
        all should be restored normally."""
        pool = _make_pool()

        hash_a = "a" * 64
        hash_b = "b" * 64

        mock_get_records.return_value = [
            _make_db_record(hash_a, vm_id=7, uuid="uuid-a"),
            _make_db_record(hash_b, vm_id=8, uuid="uuid-b"),
        ]

        pool.systemd_manager.get_services_active_states.return_value = {
            f"aleph-vm-controller@{hash_a}.service": True,
            f"aleph-vm-controller@{hash_b}.service": True,
        }

        with patch.object(pool, "_restore_running_execution", new_callable=AsyncMock) as mock_restore:
            with patch.object(pool, "_handle_dead_execution", new_callable=AsyncMock) as mock_dead:
                with patch.object(pool, "_cleanup_orphan_resources"):
                    with patch.object(pool, "update_domain_mapping", new_callable=AsyncMock):
                        await pool.load_persistent_executions()

            assert mock_restore.call_count == 2
            assert mock_dead.call_count == 0

    @patch("aleph.vm.pool.get_execution_records")
    @patch("aleph.vm.pool.get_port_mappings", new_callable=AsyncMock, return_value={})
    async def test_non_persistent_records_filtered_out(self, mock_ports, mock_get_records):
        """Non-persistent records should be ignored entirely,
        regardless of their vm_id."""
        pool = _make_pool()

        mock_get_records.return_value = [
            _make_db_record("a" * 64, vm_id=7, persistent=True, uuid="uuid-a"),
            _make_db_record("b" * 64, vm_id=7, persistent=False, uuid="uuid-b"),
            _make_db_record("c" * 64, vm_id=7, persistent=False, uuid="uuid-c"),
        ]

        pool.systemd_manager.get_services_active_states.return_value = {
            f"aleph-vm-controller@{'a' * 64}.service": True,
        }

        with patch.object(pool, "_restore_running_execution", new_callable=AsyncMock) as mock_restore:
            with patch.object(pool, "_handle_dead_execution", new_callable=AsyncMock) as mock_dead:
                with patch.object(pool, "_cleanup_orphan_resources"):
                    with patch.object(pool, "update_domain_mapping", new_callable=AsyncMock):
                        await pool.load_persistent_executions()

            # Only the persistent active record is restored
            assert mock_restore.call_count == 1
            # Non-persistent records are not even processed
            assert mock_dead.call_count == 0
