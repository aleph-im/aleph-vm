"""LocalSupervisor.recreate_network engine logic (Phase 1 P1.6a)."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.supervisor.local import LocalSupervisor
from aleph.vm.supervisor_interface.errors import InternalSupervisorError

_VM_HASH = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"


class _FakePool:
    def __init__(self, executions):
        self.executions = executions


def _running_instance_execution():
    """A running instance execution with a tap interface and persisted ports."""
    execution = MagicMock()
    execution.is_running = True
    execution.is_instance = True
    execution.vm = SimpleNamespace(vm_index=7, tap_interface="tap7")
    execution.spec = object()  # not a MessageSpec; persisted mappings authoritative
    execution.mapped_ports = {}
    execution.recreate_port_redirect_rules = AsyncMock()
    execution.fetch_port_redirect_config_and_setup = AsyncMock()
    return execution


@pytest.mark.asyncio
async def test_recreate_network_returns_summary_and_calls_helpers(mocker):
    execution = _running_instance_execution()
    pool = _FakePool({_VM_HASH: execution})
    supervisor = LocalSupervisor(pool=pool)

    remove_mock = mocker.patch(
        "aleph.vm.supervisor.local.remove_all_aleph_chains",
        return_value=(["aleph-supervisor-nat", "aleph-vm-tap7"], []),
    )
    init_mock = mocker.patch("aleph.vm.supervisor.local.initialize_nftables")
    recreate_mock = mocker.patch(
        "aleph.vm.supervisor.local.recreate_network_for_vms",
        return_value=([_VM_HASH], []),
    )
    mocker.patch(
        "aleph.vm.supervisor.local.get_port_mappings",
        new=AsyncMock(return_value={}),
    )

    result = await supervisor.recreate_network()

    assert result == {
        "success": True,
        "removed_chains_count": 2,
        "removed_chains": ["aleph-supervisor-nat", "aleph-vm-tap7"],
        "recreated_count": 1,
        "failed_count": 0,
        "recreated_vms": [_VM_HASH],
        "failed_vms": [],
    }
    remove_mock.assert_called_once()
    init_mock.assert_called_once()
    # recreate_network_for_vms gets the execution's vm_id and tap_interface.
    recreate_mock.assert_called_once()
    (running_vms,) = recreate_mock.call_args.args
    assert len(running_vms) == 1
    assert running_vms[0]["vm_id"] == 7
    assert running_vms[0]["tap_interface"] == "tap7"
    assert running_vms[0]["vm_hash"] == _VM_HASH


@pytest.mark.asyncio
async def test_recreate_network_failed_vms_yield_partial_success(mocker):
    execution = _running_instance_execution()
    pool = _FakePool({_VM_HASH: execution})
    supervisor = LocalSupervisor(pool=pool)

    mocker.patch("aleph.vm.supervisor.local.remove_all_aleph_chains", return_value=([], []))
    mocker.patch("aleph.vm.supervisor.local.initialize_nftables")
    mocker.patch(
        "aleph.vm.supervisor.local.recreate_network_for_vms",
        return_value=([], [{"vm_hash": _VM_HASH, "error": "boom"}]),
    )
    mocker.patch("aleph.vm.supervisor.local.get_port_mappings", new=AsyncMock(return_value={}))

    result = await supervisor.recreate_network()

    assert result["success"] is False
    assert result["failed_count"] == 1
    assert result["recreated_count"] == 0


@pytest.mark.asyncio
async def test_recreate_network_raises_internal_on_chain_removal_failure(mocker):
    pool = _FakePool({})
    supervisor = LocalSupervisor(pool=pool)

    mocker.patch(
        "aleph.vm.supervisor.local.remove_all_aleph_chains",
        side_effect=RuntimeError("nft broke"),
    )
    mocker.patch("aleph.vm.supervisor.local.initialize_nftables")
    mocker.patch("aleph.vm.supervisor.local.recreate_network_for_vms", return_value=([], []))

    with pytest.raises(InternalSupervisorError):
        await supervisor.recreate_network()
