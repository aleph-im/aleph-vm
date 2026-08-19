"""Agent-side registry reads in tasks.py: the domains aggregate."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash, Payment

from aleph.vm.agent.tasks import _handle_domains_aggregate
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    IpAssignment,
    VmId,
    VmInfo,
    VmStatus,
)

_HASH = ItemHash("deadbeef" * 8)


def _info(vm_hash: ItemHash, *, running: bool = True, confidential=False, backend: Backend = Backend.QEMU) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(vm_hash)),
        status=VmStatus.RUNNING if running else VmStatus.STOPPED,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=backend,
        numa_node=None,
        status_message="",
        confidential_mode=ConfidentialMode.SEV if confidential else ConfidentialMode.NONE,
    )


def _registry_with(vm_hash: ItemHash, *, payment: Payment | None, address: str = "0xabc") -> AgentVmRegistry:
    registry = AgentVmRegistry()
    registry.record(
        vm_hash,
        message=SimpleNamespace(payment=payment, address=address),
        original=MagicMock(),
        persistent=True,
    )
    return registry


def _supervisor_returning(*infos: VmInfo):
    """A supervisor stub whose get_vm answers from the given VmInfos by vm_id,
    raising VmNotFoundError for anything else. No in-process pool involved, so
    this exercises the split-mode path (the daemon owns the VMs)."""
    by_id = {info.vm_id: info for info in infos}

    async def get_vm(vm_id):
        if vm_id in by_id:
            return by_id[vm_id]
        raise VmNotFoundError(str(vm_id))

    return SimpleNamespace(get_vm=get_vm)


@pytest.mark.asyncio
async def test_domains_aggregate_triggers_for_registry_recorded_instance(mocker):
    """A message-less (spec-built / restored) instance must still trigger the
    HAProxy domain-mapping refresh when its registry record matches the owner,
    sourced through the supervisor (works in split mode, no pool)."""
    sync = mocker.patch("aleph.vm.agent.tasks.sync_domain_mappings", new=AsyncMock())
    registry = _registry_with(_HASH, payment=None, address="0xowner")
    supervisor = _supervisor_returning(_info(_HASH))
    aggregate = SimpleNamespace(content=SimpleNamespace(address="0xowner"))

    await _handle_domains_aggregate(aggregate, supervisor, registry)

    sync.assert_awaited_once_with(supervisor)


@pytest.mark.asyncio
async def test_domains_aggregate_ignores_unrelated_address(mocker):
    sync = mocker.patch("aleph.vm.agent.tasks.sync_domain_mappings", new=AsyncMock())
    registry = _registry_with(_HASH, payment=None, address="0xowner")
    supervisor = _supervisor_returning(_info(_HASH))
    aggregate = SimpleNamespace(content=SimpleNamespace(address="0xsomeoneelse"))

    await _handle_domains_aggregate(aggregate, supervisor, registry)

    sync.assert_not_awaited()


@pytest.mark.asyncio
async def test_domains_aggregate_ignores_unrecorded_execution(mocker):
    """A matching-owner instance the agent has no record for must NOT trigger a
    refresh (no registry record -> short-circuits before the address compare)."""
    sync = mocker.patch("aleph.vm.agent.tasks.sync_domain_mappings", new=AsyncMock())
    supervisor = _supervisor_returning(_info(_HASH))
    aggregate = SimpleNamespace(content=SimpleNamespace(address="0xowner"))

    await _handle_domains_aggregate(aggregate, supervisor, AgentVmRegistry())

    sync.assert_not_awaited()


@pytest.mark.asyncio
async def test_domains_aggregate_ignores_non_instance(mocker):
    """A program (FIRECRACKER, not a QEMU instance) owned by the address must
    NOT trigger a refresh."""
    sync = mocker.patch("aleph.vm.agent.tasks.sync_domain_mappings", new=AsyncMock())
    registry = _registry_with(_HASH, payment=None, address="0xowner")
    supervisor = _supervisor_returning(_info(_HASH, backend=Backend.FIRECRACKER))
    aggregate = SimpleNamespace(content=SimpleNamespace(address="0xowner"))

    await _handle_domains_aggregate(aggregate, supervisor, registry)

    sync.assert_not_awaited()


@pytest.mark.asyncio
async def test_domains_aggregate_ignores_owner_instance_absent_from_supervisor(mocker):
    """An owner-matching registry record whose VM the supervisor does not know
    (deleted, never created) must NOT trigger a refresh."""
    sync = mocker.patch("aleph.vm.agent.tasks.sync_domain_mappings", new=AsyncMock())
    registry = _registry_with(_HASH, payment=None, address="0xowner")
    supervisor = _supervisor_returning()  # get_vm always raises VmNotFoundError
    aggregate = SimpleNamespace(content=SimpleNamespace(address="0xowner"))

    await _handle_domains_aggregate(aggregate, supervisor, registry)

    sync.assert_not_awaited()


def test_pool_has_no_message_reads():
    """pool.py must not learn messages off executions; that is registry territory."""
    import inspect

    from aleph.vm import pool as pool_module

    source = inspect.getsource(pool_module)
    assert "execution.message" not in source
    assert "get_executions_by_address" not in source
