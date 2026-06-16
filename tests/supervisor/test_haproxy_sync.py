"""Agent-side HAProxy domain-mapping sync.

These tests cover the agent module that drives HAProxy from the supervisor's
`list_vms()` output, with no knowledge of HAProxy living in the supervisor.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from aleph.vm.conf import settings
from aleph.vm.orchestrator import haproxy_sync
from aleph.vm.supervisor.types import (
    Backend,
    IpAssignment,
    VmId,
    VmInfo,
    VmStatus,
)

LOCAL_HASH = "747b52c712e16642b498f16c4c6e68d5fb00ddbaf8d2a0dc7bd298d33abb9124"
OTHER_HASH = "cefb9373558927d70365746900a410f01e1340ecff0dda93deb672f55bb70ac8"


def _vm_info(vm_hash: str, ip: str) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_hash),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(address=ip, network_cidr="172.16.15.0/24", gateway="172.16.15.1"),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


@pytest.mark.asyncio
async def test_sync_domain_mappings_only_keeps_local_domains(mocker, tmp_path):
    """Only domain records pointing at a locally running VM are pushed."""
    vm_ip = "172.16.15.2"
    fake_supervisor = MagicMock(list_vms=AsyncMock(return_value=[_vm_info(LOCAL_HASH, vm_ip)]))

    domain_records = [
        {"name": "api-dev.thronetools.com", "item_hash": LOCAL_HASH, "ipv4": {"local": "172.16.15.1/32"}},
        {"name": "centurion.cybernetwork.me", "item_hash": OTHER_HASH, "ipv4": {"local": "172.16.52.1/32"}},
    ]

    mocker.patch.object(haproxy_sync, "fetch_list", AsyncMock(return_value=domain_records))
    mocker.patch.object(settings, "DOMAIN_NAME", "node.example.org")
    socket_path = tmp_path / "haproxy.sock"
    socket_path.touch()
    mocker.patch.object(settings, "HAPROXY_SOCKET", socket_path)

    pushed = mocker.patch.object(haproxy_sync, "push_entries_to_haproxy")

    result = await haproxy_sync.sync_domain_mappings(fake_supervisor)

    assert result is True
    # The non-local domain (OTHER_HASH) is dropped.
    pushed.assert_called_once()
    _, kwargs = pushed.call_args
    entries = kwargs.get("entries")
    if entries is None:
        entries = pushed.call_args.args[0]
    assert entries == {"api-dev.thronetools.com": vm_ip}


def test_pool_no_longer_owns_domain_mapping():
    """The HAProxy coupling moved out of the pool to the agent side."""
    import aleph.vm.haproxy as haproxy
    from aleph.vm.pool import VmPool

    assert not hasattr(VmPool, "update_domain_mapping")
    assert not hasattr(haproxy, "fetch_list_and_update")


@pytest.mark.asyncio
async def test_sync_domain_mappings_skips_without_socket(mocker):
    fake_supervisor = MagicMock(list_vms=AsyncMock(return_value=[]))
    mocker.patch.object(settings, "DOMAIN_NAME", "node.example.org")
    mocker.patch.object(settings, "HAPROXY_SOCKET", "/nonexistent/haproxy.sock")

    result = await haproxy_sync.sync_domain_mappings(fake_supervisor)
    assert result is False


@pytest.mark.asyncio
async def test_sync_domain_mappings_skips_with_placeholder_domain(mocker, tmp_path):
    fake_supervisor = MagicMock(list_vms=AsyncMock(return_value=[]))
    socket_path = tmp_path / "haproxy.sock"
    socket_path.touch()
    mocker.patch.object(settings, "HAPROXY_SOCKET", socket_path)
    mocker.patch.object(settings, "DOMAIN_NAME", "localhost")

    result = await haproxy_sync.sync_domain_mappings(fake_supervisor)
    assert result is False
