"""The port-forward reconcilers must treat a SEV-SNP instance's attestation
port as part of its desired forward set.

Field regression (2026-09-03): the create path mapped the manifest's RA-TLS
port, but the aggregate watcher (``reconcile_port_forwards``) and the
re-adoption healing path (``reconcile_adopted_port_forwards``) converged on
the aggregate+SSH set only, so the first pass after create tore the 8443
mapping down and the CLI's attestation-endpoint discovery broke. Mirrors
tests/supervisor/test_vprogram_port_map.py, which covers the same property
for V-PROGRAMs.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from test_snp_instance_launch import VM_HASH, snp_instance_content

from aleph.vm.agent import run as run_module
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    GuestPort,
    HostPort,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmId,
)

ATTEST_PORT = 8443
VM_ID = VmId(str(VM_HASH))


class FakeSupervisor:
    """The forward surface of the Supervisor, with a real in-memory mapping
    store (like test_vprogram_port_map's fake) so reconcile diffs behave the
    way the real hypervisor's would."""

    def __init__(self, vm_ports: list[int]):
        self._next_host_port = 40000
        self._forwards: dict[tuple[int, Protocol], int] = {}
        for port in vm_ports:
            self._forwards[(port, Protocol.TCP)] = self._next_host_port
            self._next_host_port += 1
        self.added: list[PortForwardSpec] = []
        self.removed: list[tuple[int, Protocol]] = []

    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo:
        self.added.append(spec)
        host_port = self._next_host_port
        self._next_host_port += 1
        self._forwards[(int(spec.vm_port), spec.protocol)] = host_port
        return PortForwardInfo(
            vm_id=spec.vm_id, host_port=HostPort(host_port), vm_port=spec.vm_port, protocol=spec.protocol
        )

    async def remove_port_forward(self, vm_id, host_port, protocol) -> None:
        for key, value in list(self._forwards.items()):
            if value == host_port and key[1] == protocol:
                self.removed.append(key)
                del self._forwards[key]

    async def list_port_forwards(self, vm_id=None) -> list[PortForwardInfo]:
        return [
            PortForwardInfo(vm_id=VM_ID, host_port=HostPort(host), vm_port=GuestPort(port), protocol=protocol)
            for (port, protocol), host in self._forwards.items()
        ]

    def ports(self) -> set[int]:
        return {port for (port, _protocol) in self._forwards}


@pytest.fixture
def snp_content():
    return snp_instance_content()


@pytest.fixture
def _no_aggregate(monkeypatch):
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))


@pytest.fixture
def _attest_port(monkeypatch):
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", AsyncMock(return_value=ATTEST_PORT))


@pytest.mark.asyncio
async def test_watcher_reconcile_keeps_the_attest_mapping(snp_content, _no_aggregate, _attest_port):
    """An aggregate-change reconcile of an SNP instance whose forwards are
    already correct (SSH + attest) removes nothing and adds nothing."""
    supervisor = FakeSupervisor([22, ATTEST_PORT])

    await run_module.reconcile_port_forwards(supervisor, VM_ID, snp_content)

    assert supervisor.removed == []
    assert supervisor.added == []
    assert supervisor.ports() == {22, ATTEST_PORT}


@pytest.mark.asyncio
async def test_watcher_reconcile_restores_a_missing_attest_mapping(snp_content, _no_aggregate, _attest_port):
    """A reconcile pass heals a stripped attest mapping instead of accepting
    the reduced state (the same pass used to be the one stripping it)."""
    supervisor = FakeSupervisor([22])

    await run_module.reconcile_port_forwards(supervisor, VM_ID, snp_content)

    assert supervisor.ports() == {22, ATTEST_PORT}
    assert supervisor.removed == []


@pytest.mark.asyncio
async def test_adopted_healing_includes_the_attest_port(snp_content, _no_aggregate, _attest_port):
    """Re-adoption healing (agent restart) also treats the attest port as
    desired: an adopted SNP instance found without it gets it back."""
    supervisor = FakeSupervisor([22])
    registry = AgentVmRegistry()
    registry.record(VM_HASH, message=snp_content, original=snp_content, persistent=True)

    await run_module.reconcile_adopted_port_forwards(supervisor, registry, VM_HASH)

    assert supervisor.ports() == {22, ATTEST_PORT}
    assert supervisor.removed == []


@pytest.mark.asyncio
async def test_manifest_fetch_failure_skips_healing(snp_content, _no_aggregate, monkeypatch):
    """A failed runtime-manifest fetch must skip healing (leave the forwards
    exactly as found), never converge onto a set without the attest port."""
    monkeypatch.setattr(
        run_module,
        "resolve_instance_attestation_port",
        AsyncMock(side_effect=VmSetupError("manifest unavailable")),
    )
    supervisor = FakeSupervisor([22, ATTEST_PORT])
    registry = AgentVmRegistry()
    registry.record(VM_HASH, message=snp_content, original=snp_content, persistent=True)

    await run_module.reconcile_adopted_port_forwards(supervisor, registry, VM_HASH)

    assert supervisor.ports() == {22, ATTEST_PORT}
    assert supervisor.removed == []
    assert supervisor.added == []


@pytest.mark.asyncio
async def test_plain_instance_never_fetches_a_manifest(_no_aggregate, monkeypatch):
    """A non-SNP instance's desired set is unchanged, and the manifest
    resolver is never consulted for it."""
    resolver = AsyncMock(return_value=ATTEST_PORT)
    monkeypatch.setattr(run_module, "resolve_instance_attestation_port", resolver)
    content = SimpleNamespace(address="0xabc", environment=SimpleNamespace(trusted_execution=None))

    forwards = await run_module.resolve_instance_desired_forwards(VM_ID, content)

    assert {(int(f.vm_port), f.protocol) for f in forwards} == {(22, Protocol.TCP)}
    resolver.assert_not_awaited()


@pytest.mark.asyncio
async def test_aggregate_declared_attest_port_is_not_duplicated(snp_content, _attest_port, monkeypatch):
    """A user aggregate that already forwards the attest port yields exactly
    one spec for it, not two."""
    payload = {str(VM_HASH): {"ports": {str(ATTEST_PORT): {"tcp": True, "udp": False}}}}
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value=payload))

    forwards = await run_module.resolve_instance_desired_forwards(VM_ID, snp_content)

    attest_specs = [f for f in forwards if int(f.vm_port) == ATTEST_PORT and f.protocol is Protocol.TCP]
    assert len(attest_specs) == 1
