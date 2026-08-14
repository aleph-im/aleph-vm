"""Task 1: the CRN auto-maps a running V-PROGRAM's attestation port (from
the runtime manifest's ``aleph.ra-tls`` entry) to a host IPv4 port, so an
external client (the ``aleph`` CLI) can reach the guest's RA-TLS endpoint.
Host-only DNAT, measurement-neutral (no guest image/cmdline change),
idempotent on re-adoption.

Uses the canonical cross-SDK fixture message shared with test_vprogram.py.
"""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import VerifiableProgramMessage, parse_message

from aleph.vm.agent.run import (
    create_vm_execution,
    reconcile_vprogram_port_forwards,
    start_persistent_vm,
)
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.supervisor_interface.types import (
    Backend,
    ConfidentialMode,
    GuestPort,
    HostPort,
    IpAssignment,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmId,
    VmInfo,
    VmStatus,
)

FIXTURE = Path(__file__).parent / "fixtures" / "vprogram_message.json"
ATTEST_PORT = 8443


def load_vprogram_message() -> VerifiableProgramMessage:
    message = parse_message(json.loads(FIXTURE.read_text()))
    assert isinstance(message, VerifiableProgramMessage)
    return message


def _running_vm_info(vm_hash: str) -> VmInfo:
    return VmInfo(
        vm_id=VmId(vm_hash),
        status=VmStatus.RUNNING,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        confidential_mode=ConfidentialMode.SEV_SNP,
        gpus=[],
    )


class FakeSupervisor:
    """Enough of the Supervisor surface to drive the V-PROGRAM create path
    and its port-forward reconcile. Keeps a real in-memory mapping store (not
    just a call recorder) so a second reconcile against the same desired set
    genuinely no-ops, the way the real hypervisor's diff would.
    """

    def __init__(self, info: VmInfo):
        self._info = info
        self._forwards: dict[tuple[str, int, Protocol], int] = {}
        self._next_host_port = 40000
        self.add_port_forward_calls: list = []

    async def create_vm(self, spec):
        return self._info

    async def get_vm(self, vm_id):
        return self._info

    async def delete_vm(self, vm_id, **kwargs):
        pass

    async def add_port_forward(self, spec):
        self.add_port_forward_calls.append(spec)
        key = (str(spec.vm_id), int(spec.vm_port), spec.protocol)
        host_port = self._next_host_port
        self._next_host_port += 1
        self._forwards[key] = host_port
        return PortForwardInfo(vm_id=spec.vm_id, host_port=host_port, vm_port=spec.vm_port, protocol=spec.protocol)

    async def remove_port_forward(self, vm_id, host_port, protocol):
        self._forwards = {
            key: value
            for key, value in self._forwards.items()
            if not (key[0] == str(vm_id) and value == host_port and key[2] == protocol)
        }

    async def list_port_forwards(self, vm_id=None):
        return [
            PortForwardInfo(vm_id=VmId(key[0]), host_port=value, vm_port=key[1], protocol=key[2])
            for key, value in self._forwards.items()
            if vm_id is None or key[0] == str(vm_id)
        ]


@pytest.mark.asyncio
async def test_vprogram_create_maps_attestation_port(mocker):
    """After a V-PROGRAM reaches RUNNING, the create path calls
    add_port_forward exactly once, for the manifest's RA-TLS attestation
    port (tcp); a second reconcile (e.g. re-adoption) adds no duplicate."""
    message = load_vprogram_message()
    vm_hash = message.item_hash
    mocker.patch("aleph.vm.agent.run.load_updated_message", new_callable=AsyncMock, return_value=(message, message))

    fake_spec = MagicMock()
    mocker.patch(
        "aleph.vm.agent.run.build_vprogram_spec",
        new_callable=AsyncMock,
        return_value=(fake_spec, ATTEST_PORT),
    )
    mocker.patch("aleph.vm.agent.run.persist_record", new_callable=AsyncMock)

    info = _running_vm_info(str(vm_hash))
    supervisor = FakeSupervisor(info)
    registry = AgentVmRegistry()

    await create_vm_execution(
        vm_hash,
        supervisor=supervisor,
        registry=registry,
        capacity=MagicMock(),
        persistent=True,
    )

    assert len(supervisor.add_port_forward_calls) == 1
    pf = supervisor.add_port_forward_calls[0]
    assert pf.vm_port == ATTEST_PORT
    assert pf.protocol is Protocol.TCP

    # Idempotency: re-running the reconcile (e.g. daemon re-adopts the VM on
    # restart) must not create a duplicate mapping.
    await reconcile_vprogram_port_forwards(supervisor, VmId(str(vm_hash)), ATTEST_PORT)
    assert len(supervisor.add_port_forward_calls) == 1
    active = await supervisor.list_port_forwards(VmId(str(vm_hash)))
    assert len(active) == 1


@pytest.mark.asyncio
async def test_reconcile_vprogram_no_attestation_port_is_noop():
    """A manifest with no aleph.ra-tls tcp transport (attest_port=None, the
    guard build_vprogram_spec applies) yields no forwards and no calls."""
    supervisor = FakeSupervisor(_running_vm_info("deadbeef"))
    await reconcile_vprogram_port_forwards(supervisor, VmId("deadbeef"), None)
    assert supervisor.add_port_forward_calls == []
    assert await supervisor.list_port_forwards(VmId("deadbeef")) == []


async def _start_persistent(vm_hash, supervisor, registry):
    return await start_persistent_vm(
        vm_hash,
        None,
        supervisor=supervisor,
        registry=registry,
        capacity=MagicMock(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )


@pytest.mark.asyncio
async def test_readopted_running_vprogram_heals_missing_forward(mocker):
    """A V-PROGRAM adopted already-RUNNING (agent restart) whose attestation
    forward is missing (previous life crashed between RUNNING and the forward
    setup) gets it healed from the manifest, without rebuilding the spec or
    recreating the VM. A second adoption then no-ops (idempotent heal)."""
    message = load_vprogram_message()
    vm_hash = message.item_hash
    mocker.patch(
        "aleph.vm.agent.run.resolve_vprogram_attestation_port",
        new_callable=AsyncMock,
        return_value=ATTEST_PORT,
    )
    create = mocker.patch("aleph.vm.agent.run.create_vm_execution", new_callable=AsyncMock)

    supervisor = FakeSupervisor(_running_vm_info(str(vm_hash)))
    registry = AgentVmRegistry()
    registry.record(vm_hash, message=message.content, original=message.content, persistent=True)

    await _start_persistent(vm_hash, supervisor, registry)

    create.assert_not_awaited()
    assert len(supervisor.add_port_forward_calls) == 1
    pf = supervisor.add_port_forward_calls[0]
    assert pf.vm_port == ATTEST_PORT
    assert pf.protocol is Protocol.TCP

    await _start_persistent(vm_hash, supervisor, registry)
    assert len(supervisor.add_port_forward_calls) == 1
    assert len(await supervisor.list_port_forwards(VmId(str(vm_hash)))) == 1


@pytest.mark.asyncio
async def test_readopted_vprogram_manifest_failure_leaves_forwards_as_found(mocker):
    """Healing is best-effort: when the manifest cannot be re-fetched on
    re-adoption, the allocation still succeeds and the forwards that exist
    stay exactly as found (no teardown, no removal)."""
    message = load_vprogram_message()
    vm_hash = message.item_hash
    mocker.patch(
        "aleph.vm.agent.run.resolve_vprogram_attestation_port",
        new_callable=AsyncMock,
        side_effect=VmSetupError("manifest unavailable"),
    )
    mocker.patch("aleph.vm.agent.run.create_vm_execution", new_callable=AsyncMock)

    supervisor = FakeSupervisor(_running_vm_info(str(vm_hash)))
    # An existing (possibly stale) forward that healing must not touch when
    # it cannot compute the desired set.
    await supervisor.add_port_forward(
        PortForwardSpec(
            vm_id=VmId(str(vm_hash)), host_port=HostPort(0), vm_port=GuestPort(ATTEST_PORT), protocol=Protocol.TCP
        )
    )
    supervisor.add_port_forward_calls.clear()
    registry = AgentVmRegistry()
    registry.record(vm_hash, message=message.content, original=message.content, persistent=True)

    await _start_persistent(vm_hash, supervisor, registry)

    assert supervisor.add_port_forward_calls == []
    assert len(await supervisor.list_port_forwards(VmId(str(vm_hash)))) == 1


@pytest.mark.asyncio
async def test_readopted_vprogram_without_record_leaves_supervisor_untouched(mocker):
    """No agent record (DB loss): there is nothing to derive the desired set
    from, so adoption must not touch the forwards at all."""
    message = load_vprogram_message()
    vm_hash = message.item_hash
    resolve = mocker.patch("aleph.vm.agent.run.resolve_vprogram_attestation_port", new_callable=AsyncMock)
    mocker.patch("aleph.vm.agent.run.create_vm_execution", new_callable=AsyncMock)

    supervisor = FakeSupervisor(_running_vm_info(str(vm_hash)))

    await _start_persistent(vm_hash, supervisor, AgentVmRegistry())

    resolve.assert_not_awaited()
    assert supervisor.add_port_forward_calls == []
