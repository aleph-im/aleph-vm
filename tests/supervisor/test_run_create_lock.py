"""Two start paths racing on one hash must not delete each other's VM.

``start_persistent_vm`` reads the supervisor, records the VM, downloads its
resources and creates it, with several seconds of I/O between the read and the
create. Nothing serialised that sequence per hash: the allocation reconciler
and the v1 ``/control/allocations`` handler (or ``notify_allocation``) could
both run it for the same hash, both see the VM as unknown, and both build it.
The second ``create_vm`` then failed with VmAlreadyExistsError, which the
create path treated like any other create failure: it retired the VM, and the
retire deleted the winner's live VM, dropped its record and, with fresh disks,
purged its volumes.

These tests pin the two halves of the fix: the per-hash lock that makes the
second caller wait and then find the VM up, and the VmAlreadyExistsError
handling that keeps a create which lost the race from tearing anything down.
"""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import HypervisorType
from test_supervisor_run_routing import _info, _spec
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent import create_lock
from aleph.vm.agent import run as run_module
from aleph.vm.agent.vm import retire as retire_module
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.supervisor_interface.errors import VmAlreadyExistsError, VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId
from aleph.vm.utils import get_message_executable_content

_HASH = ItemHash("deadbeef" * 8)


@pytest.fixture(autouse=True)
def _no_db_write(monkeypatch) -> None:
    """A retire drops the VM's DB records, which needs an app-level session
    these unit tests do not set up. Stubbed out: what matters here is whether
    the retire runs at all."""
    monkeypatch.setattr(retire_module, "delete_records_for_vm", AsyncMock())


@pytest.fixture
def purge(monkeypatch) -> MagicMock:
    """Spy on the volume purge a FAILED_CREATE retire ends with."""
    spy = MagicMock()
    monkeypatch.setattr(retire_module, "purge_vm_storage", spy)
    return spy


def _program_content():
    with open("examples/program_message_from_aleph.json") as fd:
        return get_message_executable_content(json.load(fd)["content"])


def _vprogram_content():
    from test_vprogram import load_vprogram_message

    return load_vprogram_message().content


def _capacity() -> SimpleNamespace:
    return SimpleNamespace(check_message=MagicMock(), resolve_gpus=AsyncMock(return_value=[]))


def _patch_message(monkeypatch, content) -> None:
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )


async def _slow_build(*_args, **_kwargs):
    """A spec build that yields to the loop, standing in for the download: it
    is the seconds between reading the supervisor and creating the VM that a
    concurrent start walks into."""
    for _ in range(5):
        await asyncio.sleep(0)
    return _spec()


def _patch_instance_path(monkeypatch) -> None:
    """Everything the instance create path does besides talking to the
    supervisor: message load, spec build, volume probe, record persistence and
    the port-forward tail."""
    _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
    monkeypatch.setattr(run_module, "build_create_vm_spec", _slow_build)
    monkeypatch.setattr(run_module, "vm_has_volumes", MagicMock(return_value=False))
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())
    monkeypatch.setattr(run_module, "resolve_instance_desired_forwards", AsyncMock(return_value=[]))
    monkeypatch.setattr(run_module, "reconcile_adopted_port_forwards", AsyncMock())


class _RacingSupervisor:
    """A supervisor that knows nothing until a create returns, and whose create
    is slow enough for a second caller to walk into it.

    ``create_vm`` yields to the loop several times, which is the download and
    boot window in miniature: without a per-hash lock the second start slips
    into it, and its own create then hits the VM the first one committed.
    """

    def __init__(self) -> None:
        self.created = False
        self.create_calls = 0
        self.deleted: list[VmId] = []

    async def get_vm(self, vm_id: VmId):
        if not self.created:
            msg = f"{vm_id} not found"
            raise VmNotFoundError(msg)
        return _info()

    async def create_vm(self, spec: Any):
        self.create_calls += 1
        if self.created:
            msg = f"{spec.vm_id} already exists"
            raise VmAlreadyExistsError(msg)
        # The id is taken as soon as the create is accepted, as it is on the
        # daemon: a second create for the same id is refused from here on.
        self.created = True
        return _info()

    async def delete_vm(self, vm_id: VmId, keep_port_mappings: bool = False) -> None:
        self.deleted.append(vm_id)
        self.created = False

    async def add_port_forward(self, forward: Any) -> None:
        return None


async def _start(supervisor: Any, registry: AgentVmRegistry) -> None:
    await run_module.start_persistent_vm(
        _HASH,
        None,
        supervisor=supervisor,
        registry=registry,
        capacity=_capacity(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )


@pytest.mark.asyncio
async def test_two_concurrent_starts_create_the_vm_once(monkeypatch) -> None:
    """The reconciler and the v1 handler starting the same hash at the same
    time: one builds it, the other waits and finds it running."""
    _patch_instance_path(monkeypatch)
    supervisor = _RacingSupervisor()
    registry = AgentVmRegistry()

    results = await asyncio.gather(_start(supervisor, registry), _start(supervisor, registry), return_exceptions=True)

    # The loser's create used to raise VmAlreadyExistsError, and the retire
    # that followed deleted the VM the winner had just brought up.
    assert supervisor.deleted == []
    assert [result for result in results if isinstance(result, BaseException)] == []
    assert supervisor.create_calls == 1
    assert supervisor.created is True
    assert registry.get(_HASH) is not None
    # And the lock is gone once both callers are out: a node that has started
    # thousands of VMs over its life keeps no lock for each.
    assert create_lock._locks == {}


@pytest.mark.asyncio
async def test_the_second_start_waits_for_the_first_to_finish(monkeypatch) -> None:
    """The lock covers the whole check-record-create sequence, not just the
    create call: the second start must not even read the supervisor while the
    first one is building."""
    _patch_instance_path(monkeypatch)
    supervisor = _RacingSupervisor()
    registry = AgentVmRegistry()
    order: list[str] = []

    real_create = supervisor.create_vm

    async def watched_create(spec: Any):
        order.append("create")
        return await real_create(spec)

    real_get = supervisor.get_vm

    async def watched_get(vm_id: VmId):
        order.append("get")
        return await real_get(vm_id)

    supervisor.create_vm = watched_create  # type: ignore[method-assign]
    supervisor.get_vm = watched_get  # type: ignore[method-assign]

    await asyncio.gather(_start(supervisor, registry), _start(supervisor, registry))

    # The winner's own sequence (get, create, then the readiness polls) runs
    # to completion before the loser's first get.
    assert order[:2] == ["get", "create"]
    assert order.count("create") == 1


@pytest.mark.asyncio
async def test_a_start_that_raises_still_releases_the_lock(monkeypatch, purge) -> None:
    """The release is in a finally and has to stay there. A create that raises
    while holding the lock would keep it for the life of the process, and every
    later start of that hash, from the reconciler and from both v1 handlers,
    would wait on a lock nobody is going to release: a VM the plan lists would
    never be built again and nothing would say why."""
    _patch_instance_path(monkeypatch)
    supervisor = _RacingSupervisor()
    registry = AgentVmRegistry()
    real_create = supervisor.create_vm

    async def create_then_recover(spec: Any):
        supervisor.create_vm = real_create  # type: ignore[method-assign]
        msg = "the hypervisor refused this one"
        raise RuntimeError(msg)

    supervisor.create_vm = create_then_recover  # type: ignore[method-assign]

    with pytest.raises(RuntimeError):
        await _start(supervisor, registry)

    assert create_lock._locks == {}

    # The timeout is the assertion: a leaked lock makes this wait forever.
    await asyncio.wait_for(_start(supervisor, registry), timeout=5)

    assert supervisor.created is True
    assert create_lock._locks == {}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("content", "build", "spec"),
    [
        pytest.param(_program_content, "build_program_create_vm_spec", lambda: (_spec(), None), id="program"),
        pytest.param(
            lambda: _make_qemu_instance_message(hypervisor=HypervisorType.qemu),
            "build_create_vm_spec",
            _spec,
            id="instance",
        ),
        pytest.param(_vprogram_content, "build_vprogram_spec", lambda: (_spec(), None), id="vprogram"),
    ],
)
async def test_a_create_that_lost_the_race_keeps_the_winners_vm(monkeypatch, purge, content, build, spec) -> None:
    """VmAlreadyExistsError means somebody else built this VM. Retiring it
    would delete a VM that is running and, on fresh disks, purge its volumes."""
    _patch_message(monkeypatch, content())
    monkeypatch.setattr(run_module, build, AsyncMock(return_value=spec()))
    monkeypatch.setattr(run_module, "vm_has_volumes", MagicMock(return_value=False))
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())
    supervisor = SimpleNamespace(
        create_vm=AsyncMock(side_effect=VmAlreadyExistsError(f"{_HASH} already exists")),
        get_vm=AsyncMock(return_value=_info()),
        delete_vm=AsyncMock(),
        add_port_forward=AsyncMock(),
    )

    await run_module.create_vm_execution(
        _HASH,
        supervisor=supervisor,
        registry=AgentVmRegistry(),
        capacity=_capacity(),
        persistent=True,
    )

    supervisor.delete_vm.assert_not_awaited()
    purge.assert_not_called()
