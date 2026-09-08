"""run._ensure_program_vm: the supervisor-driven program get-or-create."""

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aiohttp import web
from aleph_message.models import ItemHash, ProgramContent

from aleph.vm.agent import run as run_module
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.supervisor_interface.errors import (
    InsufficientResourcesError,
    VmNotFoundError,
)
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    GuestChannelSpec,
    IpAssignment,
    NetworkConfig,
    VmId,
    VmInfo,
    VmStatus,
)

VM_HASH = ItemHash("feed" * 16)
VM_ID = VmId(str(VM_HASH))


def _content() -> MagicMock:
    content = MagicMock()
    content.__class__ = ProgramContent
    content.on.persistent = False
    return content


def _fake_capacity() -> SimpleNamespace:
    """Agent-side admission stub: capacity always passes."""
    return SimpleNamespace(check_capacity=MagicMock(), resolve_gpus=AsyncMock(return_value=[]))


def _info(status: VmStatus) -> VmInfo:
    return VmInfo(
        vm_id=VM_ID,
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.FIRECRACKER,
        numa_node=None,
        status_message="",
        guest_channel_path="/tmp/v.sock",
        guest_ready_payload=b"",
    )


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VM_ID,
        backend=Backend.FIRECRACKER,
        kernel_path=Path("/opt/vmlinux.bin"),
        initrd_path=Path(""),
        disks=[],
        vcpus=1,
        memory_mib=128,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=False,
        guest_channel=GuestChannelSpec(ready_port=52),
    )


class FakeProgramClient:
    def __init__(self, ready: bool = False):
        self._ready = ready
        self.setups: list[VmId] = []
        self.forgotten: list[VmId] = []
        self._locks: dict[VmId, asyncio.Lock] = {}

    def creation_lock(self, vm_id: VmId) -> asyncio.Lock:
        return self._locks.setdefault(vm_id, asyncio.Lock())

    def is_ready(self, vm_id: VmId) -> bool:
        return self._ready

    async def setup_program(self, info, message, resources) -> None:
        self.setups.append(info.vm_id)
        self._ready = True

    async def forget(self, vm_id: VmId) -> None:
        self.forgotten.append(vm_id)


@pytest.fixture
def patched_build(monkeypatch):
    resources = SimpleNamespace()
    build = AsyncMock(return_value=(_spec(), resources))
    monkeypatch.setattr(run_module, "build_program_create_vm_spec", build)
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())
    return build


@pytest.mark.asyncio
async def test_creates_when_absent(patched_build):
    supervisor = SimpleNamespace(
        get_vm=AsyncMock(side_effect=[VmNotFoundError(VM_ID), _info(VmStatus.RUNNING)]),
        create_vm=AsyncMock(return_value=_info(VmStatus.RUNNING)),
        delete_vm=AsyncMock(),
    )
    registry = AgentVmRegistry()
    program_client = FakeProgramClient()

    info = await run_module._ensure_program_vm(
        VM_HASH,
        _content(),
        _content(),
        supervisor=supervisor,
        registry=registry,
        capacity=_fake_capacity(),
        program_client=program_client,
    )

    assert info.status is VmStatus.RUNNING
    supervisor.create_vm.assert_awaited_once()
    created_spec = supervisor.create_vm.await_args.args[0]
    assert created_spec.guest_channel is not None and created_spec.backend is Backend.FIRECRACKER
    assert program_client.setups == [VM_ID]
    assert registry.get(VM_HASH) is not None
    run_module.persist_record.assert_awaited_once()


@pytest.mark.asyncio
async def test_reuses_running_configured_vm(patched_build):
    supervisor = SimpleNamespace(
        get_vm=AsyncMock(return_value=_info(VmStatus.RUNNING)),
        create_vm=AsyncMock(),
        delete_vm=AsyncMock(),
    )
    program_client = FakeProgramClient(ready=True)

    info = await run_module._ensure_program_vm(
        VM_HASH,
        _content(),
        _content(),
        supervisor=supervisor,
        registry=AgentVmRegistry(),
        capacity=_fake_capacity(),
        program_client=program_client,
    )

    assert info.status is VmStatus.RUNNING
    supervisor.create_vm.assert_not_awaited()
    assert program_client.setups == []


@pytest.mark.asyncio
async def test_recreates_unconfigured_running_vm(patched_build, monkeypatch):
    """A running VM this agent process never configured cannot be trusted to
    accept run_code (the runtime takes one config push per boot): recreate.
    retire_vm(RECREATE) is what tears the old instance down, not a plain
    delete_vm."""
    from aleph.vm.agent.vm.retire import RetireReason

    supervisor = SimpleNamespace(
        get_vm=AsyncMock(side_effect=[_info(VmStatus.RUNNING), VmNotFoundError(VM_ID), _info(VmStatus.RUNNING)]),
        create_vm=AsyncMock(return_value=_info(VmStatus.RUNNING)),
        delete_vm=AsyncMock(),
    )
    program_client = FakeProgramClient(ready=False)
    retire = AsyncMock()
    monkeypatch.setattr(run_module, "retire_vm", retire)

    await run_module._ensure_program_vm(
        VM_HASH,
        _content(),
        _content(),
        supervisor=supervisor,
        registry=AgentVmRegistry(),
        capacity=_fake_capacity(),
        program_client=program_client,
    )

    retire.assert_awaited_once_with(VM_HASH, RetireReason.RECREATE, supervisor=supervisor)
    supervisor.delete_vm.assert_not_awaited()
    supervisor.create_vm.assert_awaited_once()
    assert program_client.setups == [VM_ID]


@pytest.mark.asyncio
async def test_setup_failure_tears_down(patched_build, monkeypatch):
    """A config-push failure retires the half-started VM as FAILED_CREATE
    (no pre-existing volumes here, so not RECREATE)."""
    from aleph.vm.agent.vm.retire import RetireReason

    supervisor = SimpleNamespace(
        get_vm=AsyncMock(side_effect=[VmNotFoundError(VM_ID), _info(VmStatus.RUNNING)]),
        create_vm=AsyncMock(return_value=_info(VmStatus.RUNNING)),
        delete_vm=AsyncMock(),
    )
    registry = AgentVmRegistry()
    program_client = FakeProgramClient()
    program_client.setup_program = AsyncMock(side_effect=RuntimeError("config push failed"))  # type: ignore[method-assign]
    retire = AsyncMock()
    monkeypatch.setattr(run_module, "retire_vm", retire)

    with pytest.raises(web.HTTPInternalServerError):
        await run_module._ensure_program_vm(
            VM_HASH,
            _content(),
            _content(),
            supervisor=supervisor,
            registry=registry,
            capacity=_fake_capacity(),
            program_client=program_client,
        )

    retire.assert_awaited_once_with(VM_HASH, RetireReason.FAILED_CREATE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()
    run_module.persist_record.assert_not_awaited()


@pytest.mark.asyncio
async def test_concurrent_cold_requests_create_once(patched_build):
    """Two concurrent requests to a cold program must yield ONE create and ONE
    configuration push — the runtime accepts a single config per boot."""
    state = {"created": False}

    async def get_vm(vm_id):
        if state["created"]:
            return _info(VmStatus.RUNNING)
        raise VmNotFoundError(vm_id)

    async def create_vm(spec):
        await asyncio.sleep(0)  # yield so the other request can race
        state["created"] = True
        return _info(VmStatus.RUNNING)

    supervisor = SimpleNamespace(get_vm=get_vm, create_vm=AsyncMock(side_effect=create_vm), delete_vm=AsyncMock())
    program_client = FakeProgramClient()
    registry = AgentVmRegistry()

    results = await asyncio.gather(
        *(
            run_module._ensure_program_vm(
                VM_HASH,
                _content(),
                _content(),
                supervisor=supervisor,
                registry=registry,
                capacity=_fake_capacity(),
                program_client=program_client,
            )
            for _ in range(2)
        )
    )

    assert all(info.status is VmStatus.RUNNING for info in results)
    supervisor.create_vm.assert_awaited_once()
    assert program_client.setups == [VM_ID]


@pytest.mark.asyncio
async def test_insufficient_resources_maps_to_503(patched_build):
    supervisor = SimpleNamespace(
        get_vm=AsyncMock(side_effect=VmNotFoundError(VM_ID)),
        create_vm=AsyncMock(side_effect=InsufficientResourcesError("full")),
        delete_vm=AsyncMock(),
    )

    with pytest.raises(web.HTTPServiceUnavailable):
        await run_module._ensure_program_vm(
            VM_HASH,
            _content(),
            _content(),
            supervisor=supervisor,
            registry=AgentVmRegistry(),
            capacity=_fake_capacity(),
            program_client=FakeProgramClient(),
        )
