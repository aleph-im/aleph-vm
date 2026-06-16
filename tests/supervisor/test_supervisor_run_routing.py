"""run.create_vm_execution routes eligible QEMU instances through the Supervisor."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash, ProgramContent
from aleph_message.models.execution.environment import (
    GpuProperties,
    HostRequirements,
    HypervisorType,
    TrustedExecutionEnvironment,
)
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.orchestrator import run as run_module
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.errors import InvalidBackendError, VmNotFoundError
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    IpAssignment,
    NetworkConfig,
    PciAddress,
    VmId,
    VmInfo,
    VmStatus,
)

_HASH = ItemHash("deadbeef" * 8)


def _gpu_request() -> GpuSpec:
    return GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id="10de:1234", model="")


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(str(_HASH)),
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
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _info(status: VmStatus = VmStatus.RUNNING) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(_HASH)),
        status=status,
        ipv4=IpAssignment(),
        ipv6=IpAssignment(),
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


def _fake_supervisor(*, create_status: VmStatus = VmStatus.RUNNING, get_status: VmStatus = VmStatus.RUNNING):
    # The agent is fully pool-free: it drives the supervisor abstraction only and
    # never reaches a pool. No ``pool`` attribute is exposed here on purpose - if
    # run.py tried to read one, these tests would AttributeError.
    return SimpleNamespace(
        create_vm=AsyncMock(return_value=_info(create_status)),
        get_vm=AsyncMock(return_value=_info(get_status)),
        add_port_forward=AsyncMock(),
        delete_vm=AsyncMock(),
        start_vm=AsyncMock(return_value=_info(VmStatus.RUNNING)),
    )


@pytest.mark.asyncio
async def test_eligible_instance_routed_through_supervisor(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    original_content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    original_message = MagicMock(content=original_content)
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    spec = _spec()
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=spec))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    persist = AsyncMock()
    monkeypatch.setattr(run_module, "persist_record", persist)

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    execution = await run_module.create_vm_execution(
        _HASH, supervisor=supervisor, registry=registry, persistent=True
    )

    supervisor.create_vm.assert_awaited_once_with(spec)
    # The message is recorded in the agent registry, not on the execution.
    record = registry.get(_HASH)
    assert record.message is content
    assert record.original is original_content
    assert record.persistent is True
    # The agent persists its own record; the hypervisor object is never touched.
    persist.assert_awaited_once_with(_HASH, record)
    # SSH port-forward applied through the abstraction.
    assert supervisor.add_port_forward.await_count >= 1
    # Spec path returns None: no caller consumes a hypervisor object from it.
    assert execution is None
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_eligible_instance_timeout_tears_down(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "_START_POLL_TIMEOUT_SECONDS", 0)

    supervisor = _fake_supervisor(get_status=VmStatus.BOOTING)  # never RUNNING
    registry = AgentVmRegistry()

    with pytest.raises(asyncio.TimeoutError):
        await run_module.create_vm_execution(_HASH, supervisor=supervisor, registry=registry, persistent=True)

    supervisor.delete_vm.assert_awaited_once_with(VmId(str(_HASH)))
    assert registry.get(_HASH) is None  # forgotten on failure


@pytest.mark.asyncio
async def test_eligible_instance_port_forward_failure_tears_down(monkeypatch):
    # Readiness succeeds but applying a port forward fails: the other failure
    # source in the same try block must trigger the same teardown.
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    supervisor = _fake_supervisor()  # get_vm reports RUNNING immediately
    supervisor.add_port_forward = AsyncMock(side_effect=RuntimeError("nftables boom"))
    registry = AgentVmRegistry()

    with pytest.raises(RuntimeError, match="nftables boom"):
        await run_module.create_vm_execution(_HASH, supervisor=supervisor, registry=registry, persistent=True)

    supervisor.delete_vm.assert_awaited_once_with(VmId(str(_HASH)))
    assert registry.get(_HASH) is None  # forgotten on failure


@pytest.mark.asyncio
async def test_firecracker_instance_rejected_via_spec_path(monkeypatch):
    """Instances are QEMU-only: a Firecracker instance is spec-eligible (it
    reaches build_create_vm_spec) and is rejected there with InvalidBackendError.
    The actual rejection is unit-tested in test_supervisor_translate.py; here we
    assert routing reaches the spec path and surfaces the error without any pool
    fallback."""
    content = _make_qemu_instance_message(hypervisor=HypervisorType.firecracker)
    message = MagicMock(content=content)
    original_message = MagicMock(content=_make_qemu_instance_message())
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    monkeypatch.setattr(
        run_module,
        "build_create_vm_spec",
        AsyncMock(side_effect=InvalidBackendError("instances are QEMU-only")),
    )

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    with pytest.raises(InvalidBackendError, match="QEMU-only"):
        await run_module.create_vm_execution(_HASH, supervisor=supervisor, registry=registry, persistent=False)

    run_module.build_create_vm_spec.assert_awaited_once()
    supervisor.create_vm.assert_not_awaited()
    assert registry.get(_HASH) is None  # nothing recorded for a rejected create


@pytest.mark.asyncio
async def test_program_routed_through_spec_program_path(monkeypatch):
    """Programs (persistent and on-demand) are created through the supervisor
    spec program path, never a pool."""
    content = MagicMock()
    content.__class__ = ProgramContent
    content.on.persistent = True
    message = MagicMock(content=content)
    original_message = MagicMock(content=content)
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    program_spec = SimpleNamespace(vm_id=VmId(str(_HASH)))
    build = AsyncMock(return_value=(program_spec, SimpleNamespace()))
    monkeypatch.setattr(run_module, "build_program_create_vm_spec", build)
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    supervisor = _fake_supervisor()
    supervisor.create_vm = AsyncMock(return_value=_info(VmStatus.RUNNING))
    registry = AgentVmRegistry()

    execution = await run_module.create_vm_execution(
        _HASH, supervisor=supervisor, registry=registry, persistent=True
    )

    build.assert_awaited_once()
    supervisor.create_vm.assert_awaited_once_with(program_spec)
    run_module.build_create_vm_spec.assert_not_awaited()
    assert execution is None
    record = registry.get(_HASH)
    assert record is not None and record.persistent is True


def test_confidential_instance_is_spec_eligible():
    """The confidential exclusion is gone: a confidential QEMU instance reaches
    the spec path (the engine takes the confidential launch)."""
    content = _make_qemu_instance_message(trusted_execution=TrustedExecutionEnvironment())
    assert run_module._is_spec_eligible(content) is True


@pytest.mark.asyncio
async def test_confidential_instance_routed_through_spec_awaiting_init(monkeypatch):
    """A confidential instance is created through the spec path and left
    awaiting its owner's session: no wait-for-running, no port forwards (the VM
    is not up), and the agent record is persisted."""
    content = _make_qemu_instance_message(trusted_execution=TrustedExecutionEnvironment())
    message = MagicMock(content=content)
    original_message = MagicMock(content=_make_qemu_instance_message())
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    spec = replace(_spec(), tee=MagicMock())
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=spec))
    persist = AsyncMock()
    monkeypatch.setattr(run_module, "persist_record", persist)
    waited = AsyncMock()
    monkeypatch.setattr(run_module, "_wait_until_running", waited)

    awaiting = replace(_info(VmStatus.BOOTING), awaiting_confidential_init=True)
    supervisor = _fake_supervisor()
    supervisor.create_vm = AsyncMock(return_value=awaiting)
    registry = AgentVmRegistry()

    execution = await run_module.create_vm_execution(
        _HASH, supervisor=supervisor, registry=registry, persistent=True
    )

    supervisor.create_vm.assert_awaited_once_with(spec)
    waited.assert_not_awaited()  # never wait on an awaiting-init VM
    supervisor.add_port_forward.assert_not_awaited()  # no forwards on a VM that is not up
    persist.assert_awaited_once()
    assert execution is None
    assert registry.get(_HASH) is not None


def test_gpu_instance_is_spec_eligible():
    """The GPU exclusion is gone: a GPU QEMU instance reaches the spec path."""
    content = _make_qemu_instance_message().model_copy(
        update={
            "requirements": HostRequirements(
                gpu=[
                    GpuProperties(
                        vendor="NVIDIA",
                        device_name="RTX",
                        device_class="0300",
                        device_id="10de:1234",
                    )
                ]
            )
        }
    )
    assert run_module._is_spec_eligible(content) is True


@pytest.mark.asyncio
async def test_gpu_instance_routed_through_supervisor(monkeypatch):
    """GPU instances reach the spec path. The agent does not touch reservations:
    it builds a spec carrying owner_address and drives create_vm. The engine
    consumes this owner's own reservation and skips other users' reservations."""
    content = _make_qemu_instance_message().model_copy(
        update={
            "requirements": HostRequirements(
                gpu=[
                    GpuProperties(
                        vendor="NVIDIA",
                        device_name="RTX",
                        device_class="0300",
                        device_id="10de:1234",
                    )
                ]
            )
        }
    )
    message = MagicMock(content=content)
    original_message = MagicMock(content=content)
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    # The spec carries a GPU request and the owner address; the engine owns the
    # reservation handling, the agent does not.
    spec = replace(_spec(), gpus=[_gpu_request()], owner_address=content.address)
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=spec))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    execution = await run_module.create_vm_execution(
        _HASH, supervisor=supervisor, registry=registry, persistent=True
    )

    # The spec the agent built carries the owner address for engine-side
    # reservation handling.
    assert supervisor.create_vm.await_args.args[0].owner_address == content.address
    supervisor.create_vm.assert_awaited_once_with(spec)
    assert execution is None


@pytest.mark.asyncio
async def test_unsupported_content_raises_clear_error_no_pool(monkeypatch):
    """A content type that is neither a program nor a spec-eligible instance is
    rejected with a clear HTTP error, never a pool fallback (there is none)."""
    from aiohttp.web_exceptions import HTTPBadRequest

    content = SimpleNamespace()  # neither ProgramContent nor InstanceContent
    message = MagicMock(content=content)
    original_message = MagicMock(content=content)
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    build = AsyncMock()
    monkeypatch.setattr(run_module, "build_create_vm_spec", build)

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    with pytest.raises(HTTPBadRequest):
        await run_module.create_vm_execution(_HASH, supervisor=supervisor, registry=registry, persistent=False)

    build.assert_not_awaited()
    supervisor.create_vm.assert_not_awaited()
    assert registry.get(_HASH) is None


@pytest.mark.asyncio
async def test_start_persistent_reuses_running(monkeypatch):
    sup = _fake_supervisor(get_status=VmStatus.RUNNING)
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    result = await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    assert result is None
    created.assert_not_awaited()  # already running -> no create


@pytest.mark.asyncio
async def test_start_persistent_creates_when_absent(monkeypatch):
    sup = _fake_supervisor()
    sup.get_vm = AsyncMock(side_effect=VmNotFoundError(_HASH))
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    created.assert_awaited_once()


@pytest.mark.asyncio
async def test_start_persistent_first_create_confidential_skips_wait(monkeypatch):
    """First-time creation of a confidential VM leaves it awaiting init: after
    create_vm_execution the VM reports awaiting_confidential_init, so the
    readiness barrier must be skipped (waiting would block forever)."""
    sup = _fake_supervisor()
    # Absent on the first poll, then awaiting-init after create.
    awaiting = replace(_info(VmStatus.BOOTING), awaiting_confidential_init=True)
    sup.get_vm = AsyncMock(side_effect=[VmNotFoundError(_HASH), awaiting])
    created = AsyncMock()
    waited = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", waited)

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    created.assert_awaited_once()
    waited.assert_not_awaited()  # never wait on an awaiting-init confidential VM


@pytest.mark.asyncio
async def test_start_persistent_resumes_stopped(monkeypatch):
    # A cleanly stopped VM is resumed in place (start_vm), not deleted and
    # recreated: stop/start is a pause/resume.
    sup = _fake_supervisor(get_status=VmStatus.STOPPED)
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    sup.start_vm.assert_awaited_once()  # STOPPED -> resume in place
    sup.delete_vm.assert_not_awaited()  # not deleted
    created.assert_not_awaited()  # not recreated


@pytest.mark.asyncio
async def test_start_persistent_recreates_after_failed(monkeypatch):
    sup = _fake_supervisor(get_status=VmStatus.FAILED)
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    sup.delete_vm.assert_awaited_once()  # FAILED -> delete then recreate
    created.assert_awaited_once()
    sup.start_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_persistent_waits_gone_then_recreates_when_stopping(monkeypatch):
    sup = _fake_supervisor(get_status=VmStatus.STOPPING)
    waited_gone = AsyncMock()
    created = AsyncMock()
    monkeypatch.setattr(run_module, "_wait_until_gone", waited_gone)
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    waited_gone.assert_awaited_once()  # STOPPING -> wait until gone
    created.assert_awaited_once()  # then recreate


@pytest.mark.asyncio
async def test_start_persistent_keeps_confidential_awaiting_init(monkeypatch):
    # A confidential VM waiting for its owner's session must not be waited-on or
    # recreated: it can only start once the owner uploads the session
    # certificates, so any wait/recreate would loop forever.
    awaiting = VmInfo(
        vm_id=VmId(str(_HASH)),
        status=VmStatus.BOOTING,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
        awaiting_confidential_init=True,
    )
    sup = _fake_supervisor()
    sup.get_vm = AsyncMock(return_value=awaiting)
    created = AsyncMock()
    waited = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", waited)

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    created.assert_not_awaited()  # not recreated
    sup.delete_vm.assert_not_awaited()  # not deleted
    waited.assert_not_awaited()  # not waited-on (would block forever)


@pytest.mark.asyncio
async def test_start_persistent_arms_update_watch(monkeypatch):
    sup = _fake_supervisor(get_status=VmStatus.RUNNING)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())
    watcher = MagicMock()
    pubsub = MagicMock()  # truthy -> WATCH_FOR_UPDATES default True -> watch armed

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        pubsub,
        supervisor=sup,
        registry=AgentVmRegistry(),
        expiry=MagicMock(),
        update_watcher=watcher,
    )
    watcher.watch.assert_called_once()
