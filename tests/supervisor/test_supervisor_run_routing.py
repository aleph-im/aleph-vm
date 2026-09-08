"""run.create_vm_execution routes eligible QEMU instances through the Supervisor."""

from __future__ import annotations

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

from aleph.vm.agent import run as run_module
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.errors import InvalidBackendError, VmNotFoundError
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GpuSpec,
    GuestPort,
    HostPort,
    IpAssignment,
    NetworkConfig,
    PciAddress,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmId,
    VmInfo,
    VmStatus,
)

_HASH = ItemHash("deadbeef" * 8)


def _resolved_gpu() -> GpuSpec:
    return GpuSpec(pci_host=PciAddress("0000:01:00.0"), supports_x_vga=True)


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


def _fake_capacity(resolved: list[GpuSpec] | None = None):
    """Agent-side admission stub: capacity always passes, GPU resolution
    returns the given resolved cards."""
    return SimpleNamespace(
        check_capacity=MagicMock(),
        resolve_gpus=AsyncMock(return_value=list(resolved or [])),
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
        _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
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
async def test_owner_record_recorded_before_resource_download(monkeypatch):
    """Regression: the owner record must reach the registry BEFORE
    build_create_vm_spec runs (it downloads the confidential rootfs/firmware,
    several seconds, then create_vm takes ~20s more). A confidential owner's
    one-shot init-session can land anywhere in that window; if the record is not
    yet present, get_agent_record_or_404 404s, the single call is lost, and the
    instance is forgotten/reaped. So owner-auth must resolve from the moment
    create begins, not only after the download completes.
    """
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    seen = {}

    async def fake_build(vm_hash, _content):
        # build_create_vm_spec is where the download happens; the owner record
        # must already be queryable here.
        seen["record_present_at_build"] = registry.get(vm_hash) is not None
        return _spec()

    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(side_effect=fake_build))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())

    await run_module.create_vm_execution(
        _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
    )

    assert (
        seen.get("record_present_at_build") is True
    ), "owner record must be recorded before build_create_vm_spec downloads resources"


@pytest.mark.asyncio
async def test_eligible_instance_timeout_retires_as_failed_create(monkeypatch):
    from aleph.vm.agent.vm.retire import RetireReason

    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "_START_POLL_TIMEOUT_SECONDS", 0)
    retire = AsyncMock()
    monkeypatch.setattr(run_module, "retire_vm", retire)

    supervisor = _fake_supervisor(get_status=VmStatus.BOOTING)  # never RUNNING
    registry = AgentVmRegistry()

    with pytest.raises(run_module.VmStartupError):
        await run_module.create_vm_execution(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    retire.assert_awaited_once_with(_HASH, RetireReason.FAILED_CREATE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_eligible_instance_port_forward_failure_retires_as_failed_create(monkeypatch):
    # Readiness succeeds but applying a port forward fails: the other failure
    # source in the same try block must trigger the same teardown.
    from aleph.vm.agent.vm.retire import RetireReason

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
    retire = AsyncMock()
    monkeypatch.setattr(run_module, "retire_vm", retire)

    with pytest.raises(RuntimeError, match="nftables boom"):
        await run_module.create_vm_execution(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    retire.assert_awaited_once_with(_HASH, RetireReason.FAILED_CREATE, supervisor=supervisor, registry=registry)
    supervisor.delete_vm.assert_not_awaited()


@pytest.fixture
def _persistent_pool(tmp_path, monkeypatch):
    """A single real volume pool (the PERSISTENT_VOLUMES_DIR fallback
    get_pools() uses when setup_pools() has not run), so vm_has_volumes can
    see actual files on disk."""
    pool0 = tmp_path / "pool0"
    pool0.mkdir()
    monkeypatch.setattr(settings, "PERSISTENT_VOLUMES_DIR", pool0)
    return pool0


@pytest.mark.asyncio
async def test_eligible_instance_failure_with_existing_volumes_retires_as_recreate(monkeypatch, _persistent_pool):
    """A failed create against volumes that already existed before the
    attempt (the re-create path for a host-persistent VM whose disks
    downloader._make_writable_volume left alone) must not wipe them: it
    retires RECREATE, which keeps the record and the disks -- not
    FAILED_CREATE, which would purge them."""
    volume_dir = _persistent_pool / str(_HASH)
    volume_dir.mkdir()
    rootfs = volume_dir / "rootfs.qcow2"
    rootfs.write_bytes(b"pre-existing-owner-data")

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
        await run_module.create_vm_execution(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    # RECREATE: the record and the pre-existing volume both survive.
    assert registry.get(_HASH) is not None
    assert rootfs.exists()
    assert rootfs.read_bytes() == b"pre-existing-owner-data"
    supervisor.delete_vm.assert_awaited_once_with(VmId(str(_HASH)), keep_port_mappings=True)


@pytest.mark.asyncio
async def test_eligible_instance_failure_without_existing_volumes_retires_as_failed_create(
    monkeypatch, _persistent_pool
):
    """A failed create that allocated fresh disks (nothing existed before
    the attempt) retires FAILED_CREATE, which purges what it just
    allocated and drops the record."""
    from aleph.vm.agent.vm import retire as retire_module

    # retire_vm(FAILED_CREATE) writes a DB record deletion; stub it out, this
    # test only cares about the volume/registry outcome.
    monkeypatch.setattr(retire_module, "delete_records_for_vm", AsyncMock())

    volume_dir = _persistent_pool / str(_HASH)
    rootfs = volume_dir / "rootfs.qcow2"

    async def _build_create_vm_spec(vm_hash, content):
        # Simulate the real build_create_vm_spec: it allocates the volume
        # file before create_vm_execution's had_volumes snapshot has a
        # chance to see it (the snapshot runs before this call).
        volume_dir.mkdir(parents=True, exist_ok=True)
        rootfs.write_bytes(b"freshly-allocated")
        return _spec()

    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", _build_create_vm_spec)
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    supervisor = _fake_supervisor()  # get_vm reports RUNNING immediately
    supervisor.add_port_forward = AsyncMock(side_effect=RuntimeError("nftables boom"))
    registry = AgentVmRegistry()

    assert not rootfs.exists()  # nothing allocated yet: had_volumes will be False

    with pytest.raises(RuntimeError, match="nftables boom"):
        await run_module.create_vm_execution(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )

    # FAILED_CREATE: the record is dropped and the freshly-allocated volume
    # is purged.
    assert registry.get(_HASH) is None
    assert not rootfs.exists()
    supervisor.delete_vm.assert_awaited_once_with(VmId(str(_HASH)), keep_port_mappings=False)


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
    # The rejection retires the never-created VM as FAILED_CREATE for real
    # (not mocked): stub out its DB write, which needs an app-level session
    # this unit test does not set up.
    from aleph.vm.agent.vm import retire as retire_module

    monkeypatch.setattr(retire_module, "delete_records_for_vm", AsyncMock())

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()

    with pytest.raises(InvalidBackendError, match="QEMU-only"):
        await run_module.create_vm_execution(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=False
        )

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
        _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
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
        _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
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
    """GPU instances reach the spec path. The agent resolves the message's
    requested device_ids to concrete host cards through its CapacityManager
    (owner = message.address) and the spec sent to create_vm carries the
    RESOLVED cards, not the request."""
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
    spec = _spec()
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=spec))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "persist_record", AsyncMock())

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()
    resolved = _resolved_gpu()
    capacity = _fake_capacity([resolved])

    execution = await run_module.create_vm_execution(
        _HASH, supervisor=supervisor, registry=registry, capacity=capacity, persistent=True
    )

    # The requested device_ids stopped at the agent: resolution ran against
    # the ledger with the message owner, and the spec that crossed the
    # boundary carries the resolved card.
    capacity.resolve_gpus.assert_awaited_once_with(["10de:1234"], owner=content.address)
    sent_spec = supervisor.create_vm.await_args.args[0]
    assert sent_spec.gpus == [resolved]
    assert sent_spec == replace(spec, gpus=[resolved])
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
        await run_module.create_vm_execution(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=False
        )

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
        capacity=_fake_capacity(),
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
        capacity=_fake_capacity(),
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
        capacity=_fake_capacity(),
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
        capacity=_fake_capacity(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    sup.start_vm.assert_awaited_once()  # STOPPED -> resume in place
    sup.delete_vm.assert_not_awaited()  # not deleted
    created.assert_not_awaited()  # not recreated


def _readopt_supervisor(*, get_status: VmStatus = VmStatus.RUNNING, current_forwards: list | None = None):
    sup = _fake_supervisor(get_status=get_status)
    sup.list_port_forwards = AsyncMock(return_value=current_forwards or [])
    sup.remove_port_forward = AsyncMock()
    return sup


def _instance_registry() -> AgentVmRegistry:
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    registry = AgentVmRegistry()
    registry.record(_HASH, message=content, original=content, persistent=True)
    return registry


async def _start_persistent(sup, registry):
    return await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=registry,
        capacity=_fake_capacity(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )


@pytest.mark.asyncio
async def test_start_persistent_readopt_instance_heals_with_strict_resolve(monkeypatch):
    """An instance adopted already-RUNNING gets its forwards reconciled from
    the aggregate, resolved strictly: on re-adoption "could not fetch" must
    mean "skip", never "converge onto the SSH-only fallback"."""
    sup = _readopt_supervisor()
    monkeypatch.setattr(run_module, "create_vm_execution", AsyncMock())
    ssh = PortForwardSpec(vm_id=VmId(str(_HASH)), host_port=HostPort(0), vm_port=GuestPort(22), protocol=Protocol.TCP)
    resolve = AsyncMock(return_value=[ssh])
    monkeypatch.setattr(run_module, "resolve_port_forwards", resolve)

    await _start_persistent(sup, _instance_registry())

    resolve.assert_awaited_once()
    await_args = resolve.await_args
    assert await_args is not None
    assert await_args.kwargs.get("strict") is True
    sup.add_port_forward.assert_awaited_once_with(ssh)
    sup.remove_port_forward.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_persistent_readopt_instance_settings_error_removes_nothing(monkeypatch):
    """A transient aggregate-fetch failure during re-adoption healing must
    leave existing forwards exactly as found and never fail the allocation."""
    existing = PortForwardInfo(
        vm_id=VmId(str(_HASH)), host_port=HostPort(24080), vm_port=GuestPort(8080), protocol=Protocol.TCP
    )
    sup = _readopt_supervisor(current_forwards=[existing])
    monkeypatch.setattr(run_module, "create_vm_execution", AsyncMock())
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(side_effect=RuntimeError("CCN down")))

    await _start_persistent(sup, _instance_registry())

    sup.remove_port_forward.assert_not_awaited()
    sup.add_port_forward.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_persistent_readopt_awaiting_init_not_healed(monkeypatch):
    """A confidential VM awaiting its owner's session is left untouched: it is
    not RUNNING, so there is nothing to heal (the create path applies forwards
    once it comes up)."""
    sup = _fake_supervisor()
    sup.get_vm = AsyncMock(return_value=replace(_info(VmStatus.DEFINED), awaiting_confidential_init=True))
    heal = AsyncMock()
    monkeypatch.setattr(run_module, "reconcile_adopted_port_forwards", heal)
    monkeypatch.setattr(run_module, "create_vm_execution", AsyncMock())

    await _start_persistent(sup, AgentVmRegistry())

    heal.assert_not_awaited()


@pytest.mark.asyncio
async def test_start_persistent_readopt_stopped_heals_after_resume(monkeypatch):
    """The resume-in-place branch ends with a RUNNING VM this agent did not
    create, so it heals forwards too (idempotent when nothing is missing)."""
    sup = _fake_supervisor(get_status=VmStatus.STOPPED)
    heal = AsyncMock()
    monkeypatch.setattr(run_module, "reconcile_adopted_port_forwards", heal)
    monkeypatch.setattr(run_module, "create_vm_execution", AsyncMock())
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    await _start_persistent(sup, AgentVmRegistry())

    sup.start_vm.assert_awaited_once()
    heal.assert_awaited_once()


@pytest.mark.asyncio
async def test_reconcile_adopted_program_content_is_a_noop():
    """Programs get no agent-side forwards: adoption healing must not touch
    the supervisor at all (a bare namespace would AttributeError if it did)."""
    registry = AgentVmRegistry()
    content = MagicMock(spec=ProgramContent)
    registry.record(_HASH, message=content, original=content, persistent=True)

    await run_module.reconcile_adopted_port_forwards(SimpleNamespace(), registry, _HASH)


@pytest.mark.asyncio
async def test_start_persistent_recreates_after_failed(monkeypatch):
    from aleph.vm.agent.vm.retire import RetireReason

    sup = _fake_supervisor(get_status=VmStatus.FAILED)
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())
    retire = AsyncMock()
    monkeypatch.setattr(run_module, "retire_vm", retire)

    await run_module.start_persistent_vm(
        ItemHash(_HASH),
        None,
        supervisor=sup,
        registry=AgentVmRegistry(),
        capacity=_fake_capacity(),
        expiry=MagicMock(),
        update_watcher=MagicMock(),
    )
    # FAILED -> delete then recreate: a recovery cycle, so RECREATE keeps the
    # persisted host-port forwards.
    retire.assert_awaited_once_with(ItemHash(_HASH), RetireReason.RECREATE, supervisor=sup)
    sup.delete_vm.assert_not_awaited()
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
        capacity=_fake_capacity(),
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
        capacity=_fake_capacity(),
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
        capacity=_fake_capacity(),
        expiry=MagicMock(),
        update_watcher=watcher,
    )
    watcher.watch.assert_called_once()


@pytest.mark.asyncio
async def test_startup_failure_maps_to_specific_http_reason(monkeypatch):
    """A VmStartupError (never reached RUNNING) surfaces as a specific HTTP
    reason, not the generic 'unhandled error during initialisation' bucket."""
    from aiohttp.web_exceptions import HTTPInternalServerError

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

    with pytest.raises(HTTPInternalServerError) as excinfo:
        await run_module.create_vm_execution_or_raise_http_error(
            _HASH, supervisor=supervisor, registry=registry, capacity=_fake_capacity(), persistent=True
        )
    assert excinfo.value.reason == "VM failed to start"


def test_program_error_mapper_maps_startup_failure():
    """The on-demand program mapper gives VmStartupError the same specific
    reason as the instance/v-program create path, so the 'every VM type'
    contract on VmStartupError holds."""
    from aiohttp.web_exceptions import HTTPInternalServerError

    with pytest.raises(HTTPInternalServerError) as excinfo:
        run_module._raise_http_for_program_error(run_module.VmStartupError("never reached RUNNING"), ItemHash(_HASH))
    assert excinfo.value.reason == "VM failed to start"
