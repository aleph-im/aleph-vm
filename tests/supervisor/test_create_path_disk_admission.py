"""Capacity admission runs before the download, once, and accounts for disk.

Every create path called check_capacity with disk_mib=0, so neither the total
disk requirement nor the largest-single-volume check ran: only the reserve
endpoint ever judged disk. Filling the number in at the old call site would
have been theatre, because that call sits *after* build_*_spec, which
downloads the resources and creates the volume files: by then the space is
already allocated and requiring it again would double-count it.

So the admission gate moves ahead of the build, where refusing still saves the
download, and the post-build call goes away: memory and vCPUs
are judged in the same single pass as disk, and only GPU resolution stays after
the build.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import HypervisorType
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.agent import run as run_module
from aleph.vm.agent.vm.reconciler import is_creating
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.resources import InsufficientResourcesError
from aleph.vm.utils import get_message_executable_content

_HASH = ItemHash("deadbeef" * 8)


@pytest.fixture(autouse=True)
def _stub_retire_db_write(monkeypatch):
    """A refused admission now retires the never-created VM as
    FAILED_CREATE, which writes a DB record deletion; stub it out, since
    these tests only care about admission ordering, not retire_vm's DB
    write, which needs an app-level session this unit test does not set up.
    """
    from aleph.vm.agent.vm import retire as retire_module

    monkeypatch.setattr(retire_module, "delete_records_for_vm", AsyncMock())


# _make_qemu_instance_message declares a single 10000 MiB rootfs and no extra
# volumes, so both the total and the largest single volume are 10000.
INSTANCE_ROOTFS_MIB = 10000


def _program_content():
    with open("examples/program_message_from_aleph.json") as fd:
        return get_message_executable_content(json.load(fd)["content"])


def _capacity(*, refuse: bool = False):
    """Admission stub. `refuse` makes every check fail, standing in for a host
    with no room left.

    ``check_capacity`` is deliberately not exposed: run.py must reach capacity
    only through ``check_message``, so a stray direct call AttributeErrors here
    instead of passing silently.
    """
    error = InsufficientResourcesError("no room", required={}, available={})
    return SimpleNamespace(
        check_message=MagicMock(side_effect=error if refuse else None),
        check_recreate=MagicMock(side_effect=error if refuse else None),
        resolve_gpus=AsyncMock(return_value=[]),
    )


def _supervisor():
    return SimpleNamespace(
        create_vm=AsyncMock(side_effect=AssertionError("create_vm must not be reached")),
        delete_vm=AsyncMock(),
    )


def _patch_message(monkeypatch, content):
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    return content


async def _create(capacity, supervisor=None, registry=None, recreate=False):
    await run_module.create_vm_execution(
        _HASH,
        supervisor=supervisor or _supervisor(),
        registry=registry if registry is not None else AgentVmRegistry(),
        capacity=capacity,
        recreate=recreate,
    )


def _admissions(capacity):
    """(content, exclude_vm_hash) of every admission call."""
    return [(c.args[0], c.kwargs.get("exclude_vm_hash")) for c in capacity.check_message.call_args_list]


def _real_capacity(mocker, *, refuse: bool = False):
    """A real CapacityManager with only check_capacity stubbed, so a test can
    read the scalars check_message derived from the message."""
    from aleph.vm.agent.capacity import CapacityManager

    manager = CapacityManager(supervisor=MagicMock(), registry=AgentVmRegistry())
    error = InsufficientResourcesError("no room", required={}, available={})
    mocker.patch.object(manager, "check_capacity", side_effect=error if refuse else None)
    mocker.patch("aleph.vm.agent.capacity.existing_volume_files", return_value={})
    return manager


class TestInstancePath:
    @pytest.mark.asyncio
    async def test_refused_before_the_download(self, monkeypatch):
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        build = AsyncMock()
        monkeypatch.setattr(run_module, "build_create_vm_spec", build)
        capacity = _capacity(refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        build.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_admission_carries_the_declared_disk(self, monkeypatch, mocker):
        """End to end through the real check_message: the message's rootfs
        size is what admission requires, as both the total and the largest
        single volume."""
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())
        capacity = _real_capacity(mocker, refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        kwargs = capacity.check_capacity.call_args.kwargs
        assert (kwargs["disk_mib"], kwargs["max_volume_mib"]) == (INSTANCE_ROOTFS_MIB, INSTANCE_ROOTFS_MIB)
        assert kwargs["exclude_vm_hash"] == _HASH

    @pytest.mark.asyncio
    async def test_admission_runs_once(self, monkeypatch):
        """The post-build re-check is gone: one message, one
        admission decision."""
        content = _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())
        capacity = _capacity(refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        assert _admissions(capacity) == [(content, _HASH)]


class TestProgramPath:
    @pytest.mark.asyncio
    async def test_refused_before_the_download(self, monkeypatch):
        _patch_message(monkeypatch, _program_content())
        build = AsyncMock()
        monkeypatch.setattr(run_module, "build_program_create_vm_spec", build)
        capacity = _capacity(refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        build.assert_not_awaited()


class TestVProgramPath:
    @pytest.mark.asyncio
    async def test_refused_before_the_bundle_fetch(self, monkeypatch):
        from test_vprogram import load_vprogram_message

        _patch_message(monkeypatch, load_vprogram_message().content)
        build = AsyncMock()
        monkeypatch.setattr(run_module, "build_vprogram_spec", build)
        capacity = _capacity(refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        build.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_admission_uses_the_instance_memory_bucket(self, monkeypatch, mocker):
        """A v-program is an SNP VM, not a Firecracker program: it is admitted
        against the instance bucket, which is also where _committed_resources
        counts it."""
        from test_vprogram import load_vprogram_message

        _patch_message(monkeypatch, load_vprogram_message().content)
        monkeypatch.setattr(run_module, "build_vprogram_spec", AsyncMock())
        capacity = _real_capacity(mocker, refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        assert [c.kwargs["is_instance"] for c in capacity.check_capacity.call_args_list] == [True]


class TestOneAdmissionOnTheHappyPath:
    """One decision per create: the pre-build admission owns disk, memory and
    vCPUs. Only GPU resolution stays after the build, so a failed download
    never consumes a GPU hold."""

    @pytest.mark.asyncio
    async def test_admission_is_asked_once_and_never_again(self, monkeypatch):
        from test_supervisor_run_routing import _info, _spec

        content = _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
        monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
        monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
        monkeypatch.setattr(run_module, "persist_record", AsyncMock())
        capacity = _capacity()
        supervisor = SimpleNamespace(
            create_vm=AsyncMock(return_value=_info()),
            get_vm=AsyncMock(return_value=_info()),
            add_port_forward=AsyncMock(),
            delete_vm=AsyncMock(),
        )

        await _create(capacity, supervisor)

        assert _admissions(capacity) == [(content, _HASH)]


class TestCreateGuard:
    """Every create path runs inside ``creating()``.

    The reconciler decides what is an orphan from the filesystem, so a create
    that stages files outside the guard can have them removed from under it
    once it outlives VOLUME_CREATE_GUARD. Admission is the first thing that
    can block for long, so the guard is taken before it: a concurrent create
    under pressure must not evict the retained directory this one is about to
    adopt.
    """

    @staticmethod
    def _capacity_watching_the_guard(seen: list[bool]):
        """An admission stub that records whether the guard is held when it
        runs, then refuses (which ends the create right there)."""
        error = InsufficientResourcesError("no room", required={}, available={})

        def check(_content, **kwargs):
            seen.append(is_creating(str(_HASH)))
            raise error

        return SimpleNamespace(check_message=MagicMock(side_effect=check), resolve_gpus=AsyncMock(return_value=[]))

    @pytest.mark.asyncio
    async def test_the_instance_path_holds_the_guard(self, monkeypatch):
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())
        seen: list[bool] = []

        with pytest.raises(InsufficientResourcesError):
            await _create(self._capacity_watching_the_guard(seen))

        assert seen == [True]
        assert not is_creating(str(_HASH))

    @pytest.mark.asyncio
    async def test_the_program_path_holds_the_guard(self, monkeypatch):
        _patch_message(monkeypatch, _program_content())
        monkeypatch.setattr(run_module, "build_program_create_vm_spec", AsyncMock())
        seen: list[bool] = []

        with pytest.raises(InsufficientResourcesError):
            await _create(self._capacity_watching_the_guard(seen))

        assert seen == [True]
        assert not is_creating(str(_HASH))

    @pytest.mark.asyncio
    async def test_the_guard_is_released_on_the_happy_path(self, monkeypatch):
        from test_supervisor_run_routing import _info, _spec

        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
        monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
        monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
        monkeypatch.setattr(run_module, "persist_record", AsyncMock())
        held: list[bool] = []

        def observe_create(spec):
            held.append(is_creating(str(_HASH)))
            return _info()

        supervisor = SimpleNamespace(
            create_vm=AsyncMock(side_effect=observe_create),
            get_vm=AsyncMock(return_value=_info()),
            add_port_forward=AsyncMock(),
            delete_vm=AsyncMock(),
        )

        await _create(_capacity(), supervisor)

        assert held == [True]
        assert not is_creating(str(_HASH))


class TestTheRecordIsTheCommitment:
    """Admission sums the registry, so a create in flight is only visible to a
    concurrent create's admission through its record. The record has to be in
    place before this create's own admission runs (its own hash is excluded
    from its own check), or two creates that only fit once both pass against
    a sum that ignores them both. The instance and V-PROGRAM paths recorded
    early already; the program path recorded after create_vm returned, which
    is exactly the window the reconciler's concurrent starts open."""

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("content", "build"),
        [
            pytest.param(_program_content, "build_program_create_vm_spec", id="program"),
            pytest.param(
                lambda: _make_qemu_instance_message(hypervisor=HypervisorType.qemu),
                "build_create_vm_spec",
                id="instance",
            ),
            pytest.param(lambda: _vprogram_content(), "build_vprogram_spec", id="vprogram"),
        ],
    )
    async def test_every_path_records_before_it_admits(self, monkeypatch, content, build):
        _patch_message(monkeypatch, content())
        monkeypatch.setattr(run_module, build, AsyncMock())
        registry = AgentVmRegistry()
        recorded_at_admission: list[bool] = []

        def refuse(*_args, **_kwargs):
            recorded_at_admission.append(registry.get(_HASH) is not None)
            raise InsufficientResourcesError("no room", required={}, available={})

        capacity = _capacity()
        capacity.check_message.side_effect = refuse

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity, registry=registry)

        assert recorded_at_admission == [True]
        # And a refused create leaves no record behind to hold capacity.
        assert registry.get(_HASH) is None


def _vprogram_content():
    from test_vprogram import load_vprogram_message

    return load_vprogram_message().content


class _PastAdmission(Exception):
    """Raised by the build stub: reaching it means admission let the create by."""


def _over_capacity_manager(mocker, registry):
    """A real CapacityManager on a node whose records already fill its bucket.

    64 GiB less the two reservations leaves a 55296 MiB instance bucket, and
    the caller records more than that, which is the state a node lands in for
    historical reasons: records made when the caps were larger, or a host that
    shrank under them. Disk is left roomy, since this is about memory.
    """
    from pathlib import Path

    from aleph.vm.agent.capacity import CapacityManager
    from aleph.vm.conf import settings

    mocker.patch.object(settings, "HOST_MEMORY_RESERVED_MIB", 2048)
    mocker.patch.object(settings, "PROGRAM_MEMORY_RESERVED_MIB", 8192)
    mocker.patch(
        "aleph.vm.agent.capacity.psutil.virtual_memory",
        return_value=mocker.Mock(total=64 * 1024 * 1024 * 1024),
    )
    mocker.patch("aleph.vm.agent.capacity.psutil.cpu_count", return_value=16)
    mocker.patch.object(CapacityManager, "_available_disk_bytes", return_value=100 * 1024 * 1024 * 1024)
    mocker.patch(
        "aleph.vm.agent.capacity.storage_pools.eligible_pool_free_bytes",
        return_value=[(SimpleNamespace(path=Path("/pool0"), index=0), 100 * 1024 * 1024 * 1024)],
    )
    mocker.patch("aleph.vm.agent.capacity.reclaimable_bytes", return_value=0)
    mocker.patch("aleph.vm.agent.capacity.existing_volume_files", return_value={})
    manager = CapacityManager(supervisor=MagicMock(), registry=registry)
    manager.resolve_gpus = AsyncMock(return_value=[])
    return manager


def _registry_holding(*hashes) -> AgentVmRegistry:
    registry = AgentVmRegistry()
    for vm_hash in hashes:
        content = _make_qemu_instance_message(memory=54_000)
        registry.record(vm_hash, message=content, original=content, persistent=True)
    return registry


class TestRebuildAdmission:
    """A rebuild reuses a reservation the node holds; a newcomer asks for one."""

    @pytest.mark.asyncio
    async def test_a_rebuild_of_a_recorded_hash_skips_the_memory_admission(self, monkeypatch):
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(side_effect=_PastAdmission))
        capacity = _capacity()

        with pytest.raises(_PastAdmission):
            await _create(capacity, registry=_registry_holding(_HASH), recreate=True)

        capacity.check_message.assert_not_called()
        assert capacity.check_recreate.call_args.kwargs["vm_hash"] == _HASH

    @pytest.mark.asyncio
    async def test_a_first_create_is_admitted_in_full_even_from_a_rebuild_caller(self, monkeypatch):
        """The flag says the caller may be rebuilding, the registry says
        whether it is. With no record there is no reservation to reuse."""
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(side_effect=_PastAdmission))
        capacity = _capacity()

        with pytest.raises(_PastAdmission):
            await _create(capacity, recreate=True)

        capacity.check_recreate.assert_not_called()
        capacity.check_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_a_caller_that_does_not_claim_a_rebuild_is_admitted_in_full(self, monkeypatch):
        """The legacy allocation route and the on-demand paths keep the full
        check whatever the registry holds."""
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(side_effect=_PastAdmission))
        capacity = _capacity()

        with pytest.raises(_PastAdmission):
            await _create(capacity, registry=_registry_holding(_HASH))

        capacity.check_recreate.assert_not_called()
        capacity.check_message.assert_called_once()

    @pytest.mark.asyncio
    async def test_a_rebuild_proceeds_on_a_node_whose_records_exceed_its_memory(self, monkeypatch, mocker):
        """The failure this is all for, against the real capacity manager. The
        node holds more than its bucket, so a crashed VM's rebuild was refused
        and #1209 kept the VM without ever building it back: one crash
        stranded it for good. Its own record is the reservation the rebuild
        uses, so nothing new is being asked for."""
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(side_effect=_PastAdmission))
        registry = _registry_holding(_HASH, ItemHash("a" * 64), ItemHash("b" * 64))

        with pytest.raises(_PastAdmission):
            await _create(_over_capacity_manager(mocker, registry), registry=registry, recreate=True)

    @pytest.mark.asyncio
    async def test_a_first_create_on_that_node_is_still_refused(self, monkeypatch, mocker):
        """The other side of it: the node really is full, and a hash it holds
        nothing for gets the honest no."""
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        build = AsyncMock(side_effect=_PastAdmission)
        monkeypatch.setattr(run_module, "build_create_vm_spec", build)
        registry = _registry_holding(ItemHash("a" * 64), ItemHash("b" * 64))

        with pytest.raises(InsufficientResourcesError):
            await _create(_over_capacity_manager(mocker, registry), registry=registry, recreate=True)

        build.assert_not_awaited()
