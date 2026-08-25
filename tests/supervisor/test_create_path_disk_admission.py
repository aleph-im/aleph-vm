"""Capacity admission runs before the download, and it accounts for disk.

Every create path called check_capacity with disk_mib=0, so neither the total
disk requirement nor the largest-single-volume check ran: only the reserve
endpoint ever judged disk. Filling the number in at the old call site would
have been theatre, because that call sits *after* build_*_spec, which
downloads the resources and creates the volume files: by then the space is
already allocated and requiring it again would double-count it.

So the admission gate moves ahead of the build, where refusing still saves the
download, and the post-build call keeps disk_mib=0 as the memory/vCPU re-check
and the GPU resolution point.
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
    with no room left."""
    error = InsufficientResourcesError("no room", required={}, available={})
    return SimpleNamespace(
        check_capacity=MagicMock(side_effect=error if refuse else None),
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


async def _create(capacity, supervisor=None):
    await run_module.create_vm_execution(
        _HASH,
        supervisor=supervisor or _supervisor(),
        registry=AgentVmRegistry(),
        capacity=capacity,
        persistent=True,
    )


def _disk_args(capacity):
    """(disk_mib, max_volume_mib) of every check_capacity call."""
    return [
        (c.kwargs.get("disk_mib"), c.kwargs.get("max_volume_mib", 0)) for c in capacity.check_capacity.call_args_list
    ]


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
    async def test_admission_carries_the_declared_disk(self, monkeypatch):
        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
        monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())
        capacity = _capacity(refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        assert _disk_args(capacity) == [(INSTANCE_ROOTFS_MIB, INSTANCE_ROOTFS_MIB)]


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
    async def test_admission_uses_the_instance_memory_bucket(self, monkeypatch):
        """A v-program is an SNP VM, not a Firecracker program: it is admitted
        against the instance bucket, as the pre-existing post-build check
        already did. requirements_from_message alone would say otherwise, since
        VerifiableProgramContent is not an InstanceContent."""
        from test_vprogram import load_vprogram_message

        _patch_message(monkeypatch, load_vprogram_message().content)
        monkeypatch.setattr(run_module, "build_vprogram_spec", AsyncMock())
        capacity = _capacity(refuse=True)

        with pytest.raises(InsufficientResourcesError):
            await _create(capacity)

        assert [c.kwargs["is_instance"] for c in capacity.check_capacity.call_args_list] == [True]


class TestBothChecksOnTheHappyPath:
    """The two checks are a contract, not a duplicate: the pre-build one owns
    disk, the post-build one re-checks memory and vCPUs (and is where GPU holds
    are resolved) without re-requiring space this VM has already taken."""

    @pytest.mark.asyncio
    async def test_disk_is_required_once_before_the_build_and_never_again(self, monkeypatch):
        from test_supervisor_run_routing import _info, _spec

        _patch_message(monkeypatch, _make_qemu_instance_message(hypervisor=HypervisorType.qemu))
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

        assert _disk_args(capacity) == [(INSTANCE_ROOTFS_MIB, INSTANCE_ROOTFS_MIB), (0, 0)]
