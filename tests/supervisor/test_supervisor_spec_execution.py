"""Tests for VmExecution spec-constructible path (message-free)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash
from aleph_message.models.execution.environment import HypervisorType

from aleph.vm.controllers.qemu.instance import AlephQemuInstance, AlephQemuResources
from aleph.vm.models import VmExecution
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def make_spec(*, internet: bool = True, vcpus: int = 4, memory_mib: int = 2048) -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(_HASH),
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
        vcpus=vcpus,
        memory_mib=memory_mib,
        tee=None,
        network=NetworkConfig(internet_access=internet, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def test_spec_properties_for_qemu_instance():
    execution = VmExecution.from_spec(make_spec(), snapshot_manager=None, systemd_manager=None)

    assert execution.is_instance is True
    assert execution.is_program is False
    assert execution.is_confidential is False
    assert execution.hypervisor is HypervisorType.qemu
    # Payment flags are agent-side; absent without a message.
    assert execution.uses_payment_stream is False
    assert execution.uses_payment_credit is False


def test_from_spec_sets_spec_and_no_message():
    execution = VmExecution.from_spec(make_spec(), snapshot_manager=None, systemd_manager=None)

    assert execution.spec is not None
    assert execution.message is None
    assert execution.original is None
    assert execution.vm_hash == ItemHash(_HASH)
    assert execution.persistent is True
    assert execution.resources is None
    assert execution.vm is None


@pytest.mark.asyncio
async def test_prepare_builds_resources_without_download(monkeypatch):
    execution = VmExecution.from_spec(make_spec(), snapshot_manager=None, systemd_manager=None)

    # download_all must never be called on the spec path.
    called = {"download": False}

    async def fail_download(_self):  # type: ignore[no-untyped-def]
        called["download"] = True

    monkeypatch.setattr(AlephQemuResources, "download_all", fail_download)

    await execution.prepare()

    assert called["download"] is False
    assert isinstance(execution.resources, AlephQemuResources)
    assert execution.resources.rootfs_path == Path("/data/rootfs.qcow2")
    assert execution.times.prepared_at is not None


@pytest.mark.asyncio
async def test_create_builds_qemu_instance_from_spec():
    execution = VmExecution.from_spec(
        make_spec(internet=False, vcpus=3, memory_mib=1024),
        snapshot_manager=None,
        systemd_manager=None,
    )
    await execution.prepare()

    vm = execution.create(vm_id=7, tap_interface=None)

    assert isinstance(vm, AlephQemuInstance)
    assert vm.vm_id == 7
    assert vm.hardware_resources.vcpus == 3
    assert vm.hardware_resources.memory == 1024
    assert vm.enable_networking is False


@pytest.mark.asyncio
async def test_start_skips_configure_and_save_for_spec(monkeypatch):
    systemd = MagicMock()
    systemd.enable_and_start = AsyncMock()
    execution = VmExecution.from_spec(make_spec(internet=False), snapshot_manager=None, systemd_manager=systemd)
    await execution.prepare()
    execution.create(vm_id=7, tap_interface=None)

    # configure() is message-coupled (cloud-init reads resources.message_content)
    # and must NOT be called on the spec path.
    execution.vm.configure = AsyncMock()
    execution.vm.setup = AsyncMock()
    execution.vm.start_guest_api = AsyncMock()
    # Controller comes up immediately.
    monkeypatch.setattr(VmExecution, "non_blocking_wait_for_boot", AsyncMock(return_value=True))
    save_record = AsyncMock()
    monkeypatch.setattr("aleph.vm.models.save_record", save_record)

    await execution.start(write_config=False)

    execution.vm.configure.assert_not_awaited()
    systemd.enable_and_start.assert_awaited_once_with(execution.controller_service)
    save_record.assert_not_awaited()  # spec path keeps no DB record
    assert execution.ready_event.is_set()


def test_start_watching_for_updates_is_noop_without_message():
    # A message-free (spec-built / reattached) execution has no Aleph message to
    # watch; start_watching_for_updates must no-op, not schedule a task that
    # would crash on `self.original` being None.
    execution = VmExecution.from_spec(make_spec(), snapshot_manager=None, systemd_manager=None)

    execution.start_watching_for_updates(pubsub=object())  # type: ignore[arg-type]

    assert execution.update_task is None
