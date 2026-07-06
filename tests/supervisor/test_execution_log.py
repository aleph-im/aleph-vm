"""VmExecution.record_usage: supervisor-side stop bookkeeping.

Pins the two things record_usage does on the stop path: dump the execution
state to the execution-log directory (diagnostics, EXECUTION_LOG_ENABLED)
and drop the persisted port mappings of non-persistent VMs. The agent's own
usage records (ExecutionRecord rows) are written agent-side by
aleph.vm.agent.vm_registry.persist_record and are not involved here.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from aleph.vm.conf import settings
from aleph.vm.models import VmExecution
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
)

_HASH = "deadbeef" * 8


def _spec(persistent: bool = True) -> CreateVmSpec:
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
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=persistent,
    )


@pytest.mark.asyncio
async def test_record_usage_dumps_execution_log_when_enabled(mocker, tmp_path):
    mocker.patch.object(settings, "EXECUTION_LOG_ENABLED", True)
    mocker.patch.object(settings, "EXECUTION_LOG_DIRECTORY", tmp_path / "executions")
    execution = VmExecution.from_spec(_spec(persistent=True), systemd_manager=None)

    await execution.record_usage()

    log_file = tmp_path / "executions" / f"{execution.uuid}.json"
    assert log_file.is_file()
    dumped = json.loads(log_file.read_text())
    assert dumped["vm_id"] == _HASH
    assert dumped["spec"]["vcpus"] == 2


@pytest.mark.asyncio
async def test_record_usage_no_dump_when_disabled(mocker, tmp_path):
    mocker.patch.object(settings, "EXECUTION_LOG_ENABLED", False)
    mocker.patch.object(settings, "EXECUTION_LOG_DIRECTORY", tmp_path / "executions")
    execution = VmExecution.from_spec(_spec(persistent=True), systemd_manager=None)

    await execution.record_usage()

    assert not (tmp_path / "executions").exists()


@pytest.mark.asyncio
async def test_record_usage_drops_port_mappings_of_non_persistent_vms(mocker, tmp_path):
    mocker.patch.object(settings, "EXECUTION_LOG_ENABLED", False)
    delete_mappings = mocker.patch("aleph.vm.models.delete_port_mappings", new_callable=AsyncMock)

    non_persistent = VmExecution.from_spec(_spec(persistent=False), systemd_manager=None)
    await non_persistent.record_usage()
    delete_mappings.assert_awaited_once_with(non_persistent.vm_id)

    delete_mappings.reset_mock()
    persistent = VmExecution.from_spec(_spec(persistent=True), systemd_manager=None)
    await persistent.record_usage()
    delete_mappings.assert_not_awaited()
