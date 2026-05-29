"""Reusable conformance checks any Supervisor implementation must pass.

Subclass SupervisorContractTests in a test module and implement the
`supervisor` fixture. Reused for the gRPC client in 0.D. This module is not
collected directly (its class name does not start with Test).
"""

import inspect
from pathlib import Path

import pytest

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import NotImplementedSupervisorError

STUB_METHODS = {
    "create_vm",
    "start_backup",
    "get_backup_status",
    "list_backups",
    "download_backup",
    "delete_backup",
    "restore_backup",
    "export_vm",
    "import_vm",
    "get_migration_status",
    "initialize_confidential",
    "get_measurement",
    "inject_secret",
}


class SupervisorContractTests:
    """Mix in and provide a `supervisor` fixture returning a Supervisor."""

    @pytest.fixture
    def supervisor(self) -> Supervisor:
        raise NotImplementedError

    def test_is_a_supervisor(self, supervisor):
        assert isinstance(supervisor, Supervisor)

    def test_implements_all_abstract_methods(self, supervisor):
        # A concrete instance exists, so abstractmethods are all overridden.
        assert type(supervisor).__abstractmethods__ == frozenset()

    @pytest.mark.asyncio
    async def test_stub_methods_raise_not_implemented(self, supervisor):
        if "create_vm" in STUB_METHODS:
            from aleph.vm.supervisor.types import (
                Backend,
                CreateVmSpec,
                NetworkConfig,
                VmId,
            )

            spec = CreateVmSpec(
                vm_id=VmId("x"),
                backend=Backend.QEMU,
                kernel_path=Path(""),
                initrd_path=Path(""),
                disks=[],
                vcpus=1,
                memory_mib=512,
                tee=None,
                network=NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
                gpus=[],
                numa_node=None,
                persistent=True,
            )
            with pytest.raises(NotImplementedSupervisorError):
                await supervisor.create_vm(spec)

    def test_streaming_methods_return_async_iterators(self, supervisor):
        for name in ("stream_logs", "download_backup"):
            method = getattr(supervisor, name)
            # async generator function, not a plain coroutine
            assert not inspect.iscoroutinefunction(method) or inspect.isasyncgenfunction(method)
