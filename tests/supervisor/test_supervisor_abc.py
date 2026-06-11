import inspect

import pytest

from aleph.vm.supervisor.abc import (
    BackupOps,
    ConfidentialOps,
    HostOps,
    LifecycleOps,
    LogsOps,
    MigrationOps,
    PortForwardingOps,
    Supervisor,
)

EXPECTED_METHODS = {
    "health",
    "get_host_info",
    "create_vm",
    "get_vm",
    "get_vm_spec",
    "list_vms",
    "delete_vm",
    "reboot_vm",
    "reinstall_vm",
    "add_port_forward",
    "remove_port_forward",
    "list_port_forwards",
    "get_logs",
    "stream_logs",
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

STREAMING_METHODS = {"stream_logs", "download_backup"}


def test_supervisor_aggregates_all_26_methods():
    abstract = Supervisor.__abstractmethods__
    assert abstract == EXPECTED_METHODS
    assert len(EXPECTED_METHODS) == 26


def test_supervisor_cannot_be_instantiated():
    with pytest.raises(TypeError):
        Supervisor()  # type: ignore[abstract]


def test_all_boundary_methods_are_coroutines():
    for name in EXPECTED_METHODS - STREAMING_METHODS:
        method = getattr(Supervisor, name)
        assert inspect.iscoroutinefunction(method), f"{name} must be async"
    for name in STREAMING_METHODS:
        method = getattr(Supervisor, name)
        assert not inspect.iscoroutinefunction(method), f"{name} returns an async iterator, not a coroutine"


def test_capability_abcs_partition_the_surface():
    by_abc = {
        HostOps: {"health", "get_host_info"},
        LifecycleOps: {"create_vm", "get_vm", "get_vm_spec", "list_vms", "delete_vm", "reboot_vm", "reinstall_vm"},
        PortForwardingOps: {"add_port_forward", "remove_port_forward", "list_port_forwards"},
        LogsOps: {"get_logs", "stream_logs"},
        BackupOps: {
            "start_backup",
            "get_backup_status",
            "list_backups",
            "download_backup",
            "delete_backup",
            "restore_backup",
        },
        MigrationOps: {"export_vm", "import_vm", "get_migration_status"},
        ConfidentialOps: {"initialize_confidential", "get_measurement", "inject_secret"},
    }
    for abc_cls, names in by_abc.items():
        assert names <= abc_cls.__abstractmethods__
