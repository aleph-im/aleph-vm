import inspect

import pytest

from aleph.vm.supervisor_interface.abc import (
    ConfidentialOps,
    EventsOps,
    HostOps,
    LifecycleOps,
    LogsOps,
    NetworkOps,
    PortForwardingOps,
    QuiesceOps,
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
    "stop_vm",
    "start_vm",
    "reboot_vm",
    "run_program_code",
    "watch_events",
    "add_port_forward",
    "remove_port_forward",
    "list_port_forwards",
    "get_logs",
    "stream_logs",
    "freeze_guest",
    "thaw_guest",
    "initialize_confidential",
    "get_measurement",
    "inject_secret",
    "recreate_network",
}

STREAMING_METHODS = {"stream_logs", "watch_events"}


def test_supervisor_aggregates_all_23_methods():
    abstract = Supervisor.__abstractmethods__
    assert abstract == EXPECTED_METHODS
    assert len(EXPECTED_METHODS) == 23


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
        LifecycleOps: {
            "create_vm",
            "get_vm",
            "get_vm_spec",
            "list_vms",
            "delete_vm",
            "stop_vm",
            "start_vm",
            "reboot_vm",
            "run_program_code",
        },
        PortForwardingOps: {"add_port_forward", "remove_port_forward", "list_port_forwards"},
        EventsOps: {"watch_events"},
        LogsOps: {"get_logs", "stream_logs"},
        QuiesceOps: {"freeze_guest", "thaw_guest"},
        ConfidentialOps: {"initialize_confidential", "get_measurement", "inject_secret"},
        NetworkOps: {"recreate_network"},
    }
    for abc_cls, names in by_abc.items():
        assert names <= abc_cls.__abstractmethods__
