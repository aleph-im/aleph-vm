"""Conformance for the Rust daemon's increment 4 stream surface, restricted
to what runs without root or KVM: WatchEvents shapes (fan-out, no replay,
Python's emission points for the unprivileged mutations), StreamLogs
end-of-stream semantics for unknown VMs, RunProgramCode's error vocabulary,
and the ephemeral Firecracker create rejection paths (all raised before any
boot side effect).

The oracle was the Python daemon (removed in 2026-08): its
``LocalSupervisor.watch_events`` / ``_emit_event`` and ``stream_logs``, the
pool's Firecracker create path plus ``SpecProgramResources.from_spec`` for
the rejections, and ``run_program_code`` for the program gates. The
expectations below are that behaviour, frozen; a deliberate change on the
Rust side updates them and the divergence registry together.
"""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

import pytest
from conftest import cargo_missing

# Reuse the seeded lifecycle world (two stopped adopted VMs).
from test_rust_daemon_lifecycle import STOPPED_HASH, _seed_root

from aleph.vm.supervisor_interface.client import GrpcSupervisor
from aleph.vm.supervisor_interface.errors import (
    InsufficientResourcesError,
    InvalidBackendError,
    VmNotFoundError,
)
from aleph.vm.supervisor_interface.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    GuestChannelSpec,
    NetworkConfig,
    VmId,
    VmStatus,
)

pytestmark = [
    pytest.mark.skipif(
        os.environ.get("ALEPH_VM_CONFORMANCE") != "1",
        reason="conformance suite is opt-in: set ALEPH_VM_CONFORMANCE=1",
    ),
    pytest.mark.skipif(cargo_missing(), reason="cargo is not on PATH"),
]

UNKNOWN_HASH = "2" * 64


def _fc_spec(vm_id: str, **overrides) -> CreateVmSpec:
    base: dict = {
        "vm_id": VmId(vm_id),
        "backend": Backend.FIRECRACKER,
        "kernel_path": Path("/opt/firecracker/vmlinux.bin"),
        "initrd_path": Path(""),
        "disks": [
            DiskSpec(
                path=Path("/tmp/runtime.squashfs"),
                readonly=True,
                format=DiskFormat.SQUASHFS,
                role=DiskRole.ROOTFS,
            )
        ],
        "vcpus": 1,
        "memory_mib": 128,
        "tee": None,
        "network": NetworkConfig(internet_access=False, requested_ipv6="", ipv6_prefix_len=0),
        "gpus": [],
        "numa_node": None,
        "persistent": False,
        "guest_channel": GuestChannelSpec(ready_port=52, ready_timeout_secs=1),
    }
    base.update(overrides)
    return CreateVmSpec(**base)


@pytest.fixture
def streams_daemon(start_daemon, execution_root: Path):
    _seed_root(execution_root)
    with start_daemon(execution_root, {"ALEPH_VM_ALLOW_VM_NETWORKING": "false"}) as (process, socket_path):
        yield execution_root, socket_path


@pytest.mark.asyncio
async def test_watch_events_fan_out_python_emission_points_no_replay(streams_daemon):
    """Two subscribers see the same events, in order, with monotone
    timestamps; a subscriber joining after the fact sees nothing (no
    replay). The unprivileged emission points: StopVm on an adopted stopped
    VM is the Python idempotent (STOPPED, STOPPED) pair, DeleteVm the
    (STOPPED, STOPPED) down transition."""
    _, socket_path = streams_daemon
    watcher_a, watcher_b, actor = GrpcSupervisor(socket_path), GrpcSupervisor(socket_path), GrpcSupervisor(socket_path)
    expected = [
        (VmStatus.STOPPED, VmStatus.STOPPED),  # idempotent stop
        (VmStatus.STOPPED, VmStatus.STOPPED),  # delete
    ]

    async def consume(client) -> list:
        events = []
        async for event in client.watch_events():
            if event.vm_id != STOPPED_HASH:
                continue
            events.append(event)
            if len(events) == len(expected):
                return events
        return events

    try:
        consumers = [asyncio.ensure_future(consume(watcher_a)), asyncio.ensure_future(consume(watcher_b))]
        # No subscription ack exists in the proto (WatchEvents deliberately
        # has no replay), so a sleep is the only readiness signal available;
        # a subscription racing the mutations below would lose events (known
        # flake risk, shared with the integration-tier copy of this pattern).
        await asyncio.sleep(0.5)

        info = await actor.stop_vm(VmId(STOPPED_HASH))
        assert info.status is VmStatus.STOPPED
        await actor.delete_vm(VmId(STOPPED_HASH))

        for consumer in consumers:
            events = await asyncio.wait_for(consumer, timeout=15)
            assert [(e.old_status, e.new_status) for e in events] == expected
            timestamps = [e.timestamp_ns for e in events]
            assert timestamps == sorted(timestamps)
            assert all(t > 0 for t in timestamps)

        # No replay: a late subscriber sees nothing of the above.
        late_stream = watcher_a.watch_events()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(anext(late_stream), timeout=1.0)
        await late_stream.aclose()
    finally:
        for client in (watcher_a, watcher_b, actor):
            await client.close()


@pytest.mark.asyncio
async def test_stream_logs_for_unknown_vms_ends_instead_of_erroring(streams_daemon):
    """Python's stream_logs: the live phase requires a tracked execution, so
    an unknown (or deleted) VM's stream simply ends; include_history=True
    still serves whatever journald holds (nothing here)."""
    _, socket_path = streams_daemon
    client = GrpcSupervisor(socket_path)
    try:
        chunks = [chunk async for chunk in client.stream_logs(VmId(UNKNOWN_HASH), include_history=False)]
        assert chunks == []
        chunks = [chunk async for chunk in client.stream_logs(VmId(UNKNOWN_HASH), include_history=True)]
        assert chunks == []
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_run_program_code_error_vocabulary(streams_daemon):
    _, socket_path = streams_daemon
    client = GrpcSupervisor(socket_path)
    try:
        # Unknown VM: NOT_FOUND, message = the vm_id itself.
        with pytest.raises(VmNotFoundError) as excinfo:
            await client.run_program_code(VmId(UNKNOWN_HASH), {"path": "/"}, timeout=5.0)
        assert str(excinfo.value) == UNKNOWN_HASH

        # A QEMU VM is not a program (the Python InvalidBackendError text).
        with pytest.raises(InvalidBackendError) as excinfo:
            await client.run_program_code(VmId(STOPPED_HASH), {"path": "/"}, timeout=5.0)
        assert str(excinfo.value) == f"VM {STOPPED_HASH} is not a program; code can only be run on programs"
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_ephemeral_create_rejections_have_zero_side_effects(streams_daemon):
    """The FC create rejection paths run before any boot side effect, so
    they are exercisable without KVM: the guest-channel requirement, the
    memory backstop (before the prepare validations), the kernel and rootfs
    checks of SpecProgramResources.from_spec, all with the Python texts."""
    root, socket_path = streams_daemon
    client = GrpcSupervisor(socket_path)
    try:
        with pytest.raises(InvalidBackendError) as excinfo:
            await client.create_vm(_fc_spec(UNKNOWN_HASH, guest_channel=None))
        assert str(excinfo.value) == "Firecracker spec VMs require a guest_channel"

        with pytest.raises(InsufficientResourcesError) as excinfo:
            await client.create_vm(_fc_spec(UNKNOWN_HASH, memory_mib=2**60))
        assert str(excinfo.value).startswith("Insufficient memory to create VM: required")

        with pytest.raises(InvalidBackendError) as excinfo:
            await client.create_vm(_fc_spec(UNKNOWN_HASH, kernel_path=Path("")))
        assert str(excinfo.value) == "A Firecracker spec requires a kernel_path"

        with pytest.raises(InvalidBackendError) as excinfo:
            await client.create_vm(_fc_spec(UNKNOWN_HASH, disks=[]))
        assert str(excinfo.value) == "CreateVmSpec has no ROOTFS disk"

        # Zero side effects: the rejected VM does not exist, nothing landed
        # on disk, and no events leaked (a failed create emits nothing).
        with pytest.raises(VmNotFoundError):
            await client.get_vm(VmId(UNKNOWN_HASH))
        assert not (root / f"{UNKNOWN_HASH}-controller.json").exists()
    finally:
        await client.close()
