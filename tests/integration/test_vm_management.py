"""Use case 2: managing a running VM — logs, stop/start, reboot, lifecycle
events and port forwards."""

from __future__ import annotations

import asyncio

import pytest
from conftest import (
    eventually,
    fc_program_spec,
    fresh_vm_id,
    make_qemu_rootfs,
    nftables_ruleset,
    qemu_instance_spec,
    requires_fc,
    requires_qemu,
    requires_root,
    vm_processes,
    wait_for_tcp_banner,
)

from aleph.vm.supervisor.types import (
    GuestPort,
    HostPort,
    PortForwardSpec,
    Protocol,
    VmStatus,
)

pytestmark = pytest.mark.asyncio


@requires_fc
async def test_get_logs_returns_guest_console_output(supervisor):
    vm_id = fresh_vm_id()
    await supervisor.create_vm(fc_program_spec(vm_id))
    try:
        # Console output reaches journald asynchronously; poll briefly.
        chunks = await eventually(
            lambda: supervisor.get_logs(vm_id),
            timeout=30,
            message="no guest console output in journald",
        )
        assert all(chunk.line for chunk in chunks)
        assert all(chunk.timestamp_ns > 0 for chunk in chunks)

        # The streaming surface serves the same history.
        streamed = []
        stream = supervisor.stream_logs(vm_id, include_history=True)
        async for chunk in stream:
            streamed.append(chunk.line)
            if len(streamed) >= min(3, len(chunks)):
                break
        await stream.aclose()
        assert streamed == [chunk.line for chunk in chunks[: len(streamed)]]
    finally:
        await supervisor.delete_vm(vm_id)


@requires_fc
async def test_firecracker_reboot_comes_back_ready(supervisor):
    """Ephemeral spec-built VMs reboot by recreation from the held spec."""
    vm_id = fresh_vm_id()
    first = await supervisor.create_vm(fc_program_spec(vm_id))
    try:
        rebooted = await supervisor.reboot_vm(vm_id)
        assert rebooted.status is VmStatus.RUNNING
        assert rebooted.guest_ready_payload, "the recreated guest must signal ready again"
        assert rebooted.started_at_ns >= first.started_at_ns
        assert (await supervisor.get_vm(vm_id)).status is VmStatus.RUNNING
    finally:
        await supervisor.delete_vm(vm_id)


@requires_fc
async def test_watch_events_streams_create_and_delete(supervisor):
    vm_id = fresh_vm_id()
    events = []
    got_two = asyncio.Event()

    async def consume():
        async for event in supervisor.watch_events():
            if event.vm_id != vm_id:
                continue
            events.append(event)
            if len(events) == 2:
                got_two.set()
                return

    consumer = asyncio.ensure_future(consume())
    await asyncio.sleep(0.5)  # let the stream subscribe server-side

    await supervisor.create_vm(fc_program_spec(vm_id))
    await supervisor.delete_vm(vm_id)
    await asyncio.wait_for(got_two.wait(), timeout=30)
    consumer.cancel()
    await asyncio.gather(consumer, return_exceptions=True)

    assert [(e.old_status, e.new_status) for e in events] == [
        (VmStatus.DEFINED, VmStatus.RUNNING),
        (VmStatus.RUNNING, VmStatus.STOPPED),
    ]
    assert events[0].timestamp_ns <= events[1].timestamp_ns


@requires_root
@requires_fc
async def test_port_forwards_round_trip(supervisor):
    vm_id = fresh_vm_id()
    await supervisor.create_vm(fc_program_spec(vm_id, internet=True))
    try:
        info = await supervisor.add_port_forward(
            PortForwardSpec(vm_id=vm_id, host_port=HostPort(0), vm_port=GuestPort(8080), protocol=Protocol.TCP)
        )
        assert info.host_port > 0
        assert info.vm_port == 8080

        listed = await supervisor.list_port_forwards(vm_id)
        assert [(f.vm_port, f.host_port, f.protocol) for f in listed] == [(8080, info.host_port, Protocol.TCP)]
        # The redirect actually landed in the host firewall.
        assert str(info.host_port) in nftables_ruleset()

        await supervisor.remove_port_forward(vm_id, info.host_port, Protocol.TCP)
        assert await supervisor.list_port_forwards(vm_id) == []
    finally:
        await supervisor.delete_vm(vm_id)


@requires_qemu
async def test_qemu_stop_start_reboot_cycle(supervisor, daemon, ssh_keypair):
    """One boot, the whole persistent lifecycle: stop keeps the VM defined,
    start brings it back, reboot restarts it; the guest is reachable after
    each transition."""
    _, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
    info = await supervisor.create_vm(spec)
    try:
        await wait_for_tcp_banner(info.ipv4.address, 22)

        stopped = await supervisor.stop_vm(vm_id)
        assert stopped.status is VmStatus.STOPPED
        await eventually(
            lambda: not vm_processes(vm_id),
            timeout=60,
            message="qemu process still alive after stop_vm",
        )
        # Stopped, not deleted: the VM stays listed.
        assert vm_id in [v.vm_id for v in await supervisor.list_vms()]

        started = await supervisor.start_vm(vm_id)
        assert started.status is VmStatus.RUNNING
        assert started.ipv4.address
        await wait_for_tcp_banner(started.ipv4.address, 22)

        rebooted = await supervisor.reboot_vm(vm_id)
        assert rebooted.status is VmStatus.RUNNING
        await wait_for_tcp_banner(rebooted.ipv4.address, 22)
    finally:
        await supervisor.delete_vm(vm_id)
