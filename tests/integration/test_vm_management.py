"""Use case 2: managing a running VM (logs, stop/start, reboot, lifecycle
events and port forwards)."""

from __future__ import annotations

import asyncio

import pytest
from conftest import (
    assert_controller_matches_impl,
    default_route_interface,
    eventually,
    fc_program_spec,
    fresh_vm_id,
    make_qemu_rootfs,
    nftables_dnat_rules,
    nftables_ruleset,
    qemu_instance_spec,
    requires_fc,
    requires_qemu,
    requires_root,
    vm_processes,
    wait_for_tcp_banner,
)

from aleph.vm.supervisor_interface.types import (
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
async def test_watch_events_streams_full_lifecycle_to_all_subscribers(supervisor):
    """create, reboot (a down-then-up pair) and delete must each reach the
    stream, and every subscriber sees the same fan-out."""
    vm_id = fresh_vm_id()
    expected_transitions = [
        (VmStatus.DEFINED, VmStatus.RUNNING),  # create
        (VmStatus.RUNNING, VmStatus.STOPPED),  # reboot, down
        (VmStatus.STOPPED, VmStatus.RUNNING),  # reboot, up
        (VmStatus.RUNNING, VmStatus.STOPPED),  # delete
    ]

    async def consume(events: list, done: asyncio.Event):
        async for event in supervisor.watch_events():
            if event.vm_id != vm_id:
                continue
            events.append(event)
            if len(events) == len(expected_transitions):
                done.set()
                return

    streams: list[tuple[list, asyncio.Event]] = [([], asyncio.Event()) for _ in range(2)]
    consumers = [asyncio.ensure_future(consume(events, done)) for events, done in streams]
    await asyncio.sleep(0.5)  # let the streams subscribe server-side

    await supervisor.create_vm(fc_program_spec(vm_id))
    await supervisor.reboot_vm(vm_id)
    await supervisor.delete_vm(vm_id)
    for _events, done in streams:
        await asyncio.wait_for(done.wait(), timeout=30)
    for consumer in consumers:
        consumer.cancel()
    await asyncio.gather(*consumers, return_exceptions=True)

    for events, _done in streams:
        assert [(e.old_status, e.new_status) for e in events] == expected_transitions
        timestamps = [e.timestamp_ns for e in events]
        assert timestamps == sorted(timestamps)


@requires_root
@requires_fc
@pytest.mark.parametrize("protocol", [Protocol.TCP, Protocol.UDP])
async def test_port_forwards_round_trip(supervisor, protocol):
    vm_id = fresh_vm_id()
    await supervisor.create_vm(fc_program_spec(vm_id, internet=True))
    try:
        info = await supervisor.add_port_forward(
            PortForwardSpec(vm_id=vm_id, host_port=HostPort(0), vm_port=GuestPort(8080), protocol=protocol)
        )
        assert info.host_port > 0
        assert info.vm_port == 8080

        listed = await supervisor.list_port_forwards(vm_id)
        assert [(f.vm_port, f.host_port, f.protocol) for f in listed] == [(8080, info.host_port, protocol)]
        # The redirect actually landed in the host firewall.
        assert str(info.host_port) in nftables_ruleset()

        await supervisor.remove_port_forward(vm_id, info.host_port, protocol)
        assert await supervisor.list_port_forwards(vm_id) == []
    finally:
        await supervisor.delete_vm(vm_id)


async def test_get_host_info_reports_the_machine(supervisor):
    info = await supervisor.get_host_info()
    assert info.cpu_count >= 1
    assert info.memory_mib > 0
    # cpu_architecture/vendor/model are best-effort (empty on some cloud
    # hosts, e.g. GitHub's Azure runners); only assert what every host has.
    assert info.kernel_version
    assert info.hostname


@requires_qemu
async def test_qemu_stop_start_reboot_cycle(supervisor, daemon, ssh_keypair):
    """One boot, the whole persistent lifecycle: stop keeps the VM defined,
    start brings it back, reboot restarts it; the guest is reachable after
    each transition and every transition reaches the event stream."""
    _, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
    info = await supervisor.create_vm(spec)

    # Both daemons serve WatchEvents since increment 4 of the Rust port: the
    # event assertions run on both matrix legs.
    events: list = []

    async def consume():
        async for event in supervisor.watch_events():
            if event.vm_id == vm_id:
                events.append((event.old_status, event.new_status))

    consumer = asyncio.ensure_future(consume())
    # No subscription ack exists in the proto (WatchEvents has no replay),
    # so a sleep is the only way to let the stream subscribe server-side
    # before the first mutation; a too-short sleep loses events (flake risk).
    await asyncio.sleep(0.5)
    try:
        await wait_for_tcp_banner(info.ipv4.address, 22)
        # The persistent QEMU launch runs through the selected controller
        # implementation (task A3: under impl=rust this is the Rust binary).
        assert_controller_matches_impl(vm_id)

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

        # Persistent transitions are observable: stop, start, reboot pair.
        await eventually(lambda: len(events) >= 4, timeout=10, message=f"missing lifecycle events: {events}")
        assert events == [
            (VmStatus.RUNNING, VmStatus.STOPPED),  # stop_vm
            (VmStatus.STOPPED, VmStatus.RUNNING),  # start_vm
            (VmStatus.RUNNING, VmStatus.STOPPED),  # reboot, down
            (VmStatus.STOPPED, VmStatus.RUNNING),  # reboot, up
        ]
    finally:
        consumer.cancel()
        await asyncio.gather(consumer, return_exceptions=True)
        await supervisor.delete_vm(vm_id)


@requires_qemu
async def test_qemu_port_forward_lands_in_the_host_firewall(supervisor, daemon, ssh_keypair):
    """AddPortForward on a running QEMU VM must install a real DNAT rule
    (visible in `nft list ruleset`) pointing at the guest, and
    RemovePortForward must take it out again. Runs on both matrix legs."""
    _, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
    info = await supervisor.create_vm(spec)
    try:
        await wait_for_tcp_banner(info.ipv4.address, 22)

        forward = await supervisor.add_port_forward(
            PortForwardSpec(vm_id=vm_id, host_port=HostPort(0), vm_port=GuestPort(22), protocol=Protocol.TCP)
        )
        assert forward.vm_port == 22
        # The rule matches ingress on the host's external interface
        # (iifname == NETWORK_INTERFACE), so no single-host probe can
        # traverse it: locally generated traffic takes the OUTPUT hook and
        # never reaches the PREROUTING chain, whatever address it targets.
        # Assert the full rule structure against the live kernel instead;
        # end-to-end traffic through the redirect is exercised externally by
        # the aleph-testnets upgrade checks, whose client connects through
        # the node's public interface.
        rules = nftables_dnat_rules(forward.host_port)
        assert rules, "DNAT rule missing from the host firewall"
        (rule,) = rules
        expr = rule["expr"]
        iif_values = [
            match["match"]["right"]
            for match in expr
            if match.get("match", {}).get("left", {}).get("meta", {}).get("key") == "iifname"
        ]
        assert iif_values == [default_route_interface()]
        dnat = next(step["dnat"] for step in expr if "dnat" in step)
        assert (dnat["addr"], dnat["port"]) == (info.ipv4.address, 22)

        await supervisor.remove_port_forward(vm_id, forward.host_port, Protocol.TCP)
        assert not nftables_dnat_rules(forward.host_port), "the DNAT rule survived RemovePortForward"
        assert await supervisor.list_port_forwards(vm_id) == []
    finally:
        await supervisor.delete_vm(vm_id)


@requires_qemu
async def test_recreate_network_keeps_a_running_vm_reachable(supervisor, daemon, ssh_keypair):
    """RecreateNetwork flushes and rebuilds every aleph chain; a running VM
    must stay reachable afterwards and its port forwards must survive."""
    _, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
    info = await supervisor.create_vm(spec)
    try:
        await wait_for_tcp_banner(info.ipv4.address, 22)
        forward = await supervisor.add_port_forward(
            PortForwardSpec(vm_id=vm_id, host_port=HostPort(0), vm_port=GuestPort(22), protocol=Protocol.TCP)
        )

        summary = await supervisor.recreate_network()
        assert summary["success"] is True
        assert vm_id in summary["recreated_vms"]

        # The guest survived the flush-and-rebuild and the persisted
        # redirect was reapplied.
        await wait_for_tcp_banner(info.ipv4.address, 22, timeout=60)
        ruleset = nftables_ruleset()
        dport = f"tcp dport {forward.host_port} "
        dnat_target = f"to {info.ipv4.address}:22"
        assert [
            line for line in ruleset.splitlines() if dport in line and dnat_target in line
        ], f"the redirect vanished after RecreateNetwork:\n{ruleset}"
        listed = await supervisor.list_port_forwards(vm_id)
        assert [(f.vm_port, f.host_port) for f in listed] == [(22, forward.host_port)]
    finally:
        await supervisor.delete_vm(vm_id)
