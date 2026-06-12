"""Use case 1: creating a VM works and the guest is reachable from the host.

Firecracker: reachability is the vsock guest channel (the guest's ready
signal arrived and the host UDS exists). QEMU: reachability is IP, a TCP
banner from the guest's sshd over the TAP network.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from conftest import (
    fc_program_spec,
    fresh_vm_id,
    make_qemu_rootfs,
    qemu_instance_spec,
    requires_fc,
    requires_qemu,
    wait_for_tcp_banner,
)

from aleph.vm.supervisor.errors import VmAlreadyExistsError, VmNotFoundError
from aleph.vm.supervisor.types import Backend, VmStatus

pytestmark = pytest.mark.asyncio


@requires_fc
async def test_firecracker_create_boots_to_ready(supervisor):
    vm_id = fresh_vm_id()
    spec = fc_program_spec(vm_id)
    info = await supervisor.create_vm(spec)
    try:
        assert info.vm_id == vm_id
        assert info.status is VmStatus.RUNNING
        assert info.backend is Backend.FIRECRACKER
        # The guest spoke on the channel: boot completed end to end.
        assert info.guest_ready_payload
        assert info.guest_channel_path
        assert Path(info.guest_channel_path).exists()
        assert info.started_at_ns > 0

        # The query surface agrees with the create response.
        fetched = await supervisor.get_vm(vm_id)
        assert fetched.status is VmStatus.RUNNING
        assert fetched.guest_channel_path == info.guest_channel_path
        assert vm_id in [v.vm_id for v in await supervisor.list_vms()]
        assert await supervisor.get_vm_spec(vm_id) == spec
    finally:
        await supervisor.delete_vm(vm_id)

    with pytest.raises(VmNotFoundError):
        await supervisor.get_vm(vm_id)


@requires_fc
async def test_firecracker_create_is_idempotent_and_guards_conflicts(supervisor):
    vm_id = fresh_vm_id()
    spec = fc_program_spec(vm_id)
    first = await supervisor.create_vm(spec)
    try:
        # Same spec again: the current VM, not a second boot.
        second = await supervisor.create_vm(spec)
        assert second.vm_id == first.vm_id
        assert second.started_at_ns == first.started_at_ns

        # A different spec under the same id is a real conflict.
        with pytest.raises(VmAlreadyExistsError):
            await supervisor.create_vm(fc_program_spec(vm_id, memory_mib=512))
    finally:
        await supervisor.delete_vm(vm_id)


@requires_qemu
async def test_qemu_create_boots_and_is_reachable_over_ip(supervisor, daemon, ssh_keypair):
    _, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
    info = await supervisor.create_vm(spec)
    try:
        assert info.status is VmStatus.RUNNING
        assert info.backend is Backend.QEMU
        assert info.ipv4.address, "a TAP-networked instance must have an IPv4 assignment"
        assert info.ipv4.gateway
        assert info.ipv4.network_cidr

        banner = await wait_for_tcp_banner(info.ipv4.address, 22)
        assert banner.startswith(b"SSH-"), f"unexpected banner: {banner!r}"

        # IPv6: the address is statically pushed into the guest via the
        # cloud-init network config, so it must answer over the TAP too.
        assert info.ipv6.address, "a TAP-networked instance must have an IPv6 assignment"
        assert info.ipv6.gateway
        banner6 = await wait_for_tcp_banner(info.ipv6.address, 22, timeout=60)
        assert banner6.startswith(b"SSH-"), f"unexpected banner over IPv6: {banner6!r}"

        assert await supervisor.get_vm_spec(vm_id) == spec
    finally:
        await supervisor.delete_vm(vm_id)
