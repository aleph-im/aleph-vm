"""Use case 3: deleting a VM releases what it held on the host (hypervisor
processes, files under the execution root, TAP interfaces, firewall rules and
systemd units). Creating and deleting repeatedly must not accumulate anything."""

from __future__ import annotations

import pytest
from conftest import (
    delete_quietly,
    eventually,
    execution_files,
    fc_program_spec,
    fresh_vm_id,
    hypervisor_children,
    list_tap_interfaces,
    make_qemu_rootfs,
    nftables_ruleset,
    qemu_instance_spec,
    requires_fc,
    requires_qemu,
    requires_root,
    systemd_unit_active,
    vm_processes,
)

from aleph.vm.supervisor.types import VmStatus

pytestmark = pytest.mark.asyncio


@requires_fc
async def test_firecracker_delete_releases_host_resources(supervisor, daemon):
    baseline = len(hypervisor_children(daemon))
    vm_id = fresh_vm_id()
    try:
        await supervisor.create_vm(fc_program_spec(vm_id))
        assert len(hypervisor_children(daemon)) == baseline + 1
    finally:
        await delete_quietly(supervisor, vm_id)

    await eventually(
        lambda: len(hypervisor_children(daemon)) == baseline,
        timeout=60,
        message="hypervisor process survived delete",
    )
    assert vm_id not in [v.vm_id for v in await supervisor.list_vms()]
    await eventually(
        lambda: execution_files(daemon, vm_id) == [],
        timeout=30,
        message=f"leftover execution files: {execution_files(daemon, vm_id)}",
    )


@requires_fc
async def test_repeated_create_delete_cycles_do_not_accumulate(supervisor, daemon):
    """Same vm_id created and deleted in a tight loop: no process, file or
    pool-state buildup between cycles."""
    baseline = len(hypervisor_children(daemon))
    vm_id = fresh_vm_id()
    try:
        for cycle in range(3):
            info = await supervisor.create_vm(fc_program_spec(vm_id))
            assert info.status is VmStatus.RUNNING, f"cycle {cycle}: boot failed"
            await supervisor.delete_vm(vm_id)
            await eventually(
                lambda: len(hypervisor_children(daemon)) == baseline,
                timeout=60,
                message=f"cycle {cycle}: hypervisor process survived delete",
            )
    finally:
        await delete_quietly(supervisor, vm_id)

    assert vm_id not in [v.vm_id for v in await supervisor.list_vms()]
    await eventually(
        lambda: execution_files(daemon, vm_id) == [],
        timeout=30,
        message=f"leftover execution files after cycles: {execution_files(daemon, vm_id)}",
    )


@requires_root
@requires_fc
async def test_networked_delete_releases_tap_and_firewall(supervisor):
    taps_before = list_tap_interfaces()
    vm_id = fresh_vm_id()
    try:
        info = await supervisor.create_vm(fc_program_spec(vm_id, internet=True))
        assert info.ipv4.address
        assert list_tap_interfaces() - taps_before, "expected a new TAP interface for the VM"
        assert info.ipv4.address in nftables_ruleset()
    finally:
        await delete_quietly(supervisor, vm_id)

    await eventually(
        lambda: list_tap_interfaces() == taps_before,
        timeout=60,
        message=f"TAP leak: {list_tap_interfaces() - taps_before}",
    )
    await eventually(
        lambda: info.ipv4.address not in nftables_ruleset(),
        timeout=60,
        message=f"firewall rules for {info.ipv4.address} survived delete",
    )


@requires_qemu
async def test_qemu_delete_releases_unit_tap_and_files(supervisor, daemon, ssh_keypair):
    _, pubkey = ssh_keypair
    taps_before = list_tap_interfaces()
    vm_id = fresh_vm_id()
    unit = f"aleph-vm-controller@{vm_id}.service"
    try:
        spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
        info = await supervisor.create_vm(spec)
        assert systemd_unit_active(unit)
        assert vm_processes(vm_id)
        assert info.ipv4.address in nftables_ruleset()
    finally:
        await delete_quietly(supervisor, vm_id)

    await eventually(lambda: not vm_processes(vm_id), timeout=90, message="qemu/controller survived delete")
    await eventually(lambda: not systemd_unit_active(unit), timeout=60, message="controller unit still active")
    await eventually(
        lambda: list_tap_interfaces() == taps_before,
        timeout=60,
        message=f"TAP leak: {list_tap_interfaces() - taps_before}",
    )
    await eventually(
        lambda: info.ipv4.address not in nftables_ruleset(),
        timeout=60,
        message=f"firewall rules for {info.ipv4.address} survived delete",
    )
    await eventually(
        lambda: execution_files(daemon, vm_id) == [],
        timeout=30,
        message=f"leftover execution files: {execution_files(daemon, vm_id)}",
    )
