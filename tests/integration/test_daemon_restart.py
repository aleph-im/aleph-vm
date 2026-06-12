"""Supervisor daemon restart: persistent VMs live in systemd controller units
and must survive a daemon stop/start; the new daemon reattaches them
(load_persistent_executions) and regains full control."""

import pytest
from conftest import (
    eventually,
    fresh_vm_id,
    make_qemu_rootfs,
    qemu_instance_spec,
    requires_qemu,
    restart_daemon,
    vm_processes,
    wait_for_tcp_banner,
)

from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.types import VmStatus

pytestmark = pytest.mark.asyncio


@requires_qemu
async def test_daemon_restart_reattaches_persistent_vm(daemon, ssh_keypair):
    """The full recovery story in one VM boot: the guest must keep running
    through the daemon restart (same qemu process, no reboot), the new
    daemon must list it as RUNNING, and, the real proof of reattachment,
    must be able to stop, start and delete it."""
    _, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)

    client = GrpcSupervisor(daemon.socket_path)
    try:
        info = await client.create_vm(spec)
        await wait_for_tcp_banner(info.ipv4.address, 22)
        qemu_before = vm_processes(vm_id)
        assert qemu_before

        await client.close()
        await restart_daemon(daemon)
        client = GrpcSupervisor(daemon.socket_path)

        # The guest never noticed: same processes, still reachable.
        assert vm_processes(vm_id) == qemu_before
        await wait_for_tcp_banner(info.ipv4.address, 22, timeout=30)

        # The new daemon reattached the execution, not just observed it.
        assert vm_id in [v.vm_id for v in await client.list_vms()]
        reattached = await client.get_vm(vm_id)
        assert reattached.status is VmStatus.RUNNING
        assert reattached.ipv4.address == info.ipv4.address

        # Control plane works end to end on the reattached execution.
        stopped = await client.stop_vm(vm_id)
        assert stopped.status is VmStatus.STOPPED
        await eventually(
            lambda: not vm_processes(vm_id),
            timeout=90,
            message="qemu still alive after stop_vm on the reattached execution",
        )

        started = await client.start_vm(vm_id)
        assert started.status is VmStatus.RUNNING
        await wait_for_tcp_banner(started.ipv4.address, 22)
    finally:
        try:
            await client.delete_vm(vm_id)
        except Exception:
            pass
        await client.close()

    await eventually(lambda: not vm_processes(vm_id), timeout=90, message="qemu/controller survived delete")
