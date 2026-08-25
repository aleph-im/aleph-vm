"""Use case 4: guest quiescence through the supervisor.

The supervisor's only part in a backup: freeze the guest filesystems
through the QEMU guest agent, thaw them again. The archives themselves are
the agent's (BackupManager, tests/supervisor/test_agent_backups.py); a
Firecracker program has no guest agent and answers "not frozen".
"""

from __future__ import annotations

import pytest
from conftest import (
    delete_quietly,
    fc_program_spec,
    fresh_vm_id,
    make_qemu_rootfs,
    qemu_instance_spec,
    requires_fc,
    requires_qemu,
    wait_for_ssh,
    wait_for_tcp_banner,
)

from aleph.vm.supervisor_interface.types import VmStatus

pytestmark = pytest.mark.asyncio


@requires_fc
async def test_freeze_is_a_no_for_firecracker_vms(supervisor):
    vm_id = fresh_vm_id()
    await supervisor.create_vm(fc_program_spec(vm_id))
    try:
        assert await supervisor.freeze_guest(vm_id) is False
        await supervisor.thaw_guest(vm_id)  # a no-op, never an error
        assert (await supervisor.get_vm(vm_id)).status is VmStatus.RUNNING
    finally:
        await delete_quietly(supervisor, vm_id)


@requires_qemu
async def test_freeze_and_thaw_a_running_qemu_guest(supervisor, daemon, ssh_keypair):
    key_path, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    try:
        spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
        info = await supervisor.create_vm(spec)
        await wait_for_tcp_banner(info.ipv4.address, 22)
        await wait_for_ssh(key_path, info.ipv4.address)

        # Frozen when the image ships qemu-guest-agent, otherwise a
        # best-effort False; either way the guest keeps running and a thaw
        # (even of an unfrozen guest) is accepted.
        frozen = await supervisor.freeze_guest(vm_id)
        assert isinstance(frozen, bool)
        if frozen:
            assert await supervisor.freeze_guest(vm_id) is True  # idempotent
        await supervisor.thaw_guest(vm_id)
        await supervisor.thaw_guest(vm_id)
        assert (await supervisor.get_vm(vm_id)).status is VmStatus.RUNNING
    finally:
        await delete_quietly(supervisor, vm_id)
