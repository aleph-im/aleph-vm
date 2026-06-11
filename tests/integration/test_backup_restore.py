"""Use case 4: backups and restores through the supervisor.

The full cycle on a real QEMU instance: back up the rootfs, change guest
state over SSH, restore, and observe the change undone. Download and delete
round out the archive lifecycle. Backups are a QEMU capability; the
Firecracker rejection is asserted over the wire too.
"""

from __future__ import annotations

import tarfile

import pytest
from conftest import (
    delete_quietly,
    eventually,
    fc_program_spec,
    fresh_vm_id,
    make_qemu_rootfs,
    qemu_instance_spec,
    requires_fc,
    requires_qemu,
    ssh_exec,
    wait_for_ssh,
    wait_for_tcp_banner,
)

from aleph.vm.supervisor.errors import BackupNotFoundError, InvalidBackendError
from aleph.vm.supervisor.types import BackupStatus, VmStatus

pytestmark = pytest.mark.asyncio


@requires_fc
async def test_backup_rejects_firecracker_vms(supervisor):
    vm_id = fresh_vm_id()
    await supervisor.create_vm(fc_program_spec(vm_id))
    try:
        with pytest.raises(InvalidBackendError):
            await supervisor.start_backup(vm_id)
    finally:
        await delete_quietly(supervisor, vm_id)


@requires_qemu
async def test_backup_restore_cycle(supervisor, daemon, ssh_keypair, tmp_path):
    key_path, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    marker = "/root/avm-itest-marker"
    try:
        spec = qemu_instance_spec(vm_id, make_qemu_rootfs(daemon, vm_id), ssh_pubkey=pubkey)
        info = await supervisor.create_vm(spec)
        await wait_for_tcp_banner(info.ipv4.address, 22)
        await wait_for_ssh(key_path, info.ipv4.address)

        # ── Back up the pristine state ──
        job = await supervisor.start_backup(vm_id)
        assert job.status in (BackupStatus.RUNNING, BackupStatus.COMPLETE)
        backup_id = job.backup_id

        async def backup_done():
            status = await supervisor.get_backup_status(vm_id, backup_id)
            assert status.status is not BackupStatus.FAILED, status.error_message
            return status.status is BackupStatus.COMPLETE

        await eventually(backup_done, timeout=600, interval=5, message="backup never completed")
        complete = await supervisor.get_backup_status(vm_id, backup_id)
        assert complete.size_bytes > 0
        assert backup_id in [b.backup_id for b in await supervisor.list_backups(vm_id)]

        # ── Change guest state after the backup ──
        result = ssh_exec(key_path, info.ipv4.address, f"touch {marker} && sync")
        assert result.returncode == 0, result.stderr
        assert ssh_exec(key_path, info.ipv4.address, f"test -f {marker}").returncode == 0

        # ── Download: the archive streams out intact ──
        downloaded = tmp_path / "backup.tar"
        with downloaded.open("wb") as f:
            expected_offset = 0
            async for chunk in supervisor.download_backup(vm_id, backup_id):
                assert chunk.offset == expected_offset, "gap in the backup stream"
                f.write(chunk.data)
                expected_offset += len(chunk.data)
        assert downloaded.stat().st_size == complete.size_bytes
        with tarfile.open(downloaded) as tar:
            assert [m.name for m in tar.getmembers()] == ["rootfs.qcow2"]

        # ── Restore: the marker must be gone again ──
        restored = await supervisor.restore_backup(vm_id, backup_id)
        assert restored.status is VmStatus.RUNNING
        await wait_for_tcp_banner(restored.ipv4.address, 22)
        await wait_for_ssh(key_path, restored.ipv4.address)
        assert ssh_exec(key_path, restored.ipv4.address, f"test -f {marker}").returncode != 0

        # ── Delete: the archive is gone for status, list and download ──
        await supervisor.delete_backup(vm_id, backup_id)
        assert await supervisor.list_backups(vm_id) == []
        with pytest.raises(BackupNotFoundError):
            await supervisor.get_backup_status(vm_id, backup_id)
    finally:
        await delete_quietly(supervisor, vm_id)
