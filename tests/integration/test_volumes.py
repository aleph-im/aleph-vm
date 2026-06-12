"""Use case 5: extra data disks. Attachment order and guest visibility,
data persistence across stop/start, and wipe-on-delete semantics."""

import pytest
from conftest import (
    eventually,
    fresh_vm_id,
    make_data_disk,
    make_qemu_rootfs,
    qemu_instance_spec,
    requires_qemu,
    ssh_exec,
    vm_processes,
    wait_for_ssh,
    wait_for_tcp_banner,
)

from aleph.vm.supervisor.types import DiskFormat, DiskRole, DiskSpec, VmStatus

pytestmark = pytest.mark.asyncio

# The data disk's virtual size; nothing else in the guest is this size, so
# the device can be located by size instead of guessing /dev/vdX names.
DATA_DISK_MIB = 64


def _find_data_device(key_path, host) -> str:
    """Locate the extra disk in the guest by its exact size."""
    result = ssh_exec(key_path, host, "lsblk -b -d -n -o NAME,SIZE")
    assert result.returncode == 0, result.stderr
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) == 2 and int(parts[1]) == DATA_DISK_MIB * 1024 * 1024:
            return f"/dev/{parts[0]}"
    raise AssertionError(f"no {DATA_DISK_MIB} MiB block device in guest:\n{result.stdout}")


@requires_qemu
async def test_extra_disk_data_survives_stop_start_and_wipe_erases_it(supervisor, daemon, ssh_keypair):
    """One boot covers the whole data-disk story: the extra disk is visible
    in the guest, data written to it survives a stop/start cycle (the disk
    is a host file, not a tmpfs), and delete(wipe=True) erases the host
    file while a plain delete would have left it."""
    key_path, pubkey = ssh_keypair
    vm_id = fresh_vm_id()
    data_disk = make_data_disk(daemon, vm_id, DATA_DISK_MIB)
    spec = qemu_instance_spec(
        vm_id,
        make_qemu_rootfs(daemon, vm_id),
        ssh_pubkey=pubkey,
        extra_disks=[DiskSpec(path=data_disk, readonly=False, format=DiskFormat.QCOW2, role=DiskRole.EXTRA)],
    )
    try:
        info = await supervisor.create_vm(spec)
        await wait_for_tcp_banner(info.ipv4.address, 22)
        await wait_for_ssh(key_path, info.ipv4.address)

        device = _find_data_device(key_path, info.ipv4.address)
        result = ssh_exec(
            key_path,
            info.ipv4.address,
            f"mkfs.ext4 -q {device} && mkdir -p /data && mount {device} /data"
            " && echo persisted > /data/marker && umount /data && sync",
        )
        assert result.returncode == 0, result.stderr

        stopped = await supervisor.stop_vm(vm_id)
        assert stopped.status is VmStatus.STOPPED
        await eventually(lambda: not vm_processes(vm_id), timeout=90, message="qemu still alive after stop_vm")

        started = await supervisor.start_vm(vm_id)
        assert started.status is VmStatus.RUNNING
        await wait_for_tcp_banner(started.ipv4.address, 22)
        await wait_for_ssh(key_path, started.ipv4.address)

        device = _find_data_device(key_path, started.ipv4.address)
        result = ssh_exec(
            key_path,
            started.ipv4.address,
            f"mkdir -p /data && mount {device} /data && cat /data/marker",
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "persisted"
    finally:
        try:
            await supervisor.delete_vm(vm_id, wipe=True)
        except Exception:
            pass

    await eventually(lambda: not vm_processes(vm_id), timeout=90, message="qemu/controller survived delete")
    assert not data_disk.exists(), "delete(wipe=True) must erase writable data volumes"
