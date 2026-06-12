"""Use case 6: error paths over the real gRPC boundary. The error class must
survive the wire (translate_rpc_error rebuilds it class-exact), and failed
calls must not corrupt the supervisor's state for subsequent ones."""

import pytest
from conftest import fc_program_spec, fresh_vm_id, requires_fc

from aleph.vm.supervisor.errors import (
    BackupNotFoundError,
    NotImplementedSupervisorError,
    VmNotFoundError,
)
from aleph.vm.supervisor.types import (
    BackupId,
    GuestPort,
    HostPort,
    PortForwardSpec,
    Protocol,
    VmId,
    VmStatus,
)

pytestmark = pytest.mark.asyncio

UNKNOWN_VM = VmId("beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef")


async def test_operations_on_unknown_vm_raise_vm_not_found(supervisor):
    """No VM is needed to know it does not exist; every lookup path must
    say so with VmNotFoundError, not a generic failure."""
    with pytest.raises(VmNotFoundError):
        await supervisor.get_vm(UNKNOWN_VM)
    with pytest.raises(VmNotFoundError):
        await supervisor.get_vm_spec(UNKNOWN_VM)
    with pytest.raises(VmNotFoundError):
        await supervisor.delete_vm(UNKNOWN_VM)
    with pytest.raises(VmNotFoundError):
        await supervisor.stop_vm(UNKNOWN_VM)
    with pytest.raises(VmNotFoundError):
        await supervisor.start_vm(UNKNOWN_VM)
    with pytest.raises(VmNotFoundError):
        await supervisor.reboot_vm(UNKNOWN_VM)
    with pytest.raises(VmNotFoundError):
        await supervisor.start_backup(UNKNOWN_VM)
    with pytest.raises(VmNotFoundError):
        await supervisor.add_port_forward(
            PortForwardSpec(vm_id=UNKNOWN_VM, host_port=HostPort(0), vm_port=GuestPort(8080), protocol=Protocol.TCP)
        )


@requires_fc
async def test_ephemeral_vm_rejects_stop_start_and_stays_usable(supervisor):
    """stop/start are persistent-only (the ephemeral cycle is delete +
    create); the rejection must leave the VM running and deletable."""
    vm_id = fresh_vm_id()
    await supervisor.create_vm(fc_program_spec(vm_id))
    try:
        with pytest.raises(NotImplementedSupervisorError):
            await supervisor.stop_vm(vm_id)
        with pytest.raises(NotImplementedSupervisorError):
            await supervisor.start_vm(vm_id)

        # The failed calls did not break the VM.
        assert (await supervisor.get_vm(vm_id)).status is VmStatus.RUNNING

        # Backup lookups for ids that were never created.
        with pytest.raises(BackupNotFoundError):
            await supervisor.get_backup_status(vm_id, BackupId(f"{vm_id}-20200101T000000000000Z"))
        with pytest.raises(BackupNotFoundError):
            async for _chunk in supervisor.download_backup(vm_id, BackupId(f"{vm_id}-20200101T000000000000Z")):
                pass
        with pytest.raises(BackupNotFoundError):
            # A backup id of another VM must not resolve through this one.
            await supervisor.get_backup_status(vm_id, BackupId(f"{UNKNOWN_VM}-20200101T000000000000Z"))
    finally:
        await supervisor.delete_vm(vm_id)

    # Double delete: the first one released the VM, the second must say so.
    with pytest.raises(VmNotFoundError):
        await supervisor.delete_vm(vm_id)
