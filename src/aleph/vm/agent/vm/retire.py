"""The one way the agent ends a VM.

Every path that used to call ``supervisor.delete_vm`` and then some subset
of ``registry.forget``, ``delete_records_for_vm`` and ``remove_*_staging``
goes through ``retire_vm`` with a reason. The reason has no default: a call
site must say what it means, which is what was missing when disks leaked
(spec S1). The supervisor's DeleteVm is quiescence only; storage policy is
decided here, agent-side, and never crosses the wire.

FAILED_CREATE is only for a create that allocated nothing pre-existing: the
create paths in ``run.py`` are also the re-create paths for a
host-persistent VM whose volumes already exist (``downloader``'s
``_make_writable_volume`` returns early when the destination is already
there), so a transient failure there (a boot timeout, an admission refusal
on node restart, a base-image download error) must not retire FAILED_CREATE
and purge the owner's disks. Those call sites snapshot whether the VM's
volumes existed before the attempt and retire RECREATE instead when they
did, keeping the record and the disks so the next create attempt lands on
the same storage.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from enum import Enum
from pathlib import Path

from aleph_message.models import ItemHash

from aleph.vm.agent.metrics import delete_records_for_vm
from aleph.vm.agent.vm.backup import purge_vm_backups
from aleph.vm.agent.vm.purge import (
    _checked_namespace,
    purge_vm_side_dirs,
    purge_vm_storage,
)
from aleph.vm.agent.vm.reclaimable import depends_on_from_content, mark_reclaimable
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.storage import (
    DEVICE_MAPPER_DIRECTORY,
    remove_base_device,
    remove_devmapper,
)
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId

logger = logging.getLogger(__name__)


class RetireReason(Enum):
    RECREATE = "recreate"  # the same VM comes back immediately: amend, crash recovery, idle reap, reboot
    GONE = "gone"  # positive knowledge it will not return: forgotten, unpaid, deallocated, migrated away
    ERASE = "erase"  # the owner asked for a wipe
    FAILED_CREATE = "failed_create"  # a create that never committed and allocated nothing pre-existing


AfterGoneHook = Callable[[], Awaitable[None]]
_after_gone: AfterGoneHook | None = None


def set_after_gone_hook(hook: AfterGoneHook | None) -> None:
    """The app registers a reconcile pass here; it runs after every GONE
    under VOLUME_RETENTION=keep so the budget is enforced right away.

    This module cannot import the reconciler (the reconciler purges through
    the same helpers and the agent wires both at startup), and a retention
    budget that is only enforced once an hour is a budget an attacker can
    burst through: create, forget, repeat.
    """
    global _after_gone  # noqa: PLW0603
    _after_gone = hook


async def teardown_namespace_devices(namespace: str) -> None:
    """Remove a VM's device-mapper snapshots without knowing its volumes.

    The inverse of ``storage.device_name_for``: ``create_devmapper`` names a
    snapshot ``<namespace>_<volume name>``, so when no message is left to
    enumerate the volumes from, /dev/mapper is the only thing that still
    remembers what this VM built. Two paths arrive here with no record: a
    create that failed before the registry commit (FAILED_CREATE is raised
    from the create path, where the record is written only after ``create_vm``
    returns) and a GONE for a VM the registry never knew. Without this their
    volume files stay held by a dm target, and ``purge_vm_storage`` refuses
    such a directory on every pass, forever.

    ``<namespace>_base`` is not removed in the loop: ``remove_devmapper``
    removes it itself, after the last snapshot of this VM is gone. A base with
    no snapshot at all (a create that died between the two ``dmsetup create``
    calls) is the one case that never reaches, so it is removed at the end.
    """
    namespace = _checked_namespace(namespace)
    mapper = Path(DEVICE_MAPPER_DIRECTORY)
    try:
        devices = sorted(mapper.glob(f"{namespace}_*"))
    except OSError:
        logger.warning("Could not list the device-mapper devices of %s", namespace, exc_info=True)
        return
    for device in devices:
        volume_name = device.name[len(namespace) + 1 :]
        if not volume_name or volume_name == "base":
            continue
        try:
            await remove_devmapper(namespace, volume_name)
        except Exception:
            logger.exception("Device teardown of %s/%s failed", namespace, volume_name)
    try:
        await remove_base_device(namespace)
    except Exception:
        logger.exception("Device teardown of the base of %s failed", namespace)


async def teardown_vm_devices(namespace: str, record: AgentVmRecord | None) -> None:
    """Remove the device-mapper snapshots and loop devices of a VM's
    parent-backed volumes.

    The agent creates them (``storage.create_devmapper``) and nothing else
    removes them, so this is the only inverse. Best effort: a failure is
    logged and the volume file stays behind, where the reconciler's dm guard
    leaves it for the next pass rather than unlinking a file a loop device
    still pins.
    """
    if record is None:
        # No message to read the volumes from: ask device-mapper instead.
        # Best effort like the rest of this function, and here that includes
        # the namespace check itself: an implausible hash raises, and a
        # teardown that cannot run must not abort the retire that would have
        # dropped the records and the rest of the storage.
        try:
            await teardown_namespace_devices(namespace)
        except Exception:
            logger.exception("Device teardown of %s failed", namespace)
        return
    namespace = _checked_namespace(namespace)
    for volume in getattr(record.message, "volumes", None) or []:
        # An instance rootfs is a qcow2 overlay, not a dm snapshot, and it is
        # not in `volumes` anyway; only a volume with a parent went through
        # create_devmapper.
        if getattr(volume, "parent", None) is None or not getattr(volume, "name", None):
            continue
        try:
            await remove_devmapper(namespace, volume.name)
        except Exception:
            logger.exception("Device teardown of %s/%s failed", namespace, volume.name)


async def retire_vm(
    vm_hash: ItemHash | str,
    reason: RetireReason,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry | None = None,
) -> None:
    """Quiesce the VM through the supervisor, then apply ``reason`` to
    everything the agent holds for it: registry record, DB records, volumes,
    session and staging directories, backups.

    RECREATE stops after the quiesce (port mappings kept, storage untouched).
    Every other reason drops the records and the side directories; GONE
    applies VOLUME_RETENTION to the volumes, ERASE and FAILED_CREATE purge
    them regardless (retention protects against administrative deletion,
    not against the owner's own request, and a VM that never ran has nothing
    worth keeping).
    """
    vm_id = VmId(str(vm_hash))
    try:
        await supervisor.delete_vm(vm_id, keep_port_mappings=reason is RetireReason.RECREATE)
    except VmNotFoundError:
        logger.debug("Retire %s (%s): the supervisor does not know it", vm_hash, reason.value)
    if reason is RetireReason.RECREATE:
        return
    if registry is None:
        msg = f"retire_vm({reason.value}) needs the registry to drop the VM's record"
        raise ValueError(msg)

    item_hash = vm_hash if isinstance(vm_hash, ItemHash) else ItemHash(str(vm_hash))
    record = registry.get(item_hash)
    registry.forget(item_hash)
    await delete_records_for_vm(str(vm_hash))
    # Before the storage pass: a volume file held by a live dm target cannot
    # be unlinked usefully, and the marker written for a kept volume would
    # describe a size the loop device still pins.
    await teardown_vm_devices(str(vm_hash), record)
    await asyncio.to_thread(_release_storage, str(vm_hash), reason, record)
    await asyncio.to_thread(purge_vm_backups, str(vm_hash))
    logger.info("Retired %s (%s)", vm_hash, reason.value)
    if reason is RetireReason.GONE and settings.VOLUME_RETENTION == "keep" and _after_gone is not None:
        # This VM's volumes just became reclaimable: bring the pool back under
        # its retention budget now rather than at the next periodic pass.
        # Best effort: the GONE call sites sweep in a loop (terminal messages,
        # unpaid VMs) with no local try, and this VM is already retired, so a
        # failing pass must not take the rest of the sweep down with it. The
        # periodic pass will retry.
        try:
            await _after_gone()
        except Exception:
            logger.exception("Storage reconcile after retiring %s failed", vm_hash)


def _release_storage(namespace: str, reason: RetireReason, record: AgentVmRecord | None) -> None:
    if reason is RetireReason.GONE and settings.VOLUME_RETENTION == "keep":
        depends_on = depends_on_from_content(record.message) if record is not None else ()
        # The record is about to be the last thing that knew who owns these
        # disks (this runs after registry.forget and delete_records_for_vm),
        # so the owner address goes into the marker with it.
        owner = str(record.message.address) if record is not None and record.message.address else None
        mark_reclaimable(namespace, "gone", depends_on, owner=owner)
        purge_vm_side_dirs(namespace)
        return
    purge_vm_storage(namespace)
