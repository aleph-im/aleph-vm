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

from aleph_message.models import ItemHash

from aleph.vm.agent.metrics import delete_records_for_vm
from aleph.vm.agent.vm.backup import purge_vm_backups
from aleph.vm.agent.vm.purge import purge_vm_side_dirs, purge_vm_storage
from aleph.vm.agent.vm.reclaimable import depends_on_from_content, mark_reclaimable
from aleph.vm.agent.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.conf import settings
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
    await asyncio.to_thread(_release_storage, str(vm_hash), reason, record)
    await asyncio.to_thread(purge_vm_backups, str(vm_hash))
    logger.info("Retired %s (%s)", vm_hash, reason.value)
    if reason is RetireReason.GONE and settings.VOLUME_RETENTION == "keep" and _after_gone is not None:
        # This VM's volumes just became reclaimable: bring the pool back under
        # its retention budget now rather than at the next periodic pass.
        await _after_gone()


def _release_storage(namespace: str, reason: RetireReason, record: AgentVmRecord | None) -> None:
    if reason is RetireReason.GONE and settings.VOLUME_RETENTION == "keep":
        depends_on = depends_on_from_content(record.message) if record is not None else ()
        mark_reclaimable(namespace, "gone", depends_on)
        purge_vm_side_dirs(namespace)
        return
    purge_vm_storage(namespace)
