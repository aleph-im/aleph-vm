import asyncio
import logging

from aleph_message.models import ExecutableContent, InstanceContent, ItemHash

from aleph.vm.orchestrator.pubsub import PubSub
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId

logger = logging.getLogger(__name__)


def update_refs(original: ExecutableContent) -> list[str]:
    """The Aleph message refs whose update should redeploy the VM.

    Adapted from VmExecution.watch_for_updates: instances watch their
    volume refs; programs also watch code / runtime / data.
    """
    volume_refs = [volume.ref for volume in (original.volumes or []) if hasattr(volume, "ref")]
    if isinstance(original, InstanceContent):
        return volume_refs
    data_ref = [original.data.ref] if original.data else []
    return [original.code.ref, original.runtime.ref, *data_ref, *volume_refs]


class UpdateWatcher:
    """Agent-owned 'redeploy on message update' subscriptions, keyed by vm_id.

    Subscription-driven counterpart to ExpiryManager. One dependency pair: the
    Supervisor (to reap) and the AgentVmRegistry (to read the watched message).
    Replaces the update methods that used to live on VmExecution.
    """

    def __init__(self, supervisor: Supervisor, registry: AgentVmRegistry) -> None:
        self.supervisor = supervisor
        self.registry = registry
        self._tasks: dict[VmId, asyncio.Task] = {}

    def watch(self, vm_id: VmId, vm_hash: ItemHash, pubsub: PubSub) -> None:
        """Start watching for updates to vm_hash, unless already watching it.

        Idempotent: a live subscription is kept (matches the old
        ``if not self.update_task`` guard). No-op when the agent has no record
        of the VM (e.g. nothing to watch)."""
        existing = self._tasks.get(vm_id)
        if existing is not None and not existing.done():
            return
        record = self.registry.get(vm_hash)
        if record is None:
            return
        refs = update_refs(record.original)
        self._tasks[vm_id] = asyncio.create_task(self._watch(vm_id, refs, pubsub), name=f"watch {vm_id}")

    def cancel(self, vm_id: VmId) -> bool:
        """Cancel a pending watch. Returns whether one existed."""
        task = self._tasks.pop(vm_id, None)
        if task is None:
            return False
        task.cancel()
        return True

    async def cancel_all(self) -> None:
        """Cancel every pending watch (shutdown cleanup)."""
        for vm_id in list(self._tasks):
            self.cancel(vm_id)

    async def _watch(self, vm_id: VmId, refs: list[str], pubsub: PubSub) -> None:
        try:
            await pubsub.msubscribe(*refs)
            logger.info("Update received for %s, reaping", vm_id)
            await self.supervisor.delete_vm(vm_id)
        except VmNotFoundError:
            logger.debug("Update-watch: VM %s already gone", vm_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Update-watch of %s failed", vm_id)
        finally:
            # Only drop our own entry: a concurrent re-watch may have replaced it.
            if self._tasks.get(vm_id) is asyncio.current_task():
                del self._tasks[vm_id]
