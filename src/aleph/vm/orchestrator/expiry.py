import asyncio
import logging
from collections.abc import Callable

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId

logger = logging.getLogger(__name__)


class ExpiryManager:
    """Agent-owned idle-teardown timers, keyed by vm_id.

    One purpose (own the timers), one dependency (the Supervisor). Replaces the
    expiry methods that used to live on VmExecution, so the idle policy no
    longer needs a VmExecution instance.
    """

    def __init__(self, supervisor: Supervisor) -> None:
        self.supervisor = supervisor
        self._tasks: dict[VmId, asyncio.Task] = {}
        self.on_reaped: Callable[[VmId], object] | None = None

    def schedule(self, vm_id: VmId, timeout: float) -> None:
        """Arm (or re-arm, extending) the idle timer for vm_id."""
        self.cancel(vm_id)
        self._tasks[vm_id] = asyncio.create_task(self._expire(vm_id, timeout), name=f"expire {vm_id}")

    def cancel(self, vm_id: VmId) -> bool:
        """Cancel a pending timer. Returns whether one existed."""
        task = self._tasks.pop(vm_id, None)
        if task is None:
            return False
        task.cancel()
        return True

    async def cancel_all(self) -> None:
        """Cancel every pending timer (shutdown cleanup)."""
        for vm_id in list(self._tasks):
            self.cancel(vm_id)

    async def _expire(self, vm_id: VmId, timeout: float) -> None:
        reaped = False
        try:
            await asyncio.sleep(timeout)
            logger.info("Idle timeout reached for %s, reaping", vm_id)
            await self.supervisor.delete_vm(vm_id)
            reaped = True
        except VmNotFoundError:
            logger.debug("Expiry: VM %s already gone", vm_id)
            reaped = True
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Expiry of %s failed", vm_id)
        finally:
            # Only drop our own entry: a concurrent re-schedule may have already
            # replaced it with a new task under the same key.
            if self._tasks.get(vm_id) is asyncio.current_task():
                del self._tasks[vm_id]
            # Cancel the sibling idle-teardown timer (the update watcher) for the
            # same VM: once reaped, its subscription would otherwise leak.
            if reaped and self.on_reaped is not None:
                self.on_reaped(vm_id)
