"""Agent-side registry of VMs the agent knows about.

An in-memory cache for messages, keyed by vm_hash. The agent owns this; the
supervisor (hypervisor) never sees it. It replaces the vestigial
``pool.message_cache``. For now it is populated on create; a later iteration
rehydrates it from the agent DB on startup and, eventually, from the network
(scheduler plan + Aleph messages). See the design doc, sections 3 and 9.
"""

from __future__ import annotations

import json
import logging
from collections.abc import ItemsView
from dataclasses import dataclass

from aleph_message.models import ExecutableContent, ItemHash

from aleph.vm.orchestrator.metrics import get_execution_records
from aleph.vm.utils import get_message_executable_content

logger = logging.getLogger(__name__)


@dataclass
class AgentVmRecord:
    """What the agent remembers about one VM: the (updated) message, the
    original message it was derived from, and whether the agent started it
    persistent. Used by agent-only consumers such as operator-API owner-auth,
    billing, and update-watching."""

    message: ExecutableContent
    original: ExecutableContent
    persistent: bool = False


class AgentVmRegistry:
    """In-memory cache of AgentVmRecord, keyed by vm_hash."""

    def __init__(self) -> None:
        self._records: dict[ItemHash, AgentVmRecord] = {}

    def record(
        self,
        vm_hash: ItemHash,
        *,
        message: ExecutableContent,
        original: ExecutableContent,
        persistent: bool = False,
    ) -> AgentVmRecord:
        record = AgentVmRecord(message=message, original=original, persistent=persistent)
        self._records[vm_hash] = record
        return record

    def get(self, vm_hash: ItemHash) -> AgentVmRecord | None:
        return self._records.get(vm_hash)

    def forget(self, vm_hash: ItemHash) -> None:
        self._records.pop(vm_hash, None)

    def items(self) -> ItemsView[ItemHash, AgentVmRecord]:
        return self._records.items()

    def __contains__(self, vm_hash: object) -> bool:
        return vm_hash in self._records

    def __len__(self) -> int:
        return len(self._records)


async def rehydrate_registry(registry: AgentVmRegistry) -> int:
    """Refill the registry from the agent DB after a restart.

    ExecutionRecords are the agent's own persisted knowledge (newest first);
    the supervisor's config-reattach is independent (design doc section 5).
    """
    count = 0
    for db_record in await get_execution_records():
        if not db_record.message:
            continue
        vm_hash = ItemHash(db_record.vm_hash)
        if vm_hash in registry:
            continue  # newest-first ordering: keep the latest record
        try:
            message = get_message_executable_content(json.loads(db_record.message))
            original = (
                get_message_executable_content(json.loads(db_record.original_message))
                if db_record.original_message
                else message
            )
        except Exception:
            logger.warning("Skipping unparseable execution record for %s", db_record.vm_hash, exc_info=True)
            continue
        registry.record(vm_hash, message=message, original=original, persistent=bool(db_record.persistent))
        count += 1
    return count
