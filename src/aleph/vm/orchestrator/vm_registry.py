"""Agent-side registry of VMs the agent knows about.

An in-memory cache for messages, keyed by vm_hash. The agent owns this; the
supervisor (hypervisor) never sees it. It replaces the vestigial
``pool.message_cache``. For now it is populated on create; a later iteration
rehydrates it from the agent DB on startup and, eventually, from the network
(scheduler plan + Aleph messages). See the design doc, sections 3 and 9.
"""

from __future__ import annotations

from dataclasses import dataclass

from aleph_message.models import ExecutableContent, ItemHash


@dataclass
class AgentVmRecord:
    """What the agent remembers about one VM: the (updated) message and the
    original message it was derived from. Used by agent-only consumers such as
    operator-API owner-auth, billing, and update-watching."""

    message: ExecutableContent
    original: ExecutableContent


class AgentVmRegistry:
    """In-memory cache of AgentVmRecord, keyed by vm_hash."""

    def __init__(self) -> None:
        self._records: dict[ItemHash, AgentVmRecord] = {}

    def record(
        self, vm_hash: ItemHash, *, message: ExecutableContent, original: ExecutableContent
    ) -> AgentVmRecord:
        record = AgentVmRecord(message=message, original=original)
        self._records[vm_hash] = record
        return record

    def get(self, vm_hash: ItemHash) -> AgentVmRecord | None:
        return self._records.get(vm_hash)

    def forget(self, vm_hash: ItemHash) -> None:
        self._records.pop(vm_hash, None)

    def __contains__(self, vm_hash: object) -> bool:
        return vm_hash in self._records

    def __len__(self) -> int:
        return len(self._records)
