"""The Supervisor abstraction: capability ABCs aggregated into one interface.

Eight capability ABCs, all async (bar the streaming iterators). A concrete
supervisor (in-process today, gRPC client in 0.D) implements all 29 methods.
Migration carries no method of its own: it rides the standard lifecycle RPCs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator

from aleph.vm.supervisor_interface.types import (
    CreateVmSpec,
    HealthInfo,
    HostInfo,
    HostPort,
    LogChunk,
    Measurement,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    VmEvent,
    VmId,
    VmInfo,
)


class HostOps(ABC):
    @abstractmethod
    async def health(self) -> HealthInfo: ...

    @abstractmethod
    async def get_host_info(self) -> HostInfo: ...


class LifecycleOps(ABC):
    @abstractmethod
    async def create_vm(self, spec: CreateVmSpec) -> VmInfo: ...

    @abstractmethod
    async def get_vm(self, vm_id: VmId) -> VmInfo: ...

    @abstractmethod
    async def get_vm_spec(self, vm_id: VmId) -> CreateVmSpec:
        """The spec a live VM was created from. Raises
        NotImplementedSupervisorError for VMs created outside the spec path."""

    @abstractmethod
    async def list_vms(self) -> list[VmInfo]: ...

    @abstractmethod
    async def delete_vm(self, vm_id: VmId, keep_port_mappings: bool = False) -> None:
        """Stop the VM, release its definition, and release every handle held
        on its storage. The VM's volumes are NOT deleted: the agent allocates
        them and is the only side that can tell a per-VM volume from a shared
        cache entry, so it owns their deletion (aleph.vm.agent.vm.purge).

        A delete is final by default, so persisted host-port mappings go too.
        keep_port_mappings=True preserves them for a delete+recreate cycle
        (crash recovery, message updates), so the recreated VM reloads the
        same host ports."""

    @abstractmethod
    async def stop_vm(self, vm_id: VmId) -> VmInfo:
        """Stop without releasing the definition; the VM stays listed
        (STOPPED) and start_vm brings it back. Persistent VMs only today."""

    @abstractmethod
    async def start_vm(self, vm_id: VmId) -> VmInfo:
        """Start a stopped VM; a no-op (current info) if already running."""

    @abstractmethod
    async def reboot_vm(self, vm_id: VmId) -> VmInfo: ...

    @abstractmethod
    async def run_program_code(self, vm_id: VmId, scope: dict, *, timeout: float) -> bytes:
        """Run one request inside a long-lived (persistent) program VM and return
        the raw runtime reply.

        Persistent programs are served through the supervisor: the agent does not
        reach the guest channel of a supervisor-owned VM. Ephemeral programs are
        recreated per request and keep the agent-side channel call. ``scope`` is
        the ASGI scope the runtime expects; the supervisor blocks until the VM is
        ready, then runs the code over its guest channel."""


class PortForwardingOps(ABC):
    @abstractmethod
    async def add_port_forward(self, spec: PortForwardSpec) -> PortForwardInfo: ...

    @abstractmethod
    async def remove_port_forward(self, vm_id: VmId, host_port: HostPort, protocol: Protocol) -> None: ...

    @abstractmethod
    async def list_port_forwards(self, vm_id: VmId | None = None) -> list[PortForwardInfo]: ...


class EventsOps(ABC):
    @abstractmethod
    def watch_events(self) -> AsyncIterator[VmEvent]:
        """Stream lifecycle transitions, no replay: snapshot with list_vms
        first, then watch."""


class LogsOps(ABC):
    @abstractmethod
    async def get_logs(self, vm_id: VmId, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]: ...

    @abstractmethod
    def stream_logs(self, vm_id: VmId, include_history: bool = False) -> AsyncIterator[LogChunk]: ...


class QuiesceOps(ABC):
    """The supervisor's part in a backup. The agent owns the archives (it
    created the disks, so it copies, stores, expires and restores them); the
    one thing it cannot do from outside the VM is quiesce the guest."""

    @abstractmethod
    async def freeze_guest(self, vm_id: VmId) -> bool:
        """Freeze the guest filesystems through the QEMU guest agent. Best
        effort: False when the agent is unavailable (nothing is frozen and
        the caller's copy is crash-consistent). A freeze is auto-thawed
        after settings.GUEST_FREEZE_TIMEOUT so a caller that dies mid-copy
        cannot leave the guest frozen."""

    @abstractmethod
    async def thaw_guest(self, vm_id: VmId) -> None:
        """Thaw a guest frozen by freeze_guest. A no-op when nothing is
        frozen."""


class ConfidentialOps(ABC):
    @abstractmethod
    async def initialize_confidential(self, vm_id: VmId, session_bytes: bytes, godh_bytes: bytes) -> None: ...

    @abstractmethod
    async def get_measurement(self, vm_id: VmId) -> Measurement: ...

    @abstractmethod
    async def inject_secret(self, vm_id: VmId, secret_header_bytes: bytes, secret_bytes: bytes) -> None: ...


class NetworkOps(ABC):
    @abstractmethod
    async def recreate_network(self) -> dict:
        """Flush and rebuild the host firewall/nftables for the local VMs.

        Returns a JSON-serialisable summary of the work done."""


class Supervisor(
    HostOps,
    LifecycleOps,
    PortForwardingOps,
    EventsOps,
    LogsOps,
    QuiesceOps,
    ConfidentialOps,
    NetworkOps,
    ABC,
):
    """The single agent-to-VM-management interface."""
