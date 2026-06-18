"""The Supervisor abstraction: capability ABCs aggregated into one interface.

Nine capability ABCs, all async (bar the streaming iterators). A concrete
supervisor (in-process today, gRPC client in 0.D) implements all 30 methods.
Migration carries no method of its own: it rides the standard lifecycle RPCs.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import AsyncIterator
from datetime import datetime

from aleph.vm.contract.types import (
    BackupChunk,
    BackupId,
    BackupInfo,
    CreateVmSpec,
    DirectoryPath,
    HealthInfo,
    HostInfo,
    HostPort,
    LogChunk,
    Measurement,
    PortForwardInfo,
    PortForwardSpec,
    Protocol,
    ReservationRequest,
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
    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None: ...

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
    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo: ...

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


class BackupOps(ABC):
    @abstractmethod
    async def start_backup(self, vm_id: VmId, quiesce_guest: bool = False, include_volumes: bool = False) -> BackupInfo:
        """Start (or return) a backup of the VM's rootfs. quiesce_guest freezes
        the guest filesystems through the QEMU agent during the copy;
        include_volumes also archives the VM's non-read-only persistent volumes."""

    @abstractmethod
    async def get_backup_status(self, vm_id: VmId, backup_id: BackupId) -> BackupInfo: ...

    @abstractmethod
    async def list_backups(self, vm_id: VmId | None = None) -> list[BackupInfo]: ...

    @abstractmethod
    def download_backup(self, vm_id: VmId, backup_id: BackupId) -> AsyncIterator[BackupChunk]: ...

    @abstractmethod
    async def delete_backup(self, vm_id: VmId, backup_id: BackupId) -> None: ...

    @abstractmethod
    async def restore_backup(self, vm_id: VmId, backup_id: BackupId) -> VmInfo: ...

    @abstractmethod
    async def restore_from_image(
        self, vm_id: VmId, image_path: DirectoryPath, max_virtual_size_bytes: int = 0
    ) -> VmInfo:
        """Restore a VM's rootfs from a QCOW2 image already staged on a host
        path (an uploaded image or a downloaded volume). Validates the image,
        rejects one whose virtual size exceeds max_virtual_size_bytes (0 = no
        cap), swaps the rootfs and restarts the VM. The agent owns the staging;
        the engine owns the disk/VM work."""


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


class ReservationOps(ABC):
    @abstractmethod
    async def reserve_resources(self, request: ReservationRequest) -> datetime:
        """Hold the resources (GPUs today) an instance requests for a user,
        returning the reservation expiry. ``request`` is a message-free
        resources DTO the agent built from the Aleph message; the
        implementation runs the same capacity admission as the create path
        before holding anything."""


class Supervisor(
    HostOps,
    LifecycleOps,
    PortForwardingOps,
    EventsOps,
    LogsOps,
    BackupOps,
    ConfidentialOps,
    NetworkOps,
    ReservationOps,
    ABC,
):
    """The single agent-to-VM-management interface."""
