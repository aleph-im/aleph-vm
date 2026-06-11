"""Agent-side guest protocols for program (microvm) VMs.

The supervisor boots a program VM and reports its vsock control socket in
``VmInfo.control_socket_path``; everything Aleph-specific that used to live
in the Firecracker program controller happens here, in the agent process:

- the **guest API** server the program calls (a host process bound to
  ``<control_socket>_53``);
- the **configuration push** (code, entrypoint, variables, network, volumes)
  over ``CONNECT 52``;
- **code execution** (`run_code`) over ``CONNECT 52``.

State is per-supervisor-VM: a VM the agent did not configure in this process
is not in ``configured`` and must be recreated before serving (the runtime
accepts exactly one configuration push after boot, so "unknown" is
indistinguishable from "already configured" and recreation is the only safe
move).
"""

from __future__ import annotations

import asyncio
import logging
from multiprocessing import Process
from pathlib import Path
from string import ascii_lowercase

import msgpack
from aleph_message.models import ItemHash, ProgramContent
from aleph_message.models.execution.base import Encoding

from aleph.vm.conf import settings
from aleph.vm.controllers.firecracker.executable import (
    VmInitNotConnectedError,
    VmSetupError,
    Volume,
)
from aleph.vm.controllers.firecracker.program import (
    AlephProgramResources,
    ConfigurationResponse,
    FileTooLargeError,
    ProgramConfiguration,
    RunCodePayload,
    read_input_data,
)
from aleph.vm.guest_api.__main__ import run_guest_api
from aleph.vm.hypervisors.firecracker.microvm import RuntimeConfiguration
from aleph.vm.storage import chown_to_jailman
from aleph.vm.supervisor.types import VmId, VmInfo

logger = logging.getLogger(__name__)


def _device_name(index: int) -> str:
    """Guest block device for the index-th non-root drive (vdb, vdc, ...).

    Mirrors MicroVM.compute_device_name; the drive order is the spec's disk
    order (CODE first when present, then EXTRA disks), which the supervisor
    preserves when it boots the VM.
    """
    return f"vd{ascii_lowercase[index + 1]}"


def build_code_and_volumes(resources: AlephProgramResources) -> tuple[bytes | None, list[Volume]]:
    """The agent half of the old get_volumes_for_program: code bytes (inline
    encodings) or a CODE drive mount (squashfs), plus guest volume mappings."""
    if resources.code_encoding == Encoding.squashfs:
        volumes = [Volume(mount="/opt/code", device=_device_name(0), read_only=True)] + [
            Volume(mount=volume.mount, device=_device_name(index + 1), read_only=volume.read_only)
            for index, volume in enumerate(resources.volumes)
        ]
        return b"", volumes

    if resources.code_path.stat().st_size > settings.MAX_PROGRAM_ARCHIVE_SIZE:
        msg = "Program file too large to pass as an inline zip"
        raise FileTooLargeError(msg)
    code = resources.code_path.read_bytes()
    volumes = [
        Volume(mount=volume.mount, device=_device_name(index), read_only=volume.read_only)
        for index, volume in enumerate(resources.volumes)
    ]
    return code, volumes


def build_program_configuration(
    info: VmInfo, message: ProgramContent, resources: AlephProgramResources
) -> ProgramConfiguration:
    code, volumes = build_code_and_volumes(resources)
    input_data = read_input_data(resources.data_path)

    ipv4 = info.ipv4 or None
    ipv6: str | None = None
    if info.ipv6:
        # The runtime expects the guest IPv6 with its prefix; VmInfo carries
        # the bare address plus the tap network, recompose `addr/prefixlen`.
        prefix_len = info.ipv6_network.rsplit("/", 1)[1] if "/" in info.ipv6_network else ""
        ipv6 = f"{info.ipv6}/{prefix_len}" if prefix_len else info.ipv6

    if ipv4 and settings.ALLOW_VM_NETWORKING and not settings.DNS_NAMESERVERS:
        msg = "Invalid configuration: DNS nameservers missing"
        raise ValueError(msg)

    nameservers: list[str] = []
    if ipv4:
        nameservers += settings.DNS_NAMESERVERS_IPV4 or []
    if ipv6:
        nameservers += settings.DNS_NAMESERVERS_IPV6 or []

    authorized_keys: list[str] | None
    if settings.USE_DEVELOPER_SSH_KEYS:
        authorized_keys = settings.DEVELOPER_SSH_KEYS
    else:
        authorized_keys = message.authorized_keys

    return ProgramConfiguration(
        ip=ipv4,
        ipv6=ipv6,
        route=info.ipv4_gateway or None,
        ipv6_gateway=info.ipv6_gateway or None,
        dns_servers=nameservers,
        code=code,
        encoding=resources.code_encoding,
        entrypoint=resources.code_entrypoint,
        input_data=input_data,
        interface=resources.code_interface,
        vm_hash=str(info.vm_id),
        volumes=volumes,
        variables=message.variables,
        authorized_keys=authorized_keys,
    )


class ProgramGuestClient:
    """Owns the agent ends of the program guest protocols, keyed by VmId."""

    def __init__(self) -> None:
        self._configured: set[VmId] = set()
        self._guest_api_processes: dict[VmId, Process] = {}
        self._creation_locks: dict[VmId, asyncio.Lock] = {}

    def creation_lock(self, vm_id: VmId) -> asyncio.Lock:
        """Serialises get-or-create per VM: the runtime accepts exactly one
        configuration push per boot, so two concurrent cold requests must not
        both create-and-configure."""
        return self._creation_locks.setdefault(vm_id, asyncio.Lock())

    def is_ready(self, vm_id: VmId) -> bool:
        """True when this agent process configured the VM (safe to run code)."""
        return vm_id in self._configured

    async def setup_program(self, info: VmInfo, message: ProgramContent, resources: AlephProgramResources) -> None:
        """Bring a freshly-booted program VM to serving state: guest API up,
        configuration pushed. Must run exactly once per VM boot."""
        if not info.control_socket_path:
            msg = f"VM {info.vm_id} reports no control socket; was it created with program_mode?"
            raise VmSetupError(msg)
        await self._start_guest_api(info)
        await self._push_configuration(info, message, resources)
        self._configured.add(info.vm_id)

    async def _start_guest_api(self, info: VmInfo) -> None:
        vsock_path = Path(f"{info.control_socket_path}_53")
        vsock_path.parent.mkdir(parents=True, exist_ok=True)
        logger.debug("Starting guest API for %s on %s", info.vm_id, vsock_path)
        process = Process(
            target=run_guest_api,
            args=(vsock_path, ItemHash(str(info.vm_id)), settings.SENTRY_DSN, settings.DOMAIN_NAME),
        )
        process.start()
        while not vsock_path.exists():
            await asyncio.sleep(0.01)
        await chown_to_jailman(vsock_path)
        self._guest_api_processes[info.vm_id] = process

    async def _push_configuration(self, info: VmInfo, message: ProgramContent, resources) -> None:
        program_config = build_program_configuration(info, message, resources)
        runtime_config = RuntimeConfiguration(version=info.runtime_version or "1.0.0")
        versioned_config = program_config.to_runtime_format(runtime_config)
        payload = versioned_config.as_msgpack()
        length = f"{len(payload)}\n".encode()

        logger.debug("Pushing program configuration to %s", info.vm_id)
        reader, writer = await asyncio.open_unix_connection(path=info.control_socket_path)
        try:
            writer.write(b"CONNECT 52\n" + length + payload)
            await writer.drain()
            await asyncio.wait_for(reader.readline(), timeout=60)
            response_raw = await asyncio.wait_for(reader.read(1_000_000), timeout=60)
            response = ConfigurationResponse(**msgpack.loads(response_raw, raw=False))
            if response.success is False:
                logger.error("Configuration of %s failed: %s", info.vm_id, response.traceback)
                raise VmSetupError(response.error)
        finally:
            writer.close()
            await writer.wait_closed()

    async def run_code(self, info: VmInfo, scope: dict, *, timeout: float) -> bytes:
        """Execute one request inside the program VM and return the raw reply."""

        async def communicate(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bytes:
            payload = RunCodePayload(scope=scope)
            writer.write(b"CONNECT 52\n" + payload.as_msgpack())
            await writer.drain()
            ack: bytes = await reader.readline()
            logger.debug("ack=%s", ack.decode())
            return await reader.read()

        try:
            reader, writer = await asyncio.open_unix_connection(path=info.control_socket_path)
        except (ConnectionRefusedError, FileNotFoundError) as error:
            msg = "MicroVM may have crashed"
            raise VmInitNotConnectedError(msg) from error
        try:
            return await asyncio.wait_for(communicate(reader, writer), timeout=timeout)
        finally:
            writer.close()
            await writer.wait_closed()

    async def forget(self, vm_id: VmId) -> None:
        """Drop agent-side guest state for a VM (after delete/reap)."""
        self._configured.discard(vm_id)
        process = self._guest_api_processes.pop(vm_id, None)
        if process and process.is_alive():
            process.terminate()
            await asyncio.sleep(0)
            if process.is_alive():
                # Give it a moment, then force.
                await asyncio.sleep(2)
                if process.is_alive():
                    process.kill()

    async def forget_all(self) -> None:
        for vm_id in list(self._guest_api_processes):
            await self.forget(vm_id)
