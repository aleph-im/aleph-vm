import asyncio
import json
import logging
from pathlib import Path
from typing import cast

import qmp
from pydantic import BaseModel

logger = logging.getLogger(__name__)


class VmSevInfo(BaseModel):
    enabled: bool
    api_major: int
    api_minor: int
    build_id: int
    policy: int
    state: str
    handle: int


class QemuGuestAgentClient:
    """Minimal QEMU Guest Agent (QGA) client over a virtio-serial socket.

    QGA uses plain JSON request/response (no QMP capability negotiation).
    The guest must have qemu-guest-agent installed and running.
    """

    def __init__(self, socket_path: Path):
        self._socket_path = socket_path
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None

    async def connect(self) -> None:
        self._reader, self._writer = await asyncio.open_unix_connection(
            str(self._socket_path),
        )

    async def close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            await self._writer.wait_closed()
            self._writer = None
            self._reader = None

    async def command(self, cmd: str) -> int | str | dict:
        """Send a QGA command and return the result.

        Raises RuntimeError on QGA-level errors.
        """
        if self._writer is None or self._reader is None:
            msg = "QGA client not connected"
            raise RuntimeError(msg)

        request = json.dumps({"execute": cmd})
        self._writer.write(request.encode() + b"\n")
        await self._writer.drain()

        line = await asyncio.wait_for(self._reader.readline(), timeout=30)
        if not line:
            msg = "QGA socket closed unexpectedly"
            raise ConnectionError(msg)

        response = json.loads(line)
        if "error" in response:
            err = response["error"]
            msg = f"QGA error: {err.get('desc', err)}"
            raise RuntimeError(msg)
        return response.get("return")

    async def fsfreeze_freeze(self) -> int:
        """Freeze all freezable guest filesystems.

        Returns:
            Number of filesystems frozen.
        """
        return cast(int, await self.command("guest-fsfreeze-freeze"))

    async def fsfreeze_thaw(self) -> int:
        """Thaw all frozen guest filesystems.

        Returns:
            Number of filesystems thawed.
        """
        return cast(int, await self.command("guest-fsfreeze-thaw"))

    async def fsfreeze_status(self) -> str:
        """Check the freeze status of guest filesystems.

        Returns:
            'thawed' or 'frozen'
        """
        return cast(str, await self.command("guest-fsfreeze-status"))


class QemuVmClient:
    def __init__(self, vm):
        self.vm = vm
        if not (vm.qmp_socket_path and vm.qmp_socket_path.exists()):
            msg = "VM is not running (QMP socket missing)"
            raise RuntimeError(msg)
        client = qmp.QEMUMonitorProtocol(str(vm.qmp_socket_path))
        client.connect()
        self.qmp_client = client
        self._qga_client: QemuGuestAgentClient | None = None

    async def connect_qga(self) -> QemuGuestAgentClient:
        """Connect to the QGA socket and return the client."""
        if self._qga_client is not None:
            return self._qga_client
        qga_path: Path | None = getattr(self.vm, "qga_socket_path", None)
        if not qga_path or not qga_path.exists():
            msg = "QEMU Guest Agent socket not available. " "Ensure qemu-guest-agent is installed in the VM image."
            raise RuntimeError(msg)
        client = QemuGuestAgentClient(qga_path)
        await client.connect()
        self._qga_client = client
        return client

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        self.qmp_client.close()
        if self._qga_client is not None:
            # Schedule async close if loop is running, otherwise ignore
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._qga_client.close())
            except RuntimeError:
                pass
            self._qga_client = None

    def query_sev_info(self) -> VmSevInfo:
        caps = self.qmp_client.command("query-sev")
        return VmSevInfo(
            enabled=caps["enabled"],
            api_major=caps["api-major"],
            api_minor=caps["api-minor"],
            handle=caps["handle"],
            state=caps["state"],
            build_id=caps["build-id"],
            policy=caps["policy"],
        )

    def query_launch_measure(self) -> str:
        measure = self.qmp_client.command("query-sev-launch-measure")
        return measure["data"]

    def inject_secret(self, packet_header: str, secret: str) -> None:
        """Inject the secret in the SEV secret area.

        :param packet_header: The packet header, as a base64 string.
        :param secret: The encoded secret, as a base64 string.
        """
        self.qmp_client.command(
            "sev-inject-launch-secret",
            **{"packet-header": packet_header, "secret": secret},
        )

    def continue_execution(self) -> None:
        """Resume the execution of the VM."""
        self.qmp_client.command("cont")

    def query_status(self):
        """Get running status."""
        return self.qmp_client.command("query-status")

    async def guest_fsfreeze_freeze(self) -> int:
        """Freeze all freezable guest filesystems via QEMU Guest Agent."""
        qga = await self.connect_qga()
        return await qga.fsfreeze_freeze()

    async def guest_fsfreeze_thaw(self) -> int:
        """Thaw all frozen guest filesystems via QEMU Guest Agent."""
        qga = await self.connect_qga()
        return await qga.fsfreeze_thaw()

    async def guest_fsfreeze_status(self) -> str:
        """Check the freeze status of guest filesystems via QEMU Guest Agent."""
        qga = await self.connect_qga()
        return await qga.fsfreeze_status()
