import json
import logging
import socket
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
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.settimeout(30)
        self._sock.connect(str(socket_path))

    def close(self) -> None:
        self._sock.close()

    def command(self, cmd: str) -> int | str | dict:
        """Send a QGA command and return the result.

        Raises RuntimeError on QGA-level errors.
        """
        request = json.dumps({"execute": cmd})
        self._sock.sendall(request.encode() + b"\n")

        buf = b""
        while True:
            chunk = self._sock.recv(4096)
            if not chunk:
                msg = "QGA socket closed unexpectedly"
                raise ConnectionError(msg)
            buf += chunk
            if b"\n" in buf:
                break

        response = json.loads(buf.split(b"\n", 1)[0])
        if "error" in response:
            err = response["error"]
            msg = f"QGA error: {err.get('desc', err)}"
            raise RuntimeError(msg)
        return response.get("return")


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

    def _get_qga(self) -> QemuGuestAgentClient:
        """Lazily connect to the QGA socket."""
        if self._qga_client is not None:
            return self._qga_client
        qga_path: Path | None = getattr(self.vm, "qga_socket_path", None)
        if not qga_path or not qga_path.exists():
            msg = "QEMU Guest Agent socket not available. " "Ensure qemu-guest-agent is installed in the VM image."
            raise RuntimeError(msg)
        self._qga_client = QemuGuestAgentClient(qga_path)
        return self._qga_client

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        self.qmp_client.close()
        if self._qga_client is not None:
            self._qga_client.close()
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
        """Inject the secret in the SEV secret area."""
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

    def guest_fsfreeze_freeze(self) -> int:
        """Freeze all freezable guest filesystems via QEMU Guest Agent.

        Returns:
            Number of filesystems frozen.
        """
        return cast(int, self._get_qga().command("guest-fsfreeze-freeze"))

    def guest_fsfreeze_thaw(self) -> int:
        """Thaw all frozen guest filesystems via QEMU Guest Agent.

        Returns:
            Number of filesystems thawed.
        """
        return cast(int, self._get_qga().command("guest-fsfreeze-thaw"))

    def guest_fsfreeze_status(self) -> str:
        """Check the freeze status of guest filesystems via QEMU Guest Agent.

        Returns:
            'thawed' or 'frozen'
        """
        return cast(str, self._get_qga().command("guest-fsfreeze-status"))
