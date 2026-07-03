"""The supervisor daemon: the hypervisor side of the process split.

Owns the VmPool (controllers, networking, systemd supervision) and serves the
gRPC contract on a Unix socket (`ALEPH_VM_SUPERVISOR_GRPC_SOCKET`, default
`EXECUTION_ROOT/supervisor.sock`). The agent process always connects to it
with `GrpcSupervisor`; there is no in-process mode.

On SIGTERM/SIGINT the gRPC server stops but VMs keep running: persistent VMs
live in systemd controller units and are reattached on the next daemon start
(`load_persistent_executions`), the same recovery path as a supervisor
restart in the monolith.

Run: `python -m aleph.vm.supervisor [--socket PATH]`
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import signal
from pathlib import Path

from aleph.vm.conf import settings

logger = logging.getLogger(__name__)


def default_socket_path() -> Path:
    # The setting always carries a value: conf derives EXECUTION_ROOT/supervisor.sock
    # when ALEPH_VM_SUPERVISOR_GRPC_SOCKET is unset. The fallback below only guards
    # against an explicitly emptied setting.
    if settings.SUPERVISOR_GRPC_SOCKET:
        return Path(settings.SUPERVISOR_GRPC_SOCKET)
    return Path(settings.EXECUTION_ROOT) / "supervisor.sock"


async def run_daemon(socket_path: Path) -> None:
    # Local imports: pulling the pool imports the controller/networking stack,
    # which must happen after settings.setup().
    from aleph.vm.pool import VmPool
    from aleph.vm.supervisor.grpc_server import serve_unix
    from aleph.vm.supervisor.local import LocalSupervisor
    from aleph.vm.utils import create_task_log_exceptions

    # The supervisor owns only its own DB (port mappings); pool.setup() sets it
    # up. The agent's executions DB is the agent process's concern.
    pool = VmPool()
    await pool.setup()

    logger.info("Reattaching executions that survived a previous run ...")
    # No guard here on purpose (kept symmetric with the in-process agent path):
    # per-VM reattach failures -- including a host missing the expected nftables
    # base chains -- are isolated inside load_persistent_executions, which marks
    # the VM failed and protects its live controller. Anything that still escapes
    # is systemic (an unparseable controller config, or a broken systemd/D-Bus)
    # and must abort startup rather than serve gRPC from a pool that does not
    # reflect what is actually running.
    await pool.load_persistent_executions()

    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists():
        # A previous daemon left its socket behind; a fresh bind needs it gone.
        socket_path.unlink()

    # Retry VMs whose reattach failed above (e.g. host networking not ready yet);
    # self-terminates once nothing is left to retry.
    retry_task = create_task_log_exceptions(pool.run_reattach_retry_loop(), name="reattach-retry-loop")

    supervisor = LocalSupervisor(pool)
    server = await serve_unix(supervisor, socket_path)

    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signum in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(signum, stop_event.set)

    logger.info("Supervisor daemon ready (socket: %s)", socket_path)
    await stop_event.wait()

    logger.info("Stopping the supervisor gRPC server (VMs keep running) ...")
    retry_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await retry_task
    await server.stop(grace=5)
    socket_path.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Aleph VM supervisor daemon (gRPC over a Unix socket)")
    parser.add_argument("--socket", type=Path, default=None, help="Unix socket path (default: settings)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | supervisord | %(levelname)s | %(message)s",
    )

    settings.setup()
    settings.check()

    socket_path = args.socket or default_socket_path()
    asyncio.run(run_daemon(socket_path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
