import time
from enum import Enum

import qmp
from pydantic import BaseModel


class VmRunStatus(str, Enum):
    """QEMU VM run status values."""

    DEBUG = "debug"
    FINISH_MIGRATE = "finish-migrate"
    INMIGRATE = "inmigrate"
    INTERNAL_ERROR = "internal-error"
    IO_ERROR = "io-error"
    PAUSED = "paused"
    POSTMIGRATE = "postmigrate"
    PRELAUNCH = "prelaunch"
    RESTORE_VM = "restore-vm"
    RUNNING = "running"
    SAVE_VM = "save-vm"
    SHUTDOWN = "shutdown"
    SUSPENDED = "suspended"
    WATCHDOG = "watchdog"
    GUEST_PANICKED = "guest-panicked"
    COLO = "colo"


class VmStatus(BaseModel):
    """Response from QEMU query-status command."""

    status: VmRunStatus
    running: bool
    singlestep: bool = False

    @property
    def is_running(self) -> bool:
        """Check if VM is actively running."""
        return self.running and self.status == VmRunStatus.RUNNING

    @property
    def is_migrating(self) -> bool:
        """Check if VM is in migration-related state."""
        return self.status in (
            VmRunStatus.INMIGRATE,
            VmRunStatus.POSTMIGRATE,
            VmRunStatus.FINISH_MIGRATE,
        )

    @property
    def is_error(self) -> bool:
        """Check if VM is in an error state."""
        return self.status in (
            VmRunStatus.INTERNAL_ERROR,
            VmRunStatus.IO_ERROR,
            VmRunStatus.GUEST_PANICKED,
            VmRunStatus.SHUTDOWN,
        )


class VmSevInfo(BaseModel):
    enabled: bool
    api_major: int
    api_minor: int
    build_id: int
    policy: int
    state: str
    handle: int


class QemuVmClient:
    def __init__(self, vm):
        self.vm = vm
        if not (vm.qmp_socket_path and vm.qmp_socket_path.exists()):
            msg = "VM is not running"
            raise Exception(msg)
        client = qmp.QEMUMonitorProtocol(str(vm.qmp_socket_path))
        client.connect()

        # qmp_client = qmp.QEMUMonitorProtocol(address=("localhost", vm.qmp_port))
        self.qmp_client = client

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def close(self) -> None:
        self.qmp_client.close()

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
        """
        Injects the secret in the SEV secret area.

        :param packet_header: The packet header, as a base64 string.
        :param secret: The encoded secret, as a base64 string.
        """

        self.qmp_client.command(
            "sev-inject-launch-secret",
            **{"packet-header": packet_header, "secret": secret},
        )

    def continue_execution(self) -> None:
        """
        Resumes the execution of the VM.
        """
        self.qmp_client.command("cont")

    def query_status(self) -> VmStatus:
        """
        Get running status.

        :return: VmStatus with status, running, and singlestep fields
        """
        result = self.qmp_client.command("query-status")
        return VmStatus.model_validate(result)

    def migrate(self, destination_uri: str, bandwidth_limit_mbps: int | None = None) -> None:
        """
        Start live migration with block and incremental mode.

        Uses: migrate -d -b -i (detach, block, incremental)
        uri format: tcp:HOST:PORT

        :param destination_uri: The destination URI (e.g., "tcp:192.168.1.100:4444")
        :param bandwidth_limit_mbps: Optional bandwidth limit in MB/s
        """
        if bandwidth_limit_mbps:
            self.qmp_client.command("migrate_set_speed", value=bandwidth_limit_mbps * 1024 * 1024)

        # Enable migration capabilities for better performance and reliability
        capabilities = [
            {"capability": "xbzrle", "state": True},  # Compression
            {"capability": "auto-converge", "state": True},  # Auto-converge for busy VMs
        ]
        self.qmp_client.command("migrate-set-capabilities", capabilities=capabilities)

        # Start migration with block migration (copies disk + memory)
        # Note: 'blk' and 'inc' are deprecated in newer QEMU, but we use them for compatibility
        self.qmp_client.command("migrate", uri=destination_uri, blk=True, inc=True)

    def query_migrate(self) -> dict:
        """
        Query migration status.

        Returns dict with keys:
        - status: 'none', 'setup', 'cancelling', 'cancelled', 'active', 'postcopy-active',
                  'postcopy-paused', 'postcopy-recover', 'completed', 'failed', 'colo', 'pre-switchover'
        - total-time: Total elapsed time (ms)
        - downtime: Downtime (ms) for completed migrations
        - expected-downtime: Expected downtime
        - ram: RAM migration stats (transferred, remaining, total, etc.)
        - disk: Disk migration stats
        """
        return self.qmp_client.command("query-migrate")

    def migrate_cancel(self) -> None:
        """Cancel ongoing migration."""
        self.qmp_client.command("migrate_cancel")

    def guest_exec(self, command: str, args: list[str] | None = None, capture_output: bool = True) -> dict:
        """
        Execute a command in the guest via qemu-guest-agent.

        :param command: The command/path to execute (e.g., "/bin/bash")
        :param args: Arguments to pass to the command
        :param capture_output: Whether to capture stdout/stderr
        :return: Dict with 'pid' key for the started process
        """
        exec_args = {"path": command, "capture-output": capture_output}
        if args:
            exec_args["arg"] = args
        return self.qmp_client.command("guest-exec", **exec_args)

    def guest_exec_status(self, pid: int) -> dict:
        """
        Get the status of a guest-exec command.

        :param pid: The PID returned by guest_exec
        :return: Dict with 'exited', 'exitcode', 'out-data', 'err-data' keys
        """
        return self.qmp_client.command("guest-exec-status", pid=pid)

    def reconfigure_guest_network(
        self,
        new_ip: str,
        gateway: str,
        nameservers: list[str],
        interface: str = "ens3",
    ) -> dict:
        """
        Reconfigure guest network via qemu-guest-agent after migration.

        This updates the netplan configuration inside the guest VM with the new
        network settings and applies them.

        :param new_ip: New IP address with CIDR notation (e.g., "10.0.0.5/24")
        :param gateway: Gateway IP address (e.g., "10.0.0.1")
        :param nameservers: List of DNS server IPs (e.g., ["8.8.8.8", "8.8.4.4"])
        :param interface: Network interface name (default: "ens3")
        :return: Dict with 'pid' key for the started process
        """
        # Build nameservers YAML list
        ns_yaml = "\n".join(f"        - {ns}" for ns in nameservers)

        netplan_config = f"""network:
  version: 2
  ethernets:
    {interface}:
      addresses: [{new_ip}]
      routes:
        - to: default
          via: {gateway}
      nameservers:
        addresses:
{ns_yaml}
"""

        # Create a script that writes the netplan config and applies it
        # Use base64 encoding to avoid escaping issues
        import base64

        config_b64 = base64.b64encode(netplan_config.encode()).decode()

        script = f"""
echo '{config_b64}' | base64 -d > /etc/netplan/50-cloud-init.yaml
netplan apply
"""

        return self.guest_exec("/bin/bash", ["-c", script])

    def wait_for_guest_agent(self, timeout_seconds: int = 60) -> bool:
        """
        Wait for the qemu-guest-agent to become available.

        :param timeout_seconds: Maximum time to wait
        :return: True if agent is available, False if timeout
        """
        start_time = time.monotonic()
        while time.monotonic() - start_time < timeout_seconds:
            try:
                # Try to ping the guest agent
                self.qmp_client.command("guest-ping")
                return True
            except Exception:
                time.sleep(1)
        return False
