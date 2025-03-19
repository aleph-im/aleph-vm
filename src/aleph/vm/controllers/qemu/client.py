import logging
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

    def query_status(self) -> None:
        """
        Get running status.
        """
        # {'status': 'prelaunch', 'singlestep': False, 'running': False}
        return self.qmp_client.command("query-status")
        
    def create_snapshot(self, snapshot_name: str) -> bool:
        """
        Create a VM snapshot using QMP. This will snapshot the VM's RAM state and disks.
        
        :param snapshot_name: Name of the snapshot
        :return: True if successful, False otherwise
        """
        try:
            logger.debug(f"Creating snapshot {snapshot_name} for VM {self.vm.vm_id}")
            self.qmp_client.command("savevm", **{"name": snapshot_name})
            return True
        except Exception as e:
            logger.error(f"Failed to create snapshot {snapshot_name} for VM {self.vm.vm_id}: {e}")
            return False
            
    def delete_snapshot(self, snapshot_name: str) -> bool:
        """
        Delete a VM snapshot using QMP.
        
        :param snapshot_name: Name of the snapshot to delete
        :return: True if successful, False otherwise
        """
        try:
            logger.debug(f"Deleting snapshot {snapshot_name} for VM {self.vm.vm_id}")
            self.qmp_client.command("delvm", **{"name": snapshot_name})
            return True
        except Exception as e:
            logger.error(f"Failed to delete snapshot {snapshot_name} for VM {self.vm.vm_id}: {e}")
            return False
            
    def list_snapshots(self) -> list[str]:
        """
        List all VM snapshots using QMP.
        
        :return: List of snapshot names
        """
        try:
            snapshots = self.qmp_client.command("query-snapshots")
            return [snapshot["name"] for snapshot in snapshots]
        except Exception as e:
            logger.error(f"Failed to list snapshots for VM {self.vm.vm_id}: {e}")
            return []
