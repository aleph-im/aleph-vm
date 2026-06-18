import asyncio
import logging
from asyncio.subprocess import Process
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from aleph_message.models import ItemHash

from aleph.vm.controllers.qemu import AlephQemuInstance
from aleph.vm.controllers.qemu.instance import AlephQemuResources, ConfigurationType
from aleph.vm.network.interfaces import TapInterface
from aleph.vm.storage import get_existing_file
from aleph.vm.contract.types import HardwareResources

if TYPE_CHECKING:
    from aleph.vm.contract.types import CreateVmSpec

logger = logging.getLogger(__name__)


class AlephQemuConfidentialResources(AlephQemuResources):
    firmware_path: Path

    async def download_firmware(self):
        # Message path only: the spec path resolves the firmware before create
        # and uses from_spec (no download).
        assert self.message_content is not None
        firmware = self.message_content.environment.trusted_execution.firmware
        self.firmware_path = await get_existing_file(firmware)

    async def download_all(self):
        await asyncio.gather(
            self.download_runtime(),
            self.download_firmware(),
            self.download_volumes(),
        )

    @classmethod
    def from_spec(cls, spec: "CreateVmSpec", namespace: str) -> "AlephQemuConfidentialResources":
        """Build a message-free confidential resources holder from a CreateVmSpec.

        No download is performed: every path (rootfs, volumes, gpus, firmware)
        is already resolved on the spec. The firmware host path comes from the
        spec's TeeConfig (resolved agent-side, like every other resource).
        """
        # Local import keeps the supervisor.* dependency out of module load order.
        from aleph.vm.contract.errors import InvalidBackendError

        resources = super().from_spec(spec, namespace)
        if spec.tee is None or spec.tee.firmware_path is None:
            # SAFETY-CRITICAL: no firmware means no measured OVMF to attest
            # against. Refuse rather than risk an unprotected confidential boot.
            raise InvalidBackendError(
                "AlephQemuConfidentialResources.from_spec requires a resolved spec.tee.firmware_path"
            )
        resources.firmware_path = Path(spec.tee.firmware_path)
        return resources


class AlephQemuConfidentialInstance(AlephQemuInstance):
    vm_id: int
    vm_hash: ItemHash
    resources: AlephQemuConfidentialResources
    enable_console: bool
    enable_networking: bool
    hardware_resources: HardwareResources
    tap_interface: TapInterface | None = None
    vm_configuration: ConfigurationType | None
    is_instance: bool
    qemu_process: Process | None
    support_snapshot = False
    persistent = True
    _queue_cancellers: dict[asyncio.Queue, Callable] = {}
    confidential_policy: int

    def __repr__(self):
        return f"<AlephQemuInstance {self.vm_id}>"

    def __str__(self):
        return f"vm-{self.vm_id}"

    def __init__(
        self,
        vm_id: int,
        vm_hash: ItemHash,
        resources: AlephQemuConfidentialResources,
        confidential_policy: int,
        enable_networking: bool = False,
        hardware_resources: HardwareResources = HardwareResources(),
        tap_interface: TapInterface | None = None,
    ):
        super().__init__(vm_id, vm_hash, resources, enable_networking, hardware_resources, tap_interface)
        self.confidential_policy = confidential_policy

    async def setup(self):
        pass

    async def wait_for_init(self) -> None:
        """Wait for the init process of the instance to be ready."""
        # FIXME: Cannot ping since network is not set up yet.
        return
