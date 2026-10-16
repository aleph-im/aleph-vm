"""Move VMs off a guest IPv6 outside the current pool.

The operator flow for a pool change is: edit IPV6_ADDRESS_POOL, restart the
agent. This startup pass does the rest: every running VM whose address lies
outside the pool is rebuilt (a persistent VM through start_persistent_vm,
an on-demand program by retiring it so its next request recreates it). A
stopped VM is left stopped; its owner's next start rebuilds it.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv6Network

from aiohttp import web
from aleph_message.models import ItemHash

from aleph.vm.agent.capacity import CapacityManager
from aleph.vm.agent.expiry import ExpiryManager
from aleph.vm.agent.guest_ipv6 import stale_ipv6
from aleph.vm.agent.run import start_persistent_vm
from aleph.vm.agent.update_watcher import UpdateWatcher
from aleph.vm.agent.vm.program_client import ProgramGuestClient
from aleph.vm.agent.vm.retire import RetireReason, retire_vm
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import SupervisorError
from aleph.vm.supervisor_interface.types import VmId, VmInfo, VmStatus
from aleph.vm.utils import create_task_log_exceptions

logger = logging.getLogger(__name__)


@dataclass
class StalePassReport:
    checked: int = 0
    stale_running: list[VmId] = field(default_factory=list)
    stale_stopped: list[VmId] = field(default_factory=list)
    moved: list[VmId] = field(default_factory=list)
    failed: list[VmId] = field(default_factory=list)
    skipped: list[VmId] = field(default_factory=list)


async def _held_network(supervisor: Supervisor, info: VmInfo) -> str:
    """The network a VM holds: live for a running VM, from its spec for a
    stopped one. Empty when unknown."""
    if info.status == VmStatus.RUNNING:
        return info.ipv6.network_cidr
    if info.status == VmStatus.STOPPED:
        try:
            return (await supervisor.get_vm_spec(info.vm_id)).network.requested_ipv6
        except SupervisorError as error:
            logger.debug("No spec for %s while checking its IPv6: %s", info.vm_id, error)
    return ""


async def rebuild_stale_vms_once(
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    capacity: CapacityManager,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
    program_client: ProgramGuestClient,
    pubsub_getter: Callable[[], object | None],
) -> StalePassReport:
    report = StalePassReport()
    try:
        pool = IPv6Network(settings.IPV6_ADDRESS_POOL)
    except ValueError:
        logger.error("IPV6_ADDRESS_POOL %r does not parse; skipping the stale IPv6 pass", settings.IPV6_ADDRESS_POOL)
        return report

    stale: list[tuple[VmId, str]] = []
    for info in await supervisor.list_vms():
        if info.status not in (VmStatus.RUNNING, VmStatus.STOPPED):
            continue
        report.checked += 1
        network = await _held_network(supervisor, info)
        if not stale_ipv6(network):
            continue
        if info.status == VmStatus.STOPPED:
            report.stale_stopped.append(info.vm_id)
            continue
        report.stale_running.append(info.vm_id)
        stale.append((info.vm_id, network))
    logger.info(
        "IPv6 pool %s: %d VMs checked, %d running outside it (rebuilding), "
        "%d stopped outside it (rebuilt on their next start)",
        pool,
        report.checked,
        len(report.stale_running),
        len(report.stale_stopped),
    )

    # One at a time: each move is a VM reboot, and a burst would starve the
    # node of memory and download bandwidth.
    for vm_id, old_network in stale:
        vm_hash = ItemHash(str(vm_id))
        record = registry.get(vm_hash)
        if record is None:
            logger.warning("%s runs on stale IPv6 network %s but has no record; leaving it alone", vm_id, old_network)
            report.skipped.append(vm_id)
            continue
        try:
            if record.persistent:
                await start_persistent_vm(
                    vm_hash,
                    pubsub_getter(),
                    supervisor=supervisor,
                    registry=registry,
                    capacity=capacity,
                    expiry=expiry,
                    update_watcher=update_watcher,
                    recreate=True,
                )
                new_network = (await supervisor.get_vm(vm_id)).ipv6.network_cidr
                logger.info("Moved %s off stale IPv6 network %s to %s", vm_id, old_network, new_network)
            else:
                await retire_vm(vm_hash, RetireReason.RECREATE, supervisor=supervisor)
                await program_client.forget(vm_id)
                logger.info(
                    "Retired on-demand %s off stale IPv6 network %s; its next request recreates it", vm_id, old_network
                )
            report.moved.append(vm_id)
        except Exception:
            logger.exception("Could not move %s off stale IPv6 network %s", vm_id, old_network)
            report.failed.append(vm_id)
    return report


async def start_stale_ipv6_pass(app: web.Application) -> None:
    """on_startup hook: run the pass in the background so a slow rebuild
    never delays the agent's boot."""

    async def _run() -> None:
        await rebuild_stale_vms_once(
            supervisor=app["supervisor"],
            registry=app["vm_registry"],
            capacity=app["capacity"],
            expiry=app["expiry"],
            update_watcher=app["update_watcher"],
            program_client=app["program_client"],
            pubsub_getter=lambda: app.get("pubsub"),
        )

    app["_stale_ipv6_pass"] = create_task_log_exceptions(_run(), name="stale ipv6 pass")
