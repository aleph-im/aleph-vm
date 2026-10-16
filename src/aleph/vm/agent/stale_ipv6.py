"""Move VMs off a guest IPv6 outside the current pool.

The operator flow for a pool change is: edit IPV6_ADDRESS_POOL, restart the
agent. This startup pass does the rest: every running VM whose address lies
outside the pool is rebuilt (a persistent VM through rebuild_if_stale, an
on-demand program by retiring it so its next request recreates it). A stopped
VM is left stopped; its owner's next start rebuilds it.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from ipaddress import IPv6Network

from aiohttp import web
from aleph_message.models import ItemHash

from aleph.vm.agent.capacity import CapacityManager
from aleph.vm.agent.create_lock import vm_create_lock
from aleph.vm.agent.expiry import ExpiryManager
from aleph.vm.agent.guest_ipv6 import stale_ipv6
from aleph.vm.agent.pubsub import PubSub
from aleph.vm.agent.run import StaleRebuild, rebuild_if_stale
from aleph.vm.agent.update_watcher import UpdateWatcher
from aleph.vm.agent.vm.program_client import ProgramGuestClient
from aleph.vm.agent.vm.retire import RetireReason, retire_vm
from aleph.vm.agent.vm_registry import AgentVmRegistry
from aleph.vm.conf import settings
from aleph.vm.supervisor_interface.abc import Supervisor
from aleph.vm.supervisor_interface.errors import SupervisorError, VmNotFoundError
from aleph.vm.supervisor_interface.types import VmId, VmInfo, VmStatus
from aleph.vm.utils import create_task_log_exceptions

logger = logging.getLogger(__name__)

# The agent may start before the supervisor answers (host reboot, upgrade):
# retry the listing every interval, for 120 s in all.
_LIST_RETRY_INTERVAL_SECONDS = 5.0
_LIST_RETRY_ATTEMPTS = 25
# Below the agent unit's TimeoutStopSec (30 s): a move in flight gets this
# long to finish on shutdown before it is cancelled.
_STOP_GRACE_SECONDS = 20.0


@dataclass
class StalePassReport:
    checked: int = 0
    not_judged: list[VmId] = field(default_factory=list)
    stale_running: list[VmId] = field(default_factory=list)
    stale_stopped: list[VmId] = field(default_factory=list)
    moved: list[VmId] = field(default_factory=list)
    awaiting_init: list[VmId] = field(default_factory=list)
    failed: list[VmId] = field(default_factory=list)
    skipped: list[VmId] = field(default_factory=list)
    # A FAILED or STOPPING VM is rebuilt by its next start, which carries an in-pool address.
    left_to_start_paths: list[VmId] = field(default_factory=list)


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


async def _list_vms(supervisor: Supervisor, stop: asyncio.Event) -> list[VmInfo] | None:
    """The supervisor's VMs, retried while it does not answer. None when it
    never did, or the agent is stopping."""
    for attempt in range(_LIST_RETRY_ATTEMPTS):
        try:
            return await supervisor.list_vms()
        except (SupervisorError, OSError) as error:
            if attempt + 1 == _LIST_RETRY_ATTEMPTS:
                break
            logger.debug("The supervisor does not list VMs yet, retrying: %s", error)
        try:
            await asyncio.wait_for(stop.wait(), timeout=_LIST_RETRY_INTERVAL_SECONDS)
            return None
        except asyncio.TimeoutError:
            pass
    logger.error(
        "Could not list VMs after %ds; VMs outside the IPv6 pool %s are not rebuilt until the next agent restart",
        int(_LIST_RETRY_INTERVAL_SECONDS * (_LIST_RETRY_ATTEMPTS - 1)),
        settings.IPV6_ADDRESS_POOL,
    )
    return None


async def _retire_on_demand_if_stale(
    vm_hash: ItemHash,
    *,
    supervisor: Supervisor,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
    program_client: ProgramGuestClient,
) -> bool:
    """Retire an on-demand program still running on a stale address, judged
    afresh under the create lock. False when it no longer is."""
    vm_id = VmId(str(vm_hash))
    async with vm_create_lock(str(vm_hash)):
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            return False
        if info.status != VmStatus.RUNNING or not stale_ipv6(info.ipv6.network_cidr):
            logger.debug(
                "%s is %s on IPv6 network %r, not retiring it", vm_id, info.status.name, info.ipv6.network_cidr
            )
            return False
        expiry.cancel(vm_id)
        update_watcher.cancel(vm_id)
        await retire_vm(vm_hash, RetireReason.RECREATE, supervisor=supervisor)
        await program_client.forget(vm_id)
        return True


async def rebuild_stale_vms_once(
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    capacity: CapacityManager,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
    program_client: ProgramGuestClient,
    pubsub_getter: Callable[[], PubSub | None],
    stop: asyncio.Event | None = None,
) -> StalePassReport:
    report = StalePassReport()
    stop = stop or asyncio.Event()
    try:
        pool = IPv6Network(settings.IPV6_ADDRESS_POOL)
    except ValueError:
        logger.error("IPV6_ADDRESS_POOL %r does not parse; skipping the stale IPv6 pass", settings.IPV6_ADDRESS_POOL)
        return report

    listed = await _list_vms(supervisor, stop)
    if listed is None:
        return report

    stale: list[tuple[VmId, str]] = []
    for info in listed:
        if info.status in (VmStatus.DEFINED, VmStatus.BOOTING):
            # No live address yet to judge; a start path judges it once up.
            report.not_judged.append(info.vm_id)
            continue
        if info.status not in (VmStatus.RUNNING, VmStatus.STOPPED):
            report.left_to_start_paths.append(info.vm_id)
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
    noteworthy = report.stale_running or report.stale_stopped or report.not_judged or report.left_to_start_paths
    logger.log(
        logging.INFO if noteworthy else logging.DEBUG,
        "IPv6 pool %s: %d VMs checked, %d running outside it (rebuilding), "
        "%d stopped outside it (rebuilt on their next start), %d still starting (not judged), "
        "%d failed or stopping (left to their start paths)",
        pool,
        report.checked,
        len(report.stale_running),
        len(report.stale_stopped),
        len(report.not_judged),
        len(report.left_to_start_paths),
    )

    # One at a time: each move is a VM reboot, and a burst would starve the
    # node of memory and download bandwidth.
    for vm_id, old_network in stale:
        if stop.is_set():
            logger.info("Agent stopping: the stale IPv6 pass leaves the remaining VMs for the next start")
            break
        vm_hash = ItemHash(str(vm_id))
        record = registry.get(vm_hash)
        if record is None:
            logger.warning("%s runs on stale IPv6 network %s but has no record; leaving it alone", vm_id, old_network)
            report.skipped.append(vm_id)
            continue
        try:
            if record.persistent:
                outcome = await rebuild_if_stale(
                    vm_hash,
                    pubsub_getter(),
                    supervisor=supervisor,
                    registry=registry,
                    capacity=capacity,
                    expiry=expiry,
                    update_watcher=update_watcher,
                )
                if outcome is StaleRebuild.SKIPPED:
                    report.skipped.append(vm_id)
                    continue
                if outcome is StaleRebuild.MOVED_AWAITING_INIT:
                    logger.info(
                        "Moved %s off stale IPv6 network %s; it now awaits its owner's confidential session "
                        "(/control/machine/%s/confidential/initialize)",
                        vm_id,
                        old_network,
                        vm_id,
                    )
                    report.awaiting_init.append(vm_id)
                else:
                    try:
                        new_network = (await supervisor.get_vm(vm_id)).ipv6.network_cidr
                    except SupervisorError as error:
                        logger.info(
                            "Moved %s off stale IPv6 network %s (its new address could not be read: %s)",
                            vm_id,
                            old_network,
                            error,
                        )
                    else:
                        logger.info("Moved %s off stale IPv6 network %s to %s", vm_id, old_network, new_network)
            else:
                retired = await _retire_on_demand_if_stale(
                    vm_hash,
                    supervisor=supervisor,
                    expiry=expiry,
                    update_watcher=update_watcher,
                    program_client=program_client,
                )
                if not retired:
                    report.skipped.append(vm_id)
                    continue
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
    stop = asyncio.Event()

    async def _run() -> None:
        await rebuild_stale_vms_once(
            supervisor=app["supervisor"],
            registry=app["vm_registry"],
            capacity=app["capacity"],
            expiry=app["expiry"],
            update_watcher=app["update_watcher"],
            program_client=app["program_client"],
            pubsub_getter=lambda: app.get("pubsub"),
            stop=stop,
        )

    app["_stale_ipv6_stop"] = stop
    app["_stale_ipv6_pass"] = create_task_log_exceptions(_run(), name="stale ipv6 pass")


async def stop_stale_ipv6_pass(app: web.Application) -> None:
    """on_cleanup hook: let a move in flight finish, then stop the pass. A move
    cancelled halfway would leave the VM retired and not recreated."""
    task = app.get("_stale_ipv6_pass")
    if task is None:
        return
    stop = app.get("_stale_ipv6_stop")
    if stop is not None:
        stop.set()
    try:
        await asyncio.wait_for(asyncio.shield(task), timeout=_STOP_GRACE_SECONDS)
    except asyncio.TimeoutError:
        logger.warning("The stale IPv6 pass did not finish within %ds; cancelling it", int(_STOP_GRACE_SECONDS))
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    except Exception:
        logger.debug("The stale IPv6 pass ended with an error", exc_info=True)
