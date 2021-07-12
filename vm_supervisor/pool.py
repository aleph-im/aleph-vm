import asyncio
import json
import logging
import math
import sys
import time
from asyncio import Task

from dataclasses import dataclass
from typing import Dict, Optional, AsyncIterable, List

import aiohttp
from yarl import URL

import pydantic.error_wrappers
from aleph_message.models import ProgramContent, Message, BaseMessage, ProgramMessage
from vm_supervisor.conf import settings
from vm_supervisor.models import VmHash
from vm_supervisor.vm.firecracker_microvm import (
    AlephFirecrackerVM,
    AlephFirecrackerResources,
)

logger = logging.getLogger(__name__)


@dataclass
class StartedVM:
    vm: AlephFirecrackerVM
    program: ProgramContent
    timeout_task: Optional[asyncio.Task] = None


async def subscribe_via_ws(url) -> AsyncIterable[BaseMessage]:
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(url) as ws:
            logger.debug(f"Websocket connected on {url}")
            async for msg in ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    # Patch data format to match HTTP GET format
                    data["_id"] = {"$oid": data["_id"]}
                    try:
                        yield Message(**data)
                    except pydantic.error_wrappers.ValidationError as error:
                        print(error.json())
                        print(error.raw_errors)
                        raise
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    break


class VmPool:
    """Pool of VMs already started and used to decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.

    The counter is used by the VMs to set their tap interface name and the corresponding
    IPv4 subnet.
    """

    counter: int  # Used to provide distinct ids to network interfaces
    starting_vms: Dict[VmHash, bool]  # Lock containing hash of VMs being started
    started_vms: Dict[VmHash, StartedVM]  # Shared pool of VMs already started
    watchers: Dict[str, List[Task]]
    message_cache: Dict[str, ProgramMessage] = {}

    def __init__(self):
        self.counter = settings.START_ID_INDEX
        self.starting_vms = {}
        self.started_vms = {}
        self.watchers = {}

    async def create_a_vm(self, program: ProgramContent, vm_hash: VmHash) -> AlephFirecrackerVM:
        """Create a new Aleph Firecracker VM from an Aleph function message."""
        vm_resources = AlephFirecrackerResources(program, vm_hash)
        await vm_resources.download_all()
        self.counter += 1
        vm = AlephFirecrackerVM(
            vm_id=self.counter,
            vm_hash=vm_hash,
            resources=vm_resources,
            enable_networking=program.environment.internet,
            hardware_resources=program.resources,
        )
        try:
            await vm.setup()
            await vm.start()
            await vm.configure()
            await vm.start_guest_api()
            return vm
        except Exception:
            await vm.teardown()
            raise

    async def get_or_create(self, program: ProgramContent, vm_hash: VmHash) -> AlephFirecrackerVM:
        """Provision a VM in the pool, then return the first VM from the pool."""
        # Wait for a VM already starting to be available
        while self.starting_vms.get(vm_hash):
            await asyncio.sleep(0.01)

        started_vm = self.started_vms.get(vm_hash)
        if started_vm:
            if started_vm.timeout_task:
                started_vm.timeout_task.cancel()
            return started_vm.vm
        else:
            self.starting_vms[vm_hash] = True
            try:
                vm = await self.create_a_vm(program=program, vm_hash=vm_hash)
                self.started_vms[vm_hash] = StartedVM(vm=vm, program=program)
                return vm
            finally:
                del self.starting_vms[vm_hash]

    async def get(self, vm_hash: VmHash) -> Optional[AlephFirecrackerVM]:
        started_vm = self.started_vms.get(vm_hash)
        if started_vm:
            started_vm.timeout_task.cancel()
            return started_vm.vm
        else:
            return None

    def stop_after_timeout(self, vm_hash: VmHash, timeout: float = 1.0) -> None:
        """Keep a VM running for `timeout` seconds in case another query comes by."""
        print('SS', self.started_vms)

        if settings.FAKE_DATA:
            vm_hash = list(self.started_vms.keys())[0]

        started_vm = self.started_vms[vm_hash]

        if started_vm.timeout_task:
            logger.debug("VM already has a timeout. Extending it.")
            started_vm.timeout_task.cancel()

        loop = asyncio.get_event_loop()
        if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
            # Task can be named
            started_vm.timeout_task = loop.create_task(self.expire(vm_hash, timeout), name=vm_hash)
        else:
            started_vm.timeout_task = loop.create_task(self.expire(vm_hash, timeout))

    async def expire(self, vm_hash: VmHash, timeout: float) -> None:
        """Coroutine that will stop the VM after 'timeout' seconds."""
        await asyncio.sleep(timeout)
        started_vm = self.started_vms[vm_hash]
        del self.started_vms[vm_hash]
        await started_vm.vm.teardown()

    def watch_for_updates(self, original_message: ProgramMessage):
        loop = asyncio.get_event_loop()
        for ref in filter(None, (
                #message.item_hash,  # Ignore updates of the VM itself
                original_message.content.runtime.ref,  # Watch for runtime updates
                original_message.content.code.ref,     # Watch for code updates
                # Watch for data updates
                original_message.content.data.ref if original_message.content.data else None,
                # Watch for immutable volume updates
                *(volume.ref for volume in original_message.content.volumes if hasattr(volume, 'ref'))
        )):
            task = loop.create_task(
                self.watch_for_updates_task(
                    VmHash(original_message.item_hash), ref,
                    original_message.content.address, original_message.time))
            # Register task
            self.watchers[original_message.item_hash] = self.watchers.get(original_message.item_hash) or []
            self.watchers[original_message.item_hash].append(task)

    async def watch_for_updates_task(self, vm_hash: VmHash, ref: str, address: str,
                                     start_date: float):
        params = {
            "refs": ref,
            "addresses": address,  # Must be sent by the same address as the VM
            # TODO: Watch each resource based on it's own previous address, not the VM address
            "startDate": int(start_date),  # Only watch for updates after the VM has been published
        }
        # url = URL(f"{settings.API_SERVER}/api/ws0/messages").with_query(params)
        url = URL(f"{settings.API_SERVER}/api/ws0/messages").with_query({"startDate": math.floor(time.time())})

        print(f"URL, {url}")
        async for message in subscribe_via_ws(url):
            logger.info(f"Update received: {message.item_hash}")

            # Remove the VM from the cache
            print("Cache=", self.message_cache)

            try:
                del self.message_cache[vm_hash]
            except KeyError:
                pass

            # print("ALL_TASKS", asyncio.all_tasks())
            # for watcher in self.watchers.get(vm_hash, []):
            #     if not watcher.done():
            #         watcher.cancel()

            started_vm = self.started_vms.get(vm_hash)
            if started_vm:
                del self.started_vms[vm_hash]
                await started_vm.vm.teardown()
