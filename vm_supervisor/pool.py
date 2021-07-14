import asyncio
from _datetime import datetime
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
from .conf import settings
from .models import VmHash
from .pubsub import PubSub
from .vm.firecracker_microvm import (
    AlephFirecrackerVM,
    AlephFirecrackerResources,
)

logger = logging.getLogger(__name__)


class VmExecution:
    vm_hash: VmHash
    program: ProgramContent
    resources: Optional[AlephFirecrackerResources]
    vm: AlephFirecrackerVM = None

    defined_at: datetime = None
    preparing_at: Optional[datetime] = None
    prepared_at: Optional[datetime] = None
    starting_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    stopping_at: Optional[datetime] = None
    stopped_at: Optional[datetime] = None

    expire_task: Optional[asyncio.Task] = None

    @property
    def is_running(self):
        return self.starting_at and not (self.stopping_at)

    def __init__(self, vm_hash: VmHash, program: Optional[ProgramContent] = None):
        self.vm_hash = vm_hash
        self.program = program
        self.defined_at = datetime.now()

    async def prepare(self):
        """Download VM required files"""
        self.preparing_at = datetime.now()
        vm_resources = AlephFirecrackerResources(self.program, namespace=self.vm_hash)
        await vm_resources.download_all()
        self.prepared_at = datetime.now()
        self.resources = vm_resources

    async def create(self, address: int) -> AlephFirecrackerVM:
        self.starting_at = datetime.now()
        self.vm = vm = AlephFirecrackerVM(
            vm_id=address,
            vm_hash=self.vm_hash,
            resources=self.resources,
            enable_networking=self.program.environment.internet,
            hardware_resources=self.program.resources,
        )
        try:
            await vm.setup()
            await vm.start()
            await vm.configure()
            await vm.start_guest_api()
            self.started_at = datetime.now()
            return vm
        except Exception:
            await vm.teardown()
            raise

    def stop_after_timeout(self, timeout: float = 5.0) -> Task:
        if self.expire_task:
            logger.debug("VM already has a timeout. Extending it.")
            self.expire_task.cancel()

        loop = asyncio.get_event_loop()
        if sys.version_info.major >= 3 and sys.version_info.minor >= 8:
            # Task can be named
            self.expire_task = loop.create_task(self.expire(timeout),
                                                name=f"expire {self.vm.vm_id}")
        else:
            self.expire_task = loop.create_task(self.expire(timeout))
        return self.expire_task

    async def expire(self, timeout: float) -> None:
        """Coroutine that will stop the VM after 'timeout' seconds."""
        await asyncio.sleep(timeout)
        assert self.started_at
        if self.stopped_at or self.stopped_at:
            return
        self.stopping_at = datetime.now()
        await self.vm.teardown()
        self.stopped_at = datetime.now()

    def cancel_expiration(self) -> bool:
        if self.expire_task:
            self.expire_task.cancel()
            return True
        else:
            return False

    async def stop(self):
        self.stopping_at = datetime.now()
        await self.vm.teardown()
        self.stopped_at = datetime.now()

    def start_watching_for_updates(self, pubsub: PubSub):
        pool = asyncio.get_running_loop()
        pool.create_task(self.watch_for_updates(pubsub=pubsub))

    async def watch_for_updates(self, pubsub: PubSub):
        await pubsub.msubscibe(
            self.program.code.ref,
            self.program.runtime.ref,
        )
        await self.stop()


class VmPool:
    """Pool of VMs already started and used to decrease response time.
    After running, a VM is saved for future reuse from the same function during a
    configurable duration.

    The counter is used by the VMs to set their tap interface name and the corresponding
    IPv4 subnet.
    """

    counter: int  # Used to provide distinct ids to network interfaces
    executions: Dict[VmHash, VmExecution]
    message_cache: Dict[str, ProgramMessage] = {}

    def __init__(self):
        self.counter = settings.START_ID_INDEX
        self.executions = {}

    async def create_a_vm(self, program: ProgramContent, vm_hash: VmHash) -> VmExecution:
        """Create a new Aleph Firecracker VM from an Aleph function message."""
        execution = VmExecution(vm_hash=vm_hash, program=program)
        self.executions[vm_hash] = execution
        await execution.prepare()
        self.counter += 1
        await execution.create(address=self.counter)
        return execution

    async def get_or_create(self, program: ProgramContent, vm_hash: VmHash) -> VmExecution:
        """Provision a VM in the pool, then return the first VM from the pool."""
        # Wait for a VM already starting to be available
        execution: VmExecution = self.executions.get(vm_hash) \
                                 or await self.create_a_vm(program=program, vm_hash=vm_hash)
        execution.cancel_expiration()
        return execution

    async def get_running_vm(self, vm_hash: VmHash) -> Optional[VmExecution]:
        execution = self.executions.get(vm_hash)
        if execution and execution.is_running:
            execution.cancel_expiration()
            return execution
        else:
            return None
