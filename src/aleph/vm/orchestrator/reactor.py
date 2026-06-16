import logging
from collections.abc import Coroutine

from aleph_message.models import AlephMessage
from aleph_message.models.execution.environment import Subscription

from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.orchestrator.update_watcher import UpdateWatcher
from aleph.vm.orchestrator.vm.program_client import ProgramGuestClient
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.pool import VmPool
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.utils import create_task_log_exceptions

from .pubsub import PubSub
from .run import run_code_on_event

logger = logging.getLogger(__name__)


def is_equal_or_includes(value, compare_to) -> bool:
    if isinstance(value, str):
        return value == compare_to
    elif isinstance(value, dict):
        for subkey, subvalue in value.items():
            if not hasattr(compare_to, subkey):
                return False
            if not is_equal_or_includes(subvalue, getattr(compare_to, subkey)):
                return False
        return True
    else:
        msg = "Unsupported value"
        raise ValueError(msg)


def subscription_matches(subscription: Subscription, message: AlephMessage) -> bool:
    if not subscription:
        # Require at least one value to match
        return False
    for key, value in subscription.dict().items():
        if not is_equal_or_includes(value, getattr(message, key)):
            return False
    return True


class Reactor:
    pubsub: PubSub
    pool: VmPool
    supervisor: Supervisor
    expiry: ExpiryManager
    update_watcher: UpdateWatcher
    registry: AgentVmRegistry
    listeners: list[AlephMessage]

    def __init__(
        self,
        pubsub: PubSub,
        pool: VmPool,
        supervisor: Supervisor,
        expiry: ExpiryManager,
        update_watcher: UpdateWatcher,
        registry: AgentVmRegistry,
        program_client: ProgramGuestClient,
    ):
        self.pubsub = pubsub
        self.pool = pool
        self.supervisor = supervisor
        self.expiry = expiry
        self.update_watcher = update_watcher
        self.registry = registry
        self.program_client = program_client
        self.listeners = []

    async def trigger(self, message: AlephMessage):
        coroutines: list[Coroutine] = []

        for listener in self.listeners:
            if not listener.content.on.message:
                logger.warning(
                    r"Program with no subscription was registered in reactor listeners: {listener.item_hash}"
                )
                continue

            for subscription in listener.content.on.message:
                if subscription_matches(subscription, message):
                    vm_hash = listener.item_hash
                    event = message.model_dump_json()
                    # Register the listener in the list of coroutines to run asynchronously:
                    coroutines.append(
                        run_code_on_event(
                            vm_hash,
                            event,
                            self.pubsub,
                            pool=self.pool,
                            supervisor=self.supervisor,
                            expiry=self.expiry,
                            update_watcher=self.update_watcher,
                            registry=self.registry,
                            program_client=self.program_client,
                        )
                    )
                    break

        # Call all listeners asynchronously from the event loop:
        for coroutine in coroutines:
            create_task_log_exceptions(coroutine)

    def register(self, message: AlephMessage):
        if message.content.on.message:
            self.listeners.append(message)
        else:
            logger.debug(f"Program with no subscription cannot be registered in reactor listeners: {message.item_hash}")
