import logging
from collections.abc import Coroutine

from aleph_message.models import AlephMessage
from aleph_message.models.execution.environment import Subscription

from aleph.vm.pool import VmPool
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
    listeners: list[AlephMessage]

    def __init__(self, pubsub: PubSub, pool: VmPool):
        self.pubsub = pubsub
        self.pool = pool
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
                    event = message.json()
                    # Register the listener in the list of coroutines to run asynchronously:
                    coroutines.append(run_code_on_event(vm_hash, event, self.pubsub, pool=self.pool))
                    break

        # Call all listeners asynchronously from the event loop:
        for coroutine in coroutines:
            create_task_log_exceptions(coroutine)

    def register(self, message: AlephMessage):
        if message.content.on.message:
            self.listeners.append(message)
        else:
            logger.debug(f"Program with no subscription cannot be registered in reactor listeners: {message.item_hash}")
