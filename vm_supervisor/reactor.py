import asyncio
import logging
from typing import List, Dict, Coroutine

from aleph_message.models.program import Subscription

from aleph_message.models import Message, ProgramMessage
from vm_supervisor.pubsub import PubSub
from vm_supervisor.run import run_code_on_event

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
        raise ValueError("Unsupported value")


def subscription_matches(subscription: Subscription, message: ProgramMessage) -> bool:
    if not subscription:
        # Require at least one value to match
        return False
    for key, value in subscription.dict().items():
        if not is_equal_or_includes(value, getattr(message, key)):
            return False
    return True


class Reactor:

    pubsub: PubSub
    listeners: List[ProgramMessage]

    def __init__(self, pubsub: PubSub):
        self.pubsub = pubsub
        self.listeners = []

    async def trigger(self, message: Message):
        coroutines: List[Coroutine] = []

        for listener in self.listeners:
            if not listener.content.on.message:
                logger.warning(
                    "Program with no subscription was registered in reactor listeners: "
                    f"{listener.item_hash}"
                )
                continue

            for subscription in listener.content.on.message:
                if subscription_matches(subscription, message):
                    vm_hash = listener.item_hash
                    event = message.json()
                    # Register the listener in the list of coroutines to run asynchronously:
                    coroutines.append(run_code_on_event(vm_hash, event, self.pubsub))
                    break

        # Call all listeners asynchronously from the event loop:
        loop = asyncio.get_event_loop()
        for coroutine in coroutines:
            loop.create_task(coroutine)

    def register(self, message: ProgramMessage):
        if message.content.on.message:
            self.listeners.append(message)
        else:
            logger.debug(
                "Program with no subscription cannot be registered in reactor listeners: "
                f"{message.item_hash}"
            )
