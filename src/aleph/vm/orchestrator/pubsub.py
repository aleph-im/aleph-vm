"""
Small async PubSub implementation.
Used to trigger VM shutdown on updates.
"""

import asyncio
import logging
from collections.abc import Hashable

from aleph_message.models import AlephMessage, ChainRef, ItemHash

logger = logging.getLogger(__name__)


class PubSub:
    subscribers: dict[Hashable, set[asyncio.Queue[set]]]

    def __init__(self):
        self.subscribers = {}

    async def subscribe(self, key):
        queue: asyncio.Queue[AlephMessage] = asyncio.Queue()
        self.subscribers.setdefault(key, set()).add(queue)
        await queue.get()

        # Cleanup: remove the queue from the subscribers
        subscriber = self.subscribers.get(key)
        if subscriber:
            subscriber.discard(queue)
        # Remove keys with no remaining queue
        if not self.subscribers.get(key):
            self.subscribers.pop(key)

    async def msubscribe(self, *keys):
        """Subscribe to multiple keys"""
        keys = tuple(key for key in keys if key is not None)
        logger.debug(f"msubscribe({keys})")

        queue: asyncio.Queue[AlephMessage] = asyncio.Queue()

        # Register the queue on all keys
        for key in keys:
            self.subscribers.setdefault(key, set()).add(queue)

        # Wait for any subscription
        await queue.get()

        # Cleanup: remove the queue from the subscribers
        for key in keys:
            for subscriber in list(self.subscribers.values()):
                subscriber.discard(queue)
                # Remove keys with no remaining queue (empty set remaining)
                if self.subscribers.get(key) == set():
                    self.subscribers.pop(key)

    async def publish(self, key: ItemHash | str | ChainRef, value: AlephMessage):
        for queue in self.subscribers.get(key, ()):
            await queue.put(value)
