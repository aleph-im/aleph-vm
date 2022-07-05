"""
Small async PubSub implementation.
Used to trigger VM shutdown on updates.
"""

import asyncio
import logging
from typing import Dict, Hashable, Set

logger = logging.getLogger(__name__)


class PubSub:
    subscribers: Dict[Hashable, Set[asyncio.Queue]]

    def __init__(self):
        self.subscribers = {}

    async def subscribe(self, key):
        queue = asyncio.Queue()
        self.subscribers.setdefault(key, set()).add(queue)
        await queue.get()

        # Cleanup: remove the queue from the subscribers
        self.subscribers.get(key).discard(queue)
        # Remove keys with no remaining queue
        if not self.subscribers.get(key):
            self.subscribers.pop(key)

        return

    async def msubscribe(self, *keys):
        """Subscribe to multiple keys"""
        keys = tuple(key for key in keys if key is not None)
        logger.debug(f"msubscribe({keys})")

        queue = asyncio.Queue()

        # Register the queue on all keys
        for key in keys:
            self.subscribers.setdefault(key, set()).add(queue)

        # Wait for any subscription
        await queue.get()

        # Cleanup: remove the queue from the subscribers
        for key in keys:
            for subscriber in self.subscribers.values():
                subscriber.discard(queue)
                # Remove keys with no remaining queue
                if not self.subscribers.get(key):
                    self.subscribers.pop(key)

        return

    async def publish(self, key, value):
        for queue in self.subscribers.get(key, tuple()):
            await queue.put(value)
