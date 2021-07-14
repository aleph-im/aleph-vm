import asyncio
from typing import Dict, Hashable, Set


class PubSub:
    subscribers: Dict[Hashable, Set[asyncio.Queue]]

    def __init__(self):
        self.subscribers = {}

    async def subscribe(self, key):
        queue = asyncio.Queue()
        self.subscribers.setdefault(key, set()).add(queue)
        return await queue.get()

    async def msubscibe(self, *keys):
        """Subscribe to multiple keys"""
        queue = asyncio.Queue()
        for key in keys:
            self.subscribers.setdefault(key, set()).add(queue)
        return await queue.get()

    async def publish(self, key, value):
        for queue in self.subscribers.get(key, tuple()):
            await queue.put(value)
