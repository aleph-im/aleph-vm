import asyncio
import logging
from pathlib import Path

import aiohttp
from aiohttp import web

from aleph.vm.utils import create_task_log_exceptions

logger = logging.getLogger(__name__)

DISCOVERY_RETRY_INTERVAL = 5 * 60  # 5 minutes

CACHE_FILENAME = "node-hash"


class NodeIdentity:
    """Manages the node's own hash identity."""

    def __init__(
        self,
        node_hash: str | None,
        owner_address: str,
        domain_name: str,
        cache_dir: Path,
    ):
        self._explicit_hash = node_hash
        self._owner_address = owner_address
        self._domain_name = domain_name
        self._cache_dir = cache_dir
        self._resolved_hash: str | None = None

    def get_node_hash(self) -> str | None:
        return self._resolved_hash

    def resolve(self) -> None:
        """Resolve the node hash from setting or cache. Call once at startup."""
        if self._explicit_hash:
            self._resolved_hash = self._explicit_hash
            logger.info(f"Node hash set from config: {self._resolved_hash}")
            return

        cached = self._read_cache()
        if cached:
            self._resolved_hash = cached
            logger.info(f"Node hash loaded from cache: {self._resolved_hash}")
            return

        if not self._owner_address:
            logger.warning("Neither NODE_HASH nor OWNER_ADDRESS is set. " "Node will not know its own identity.")
            return

        # Auto-discovery needed — handled by the async discovery task.
        logger.info("Node hash not cached. Auto-discovery will attempt to resolve it.")

    def set_discovered_hash(self, node_hash: str) -> None:
        """Set the hash after successful API discovery and write to cache."""
        self._resolved_hash = node_hash
        self._write_cache(node_hash)
        logger.info(f"Node hash discovered and cached: {node_hash}")

    def needs_discovery(self) -> bool:
        """Return True if auto-discovery should be attempted."""
        return self._resolved_hash is None and self._explicit_hash is None and bool(self._owner_address)

    @property
    def owner_address(self) -> str:
        return self._owner_address

    @property
    def domain_name(self) -> str:
        return self._domain_name

    def _read_cache(self) -> str | None:
        cache_file = self._cache_dir / CACHE_FILENAME
        if cache_file.is_file():
            content = cache_file.read_text().strip()
            if content:
                return content
        return None

    def _write_cache(self, node_hash: str) -> None:
        cache_file = self._cache_dir / CACHE_FILENAME
        try:
            cache_file.write_text(node_hash)
        except OSError as e:
            logger.warning(f"Failed to write node hash cache to {cache_file}: {e}")


def _normalize_url(url: str) -> str:
    """Normalize a URL for comparison by stripping trailing slashes."""
    return url.rstrip("/")


async def discover_node_hash(identity: NodeIdentity, api_server: str) -> str | None:
    """Query the Aleph API to find this node's hash by owner + domain match.

    Returns the node hash if exactly one match is found, None otherwise.
    """
    expected_url = _normalize_url(f"https://{identity.domain_name}")
    params = {
        "addresses": identity.owner_address,
        "types": "corechan-operation",
    }

    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{api_server}/api/v0/posts.json", params=params) as resp:
                resp.raise_for_status()
                data = await resp.json()
    except Exception as e:
        logger.warning(f"Failed to query Aleph API for node discovery: {e}")
        return None

    posts = data.get("posts", [])
    matches: list[dict] = []
    for post in posts:
        try:
            content = post["content"]["content"]
            if content.get("action") != "create-resource-node":
                continue
            address = content.get("details", {}).get("address", "")
            if _normalize_url(address) == expected_url:
                matches.append(
                    {
                        "item_hash": post["item_hash"],
                        "name": content.get("details", {}).get("name", ""),
                        "address": address,
                    }
                )
        except (KeyError, TypeError):
            continue

    if len(matches) == 1:
        return matches[0]["item_hash"]
    elif len(matches) == 0:
        logger.info(f"No CRN registration found for owner {identity.owner_address} " f"matching URL {expected_url}")
        return None
    else:
        logger.warning(
            f"Multiple CRN registrations found for owner "
            f"{identity.owner_address}. Cannot auto-discover node hash. "
            f"Set ALEPH_VM_NODE_HASH explicitly. Matches: {matches}"
        )
        return None


async def _discovery_loop(identity: NodeIdentity, api_server: str) -> None:
    """Background loop: attempt API discovery, retry every 5 min on failure."""
    while identity.needs_discovery():
        node_hash = await discover_node_hash(identity, api_server)
        if node_hash:
            identity.set_discovered_hash(node_hash)
            return
        await asyncio.sleep(DISCOVERY_RETRY_INTERVAL)


async def start_node_hash_discovery(app: web.Application) -> None:
    """aiohttp on_startup hook. Resolve node hash and start background
    discovery if needed."""
    identity: NodeIdentity = app["node_identity"]
    identity.resolve()

    if identity.needs_discovery():
        from aleph.vm.conf import settings

        app["node_hash_discovery"] = create_task_log_exceptions(
            _discovery_loop(identity, settings.API_SERVER),
            name="node_hash_discovery",
        )


async def stop_node_hash_discovery(app: web.Application) -> None:
    """aiohttp on_cleanup hook."""
    task = app.get("node_hash_discovery")
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            logger.debug("Node hash discovery task cancelled")
