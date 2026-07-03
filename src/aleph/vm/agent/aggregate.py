from logging import getLogger
from typing import Any, TypedDict

import aiohttp
from pydantic import BaseModel, Field, ValidationError

from aleph.vm.conf import settings
from aleph.vm.utils.cache import AsyncTTLCache
from aleph.vm.utils.http import get_session

logger = getLogger(__name__)


class CompatibleGPU(BaseModel):
    """Shape of one ``compatible_gpus`` entry in the settings aggregate."""

    vendor: str = Field(description="GPU vendor name")
    model: str = Field(description="GPU model name")
    name: str = Field(description="GPU full name")
    device_id: str = Field(description="GPU device id code including vendor_id and model_id")


class AggregateSettingsDict(TypedDict):
    compatible_gpus: list[Any]
    community_wallet_address: str
    community_wallet_timestamp: int
    # Optional in practice (older aggregates omit it); accessed via .get().
    authorized_allocation_signers: list[str]


_settings_cache = AsyncTTLCache(ttl_seconds=60.0)


async def fetch_aggregate_settings() -> AggregateSettingsDict | None:
    """Fetch the settings aggregate from the PyAleph API."""
    session = get_session()
    url = f"{settings.API_SERVER}/api/v0/aggregates/{settings.SETTINGS_AGGREGATE_ADDRESS}.json?keys=settings"
    logger.info(f"Fetching settings aggregate from {url}")
    resp = await session.get(url)
    resp.raise_for_status()

    resp_data = await resp.json()
    return resp_data["data"]["settings"]


async def get_aggregate_settings() -> AggregateSettingsDict | None:
    """Return the settings aggregate, fetching and caching as needed."""
    cached = _settings_cache.get("settings")
    if cached is not None:
        return cached

    try:
        aggregate = await fetch_aggregate_settings()
        _settings_cache.set("settings", aggregate)
        return aggregate
    except Exception:
        logger.exception("Failed to fetch aggregate settings")
        return None


async def update_aggregate_settings() -> None:
    """Refresh the settings aggregate cache if stale."""
    await get_aggregate_settings()


def get_compatible_gpus() -> list[CompatibleGPU]:
    """Return the validated GPU whitelist from the cached settings aggregate.

    The aggregate is remote data: a malformed entry is skipped with a warning
    rather than propagating (a raise here would take down every consumer,
    e.g. the public usage endpoint) and older aggregates may omit the key."""
    cached = _settings_cache.get("settings")
    if not cached:
        return []
    gpus = []
    for entry in cached.get("compatible_gpus") or []:
        try:
            gpus.append(CompatibleGPU.model_validate(entry))
        except ValidationError:
            logger.warning(f"Skipping malformed compatible_gpus aggregate entry: {entry!r}")
    return gpus


async def get_user_aggregate(addr: str, keys_arg: list[str]) -> dict:
    """
    Get the settings Aggregate dict from the PyAleph API Aggregate.

    API Endpoint:
        GET /api/v0/aggregates/{address}.json?keys=settings

    For more details, see the PyAleph API documentation:
    https://github.com/aleph-im/pyaleph/blob/master/src/aleph/web/controllers/routes.py#L62
    """

    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/aggregates/{addr}.json"
        logger.info(f"Fetching aggregate from {url}")
        resp = await session.get(url, params={"keys": ",".join(keys_arg)})
        # No aggregate for the user
        if resp.status == 404:
            return {}
        # Raise an error if the request failed

        resp.raise_for_status()

        resp_data = await resp.json()
        return resp_data["data"] or {}


async def get_user_settings(addr: str, key) -> dict:
    aggregate = await get_user_aggregate(addr, [key])
    return aggregate.get(key, {})
