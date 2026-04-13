from datetime import datetime, timezone
from decimal import ROUND_FLOOR, Decimal
from logging import getLogger
from typing import Any, TypedDict

from aleph.vm.conf import settings
from aleph.vm.orchestrator.cache import AsyncTTLCache
from aleph.vm.orchestrator.http import get_session

logger = getLogger(__name__)


class AggregateSettingsDict(TypedDict):
    compatible_gpus: list[Any]
    community_wallet_address: str
    community_wallet_timestamp: int


PRICE_PRECISION = 18

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


async def get_community_wallet_address() -> str | None:
    setting_aggr = await get_aggregate_settings()
    return setting_aggr and setting_aggr.get("community_wallet_address")


async def get_community_wallet_start() -> datetime:
    """Community wallet start time.

    After this timestamp. New PAYG must include a payment to the community wallet"""
    setting_aggr = await get_aggregate_settings()
    if setting_aggr is None or "community_wallet_timestamp" not in setting_aggr:
        return datetime.now(tz=timezone.utc)
    timestamp = setting_aggr["community_wallet_timestamp"]
    start_datetime = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    return start_datetime


async def is_after_community_wallet_start(dt: datetime | None = None) -> bool:
    """Community wallet start time"""
    if not dt:
        dt = datetime.now(tz=timezone.utc)
    start_dt = await get_community_wallet_start()
    return dt > start_dt


def format_cost(v: Decimal | str, p: int = PRICE_PRECISION) -> Decimal:
    return Decimal(v).quantize(Decimal(1) / Decimal(10**p), ROUND_FLOOR)


def get_compatible_gpus() -> list[Any]:
    """Return compatible GPUs from the cached settings aggregate."""
    cached = _settings_cache.get("settings")
    if not cached:
        return []
    return cached["compatible_gpus"]


# ---- Runtimes aggregate ----

_runtimes_cache = AsyncTTLCache(ttl_seconds=300.0)


class RuntimeEntry(TypedDict, total=False):
    id: str
    name: str
    type: str  # "program", "instance", "rescue", "firmware"
    item_hash: str
    default: bool
    firmware_hash: str  # only for type == "firmware"


async def fetch_runtimes_aggregate() -> list[RuntimeEntry]:
    """Fetch the runtimes aggregate from the Aleph API."""
    session = get_session()
    url = f"{settings.API_SERVER}/api/v0/aggregates/" f"{settings.SETTINGS_AGGREGATE_ADDRESS}.json?keys=runtimes"
    logger.debug("Fetching runtimes aggregate from %s", url)
    resp = await session.get(url)
    resp.raise_for_status()
    resp_data = await resp.json()
    return resp_data["data"]["runtimes"]


async def get_runtimes() -> list[RuntimeEntry]:
    """Return the runtimes list, fetching and caching as needed."""
    cached = _runtimes_cache.get("runtimes")
    if cached is not None:
        return cached

    try:
        runtimes = await fetch_runtimes_aggregate()
        _runtimes_cache.set("runtimes", runtimes)
        return runtimes
    except Exception:
        logger.exception("Failed to fetch runtimes aggregate")
        return []


async def get_runtime_by_id(runtime_id: str) -> RuntimeEntry | None:
    """Find a specific runtime entry by its id."""
    runtimes = await get_runtimes()
    for entry in runtimes:
        if entry.get("id") == runtime_id:
            return entry
    return None


async def get_default_runtime(runtime_type: str) -> RuntimeEntry | None:
    """Find the default runtime entry for a given type.

    Falls back to the first entry of that type if none is marked
    as default, so the caller always gets a result when at least
    one entry of the requested type exists.
    """
    runtimes = await get_runtimes()
    first_of_type: RuntimeEntry | None = None
    for entry in runtimes:
        if entry.get("type") != runtime_type:
            continue
        if entry.get("default"):
            return entry
        if first_of_type is None:
            first_of_type = entry
    return first_of_type
