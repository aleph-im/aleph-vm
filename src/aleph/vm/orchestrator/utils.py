from datetime import datetime, timezone
from decimal import ROUND_FLOOR, Decimal
from logging import getLogger
from typing import Any, TypedDict

from aleph_message.models import InstanceContent, ProgramContent

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


def get_execution_disk_size(message: InstanceContent | ProgramContent) -> int:
    disk_size_mib = 0

    # For Programs the disk size depends on the runtime
    # TODO: Find the real size of the runtime and for the code volumes
    if isinstance(message, InstanceContent):
        disk_size_mib = message.rootfs.size_mib

    # For volumes, only the persistent and ephemeral volumes have a size field
    # TODO: Find the real size of Inmutable volumes
    for volume in message.volumes:
        if getattr(volume, "size_mib", None):
            disk_size_mib += volume.size_mib

    return disk_size_mib
