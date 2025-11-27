from datetime import datetime, timedelta, timezone
from decimal import ROUND_FLOOR, Decimal
from logging import getLogger
from typing import Any, TypedDict

import aiohttp
from aleph_message.models import InstanceContent, ProgramContent

from aleph.vm.conf import settings

logger = getLogger(__name__)


class AggregateSettingsDict(TypedDict):
    compatible_gpus: list[Any]
    community_wallet_address: str
    community_wallet_timestamp: int


LAST_AGGREGATE_SETTINGS: AggregateSettingsDict | None = None
LAST_AGGREGATE_SETTINGS_FETCHED_AT: datetime | None = None
PRICE_PRECISION = 18  # Price precision


async def fetch_aggregate_settings() -> AggregateSettingsDict | None:
    """
    Get the settings Aggregate dict from the PyAleph API Aggregate.

    API Endpoint:
        GET /api/v0/aggregates/{address}.json?keys=settings

    For more details, see the PyAleph API documentation:
    https://github.com/aleph-im/pyaleph/blob/master/src/aleph/web/controllers/routes.py#L62
    """

    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/aggregates/{settings.SETTINGS_AGGREGATE_ADDRESS}.json?keys=settings"
        logger.info(f"Fetching settings aggregate from {url}")
        resp = await session.get(url)

        # Raise an error if the request failed
        resp.raise_for_status()

        resp_data = await resp.json()
        return resp_data["data"]["settings"]


async def update_aggregate_settings():
    global LAST_AGGREGATE_SETTINGS  # noqa: PLW0603
    global LAST_AGGREGATE_SETTINGS_FETCHED_AT  # noqa: PLW0603

    if (
        not LAST_AGGREGATE_SETTINGS
        or LAST_AGGREGATE_SETTINGS_FETCHED_AT
        and datetime.now(tz=timezone.utc) - LAST_AGGREGATE_SETTINGS_FETCHED_AT > timedelta(minutes=1)
    ):
        try:
            aggregate = await fetch_aggregate_settings()
            LAST_AGGREGATE_SETTINGS = aggregate
            LAST_AGGREGATE_SETTINGS_FETCHED_AT = datetime.now(tz=timezone.utc)

        except Exception:
            logger.exception("Failed to fetch aggregate settings")


async def get_aggregate_settings() -> AggregateSettingsDict | None:
    """The settings aggregate is a special aggregate  used to share some common settings for VM setup

    Ensure the cached version is up to date and return it"""
    await update_aggregate_settings()

    if not LAST_AGGREGATE_SETTINGS:
        logger.error("No setting aggregate")
    return LAST_AGGREGATE_SETTINGS


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
    if not LAST_AGGREGATE_SETTINGS:
        return []
    return LAST_AGGREGATE_SETTINGS["compatible_gpus"]


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
