from typing import Any

import aiohttp

from aleph.vm.conf import settings


async def fetch_aggregate_settings() -> dict[str, Any] | None:
    """
    Get the settings Aggregate dict from the PyAleph API Aggregate.

    API Endpoint:
        GET /api/v0/aggregates/{address}.json?keys=settings

    For more details, see the PyAleph API documentation:
    https://github.com/aleph-im/pyaleph/blob/master/src/aleph/web/controllers/routes.py#L62
    """
    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/aggregates/{settings.SETTINGS_AGGREGATE_ADDRESS}.json?keys=settings"
        resp = await session.get(url)

        # Raise an error if the request failed
        resp.raise_for_status()

        resp_data = await resp.json()
        return resp_data["data"]["settings"]


async def update_aggregate_settings():
    aggregate_settings = await fetch_aggregate_settings()
    if aggregate_settings:
        settings.COMPATIBLE_GPUS = aggregate_settings["compatible_gpus"]
        settings.COMMUNITY_WALLET_ADDRESS = aggregate_settings["community_wallet_address"]
