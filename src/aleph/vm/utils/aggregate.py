from logging import getLogger

import aiohttp

from aleph.vm.conf import settings

logger = getLogger(__name__)


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
