from datetime import datetime, timezone
from decimal import ROUND_FLOOR, Decimal
from logging import getLogger

from aleph.vm.conf import settings
from aleph.vm.utils.aggregate import get_aggregate_settings

logger = getLogger(__name__)

PRICE_PRECISION = 18


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


async def get_authorized_allocation_signers() -> set[str]:
    """Effective allow-list of ETH addresses for the Aleph-EIP191-V1 scheduler
    auth path, lowercased for case-insensitive comparison against the recovered
    signer. Resolved with precedence: local override > settings aggregate >
    built-in default.

    1. ``settings.AUTHORIZED_ALLOCATION_SIGNERS`` (local override): if non-empty,
       used verbatim and nothing else is consulted. This gives operators an
       immediate, network-independent rotation/revocation path — they can add a
       new scheduler key or drop a compromised one without waiting for the
       aggregate's owner key to publish an update.
    2. The network settings aggregate's ``authorized_allocation_signers`` key:
       used when non-empty, so the foundation can rotate the scheduler key
       network-wide (a non-empty list replaces the built-in default below).
    3. ``settings.DEFAULT_ALLOCATION_SIGNERS`` (built-in): the fallback used when
       the override is unset and the aggregate yields no signers (unfetchable, or
       the key is absent/empty). Ships with the official scheduler so a fresh CRN
       works on day one and stays reachable if the aggregate is down. An empty
       aggregate list is treated as "no opinion" and falls back here rather than
       authorizing no one, so a stray empty publication can't brick scheduling.
    """
    local = settings.AUTHORIZED_ALLOCATION_SIGNERS
    if local:
        return {addr.lower() for addr in local}
    aggregate = await get_aggregate_settings()
    if aggregate:
        signers = aggregate.get("authorized_allocation_signers") or []
        if signers:
            return {addr.lower() for addr in signers}
    return {addr.lower() for addr in settings.DEFAULT_ALLOCATION_SIGNERS}
