import asyncio
import logging
from decimal import Decimal
from typing import Iterable, Optional

import aiohttp
from aleph_message.models import ItemHash, PaymentType
from eth_typing import HexAddress
from eth_utils import from_wei
from superfluid import CFA_V1, Web3FlowInfo

from aleph.vm.conf import settings
from aleph.vm.models import VmExecution
from aleph.vm.utils import to_normalized_address

logger = logging.getLogger(__name__)


async def fetch_balance_of_address(address: str) -> Decimal:
    """
    Get the balance of the user from the PyAleph API.

    API Endpoint:
        GET /api/v0/addresses/{address}/balance

    For more details, see the PyAleph API documentation:
    https://github.com/aleph-im/pyaleph/blob/master/src/aleph/web/controllers/routes.py#L62
    """

    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/{address}/balance"
        resp = await session.get(url)

        # Consider the balance as null if the address is not found
        if resp.status == 404:
            return Decimal(0)

        # Raise an error if the request failed
        resp.raise_for_status()

        resp_data = await resp.json()
        return resp_data["balance"]


async def fetch_execution_flow_price(item_hash: ItemHash) -> Decimal:
    """Fetch the flow price of an execution from the reference API server."""
    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/price/{item_hash}"
        resp = await session.get(url)
        # Raise an error if the request failed
        resp.raise_for_status()

        resp_data = await resp.json()
        required_flow: float = resp_data["required_tokens"]
        payment_type: Optional[str] = resp_data["payment_type"]

        if payment_type is None:
            raise ValueError("Payment type must be specified in the message")
        elif payment_type != PaymentType.superfluid:
            raise ValueError(f"Payment type {payment_type} is not supported")

        return Decimal(required_flow)


async def fetch_execution_hold_price(item_hash: ItemHash) -> Decimal:
    """Fetch the hold price of an execution from the reference API server."""
    async with aiohttp.ClientSession() as session:
        url = f"{settings.API_SERVER}/api/v0/price/{item_hash}"
        resp = await session.get(url)
        # Raise an error if the request failed
        resp.raise_for_status()

        resp_data = await resp.json()
        required_hold: float = resp_data["required_tokens"]
        payment_type: Optional[str] = resp_data["payment_type"]

        if payment_type not in (None, PaymentType.hold):
            raise ValueError(f"Payment type {payment_type} is not supported")

        return Decimal(required_hold)


class InvalidAddressError(ValueError):
    """The blockchain address could not be parsed."""

    pass


async def get_stream(sender: str, receiver: str, chain) -> Decimal:
    """
    Get the stream of the user from the Superfluid API.
    See https://community.aleph.im/t/pay-as-you-go-using-superfluid/98/11
    """
    # TODO: Convert chain str to ID
    chain_id = 43113
    superfluid_instance = CFA_V1(settings.PAYMENT_RPC_API, chain_id)

    try:
        super_token: HexAddress = to_normalized_address(settings.PAYMENT_SUPER_TOKEN)
    except ValueError as error:
        raise InvalidAddressError(f"Invalid token address '{settings.PAYMENT_SUPER_TOKEN}' - {error.args}") from error

    try:
        sender_address: HexAddress = to_normalized_address(sender)
    except ValueError as error:
        raise InvalidAddressError(f"Invalid sender address '{sender}' - {error.args}") from error

    try:
        receiver_address: HexAddress = to_normalized_address(receiver)
    except ValueError as error:
        raise InvalidAddressError(f"Invalid receiver address '{receiver}' - {error.args}") from error

    # Run the network request in a background thread and wait for it to complete.
    loop = asyncio.get_event_loop()
    flow_data: Web3FlowInfo = await loop.run_in_executor(
        None, superfluid_instance.get_flow, super_token, sender_address, receiver_address
    )
    # TODO: Implement and use the SDK to make the conversion
    stream = from_wei(flow_data["flowRate"], "ether")
    return Decimal(stream)


async def compute_required_balance(executions: Iterable[VmExecution]) -> Decimal:
    """Get the balance required for the resources of the user from the messages and the pricing aggregate."""
    costs = await asyncio.gather(*(fetch_execution_hold_price(execution.vm_hash) for execution in executions))
    return sum(costs, Decimal(0))


async def compute_required_flow(executions: Iterable[VmExecution]) -> Decimal:
    """Compute the flow required for a collection of executions, typically all executions from a specific address"""
    flows = await asyncio.gather(*(fetch_execution_flow_price(execution.vm_hash) for execution in executions))
    return sum(flows, Decimal(0))
