import logging
import math
from decimal import Decimal
from typing import Iterable

import aiohttp
from eth_typing import HexAddress
from eth_utils import from_wei
from superfluid import CFA_V1, Web3FlowInfo

from aleph.vm.conf import settings
from aleph.vm.constants import HOUR, GiB, MiB
from aleph.vm.controllers.firecracker.program import AlephProgramResources
from aleph.vm.models import VmExecution
from aleph.vm.utils import get_path_size, to_normalized_address

logger = logging.getLogger(__name__)


async def get_balance(address: str) -> Decimal:
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


def get_stream(sender: str, receiver: str, chain) -> Decimal:
    """
    Get the stream of the user from the Superfluid API.
    See https://community.aleph.im/t/pay-as-you-go-using-superfluid/98/11
    """
    # TODO: Convert chain str to ID
    chain_id = 43113
    superfluid_instance = CFA_V1(settings.PAYMENT_RPC_API, chain_id)

    super_token: HexAddress = to_normalized_address(settings.PAYMENT_SUPER_TOKEN)
    sender_address: HexAddress = to_normalized_address(sender)
    receiver_address: HexAddress = to_normalized_address(receiver)

    flow_data: Web3FlowInfo = superfluid_instance.get_flow(super_token, sender_address, receiver_address)
    # TODO: Implement and use the SDK to make the conversion
    stream = from_wei(flow_data["flowRate"], "ether")
    return Decimal(stream)


async def compute_required_balance(executions: Iterable[VmExecution]) -> Decimal:
    """Get the balance required for the resources of the user from the messages and the pricing aggregate."""
    balance = Decimal(0)
    for execution in executions:
        balance += await compute_execution_hold_cost(execution)

    return Decimal(balance)


async def compute_execution_hold_cost(execution: VmExecution) -> Decimal:
    # TODO: Use PAYMENT_PRICING_AGGREGATE when possible
    compute_unit_cost = 200 if execution.persistent else 2000

    compute_units_required = _get_nb_compute_units(execution)
    compute_unit_multiplier = _get_compute_unit_multiplier(execution)

    compute_unit_price = Decimal(compute_units_required) * Decimal(compute_unit_multiplier) * Decimal(compute_unit_cost)
    additional_storage_hold_price = await _get_additional_storage_hold_price(execution)
    price = compute_unit_price + additional_storage_hold_price
    return Decimal(price)


async def _get_additional_storage_hold_price(execution: VmExecution) -> Decimal:
    # TODO: Use PAYMENT_PRICING_AGGREGATE when possible
    nb_compute_units = _get_nb_compute_units(execution)
    free_storage_per_compute_unit = 2 * GiB if not execution.persistent else 20 * GiB

    total_volume_size = await _get_execution_storage_size(execution)
    additional_storage = max(total_volume_size - (free_storage_per_compute_unit * nb_compute_units), 0)
    price = Decimal(additional_storage) / 20 / MiB
    return price


def _get_nb_compute_units(execution: VmExecution) -> int:
    """A compute unit is currently defined as: 1 vcpu, 2048 MB of memory."""
    cpu = execution.vm.hardware_resources.vcpus
    memory = math.ceil(execution.vm.hardware_resources.memory / 2048)
    nb_compute_units = cpu if cpu >= memory else memory
    return nb_compute_units


def _get_compute_unit_multiplier(execution: VmExecution) -> int:
    compute_unit_multiplier = 1
    if not execution.persistent and execution.message.environment.internet:
        compute_unit_multiplier += 1
    return compute_unit_multiplier


async def _get_execution_storage_size(execution: VmExecution) -> int:
    size = 0

    if execution.is_instance:
        size += execution.message.rootfs.size_mib * MiB
    elif execution.is_program:
        if isinstance(execution.resources, AlephProgramResources):
            size += await get_path_size(execution.resources.code_path)
            if execution.resources.data_path:
                size += await get_path_size(execution.resources.data_path)

    for volume in execution.resources.volumes:
        size += await get_path_size(volume.path_on_host)

    return size


async def get_required_flow(executions: Iterable[VmExecution]) -> Decimal:
    """Compute the flow required for the resources of the user from the messages and the pricing aggregate"""
    flow = Decimal(0)
    for execution in executions:
        flow += await compute_execution_flow_cost(execution)

    return Decimal(flow)


async def compute_execution_flow_cost(execution: VmExecution) -> Decimal:
    # TODO: Use PAYMENT_PRICING_AGGREGATE when possible
    compute_unit_cost_hour = 0.11 if execution.persistent else 0.011
    compute_unit_cost_second = compute_unit_cost_hour / HOUR

    compute_units_required = _get_nb_compute_units(execution)
    compute_unit_multiplier = _get_compute_unit_multiplier(execution)

    compute_unit_price = (
        Decimal(compute_units_required) * Decimal(compute_unit_multiplier) * Decimal(compute_unit_cost_second)
    )

    additional_storage_flow_price = await _get_additional_storage_flow_price(execution)
    price = compute_unit_price + additional_storage_flow_price

    return Decimal(price)


async def _get_additional_storage_flow_price(execution: VmExecution) -> Decimal:
    # TODO: Use PAYMENT_PRICING_AGGREGATE when possible
    additional_storage_hour_price = 0.000000977
    additional_storage_second_price = Decimal(additional_storage_hour_price) / Decimal(HOUR)
    nb_compute_units = _get_nb_compute_units(execution)
    free_storage_per_compute_unit = 2 * GiB if not execution.persistent else 20 * GiB

    total_volume_size = await _get_execution_storage_size(execution)
    additional_storage = max(
        Decimal(total_volume_size) - (Decimal(free_storage_per_compute_unit) * Decimal(nb_compute_units)), Decimal(0)
    )
    price = additional_storage / additional_storage_second_price / Decimal(MiB)
    return Decimal(price)
