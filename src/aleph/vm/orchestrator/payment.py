from decimal import Decimal
from typing import Iterable

from aleph.vm.models import VmExecution


async def get_balance(address: str) -> Decimal:
    """Get the balance of the user from the PyAleph."""
    # See https://github.com/aleph-im/pyaleph/blob/master/src/aleph/web/controllers/routes.py#L62
    # "/api/v0/addresses/{address}/balance"
    # TODO
    raise NotImplementedError()


def get_stream(sender, receiver, chain):
    # See https://community.aleph.im/t/pay-as-you-go-using-superfluid/98/11
    # TODO
    raise NotImplementedError()


async def get_required_balance(executions: Iterable[VmExecution]) -> Decimal:
    """Get the balance required for the resources of the user from the messages and the pricing aggregate."""
    # TODO
    raise NotImplementedError()


async def get_required_flow(executions: Iterable[VmExecution]) -> Decimal:
    """Compute the flow required for the resources of the user from the messages and the pricing aggregate"""
    # TODO
    raise NotImplementedError()
