from decimal import Decimal

import pytest

from aleph.vm.conf import settings
from aleph.vm.orchestrator.payment import (
    fetch_balance_of_address,
    fetch_credit_balance_of_address,
)


@pytest.fixture()
def mock_get_address_balance(mocker):
    # http://51.159.106.166:4024/api/v0/addresses/0x5f78199cd833c1dc1735bee4a7416caaE58Facca/balance
    fake = {
        "address": "0x555559cd833c1dc1735bee4a7416caaE58Facca",
        "balance": 57000.0,
        "details": {"AVAX": 3000.0, "BASE": 52000.0, "ETH": 2000.0},
        "locked_amount": 4010.008710650127,
        "credit_balance": 10000,
    }
    mocker.patch("aleph.vm.orchestrator.payment.get_address_balance", new=mocker.AsyncMock(return_value=fake))

    return fake


@pytest.mark.asyncio
async def test_fetch_balance_of_address(mocker, mock_get_address_balance):
    """ """
    mocker.patch.object(settings, "API_SERVER", "https://fake.aleph.cloud")
    balance = await fetch_balance_of_address("0x555559cd833c1dc1735bee4a7416caaE58Facca")
    assert balance == Decimal("57000")


@pytest.mark.asyncio
async def test_fetch_credit_balance_of_address(mocker, mock_get_address_balance):
    """ """
    mocker.patch.object(settings, "API_SERVER", "https://fake.aleph.cloud")
    balance = await fetch_credit_balance_of_address("0x555559cd833c1dc1735bee4a7416caaE58Facca")
    assert balance == Decimal("10000.0")


@pytest.mark.asyncio
async def test_fetch_credit_balance_of_address_empty_response(
    mocker,
):
    """ """
    mocker.patch.object(settings, "API_SERVER", "https://fake.aleph.cloud")
    mocker.patch("aleph.vm.orchestrator.payment.get_address_balance", new=mocker.AsyncMock(return_value={}))

    balance = await fetch_credit_balance_of_address("0x555559cd833c1dc1735bee4a7416caaE58Facca")
    assert balance == Decimal("0")


@pytest.mark.asyncio
async def test_fetch_balance_of_address_empty_response(
    mocker,
):
    """ """
    mocker.patch.object(settings, "API_SERVER", "https://fake.aleph.cloud")
    mocker.patch("aleph.vm.orchestrator.payment.get_address_balance", new=mocker.AsyncMock(return_value={}))

    balance = await fetch_balance_of_address("0x555559cd833c1dc1735bee4a7416caaE58Facca")
    assert balance == Decimal("0")
