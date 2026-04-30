import socket
from unittest.mock import AsyncMock, MagicMock, Mock, patch

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator.status import check_internet
from aleph.vm.orchestrator.views.host_status import (
    check_host_http_ipv4,
    check_host_http_ipv6,
    check_http_connectivity_with_fallback,
)


@pytest.mark.asyncio
async def test_check_internet_wrong_result_code():
    vm_id = ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe")

    mock_session = Mock()
    mock_session.get = MagicMock()

    mock_session.get.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"result": 200, "headers": {"Server": "nginx"}}
    )
    assert await check_internet(mock_session, vm_id) is True

    mock_session.get.return_value.__aenter__.return_value.json = AsyncMock(
        return_value={"result": 400, "headers": {"Server": "nginx"}}
    )
    assert await check_internet(mock_session, vm_id) is False


@pytest.mark.asyncio
async def test_fallback_stops_at_first_success():
    """Fallback returns True immediately on first successful URL."""
    calls = []

    async def mock_endpoint(url, socket_family=None, session=None):
        calls.append(url)
        return url == "http://first.example/"

    with (
        patch("aleph.vm.orchestrator.views.host_status.check_http_endpoint", side_effect=mock_endpoint),
        patch("aleph.vm.orchestrator.views.host_status.aiohttp.ClientSession") as mock_session_cls,
        patch("aleph.vm.orchestrator.views.host_status.aiohttp.TCPConnector"),
    ):
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        urls = ["http://first.example/", "http://second.example/", "http://third.example/"]
        result = await check_http_connectivity_with_fallback(urls, socket.AF_INET)

    assert result is True
    assert calls == ["http://first.example/"]


@pytest.mark.asyncio
async def test_fallback_tries_all_urls_on_failure():
    """Fallback tries every URL before returning False."""
    calls = []

    async def mock_endpoint(url, socket_family=None, session=None):
        calls.append(url)
        return False

    with (
        patch("aleph.vm.orchestrator.views.host_status.check_http_endpoint", side_effect=mock_endpoint),
        patch("aleph.vm.orchestrator.views.host_status.aiohttp.ClientSession") as mock_session_cls,
        patch("aleph.vm.orchestrator.views.host_status.aiohttp.TCPConnector"),
    ):
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        urls = ["http://a.example/", "http://b.example/", "http://c.example/"]
        result = await check_http_connectivity_with_fallback(urls, socket.AF_INET)

    assert result is False
    assert calls == urls


@pytest.mark.asyncio
async def test_fallback_stops_at_second_url():
    """Fallback stops as soon as a URL succeeds, skipping the rest."""
    calls = []

    async def mock_endpoint(url, socket_family=None, session=None):
        calls.append(url)
        return url == "http://second.example/"

    with (
        patch("aleph.vm.orchestrator.views.host_status.check_http_endpoint", side_effect=mock_endpoint),
        patch("aleph.vm.orchestrator.views.host_status.aiohttp.ClientSession") as mock_session_cls,
        patch("aleph.vm.orchestrator.views.host_status.aiohttp.TCPConnector"),
    ):
        mock_session_cls.return_value.__aenter__ = AsyncMock(return_value=MagicMock())
        mock_session_cls.return_value.__aexit__ = AsyncMock(return_value=False)

        urls = ["http://first.example/", "http://second.example/", "http://third.example/"]
        result = await check_http_connectivity_with_fallback(urls, socket.AF_INET)

    assert result is True
    assert calls == ["http://first.example/", "http://second.example/"]


@pytest.mark.asyncio
async def test_check_host_http_ipv4_returns_false_on_timeout():
    """@return_false_on_timeout catches TimeoutError and returns False."""
    with patch(
        "aleph.vm.orchestrator.views.host_status.check_http_connectivity_with_fallback",
        side_effect=TimeoutError,
    ):
        result = await check_host_http_ipv4()
    assert result is False


@pytest.mark.asyncio
async def test_check_host_http_ipv6_returns_false_on_timeout():
    with patch(
        "aleph.vm.orchestrator.views.host_status.check_http_connectivity_with_fallback",
        side_effect=TimeoutError,
    ):
        result = await check_host_http_ipv6()
    assert result is False
