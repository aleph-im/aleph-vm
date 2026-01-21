from unittest.mock import patch

import netifaces
import pytest

from aleph.vm.network.get_interface_ipv4 import get_interface_ipv4


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_returns_global_address_when_available(mock_netifaces):
    """Should return the global IPv4 address when one exists."""
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = netifaces.AF_INET
    mock_netifaces.ifaddresses.return_value = {netifaces.AF_INET: [{"addr": "8.8.8.8", "netmask": "255.255.255.0"}]}

    result = get_interface_ipv4("eth0")

    assert result == "8.8.8.8"


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_returns_global_address_over_private(mock_netifaces):
    """Should prefer global address over private when both exist."""
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = netifaces.AF_INET
    mock_netifaces.ifaddresses.return_value = {
        netifaces.AF_INET: [
            {"addr": "192.168.1.100", "netmask": "255.255.255.0"},
            {"addr": "185.180.200.50", "netmask": "255.255.255.0"},
        ]
    }

    result = get_interface_ipv4("eth0")

    assert result == "185.180.200.50"


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_fallback_to_first_address_when_no_global(mock_netifaces, caplog):
    """Should fallback to first address when no global address exists and log a warning."""
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = netifaces.AF_INET
    mock_netifaces.ifaddresses.return_value = {
        netifaces.AF_INET: [{"addr": "192.168.1.100", "netmask": "255.255.255.0"}]
    }

    result = get_interface_ipv4("eth0")

    assert result == "192.168.1.100"
    assert "No global IPv4 address found for interface eth0" in caplog.text
    assert "falling back to non-global address: 192.168.1.100" in caplog.text


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_fallback_to_first_private_address(mock_netifaces, caplog):
    """Should fallback to first private address when multiple non-global addresses exist."""
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = netifaces.AF_INET
    mock_netifaces.ifaddresses.return_value = {
        netifaces.AF_INET: [
            {"addr": "10.0.0.1", "netmask": "255.0.0.0"},
            {"addr": "172.16.0.1", "netmask": "255.255.0.0"},
            {"addr": "192.168.1.1", "netmask": "255.255.255.0"},
        ]
    }

    result = get_interface_ipv4("eth0")

    assert result == "10.0.0.1"
    assert "No global IPv4 address found for interface eth0" in caplog.text


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_fallback_to_link_local_when_only_option(mock_netifaces, caplog):
    """Should fallback to link-local address when it's the only option."""
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = netifaces.AF_INET
    mock_netifaces.ifaddresses.return_value = {netifaces.AF_INET: [{"addr": "169.254.1.1", "netmask": "255.255.0.0"}]}

    result = get_interface_ipv4("eth0")

    assert result == "169.254.1.1"
    assert "No global IPv4 address found for interface eth0" in caplog.text


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_raises_error_for_nonexistent_interface(mock_netifaces):
    """Should raise ValueError when interface doesn't exist."""
    mock_netifaces.interfaces.return_value = ["eth0", "lo"]

    with pytest.raises(ValueError, match="Interface wlan0 does not exist"):
        get_interface_ipv4("wlan0")


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_raises_error_when_no_ipv4_address(mock_netifaces):
    """Should raise ValueError when interface has no IPv4 address."""
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = netifaces.AF_INET
    mock_netifaces.ifaddresses.return_value = {}

    with pytest.raises(ValueError, match="No IPv4 address found for interface eth0"):
        get_interface_ipv4("eth0")


@patch("aleph.vm.network.get_interface_ipv4.netifaces")
def test_returns_first_global_when_multiple_globals(mock_netifaces):
    """Should return first global address when multiple global addresses exist."""
    mock_netifaces.interfaces.return_value = ["eth0"]
    mock_netifaces.AF_INET = netifaces.AF_INET
    mock_netifaces.ifaddresses.return_value = {
        netifaces.AF_INET: [
            {"addr": "8.8.8.8", "netmask": "255.255.255.0"},
            {"addr": "1.1.1.1", "netmask": "255.255.255.0"},
        ]
    }

    result = get_interface_ipv4("eth0")

    assert result == "8.8.8.8"
