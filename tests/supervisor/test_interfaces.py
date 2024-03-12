from ipaddress import IPv4Interface
from subprocess import run

import pytest
from pyroute2 import IPRoute

from aleph.vm.network.interfaces import (
    add_ip_address,
    create_tap_interface,
    delete_tap_interface,
    set_link_up,
)


def test_create_tap_interface():
    """Test the creation of a TAP interface and related error handling."""
    test_device_name = "test_tap"
    try:
        with IPRoute() as ipr:
            create_tap_interface(ipr, test_device_name)
            # Check that the interface was created
            assert run(["ip", "link", "show", test_device_name], check=False).returncode == 0
            # Create the interface a second time, which should be ignored
            create_tap_interface(ipr, test_device_name)
    finally:
        run(["ip", "tuntap", "del", test_device_name, "mode", "tap"], check=False)


def test_add_ip_address():
    """Test the addition of an IP address to an interface."""
    test_device_name = "test_tap"
    test_ipv4 = IPv4Interface(("10.10.10.10", 24))
    try:
        with IPRoute() as ipr:
            # We need an interface to add an address to
            create_tap_interface(ipr, test_device_name)
            # Add an IP address to the interface
            add_ip_address(ipr, test_device_name, test_ipv4)
            # Check that the address was added
            assert run(["ip", "address", "show", test_device_name], check=False).returncode == 0
            # Add the same address again, which should be ignored
            add_ip_address(ipr, test_device_name, test_ipv4)
    finally:
        # Delete the interface, ignoring any errors
        run(["ip", "tuntap", "del", test_device_name, "mode", "tap"], check=False)

    # Without an interface, the function should raise an error
    with pytest.raises(FileNotFoundError):
        add_ip_address(IPRoute(), test_device_name, test_ipv4)


def test_link_up_down():
    """Test the addition of an IP address to an interface."""
    test_device_name = "test_tap"
    try:
        with IPRoute() as ipr:
            # We need an interface to set the link up
            create_tap_interface(ipr, test_device_name)

            set_link_up(ipr, test_device_name)
            # Check that the interface is up
            assert run(["ip", "link", "show", test_device_name], check=False).returncode == 0
            # Delete the interface
            delete_tap_interface(ipr, test_device_name)
            # Check that the interface is down
            assert run(["ip", "link", "show", test_device_name], check=False).returncode != 0
    finally:
        # Delete the interface, ignoring any errors
        run(["ip", "tuntap", "del", test_device_name, "mode", "tap"], check=False)
