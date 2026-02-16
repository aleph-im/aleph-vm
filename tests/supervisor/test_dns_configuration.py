# Avoid failures linked to nftables when initializing the global VmPool object
import os

os.environ["ALEPH_VM_ALLOW_VM_NETWORKING"] = "False"

from unittest import mock

import pytest

from aleph.vm.conf import Settings


class TestDnsNameserverSeparation:
    """Tests for DNS_NAMESERVERS_IPV4 and DNS_NAMESERVERS_IPV6 auto-population logic."""

    def test_ipv4_only_nameservers_are_correctly_separated(self):
        """IPv4-only nameservers should all go to DNS_NAMESERVERS_IPV4."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "8.8.4.4", "1.1.1.1"],
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
        assert settings.DNS_NAMESERVERS_IPV6 == []

    def test_ipv6_only_nameservers_are_correctly_separated(self):
        """IPv6-only nameservers should all go to DNS_NAMESERVERS_IPV6."""
        settings = Settings(
            DNS_NAMESERVERS=["2606:4700:4700::1111", "2001:4860:4860::8888"],
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        assert settings.DNS_NAMESERVERS_IPV4 == []
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111", "2001:4860:4860::8888"]

    def test_mixed_nameservers_are_correctly_separated(self):
        """Mixed IPv4/IPv6 nameservers should be separated into correct lists."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4"]
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111"]

    def test_ipv6_addresses_never_appear_in_ipv4_list(self):
        """IPv6 addresses should never appear in the IPv4 list."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "2606:4700:4700::1111", "8.8.4.4", "2001:4860:4860::8888"],
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # Verify no IPv6 addresses in IPv4 list
        for server in settings.DNS_NAMESERVERS_IPV4:
            assert ":" not in server, f"IPv6 address {server} found in IPv4 list"

        # Verify all IPv4 addresses are correct
        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4"]
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111", "2001:4860:4860::8888"]

    def test_multiple_setup_calls_do_not_cause_duplicates(self):
        """Calling setup() multiple times should not cause duplicate entries."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            # Call setup multiple times
            settings.setup()
            settings.setup()
            settings.setup()

        # Should still have only 2 IPv4 and 1 IPv6, not duplicates
        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4"]
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111"]

    def test_user_provided_ipv4_list_is_preserved(self):
        """User-provided DNS_NAMESERVERS_IPV4 should not be overwritten."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV4=["1.1.1.1"],  # User explicitly set this
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # User-provided list should be preserved
        assert settings.DNS_NAMESERVERS_IPV4 == ["1.1.1.1"]
        # IPv6 list should be auto-populated since it was None
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111"]

    def test_user_provided_ipv6_list_is_preserved(self):
        """User-provided DNS_NAMESERVERS_IPV6 should not be overwritten."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=["2001:4860:4860::8888"],  # User explicitly set this
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # IPv4 list should be auto-populated since it was None
        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4"]
        # User-provided list should be preserved
        assert settings.DNS_NAMESERVERS_IPV6 == ["2001:4860:4860::8888"]

    def test_user_provided_empty_lists_are_preserved(self):
        """User-provided empty lists should be preserved (not auto-populated)."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV4=[],  # User explicitly set empty
            DNS_NAMESERVERS_IPV6=[],  # User explicitly set empty
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # Empty lists should be preserved
        assert settings.DNS_NAMESERVERS_IPV4 == []
        assert settings.DNS_NAMESERVERS_IPV6 == []

    def test_empty_dns_nameservers_results_in_empty_lists(self):
        """Empty DNS_NAMESERVERS should result in empty IPv4 and IPv6 lists."""
        settings = Settings(
            DNS_NAMESERVERS=[],
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        assert settings.DNS_NAMESERVERS_IPV4 == []
        assert settings.DNS_NAMESERVERS_IPV6 == []

    def test_none_dns_nameservers_results_in_empty_lists(self):
        """None DNS_NAMESERVERS should result in empty IPv4 and IPv6 lists."""
        settings = Settings(
            DNS_NAMESERVERS=None,
            DNS_NAMESERVERS_IPV4=None,
            DNS_NAMESERVERS_IPV6=None,
            DNS_RESOLUTION=None,  # Disable auto-detection
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        assert settings.DNS_NAMESERVERS_IPV4 == []
        assert settings.DNS_NAMESERVERS_IPV6 == []


class TestDnsNameserverValidation:
    """Tests for validation of user-provided DNS_NAMESERVERS_IPV4 and DNS_NAMESERVERS_IPV6 lists."""

    def test_ipv6_addresses_filtered_from_user_provided_ipv4_list(self):
        """IPv6 addresses in user-provided DNS_NAMESERVERS_IPV4 should be filtered out."""
        settings = Settings(
            DNS_NAMESERVERS=["1.1.1.1"],
            # User incorrectly included IPv6 addresses in IPv4 list
            DNS_NAMESERVERS_IPV4=["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # IPv6 addresses should be filtered out from IPv4 list
        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4"]
        # IPv6 list should be auto-populated from DNS_NAMESERVERS
        assert settings.DNS_NAMESERVERS_IPV6 == []

    def test_ipv4_addresses_filtered_from_user_provided_ipv6_list(self):
        """IPv4 addresses in user-provided DNS_NAMESERVERS_IPV6 should be filtered out."""
        settings = Settings(
            DNS_NAMESERVERS=["2001:4860:4860::8888"],
            DNS_NAMESERVERS_IPV4=None,
            # User incorrectly included IPv4 addresses in IPv6 list
            DNS_NAMESERVERS_IPV6=["2606:4700:4700::1111", "8.8.8.8", "8.8.4.4"],
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # IPv4 list should be auto-populated from DNS_NAMESERVERS
        assert settings.DNS_NAMESERVERS_IPV4 == []
        # IPv4 addresses should be filtered out from IPv6 list
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111"]

    def test_production_bug_scenario_ipv6_in_ipv4_list_with_duplicates(self):
        """
        Reproduces the production bug where DNS_NAMESERVERS_IPV4 contained IPv6 addresses.

        Production data showed:
        - DNS_NAMESERVERS: ["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"]
        - DNS_NAMESERVERS_IPV4: ["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111", ...]  (with duplicates)
        - DNS_NAMESERVERS_IPV6: ["2606:4700:4700::1111"]
        """
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "8.8.4.4", "2606:4700:4700::1111"],
            # Simulating corrupted state with IPv6 in IPv4 list and duplicates
            DNS_NAMESERVERS_IPV4=[
                "8.8.8.8",
                "8.8.4.4",
                "2606:4700:4700::1111",
                "2606:4700:4700::1111",
                "2606:4700:4700::1111",
            ],
            DNS_NAMESERVERS_IPV6=["2606:4700:4700::1111"],
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # All IPv6 addresses should be filtered from IPv4 list
        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4"]
        # No IPv6 addresses should be present in IPv4 list
        for server in settings.DNS_NAMESERVERS_IPV4:
            assert ":" not in server, f"IPv6 address {server} found in IPv4 list"
        # IPv6 list should remain unchanged (valid IPv6 addresses)
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111"]

    def test_user_provided_ipv4_list_with_only_ipv6_becomes_empty(self):
        """User-provided IPv4 list with only IPv6 addresses should become empty after filtering."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8"],
            # User incorrectly set IPv4 list with only IPv6 addresses
            DNS_NAMESERVERS_IPV4=["2606:4700:4700::1111", "2001:4860:4860::8888"],
            DNS_NAMESERVERS_IPV6=None,
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # All addresses were IPv6, so IPv4 list should be empty after filtering
        assert settings.DNS_NAMESERVERS_IPV4 == []

    def test_user_provided_ipv6_list_with_only_ipv4_becomes_empty(self):
        """User-provided IPv6 list with only IPv4 addresses should become empty after filtering."""
        settings = Settings(
            DNS_NAMESERVERS=["2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV4=None,
            # User incorrectly set IPv6 list with only IPv4 addresses
            DNS_NAMESERVERS_IPV6=["8.8.8.8", "8.8.4.4"],
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # All addresses were IPv4, so IPv6 list should be empty after filtering
        assert settings.DNS_NAMESERVERS_IPV6 == []

    def test_mixed_valid_invalid_addresses_in_both_lists(self):
        """Both lists with mixed valid/invalid addresses should be properly filtered."""
        settings = Settings(
            DNS_NAMESERVERS=["1.1.1.1", "2001:4860:4860::8844"],
            # Mixed valid and invalid addresses in both lists
            DNS_NAMESERVERS_IPV4=["8.8.8.8", "2606:4700:4700::1111", "8.8.4.4", "2001:4860:4860::8888"],
            DNS_NAMESERVERS_IPV6=["2606:4700:4700::1111", "1.1.1.1", "2001:4860:4860::8888", "9.9.9.9"],
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()

        # Only IPv4 addresses remain in IPv4 list
        assert settings.DNS_NAMESERVERS_IPV4 == ["8.8.8.8", "8.8.4.4"]
        # Only IPv6 addresses remain in IPv6 list
        assert settings.DNS_NAMESERVERS_IPV6 == ["2606:4700:4700::1111", "2001:4860:4860::8888"]

    def test_validation_is_idempotent_multiple_setup_calls(self):
        """Calling setup() multiple times on already-filtered lists should be idempotent."""
        settings = Settings(
            DNS_NAMESERVERS=["8.8.8.8", "2606:4700:4700::1111"],
            DNS_NAMESERVERS_IPV4=["8.8.8.8", "2606:4700:4700::1111"],  # Invalid: contains IPv6
            DNS_NAMESERVERS_IPV6=["2606:4700:4700::1111", "8.8.8.8"],  # Invalid: contains IPv4
        )
        with mock.patch.object(settings, "NETWORK_INTERFACE", "eth0"):
            settings.setup()
            first_ipv4 = settings.DNS_NAMESERVERS_IPV4.copy()
            first_ipv6 = settings.DNS_NAMESERVERS_IPV6.copy()

            # Call setup again
            settings.setup()
            settings.setup()

        # Lists should be the same after multiple setup() calls
        assert settings.DNS_NAMESERVERS_IPV4 == first_ipv4 == ["8.8.8.8"]
        assert settings.DNS_NAMESERVERS_IPV6 == first_ipv6 == ["2606:4700:4700::1111"]
