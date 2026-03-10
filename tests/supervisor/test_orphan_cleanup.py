"""Tests for orphan resource detection and cleanup functions."""

from unittest.mock import MagicMock, patch

import pytest

from aleph.vm.conf import settings
from aleph.vm.network.firewall import get_orphan_vm_chain_ids
from aleph.vm.network.interfaces import (
    get_orphan_tap_vm_ids,
    remove_orphan_tap_interfaces,
)


class TestGetOrphanVmChainIds:
    """Tests for get_orphan_vm_chain_ids chain-name parsing."""

    def _chain_names(self, vm_ids: list[int]) -> list[str]:
        prefix = settings.NFTABLES_CHAIN_PREFIX
        names = []
        for vm_id in vm_ids:
            names.append(f"{prefix}-vm-nat-{vm_id}")
            names.append(f"{prefix}-vm-filter-{vm_id}")
        return names

    @patch("aleph.vm.network.firewall.get_all_aleph_chains")
    def test_detects_orphan_ids(self, mock_chains):
        mock_chains.return_value = self._chain_names([1, 2, 3])
        result = get_orphan_vm_chain_ids(active_vm_ids={1})
        assert result == {2, 3}

    @patch("aleph.vm.network.firewall.get_all_aleph_chains")
    def test_no_orphans_when_all_active(self, mock_chains):
        mock_chains.return_value = self._chain_names([1, 2])
        result = get_orphan_vm_chain_ids(active_vm_ids={1, 2})
        assert result == set()

    @patch("aleph.vm.network.firewall.get_all_aleph_chains")
    def test_all_orphans_when_none_active(self, mock_chains):
        mock_chains.return_value = self._chain_names([5, 10])
        result = get_orphan_vm_chain_ids(active_vm_ids=set())
        assert result == {5, 10}

    @patch("aleph.vm.network.firewall.get_all_aleph_chains")
    def test_ignores_non_vm_chains(self, mock_chains):
        prefix = settings.NFTABLES_CHAIN_PREFIX
        mock_chains.return_value = [
            f"{prefix}-supervisor-nat",
            f"{prefix}-supervisor-filter",
            f"{prefix}-supervisor-prerouting",
        ]
        result = get_orphan_vm_chain_ids(active_vm_ids=set())
        assert result == set()

    @patch("aleph.vm.network.firewall.get_all_aleph_chains")
    def test_ignores_non_numeric_suffix(self, mock_chains):
        prefix = settings.NFTABLES_CHAIN_PREFIX
        mock_chains.return_value = [
            f"{prefix}-vm-nat-abc",
            f"{prefix}-vm-filter-",
        ]
        result = get_orphan_vm_chain_ids(active_vm_ids=set())
        assert result == set()

    @patch("aleph.vm.network.firewall.get_all_aleph_chains")
    def test_empty_chain_list(self, mock_chains):
        mock_chains.return_value = []
        result = get_orphan_vm_chain_ids(active_vm_ids={1, 2})
        assert result == set()

    @patch("aleph.vm.network.firewall.get_all_aleph_chains")
    def test_deduplicates_across_nat_and_filter(self, mock_chains):
        """A vm_id appearing in both nat and filter chains is returned once."""
        mock_chains.return_value = self._chain_names([42])
        result = get_orphan_vm_chain_ids(active_vm_ids=set())
        assert result == {42}


def _make_link(ifname: str) -> dict:
    """Build a minimal pyroute2 link dict."""
    return {"attrs": [("IFLA_IFNAME", ifname)]}


class TestGetOrphanTapVmIds:
    """Tests for get_orphan_tap_vm_ids interface-name parsing."""

    @patch("aleph.vm.network.interfaces.IPRoute")
    def test_detects_orphan_taps(self, mock_iproute_cls):
        ipr = MagicMock()
        ipr.get_links.return_value = [
            _make_link("vmtap1"),
            _make_link("vmtap2"),
            _make_link("vmtap3"),
        ]
        mock_iproute_cls.return_value.__enter__ = MagicMock(return_value=ipr)
        mock_iproute_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = get_orphan_tap_vm_ids(active_vm_ids={1})
        assert sorted(result) == [(2, "vmtap2"), (3, "vmtap3")]

    @patch("aleph.vm.network.interfaces.IPRoute")
    def test_ignores_non_vmtap_interfaces(self, mock_iproute_cls):
        ipr = MagicMock()
        ipr.get_links.return_value = [
            _make_link("eth0"),
            _make_link("lo"),
            _make_link("docker0"),
        ]
        mock_iproute_cls.return_value.__enter__ = MagicMock(return_value=ipr)
        mock_iproute_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = get_orphan_tap_vm_ids(active_vm_ids=set())
        assert result == []

    @patch("aleph.vm.network.interfaces.IPRoute")
    def test_ignores_non_numeric_vmtap(self, mock_iproute_cls):
        ipr = MagicMock()
        ipr.get_links.return_value = [_make_link("vmtapabc")]
        mock_iproute_cls.return_value.__enter__ = MagicMock(return_value=ipr)
        mock_iproute_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = get_orphan_tap_vm_ids(active_vm_ids=set())
        assert result == []

    @patch("aleph.vm.network.interfaces.IPRoute")
    def test_no_orphans_when_all_active(self, mock_iproute_cls):
        ipr = MagicMock()
        ipr.get_links.return_value = [
            _make_link("vmtap1"),
            _make_link("vmtap2"),
        ]
        mock_iproute_cls.return_value.__enter__ = MagicMock(return_value=ipr)
        mock_iproute_cls.return_value.__exit__ = MagicMock(return_value=False)

        result = get_orphan_tap_vm_ids(active_vm_ids={1, 2})
        assert result == []


class TestRemoveOrphanTapInterfaces:
    """Tests for remove_orphan_tap_interfaces counting accuracy."""

    @patch("aleph.vm.network.interfaces.IPRoute")
    @patch("aleph.vm.network.interfaces.get_orphan_tap_vm_ids")
    def test_counts_only_successful_deletions(self, mock_get_orphans, mock_iproute_cls):
        mock_get_orphans.return_value = [
            (1, "vmtap1"),
            (2, "vmtap2"),
            (3, "vmtap3"),
        ]
        ipr = MagicMock()
        # First deletion succeeds, second fails, third succeeds
        ipr.link_lookup.side_effect = [[10], [20], [30]]
        ipr.link.side_effect = [None, OSError("busy"), None]
        mock_iproute_cls.return_value.__enter__ = MagicMock(return_value=ipr)
        mock_iproute_cls.return_value.__exit__ = MagicMock(return_value=False)

        removed = remove_orphan_tap_interfaces(active_vm_ids=set())
        assert removed == 2

    @patch("aleph.vm.network.interfaces.IPRoute")
    @patch("aleph.vm.network.interfaces.get_orphan_tap_vm_ids")
    def test_returns_zero_when_no_orphans(self, mock_get_orphans, mock_iproute_cls):
        mock_get_orphans.return_value = []
        ipr = MagicMock()
        mock_iproute_cls.return_value.__enter__ = MagicMock(return_value=ipr)
        mock_iproute_cls.return_value.__exit__ = MagicMock(return_value=False)

        removed = remove_orphan_tap_interfaces(active_vm_ids=set())
        assert removed == 0
