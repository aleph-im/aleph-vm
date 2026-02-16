"""Tests for Interface.from_entrypoint() method."""

import pytest

from aleph.vm.controllers.firecracker.program import Interface


class TestInterfaceFromEntrypoint:
    """Tests for Interface.from_entrypoint()."""

    def test_asgi_entrypoint_auto_detected(self):
        """Entrypoints with ':' should be detected as ASGI."""
        assert Interface.from_entrypoint("main:app") == Interface.asgi

    def test_executable_entrypoint_auto_detected(self):
        """Entrypoints without ':' should be detected as executable."""
        assert Interface.from_entrypoint("run.sh") == Interface.executable

    def test_hint_asgi_overrides_auto_detection(self):
        """Explicit 'asgi' hint should return asgi even for executable-like entrypoint."""
        assert Interface.from_entrypoint("run.sh", interface_hint="asgi") == Interface.asgi

    def test_hint_executable_overrides_auto_detection(self):
        """Explicit 'executable' hint should return executable even for asgi-like entrypoint."""
        assert Interface.from_entrypoint("main:app", interface_hint="executable") == Interface.executable

    def test_hint_binary_maps_to_executable(self):
        """aleph-message uses 'binary' which should map to 'executable'."""
        assert Interface.from_entrypoint("main:app", interface_hint="binary") == Interface.executable

    def test_hint_none_falls_through_to_auto_detection(self):
        """None hint should use auto-detection."""
        assert Interface.from_entrypoint("main:app", interface_hint=None) == Interface.asgi
        assert Interface.from_entrypoint("run.sh", interface_hint=None) == Interface.executable

    def test_invalid_hint_falls_through_to_auto_detection(self):
        """Invalid hint should fall back to auto-detection."""
        assert Interface.from_entrypoint("main:app", interface_hint="invalid") == Interface.asgi
        assert Interface.from_entrypoint("run.sh", interface_hint="invalid") == Interface.executable
