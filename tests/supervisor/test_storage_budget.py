import pytest

from aleph.vm.conf import settings
from aleph.vm.storage_budget import parse_budget


@pytest.mark.parametrize(
    ("value", "total", "expected"),
    [
        ("10%", 1000, 100),
        ("0%", 1000, 0),
        ("100%", 1000, 1000),
        ("512M", 0, 512 * 1024 * 1024),
        ("50G", 0, 50 * 1024**3),
        ("2T", 0, 2 * 1024**4),
        ("4096", 0, 4096),
        (4096, 0, 4096),
    ],
)
def test_parse_budget(value, total, expected):
    assert parse_budget(value, total) == expected


@pytest.mark.parametrize("value", ["", "ten percent", "-5%", "150%", "10X", "-1"])
def test_parse_budget_rejects_garbage(value):
    with pytest.raises(ValueError):
        parse_budget(value, 1000)


def test_settings_defaults():
    assert settings.VOLUME_RETENTION == "reap"
    assert settings.VOLUME_RETENTION_BUDGET == "10%"
    assert settings.VOLUME_RECONCILE_INTERVAL == 3600
    assert settings.VOLUME_CREATE_GUARD == 600
    assert settings.CACHE_BUDGET == "20%"
    assert settings.MAX_RUNTIME_ARCHIVE_SIZE == 100 * 1024**3
