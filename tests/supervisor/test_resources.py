from pathlib import Path
from unittest import mock

from aleph.vm.agent.resources import hugepages_free_bytes
from aleph.vm.resources import get_gpu_devices


def _make_hugepage_pool(root: Path, name: str, free: str) -> None:
    pool = root / name
    pool.mkdir(parents=True)
    (pool / "free_hugepages").write_text(free)


def test_hugepages_free_bytes_sums_all_pool_sizes(tmp_path):
    _make_hugepage_pool(tmp_path, "hugepages-2048kB", "1024\n")
    _make_hugepage_pool(tmp_path, "hugepages-1048576kB", "2\n")
    assert hugepages_free_bytes(tmp_path) == 1024 * 2048 * 1024 + 2 * 1048576 * 1024


def test_hugepages_free_bytes_without_hugepage_sysfs_is_zero(tmp_path):
    assert hugepages_free_bytes(tmp_path / "missing") == 0


def test_hugepages_free_bytes_skips_unreadable_pools(tmp_path):
    # A pool directory without the counter file, and one with garbage in it:
    # both are skipped, the readable pool is still counted.
    (tmp_path / "hugepages-2048kB").mkdir()
    _make_hugepage_pool(tmp_path, "hugepages-1048576kB", "garbage\n")
    _make_hugepage_pool(tmp_path, "hugepages-4096kB", "3\n")
    assert hugepages_free_bytes(tmp_path) == 3 * 4096 * 1024


def mock_is_kernel_enabled_gpu(pci_host: str) -> bool:
    value = True if pci_host == "01:00.0" else False
    return value


def test_get_gpu_devices():
    class DevicesReturn:
        stdout: str = (
            '00:1f.0 "ISA bridge [0601]" "Intel Corporation [8086]" "Device [7a06]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n00:1f.4 "SMBus [0c05]" "Intel Corporation [8086]" "Raptor Lake-S PCH SMBus Controller [7a23]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n00:1f.5 "Serial bus controller [0c80]" "Intel Corporation [8086]" "Raptor Lake SPI (flash) Controller [7a24]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n01:00.0 "VGA compatible controller [0300]" "NVIDIA Corporation [10de]" "AD104GL [RTX 4000 SFF Ada Generation] [27b0]" -ra1 -p00 "NVIDIA Corporation [10de]" "AD104GL [RTX 4000 SFF Ada Generation] [16fa]"'
            '\n01:00.1 "Audio device [0403]" "NVIDIA Corporation [10de]" "Device [22bc]" -ra1 -p00 "NVIDIA Corporation [10de]" "Device [16fa]"'
            '\n02:00.0 "Non-Volatile memory controller [0108]" "Samsung Electronics Co Ltd [144d]" "NVMe SSD Controller PM9A1/PM9A3/980PRO [a80a]" -p02 "Samsung Electronics Co Ltd [144d]" "NVMe SSD Controller PM9A1/PM9A3/980PRO [aa0a]"'
        )

    with mock.patch(
        "subprocess.run",
        return_value=DevicesReturn(),
    ):
        with mock.patch(
            "aleph.vm.resources.is_kernel_enabled_gpu",
            wraps=mock_is_kernel_enabled_gpu,
        ):
            expected_gpu_devices = get_gpu_devices()

            assert expected_gpu_devices[0].vendor == "NVIDIA"
            assert expected_gpu_devices[0].device_name == "AD104GL [RTX 4000 SFF Ada Generation]"
            assert expected_gpu_devices[0].device_class == "0300"
            assert expected_gpu_devices[0].pci_host == "01:00.0"
            assert expected_gpu_devices[0].device_id == "10de:27b0"


def test_disk_usage_counts_reclaimable_bytes_as_available(mocker):
    """What the node advertises must match what it will admit: retained
    volumes are evicted on demand, so they are available disk, not usage
    (spec section 1). Advertising less than admission accepts would make the
    scheduler stop sending work the node can still take."""
    from types import SimpleNamespace

    from aleph.vm.agent.resources import _disk_usage_from_pools

    mocker.patch("aleph.vm.agent.resources.pools_disk_usage", return_value=(1_000_000, 400_000))
    mocker.patch("aleph.vm.agent.resources.reclaimable_bytes", return_value=100_000)

    usage = _disk_usage_from_pools(SimpleNamespace(available_disk_bytes=0))

    assert usage.total_kB == 1000
    assert usage.available_kB == 500


def test_disk_usage_adds_reclaimable_to_the_supervisors_figure(mocker):
    from types import SimpleNamespace

    from aleph.vm.agent.resources import _disk_usage_from_pools

    mocker.patch("aleph.vm.agent.resources.pools_disk_usage", return_value=(1_000_000, 400_000))
    mocker.patch("aleph.vm.agent.resources.reclaimable_bytes", return_value=100_000)

    usage = _disk_usage_from_pools(SimpleNamespace(available_disk_bytes=200_000))

    assert usage.available_kB == 300
