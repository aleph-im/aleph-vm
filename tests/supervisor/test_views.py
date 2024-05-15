import tempfile
from copy import deepcopy
from pathlib import Path
from unittest import mock
from unittest.mock import call

import pytest
from aiohttp import web
from aleph_message.models import InstanceContent
from pytest_mock import MockerFixture

from aleph.vm.conf import settings
from aleph.vm.models import VmExecution
from aleph.vm.orchestrator.supervisor import setup_webapp
from aleph.vm.pool import VmPool
from aleph.vm.sevclient import SevClient


@pytest.fixture()
def mock_instance_content():
    fake = {
        "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "time": 1713874241.800818,
        "allow_amend": False,
        "metadata": None,
        "authorized_keys": None,
        "variables": None,
        "environment": {"reproducible": False, "internet": True, "aleph_api": True, "shared_cache": False},
        "resources": {"vcpus": 1, "memory": 256, "seconds": 30, "published_ports": None},
        "payment": {"type": "superfluid", "chain": "BASE"},
        "requirements": None,
        "replaces": None,
        "rootfs": {
            "parent": {"ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"},
            "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            "use_latest": True,
            "comment": "",
            "persistence": "host",
            "size_mib": 1000,
        },
    }

    return fake


@pytest.mark.asyncio
async def test_allocation_fails_on_invalid_item_hash(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid item_hash is provided."""
    app = setup_webapp(pool=None)
    client = await aiohttp_client(app)
    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    response: web.Response = await client.post(
        "/control/allocations", json={"persistent_vms": ["not-an-ItemHash"]}, headers={"X-Auth-Signature": "test"}
    )
    assert response.status == 400
    response = await response.json()
    for error in response:
        error.pop("url", None)

    assert response == [
        {
            "loc": ["persistent_vms", 0],
            "msg": "Value error, Could not determine hash type: 'not-an-ItemHash'",
            "type": "value_error",
            "ctx": {"error": "Could not determine hash type: 'not-an-ItemHash'"},
            "input": "not-an-ItemHash",
        },
    ]


@pytest.mark.asyncio
async def test_system_usage(aiohttp_client, mocker, mock_app_with_pool):
    """Test that the usage system endpoints responds. No auth needed"""

    client = await aiohttp_client(await mock_app_with_pool)
    response: web.Response = await client.get("/about/usage/system")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert "cpu" in resp
    assert resp["cpu"]["count"] > 0


FAKE_SYSTEM_INFO = {
    "cpu": {
        "id": "cpu",
        "class": "processor",
        "claimed": True,
        "handle": "DMI:0400",
        "description": "CPU",
        "product": "AMD EPYC 7763 64-Core Processor",
        "vendor": "Advanced Micro Devices [AMD]",
        "physid": "400",
        "businfo": "cpu@0",
        "version": "25.1.1",
        "slot": "CPU 0",
        "units": "Hz",
        "size": 2000000000,
        "capacity": 2000000000,
        "width": 64,
        "configuration": {"cores": "8", "enabledcores": "8", "microcode": "167776681", "threads": "1"},
        "capabilities": {
            "fpu": "mathematical co-processor",
            "fpu_exception": "FPU exceptions reporting",
            "wp": True,
            "vme": "virtual mode extensions",
            "de": "debugging extensions",
            "pse": "page size extensions",
            "tsc": "time stamp counter",
            "msr": "model-specific registers",
            "pae": "4GB+ memory addressing (Physical Address Extension)",
            "mce": "machine check exceptions",
            "cx8": "compare and exchange 8-byte",
            "apic": "on-chip advanced programmable interrupt controller (APIC)",
            "sep": "fast system calls",
            "mtrr": "memory type range registers",
            "pge": "page global enable",
            "mca": "machine check architecture",
            "cmov": "conditional move instruction",
            "pat": "page attribute table",
            "pse36": "36-bit page size extensions",
            "clflush": True,
            "mmx": "multimedia extensions (MMX)",
            "fxsr": "fast floating point save/restore",
            "sse": "streaming SIMD extensions (SSE)",
            "sse2": "streaming SIMD extensions (SSE2)",
            "ht": "HyperThreading",
            "syscall": "fast system calls",
            "nx": "no-execute bit (NX)",
            "mmxext": "multimedia extensions (MMXExt)",
            "fxsr_opt": True,
            "pdpe1gb": True,
            "rdtscp": True,
            "rep_good": True,
            "nopl": True,
            "cpuid": True,
            "extd_apicid": True,
            "tsc_known_freq": True,
            "pni": True,
            "pclmulqdq": True,
            "ssse3": True,
            "fma": True,
            "cx16": True,
            "pcid": True,
            "sse4_1": True,
            "sse4_2": True,
            "x2apic": True,
            "movbe": True,
            "popcnt": True,
            "tsc_deadline_timer": True,
            "aes": True,
            "xsave": True,
            "avx": True,
            "f16c": True,
            "rdrand": True,
            "hypervisor": True,
            "lahf_lm": True,
            "cmp_legacy": True,
            "svm": True,
            "cr8_legacy": True,
            "abm": True,
            "sse4a": True,
            "misalignsse": True,
            "3dnowprefetch": True,
            "osvw": True,
            "perfctr_core": True,
            "invpcid_single": True,
            "ssbd": True,
            "ibrs": True,
            "ibpb": True,
            "stibp": True,
            "vmmcall": True,
            "fsgsbase": True,
            "tsc_adjust": True,
            "bmi1": True,
            "avx2": True,
            "smep": True,
            "bmi2": True,
            "erms": True,
            "invpcid": True,
            "rdseed": True,
            "adx": True,
            "clflushopt": True,
            "clwb": True,
            "sha_ni": True,
            "xsaveopt": True,
            "xsavec": True,
            "xgetbv1": True,
            "xsaves": True,
            "clzero": True,
            "xsaveerptr": True,
            "wbnoinvd": True,
            "arat": True,
            "npt": True,
            "nrip_save": True,
            "umip": True,
            "pku": True,
            "vaes": True,
            "vpclmulqdq": True,
            "rdpid": True,
            "fsrm": True,
            "arch_capabilities": True,
        },
    },
    "memory": {
        "id": "memory",
        "class": "memory",
        "claimed": True,
        "handle": "DMI:1000",
        "description": "System Memory",
        "physid": "1000",
        "units": "bytes",
        "size": 17179869184,
        "configuration": {"errordetection": "multi-bit-ecc"},
        "capabilities": {"ecc": "Multi-bit error-correcting code (ECC)"},
        "children": [
            {
                "id": "bank",
                "class": "memory",
                "claimed": True,
                "handle": "DMI:1100",
                "description": "DIMM RAM",
                "vendor": "QEMU",
                "physid": "0",
                "slot": "DIMM 0",
                "units": "bytes",
                "size": 17179869184,
            }
        ],
    },
}


@pytest.mark.asyncio
async def test_system_usage_mock(aiohttp_client, mocker, mock_app_with_pool):
    """Test that the usage system endpoints response value. No auth needed"""

    mocker.patch("aleph.vm.orchestrator.machine.get_hardware_info", FAKE_SYSTEM_INFO)
    mocker.patch(
        "psutil.getloadavg",
        lambda: [1, 2, 3],
    )
    mocker.patch(
        "psutil.cpu_count",
        lambda: 200,
    )

    client = await aiohttp_client(await mock_app_with_pool)
    response: web.Response = await client.get("/about/usage/system")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert resp["properties"]["cpu"]["architecture"] == "x86_64"
    assert resp["properties"]["cpu"]["vendor"] == "AuthenticAMD"
    assert resp["cpu"]["load_average"] == {"load1": 1.0, "load15": 3.0, "load5": 2.0}
    assert resp["cpu"]["count"] == 200


@pytest.mark.asyncio
async def test_system_capability_mock(aiohttp_client, mocker):
    """Test that the capability system endpoints response value. No auth needed"""
    mocker.patch("aleph.vm.orchestrator.machine.get_hardware_info", FAKE_SYSTEM_INFO)
    mocker.patch(
        "psutil.getloadavg",
        lambda: [1, 2, 3],
    )
    mocker.patch(
        "psutil.cpu_count",
        lambda: 200,
    )
    app = setup_webapp(pool=None)
    client = await aiohttp_client(app)
    response: web.Response = await client.get("/about/capability")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert resp == {
        "cpu": {
            "architecture": "x86_64",
            "vendor": "AuthenticAMD",
            "model": "AMD EPYC 7763 64-Core Processor",
            "frequency": "2000000000",
            "count": "200",
        },
        "memory": {"size": "17179869184", "units": "bytes", "type": "", "clock": None, "clock_units": ""},
    }


@pytest.mark.asyncio
async def test_allocation_invalid_auth_token(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid auth token is provided."""
    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    app = setup_webapp(pool=None)
    client = await aiohttp_client(app)
    response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "notTest"},
    )
    assert response.status == 401
    assert await response.json() == {"error": "Authentication token received is invalid"}


@pytest.mark.asyncio
async def test_allocation_missing_auth_token(aiohttp_client):
    """Test that the allocation endpoint fails when auth token is not provided."""
    app = setup_webapp(pool=None)
    client = await aiohttp_client(app)
    response: web.Response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
    )
    assert response.status == 401
    assert await response.json() == {"error": "Authentication token is missing"}


@pytest.mark.asyncio
async def test_allocation_valid_token(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid auth is provided.

    This is a very simple test that don't start or stop any VM so the mock is minimal"""

    class FakeVmPool:
        def get_persistent_executions(self):
            return []

    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    app = setup_webapp(pool=FakeVmPool())
    app["pubsub"] = None
    client = await aiohttp_client(app)

    response: web.Response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "test"},
    )
    assert response.status == 200
    assert await response.json() == {"success": True, "successful": [], "failing": [], "errors": {}}


@pytest.mark.asyncio
async def test_v2_executions_list_one_vm(aiohttp_client, mock_app_with_pool, mock_instance_content):
    web_app = await mock_app_with_pool
    pool = web_app["vm_pool"]
    message = InstanceContent.model_validate(mock_instance_content)

    hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )
    pool.executions = {hash: execution}
    client = await aiohttp_client(web_app)
    response: web.Response = await client.get(
        "/v2/about/executions/list",
    )
    assert response.status == 200
    assert await response.json() == {
        "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca": {
            "networking": {},
            "status": {
                "defined_at": str(execution.times.defined_at),
                "preparing_at": None,
                "prepared_at": None,
                "starting_at": None,
                "started_at": None,
                "stopping_at": None,
                "stopped_at": None,
            },
            "running": None,
        }
    }


@pytest.mark.asyncio
async def test_v2_executions_list_vm_network(aiohttp_client, mocker, mock_app_with_pool, mock_instance_content):
    "Test locally but do not create"
    web_app = await mock_app_with_pool
    pool = web_app["vm_pool"]
    message = InstanceContent.model_validate(mock_instance_content)

    vm_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    execution = VmExecution(
        vm_hash=hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )
    vm_id = 3
    from aleph.vm.network.hostnetwork import Network, make_ipv6_allocator

    network = Network(
        vm_ipv4_address_pool_range=settings.IPV4_ADDRESS_POOL,
        vm_network_size=settings.IPV4_NETWORK_PREFIX_LENGTH,
        external_interface=settings.NETWORK_INTERFACE,
        ipv6_allocator=make_ipv6_allocator(
            allocation_policy=settings.IPV6_ALLOCATION_POLICY,
            address_pool=settings.IPV6_ADDRESS_POOL,
            subnet_prefix=settings.IPV6_SUBNET_PREFIX,
        ),
        use_ndp_proxy=False,
        ipv6_forwarding_enabled=False,
    )
    network.setup()

    from aleph.vm.vm_type import VmType

    vm_type = VmType.from_message_content(message)
    tap_interface = await network.prepare_tap(vm_id, vm_hash, vm_type)
    # await network.create_tap(vm_id, tap_interface)
    execution.vm = mocker.Mock()
    execution.vm.tap_interface = tap_interface

    pool.executions = {vm_hash: execution}
    client = await aiohttp_client(web_app)
    response: web.Response = await client.get(
        "/v2/about/executions/list",
    )
    assert response.status == 200
    assert await response.json() == {
        "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca": {
            "networking": {
                "ipv4_network": "172.16.3.0/24",
                "ipv6_network": "fc00:1:2:3:3:deca:deca:dec0/124",
                "ipv6_ip": "fc00:1:2:3:3:deca:deca:dec1",
            },
            "status": {
                "defined_at": str(execution.times.defined_at),
                "preparing_at": None,
                "prepared_at": None,
                "starting_at": None,
                "started_at": None,
                "stopping_at": None,
                "stopped_at": None,
            },
            "running": None,
        }
    }


@pytest.mark.asyncio
async def test_v2_executions_list_empty(aiohttp_client, mock_app_with_pool):
    client = await aiohttp_client(await mock_app_with_pool)
    response: web.Response = await client.get(
        "/v2/about/executions/list",
    )
    assert response.status == 200
    assert await response.json() == {}


@pytest.mark.asyncio
async def test_about_certificates_missing_setting(aiohttp_client):
    """Test that the certificates system endpoint returns an error if the setting isn't enabled"""
    settings.ENABLE_CONFIDENTIAL_COMPUTING = False

    app = setup_webapp(pool=None)
    app["sev_client"] = SevClient(Path().resolve(), Path("/opt/sevctl").resolve())
    client = await aiohttp_client(app)
    response: web.Response = await client.get("/about/certificates")
    assert response.status == 503
    assert await response.json() == {"error": "Confidential computing setting not enabled on that server"}


@pytest.mark.asyncio
async def test_about_certificates(aiohttp_client):
    """Test that the certificates system endpoint responds. No auth needed"""

    settings.ENABLE_QEMU_SUPPORT = True
    settings.ENABLE_CONFIDENTIAL_COMPUTING = True
    settings.setup()

    with mock.patch(
        "pathlib.Path.is_file",
        return_value=False,
    ) as is_file_mock:
        with mock.patch(
            "aleph.vm.sevclient.run_in_subprocess",
            return_value=True,
        ) as export_mock:
            with tempfile.TemporaryDirectory() as tmp_dir:
                app = setup_webapp(pool=None)
                sev_client = SevClient(Path(tmp_dir), Path("/opt/sevctl"))
                app["sev_client"] = sev_client
                # Create mock file to return it
                Path(sev_client.certificates_archive).touch(exist_ok=True)

                client = await aiohttp_client(app)
                response: web.Response = await client.get("/about/certificates")
                assert response.status == 200
                is_file_mock.assert_has_calls([call()])
                certificates_expected_dir = sev_client.certificates_archive
                export_mock.assert_called_once_with(
                    ["/opt/sevctl", "export", str(certificates_expected_dir)], check=True
                )


@pytest.fixture
def mock_aggregate_settings(mocker: MockerFixture):
    mocker.patch(
        "aleph.vm.orchestrator.utils.fetch_aggregate_settings",
        return_value={
            "compatible_gpus": [
                {"name": "AD102GL [L40S]", "model": "L40S", "vendor": "NVIDIA", "device_id": "10de:26b9"},
                {"name": "GB202 [GeForce RTX 5090]", "model": "RTX 5090", "vendor": "NVIDIA", "device_id": "10de:2685"},
                {
                    "name": "GB202 [GeForce RTX 5090 D]",
                    "model": "RTX 5090",
                    "vendor": "NVIDIA",
                    "device_id": "10de:2687",
                },
                {"name": "AD102 [GeForce RTX 4090]", "model": "RTX 4090", "vendor": "NVIDIA", "device_id": "10de:2684"},
                {
                    "name": "AD102 [GeForce RTX 4090 D]",
                    "model": "RTX 4090",
                    "vendor": "NVIDIA",
                    "device_id": "10de:2685",
                },
                {"name": "GA102 [GeForce RTX 3090]", "model": "RTX 3090", "vendor": "NVIDIA", "device_id": "10de:2204"},
                {
                    "name": "GA102 [GeForce RTX 3090 Ti]",
                    "model": "RTX 3090",
                    "vendor": "NVIDIA",
                    "device_id": "10de:2203",
                },
                {
                    "name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "model": "RTX 4000 ADA",
                    "vendor": "NVIDIA",
                    "device_id": "10de:27b0",
                },
                {
                    "name": "AD104GL [RTX 4000 Ada Generation]",
                    "model": "RTX 4000 ADA",
                    "vendor": "NVIDIA",
                    "device_id": "10de:27b2",
                },
                {"name": "GH100 [H100]", "model": "H100", "vendor": "NVIDIA", "device_id": "10de:2336"},
                {"name": "GH100 [H100 NVSwitch]", "model": "H100", "vendor": "NVIDIA", "device_id": "10de:22a3"},
                {"name": "GH100 [H100 CNX]", "model": "H100", "vendor": "NVIDIA", "device_id": "10de:2313"},
                {"name": "GH100 [H100 SXM5 80GB]", "model": "H100", "vendor": "NVIDIA", "device_id": "10de:2330"},
                {"name": "GH100 [H100 PCIe]", "model": "H100", "vendor": "NVIDIA", "device_id": "10de:2331"},
                {"name": "GA100", "model": "A100", "vendor": "NVIDIA", "device_id": "10de:2080"},
                {"name": "GA100", "model": "A100", "vendor": "NVIDIA", "device_id": "10de:2081"},
                {"name": "GA100 [A100 SXM4 80GB]", "model": "A100", "vendor": "NVIDIA", "device_id": "10de:20b2"},
                {"name": "GA100 [A100 PCIe 80GB]", "model": "A100", "vendor": "NVIDIA", "device_id": "10de:20b5"},
                {"name": "GA100 [A100X]", "model": "A100", "vendor": "NVIDIA", "device_id": "10de:20b8"},
            ],
            "community_wallet_address": "0x5aBd3258C5492fD378EBC2e0017416E199e5Da56",
            "community_wallet_timestamp": 1739996239,
        },
    )


@pytest.fixture
async def mock_app_with_pool(mocker, mock_aggregate_settings):
    """Set up VmPool with GPU and supervisor webserver"""
    device_return = mocker.Mock(
        stdout=(
            '00:1f.0 "ISA bridge [0601]" "Intel Corporation [8086]" "Device [7a06]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n00:1f.4 "SMBus [0c05]" "Intel Corporation [8086]" "Raptor Lake-S PCH SMBus Controller [7a23]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n00:1f.5 "Serial bus controller [0c80]" "Intel Corporation [8086]" "Raptor Lake SPI (flash) Controller [7a24]" -r11 -p00 "ASUSTeK Computer Inc. [1043]" "Device [8882]"'
            '\n01:00.0 "VGA compatible controller [0300]" "NVIDIA Corporation [10de]" "AD104GL [RTX 4000 SFF Ada Generation] [27b0]" -ra1 -p00 "NVIDIA Corporation [10de]" "AD104GL [RTX 4000 SFF Ada Generation] [27b0]"'
            '\n01:00.1 "Audio device [0403]" "NVIDIA Corporation [10de]" "Device [22bc]" -ra1 -p00 "NVIDIA Corporation [10de]" "Device [16fa]"'
            '\n02:00.0 "Non-Volatile memory controller [0108]" "Samsung Electronics Co Ltd [144d]" "NVMe SSD Controller PM9A1/PM9A3/980PRO [a80a]" -p02 "Samsung Electronics Co Ltd [144d]" "NVMe SSD Controller PM9A1/PM9A3/980PRO [aa0a]"'
        )
    )
    mocker.patch(
        "aleph.vm.resources.subprocess.run",
        return_value=device_return,
    )

    def mock_is_kernel_enabled_gpu(pci_host: str) -> bool:
        value = True if pci_host == "01:00.0" else False
        return value

    mocker.patch(
        "aleph.vm.resources.is_kernel_enabled_gpu",
        wraps=mock_is_kernel_enabled_gpu,
    )

    mocker.patch.object(settings, "ENABLE_GPU_SUPPORT", True)
    pool = VmPool()
    await pool.setup()
    app = setup_webapp(pool=pool)
    return app


@pytest.mark.asyncio
async def test_system_usage_gpu_ressources(aiohttp_client, mocker, mock_app_with_pool):
    """Test gpu are properly listed"""
    client = await aiohttp_client(await mock_app_with_pool)

    response: web.Response = await client.get("/about/usage/system")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert "gpu" in resp
    assert resp["cpu"]["count"] > 0
    assert resp["gpu"]["devices"] == [
        {
            "vendor": "NVIDIA",
            "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
            "device_class": "0300",
            "model": "RTX 4000 ADA",
            "pci_host": "01:00.0",
            "device_id": "10de:27b0",
            "compatible": True,
        }
    ]
    assert resp["gpu"]["available_devices"] == [
        {
            "vendor": "NVIDIA",
            "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
            "device_class": "0300",
            "model": "RTX 4000 ADA",
            "pci_host": "01:00.0",
            "device_id": "10de:27b0",
            "compatible": True,
        }
    ]


@pytest.mark.asyncio
async def test_reserve_resources(aiohttp_client, mocker, mock_app_with_pool):
    """Test gpu are properly listed"""
    app = await mock_app_with_pool
    client = await aiohttp_client(app)
    sender = "mock_address"

    # Disable auth
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=sender,
    )
    instance_content = {
        "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "time": 1713874241.800818,
        "allow_amend": False,
        "metadata": None,
        "authorized_keys": None,
        "variables": None,
        "environment": {
            "reproducible": False,
            "internet": True,
            "aleph_api": True,
            "shared_cache": False,
            "hypervisor": "qemu",
        },
        "resources": {
            "vcpus": 1,
            "memory": 256,
            "seconds": 30,
            "published_ports": None,
        },
        "payment": {"type": "superfluid", "chain": "BASE"},
        "requirements": {
            "node": {
                "node_hash": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            },
            "gpu": [
                {
                    "device_id": "10de:27b0",
                    "vendor": "NVIDIA",
                    "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "device_class": "0300",
                }
            ],
        },
        "replaces": None,
        "rootfs": {
            "parent": {"ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"},
            "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            "use_latest": True,
            "comment": "",
            "persistence": "host",
            "size_mib": 1000,
        },
    }
    InstanceContent.model_validate(instance_content)

    response: web.Response = await client.post("/control/reserve_resources", json=instance_content)
    assert response.status == 200, await response.text()
    resp = await response.json()
    assert "expires" in resp
    assert resp["status"] == "reserved"
    assert len(app["vm_pool"].reservations) == 1

    # make a second reservation
    response2: web.Response = await client.post("/control/reserve_resources", json=instance_content)
    assert response2.status == 200
    resp2 = await response2.json()
    assert "expires" in resp2
    assert resp2["status"] == "reserved"
    assert resp2["expires"] > resp["expires"]
    assert len(app["vm_pool"].reservations) == 1

    # another user try to reserve, should return an error
    other_user = "other_user"
    with mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=other_user,
    ):
        response3: web.Response = await client.post("/control/reserve_resources", json=instance_content)
    assert response3.status == 400, await response3.text()
    resp3 = await response3.json()
    assert resp3 == {
        "status": "error",
        "error": "Failed to reserves all resources",
        "reason": "Failed to find available GPU matching spec vendor='NVIDIA' device_name='AD104GL [RTX 4000 SFF Ada "
        "Generation]' device_class=<GpuDeviceClass.VGA_COMPATIBLE_CONTROLLER: '0300'> device_id='10de:27b0'",
    }
    assert len(app["vm_pool"].reservations) == 1

    # Try to reserve a GPU that the CRN doesn't have

    instance_content2: dict = deepcopy(instance_content)
    instance_content2["requirements"]["gpu"] = (
        [
            {
                "device_id": "10de:FAKE",
                "vendor": "NVIDIA",
                "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                "device_class": "0300",
            }
        ],
    )
    response4: web.Response = await client.post("/control/reserve_resources", json=instance_content2)
    assert response4.status == 400, await response3.text()


@pytest.mark.asyncio
async def test_reserve_resources_double_fail(aiohttp_client, mocker, mock_app_with_pool):
    """Attempt to reserve two GPU but the CRN only has one"""
    app = await mock_app_with_pool
    client = await aiohttp_client(app)
    sender = "mock_address"

    # Disable auth
    mocker.patch(
        "aleph.vm.orchestrator.views.authentication.authenticate_jwk",
        return_value=sender,
    )
    instance_content = {
        "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "time": 1713874241.800818,
        "allow_amend": False,
        "metadata": None,
        "authorized_keys": None,
        "variables": None,
        "environment": {
            "reproducible": False,
            "internet": True,
            "aleph_api": True,
            "shared_cache": False,
            "hypervisor": "qemu",
        },
        "resources": {
            "vcpus": 1,
            "memory": 256,
            "seconds": 30,
            "published_ports": None,
        },
        "payment": {"type": "superfluid", "chain": "BASE"},
        "requirements": {
            "node": {
                "node_hash": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            },
            "gpu": [
                {
                    "device_id": "10de:27b0",
                    "vendor": "NVIDIA",
                    "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "device_class": "0300",
                },
                {
                    "device_id": "10de:27b0",
                    "vendor": "NVIDIA",
                    "device_name": "AD104GL [RTX 4000 SFF Ada Generation]",
                    "device_class": "0300",
                },
            ],
        },
        "replaces": None,
        "rootfs": {
            "parent": {"ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"},
            "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            "use_latest": True,
            "comment": "",
            "persistence": "host",
            "size_mib": 1000,
        },
    }
    InstanceContent.model_validate(instance_content)

    response: web.Response = await client.post("/control/reserve_resources", json=instance_content)
    assert response.status == 400, await response.text()
    resp = await response.json()
    assert resp["status"] == "error", await response.text()
    assert len(app["vm_pool"].reservations) == 0
