import pytest
from aiohttp import web

from aleph.vm.conf import settings
from aleph.vm.orchestrator.machine import get_hardware_info
from aleph.vm.orchestrator.supervisor import setup_webapp


@pytest.mark.asyncio
async def test_allocation_fails_on_invalid_item_hash(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid item_hash is provided."""
    app = setup_webapp()
    client = await aiohttp_client(app)
    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    response: web.Response = await client.post(
        "/control/allocations", json={"persistent_vms": ["not-an-ItemHash"]}, headers={"X-Auth-Signature": "test"}
    )
    assert response.status == 400
    assert await response.json() == [
        {
            "loc": [
                "persistent_vms",
                0,
            ],
            "msg": "Could not determine hash type: 'not-an-ItemHash'",
            "type": "value_error.unknownhash",
        },
    ]


@pytest.mark.asyncio
async def test_system_usage(aiohttp_client):
    """Test that the usage system endpoints responds. No auth needed"""
    app = setup_webapp()
    client = await aiohttp_client(app)
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
async def test_system_usage_mock(aiohttp_client, mocker):
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
    app = setup_webapp()
    client = await aiohttp_client(app)
    response: web.Response = await client.get("/about/usage/system")
    assert response.status == 200
    # check if it is valid json
    resp = await response.json()
    assert resp["properties"]["cpu"]["architecture"] == "x86_64"
    assert resp["properties"]["cpu"]["vendor"] == "AuthenticAMD"
    assert resp["cpu"]["load_average"] == {"load1": 1.0, "load15": 3.0, "load5": 2.0}
    assert resp["cpu"]["count"] == 200


@pytest.mark.asyncio
async def test_allocation_invalid_auth_token(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid auth token is provided."""
    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    app = setup_webapp()
    client = await aiohttp_client(app)
    response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "notTest"},
    )
    assert response.status == 401
    assert await response.text() == "Authentication token received is invalid"


@pytest.mark.asyncio
async def test_allocation_missing_auth_token(aiohttp_client):
    """Test that the allocation endpoint fails when auth token is not provided."""
    app = setup_webapp()
    client = await aiohttp_client(app)
    response: web.Response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
    )
    assert response.status == 401
    assert await response.text() == "Authentication token is missing"


@pytest.mark.asyncio
async def test_allocation_valid_token(aiohttp_client):
    """Test that the allocation endpoint fails when an invalid auth is provided.

    This is a very simple test that don't start or stop any VM so the mock is minimal"""

    class FakeVmPool:
        def get_persistent_executions(self):
            return []

    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    app = setup_webapp()
    app["vm_pool"] = FakeVmPool()
    app["pubsub"] = FakeVmPool()
    client = await aiohttp_client(app)

    response: web.Response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "test"},
    )
    assert response.status == 200
    assert await response.json() == {"success": True, "successful": [], "failing": [], "errors": {}}
