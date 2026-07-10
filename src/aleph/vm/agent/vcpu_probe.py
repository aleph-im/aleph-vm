"""Probe QEMU for the SNP guest CPU models this host can actually launch.

The scheduler matches a v-program's launch-measurement vcpu_type against the
models advertised here, so the source of truth must be QEMU itself (this
exact QEMU build + host kernel + silicon), not a static CPUID table.
"""

import asyncio
import json
import logging

from aleph.vm.utils import async_cache, check_amd_sev_snp_supported

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 15.0


async def _read_qmp_response(stdout: asyncio.StreamReader) -> dict:
    """Read the next QMP response, skipping asynchronous events."""
    while True:
        line = await stdout.readline()
        if not line:
            msg = "QMP stream closed before a response arrived"
            raise RuntimeError(msg)
        message = json.loads(line)
        if "event" in message:
            continue
        return message


async def query_cpu_definitions() -> list[dict]:
    """Ask a KVM-accelerated QEMU which CPU models it can launch on this host."""
    process = await asyncio.create_subprocess_exec(
        "qemu-system-x86_64",
        "-machine",
        "none",
        "-accel",
        "kvm",
        "-display",
        "none",
        "-nodefaults",
        "-qmp",
        "stdio",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            greeting = await _read_qmp_response(process.stdout)
            if "QMP" not in greeting:
                msg = f"Unexpected QMP greeting: {greeting}"
                raise RuntimeError(msg)
            definitions: list[dict] | None = None
            for command in ("qmp_capabilities", "query-cpu-definitions", "quit"):
                process.stdin.write(json.dumps({"execute": command}).encode() + b"\n")
                await process.stdin.drain()
                response = await _read_qmp_response(process.stdout)
                if command == "query-cpu-definitions":
                    definitions = response["return"]
            await process.wait()
    finally:
        if process.returncode is None:
            process.kill()
    assert definitions is not None
    return definitions


def filter_snp_vcpu_types(definitions: list[dict]) -> list[str]:
    """Keep the EPYC-family models QEMU reports as runnable on this host
    (empty unavailable-features means every feature the model needs exists)."""
    return sorted(
        definition["name"]
        for definition in definitions
        if definition["name"].startswith("EPYC") and not definition.get("unavailable-features")
    )


@async_cache
async def get_supported_snp_vcpu_types() -> list[str]:
    """SNP guest CPU models this node can launch; [] when SNP is unsupported
    or the probe fails. We never advertise what we cannot prove."""
    if not check_amd_sev_snp_supported():
        return []
    try:
        definitions = await query_cpu_definitions()
    except Exception:
        logger.warning("QEMU vCPU probe failed, not advertising SNP guest models", exc_info=True)
        return []
    return filter_snp_vcpu_types(definitions)
