"""Probe QEMU for the SNP guest CPU models this host can actually launch.

The scheduler matches a v-program's launch-measurement vcpu_type against the
models advertised here, so the source of truth must be QEMU itself (this
exact QEMU build + host kernel + silicon), not a static CPUID table.
"""

import asyncio
import json
import logging
import time

from aleph.vm.utils import check_amd_sev_snp_supported

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 15.0

# How long a failed probe is remembered before it is retried. Long enough that
# a host with no working qemu is not re-probed (and stalled for up to
# PROBE_TIMEOUT_SECONDS) on every usage poll and every launch, short enough
# that a transient failure at boot heals without anyone restarting the agent.
PROBE_RETRY_SECONDS = 60.0


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

    async def _converse() -> list[dict]:
        assert process.stdin is not None and process.stdout is not None
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
        assert definitions is not None
        return definitions

    try:
        return await asyncio.wait_for(_converse(), timeout=PROBE_TIMEOUT_SECONDS)
    finally:
        if process.returncode is None:
            process.kill()


# Features QEMU reports as unavailable when the host runs kvm_amd nested=0.
# They exist only to run nested hypervisors inside the guest: an SEV-SNP
# guest never uses them, and the launch path passes -cpu without enforce, so
# QEMU merely masks them with a warning. Disabling nested virt is a
# legitimate host hardening posture and must not empty the advertisement.
# The set is the SVM feature word (CPUID 0x8000_000A EDX) plus the svm bit
# itself (0x8000_0001 ECX).
NESTED_VIRT_FEATURES = frozenset(
    {
        "svm",
        "npt",
        "lbrv",
        "svm-lock",
        "nrip-save",
        "tsc-scale",
        "vmcb-clean",
        "flushbyasid",
        "decodeassists",
        "pause-filter",
        "pfthreshold",
        "avic",
        "v-vmsave-vmload",
        "vgif",
        "x2avic",
        "svme-addr-chk",
        "vnmi",
    }
)


def filter_snp_vcpu_types(definitions: list[dict]) -> list[str]:
    """Keep the EPYC-family models QEMU reports as runnable on this host.

    Unavailable features that only matter for nested virtualization are
    ignored: see NESTED_VIRT_FEATURES."""
    return sorted(
        definition["name"]
        for definition in definitions
        if definition["name"].startswith("EPYC")
        and not (set(definition.get("unavailable-features") or ()) - NESTED_VIRT_FEATURES)
    )


class _ProbeCache:
    """Process-wide memory of the QEMU probe.

    A successful probe is a fact about this QEMU build, kernel and silicon, so it
    is kept for the life of the process. A failed one is not a fact about the
    host, only about that attempt (a spawn that timed out during boot, say), so
    it is kept only for PROBE_RETRY_SECONDS and then tried again. The generic
    ``async_cache`` cannot tell the two apart: it would pin the empty list from
    a failed attempt forever, and this list feeds both what the node advertises
    and which models it will launch, so one bad probe at startup would take the
    node out of the confidential pool until someone restarted the agent.

    The lock keeps concurrent first callers (the usage endpoint and a launch
    racing at startup) from each spawning a qemu.
    """

    def __init__(self) -> None:
        self.supported: list[str] | None = None
        self.failed_at: float | None = None
        self.lock = asyncio.Lock()

    def reset(self) -> None:
        self.supported = None
        self.failed_at = None


_probe_cache = _ProbeCache()


def reset_snp_vcpu_probe_cache() -> None:
    """Forget the cached probe. For tests; production never needs it."""
    _probe_cache.reset()


async def get_supported_snp_vcpu_types() -> list[str]:
    """SNP guest CPU models this node can launch; [] when SNP is unsupported
    or the probe fails. We never advertise what we cannot prove."""
    if not check_amd_sev_snp_supported():
        return []
    async with _probe_cache.lock:
        if _probe_cache.supported is not None:
            return _probe_cache.supported
        now = time.monotonic()
        if _probe_cache.failed_at is not None and now - _probe_cache.failed_at < PROBE_RETRY_SECONDS:
            return []
        try:
            definitions = await query_cpu_definitions()
        except Exception:
            _probe_cache.failed_at = now
            logger.warning(
                "QEMU vCPU probe failed, not advertising SNP guest models; retrying in %ss",
                PROBE_RETRY_SECONDS,
                exc_info=True,
            )
            return []
        _probe_cache.supported = filter_snp_vcpu_types(definitions)
        return _probe_cache.supported
