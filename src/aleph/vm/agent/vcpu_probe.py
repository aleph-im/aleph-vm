"""Probe QEMU for the SNP guest CPU models this host can actually launch.

The scheduler matches a v-program's launch-measurement vcpu_type against the
models advertised here, so the source of truth must be QEMU itself (this
exact QEMU build + host kernel + silicon), not a static CPUID table.
"""

import asyncio
import json
import logging
import time
from dataclasses import dataclass

from aleph.vm.utils import check_amd_sev_snp_supported

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 15.0

# How long a failed probe is remembered before it is retried. Long enough that
# a host with no working qemu is not re-probed (and stalled for up to
# PROBE_TIMEOUT_SECONDS) on every usage poll and every launch, short enough
# that a transient failure at boot heals without anyone restarting the agent.
PROBE_RETRY_SECONDS = 60.0

# The QOM type QEMU registers only when it can actually launch SEV-SNP
# guests. Older QEMU (e.g. the 8.2.2 Ubuntu 24.04 ships) reports EPYC CPU
# models fine but has no such object, so every SNP launch would fail.
SNP_GUEST_QOM_TYPE = "sev-snp-guest"


@dataclass(frozen=True)
class QemuSnpFacts:
    cpu_definitions: list[dict]
    qom_type_names: frozenset[str]
    qemu_version: str  # "9.1.2", or "" when the greeting lacks one


@dataclass(frozen=True)
class SnpLaunchCapability:
    supported_vcpu_types: list[str]
    unavailable_reason: str | None  # None iff supported_vcpu_types is non-empty


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


async def query_qemu_snp_facts() -> QemuSnpFacts:
    """Ask a KVM-accelerated QEMU which CPU models it can launch on this host,
    and whether it has the object needed to launch SEV-SNP guests at all."""
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
        # QMP replies are single JSON lines that keep growing with QEMU
        # releases (qom-list-types measured 43 KB on QEMU 10.2.1, already 66%
        # of asyncio's default 64 KiB readline limit); raise it well above
        # that so a future QEMU does not make every probe fail forever.
        limit=2**20,
    )
    assert process.stdin is not None and process.stdout is not None

    async def _converse() -> QemuSnpFacts:
        assert process.stdin is not None and process.stdout is not None
        greeting = await _read_qmp_response(process.stdout)
        if "QMP" not in greeting:
            msg = f"Unexpected QMP greeting: {greeting}"
            raise RuntimeError(msg)
        version_info = greeting.get("QMP", {}).get("version", {}).get("qemu", {})
        qemu_version = ""
        if version_info:
            qemu_version = f"{version_info.get('major')}.{version_info.get('minor')}.{version_info.get('micro')}"
        definitions: list[dict] | None = None
        qom_types: list[dict] | None = None
        for command in ("qmp_capabilities", "query-cpu-definitions", "qom-list-types", "quit"):
            process.stdin.write(json.dumps({"execute": command}).encode() + b"\n")
            await process.stdin.drain()
            response = await _read_qmp_response(process.stdout)
            if command == "query-cpu-definitions":
                definitions = response["return"]
            elif command == "qom-list-types":
                qom_types = response["return"]
        await process.wait()
        assert definitions is not None
        assert qom_types is not None
        return QemuSnpFacts(
            cpu_definitions=definitions,
            qom_type_names=frozenset(entry["name"] for entry in qom_types),
            qemu_version=qemu_version,
        )

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
# The set is every name QEMU gives to the SVM feature word (FEAT_SVM over
# CPUID 0x8000_000A EDX in target/i386/cpu.c; gmet is on QEMU master and not
# yet in a release) plus the svm bit itself (0x8000_0001 ECX): exactly the
# features Linux KVM exposes only when kvm_amd runs with nested=1.
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
        "gmet",
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


def _capability_from_facts(facts: QemuSnpFacts) -> SnpLaunchCapability:
    if SNP_GUEST_QOM_TYPE not in facts.qom_type_names:
        version = facts.qemu_version or "unknown version"
        return SnpLaunchCapability(
            [],
            f"QEMU ({version}) has no '{SNP_GUEST_QOM_TYPE}' object and cannot launch "
            f"SEV-SNP guests. QEMU >= 9.1 is required (of the packaged targets, "
            f"Debian 13 and Ubuntu 26.04 ship one).",
        )
    supported = filter_snp_vcpu_types(facts.cpu_definitions)
    if not supported:
        return SnpLaunchCapability(
            [],
            "QEMU reports no launchable EPYC guest CPU model on this host "
            "(every EPYC model has genuinely unavailable features).",
        )
    return SnpLaunchCapability(supported, None)


_NO_SILICON = SnpLaunchCapability(
    [],
    "host kernel does not expose SEV-SNP: kvm_amd sev_snp parameter is not 'Y' "
    "or /dev/sev is missing (BIOS SNP setting, kernel version, or firmware).",
)
_PROBE_FAILED = SnpLaunchCapability([], "QEMU vCPU probe failed; see agent logs.")


class _ProbeCache:
    """Process-wide memory of the QEMU probe.

    A successful, non-empty probe is a fact about this QEMU build, kernel and
    silicon, so it is kept for the life of the process. An exception, or a
    successful probe that comes back empty (no launchable model, or no
    sev-snp-guest object), is not a durable fact: a live QEMU upgrade can fix
    it, so it is kept only for PROBE_RETRY_SECONDS and then tried again. The
    generic ``async_cache`` cannot tell the two apart: it would pin the empty
    result forever, and this feeds both what the node advertises and which
    models it will launch, so one bad probe at startup (or a QEMU that has
    since been upgraded) would take the node out of the confidential pool
    until someone restarted the agent.

    The lock keeps concurrent first callers (the usage endpoint and a launch
    racing at startup) from each spawning a qemu.
    """

    def __init__(self) -> None:
        self.kept: SnpLaunchCapability | None = None
        self.failed_at: float | None = None
        self.last_empty: SnpLaunchCapability | None = None
        self.lock = asyncio.Lock()

    def reset(self) -> None:
        self.kept = None
        self.failed_at = None
        self.last_empty = None


_probe_cache = _ProbeCache()


def reset_snp_vcpu_probe_cache() -> None:
    """Forget the cached probe. For tests; production never needs it."""
    _probe_cache.reset()


async def get_snp_launch_capability() -> SnpLaunchCapability:
    """The SNP guest CPU models this node can actually launch, and why not
    when it can't. We never advertise what we cannot prove."""
    if not check_amd_sev_snp_supported():
        return _NO_SILICON
    async with _probe_cache.lock:
        if _probe_cache.kept is not None:
            return _probe_cache.kept
        now = time.monotonic()
        if _probe_cache.failed_at is not None and now - _probe_cache.failed_at < PROBE_RETRY_SECONDS:
            return _probe_cache.last_empty or _PROBE_FAILED
        try:
            facts = await query_qemu_snp_facts()
        except Exception:
            _probe_cache.failed_at = now
            _probe_cache.last_empty = None
            logger.warning(
                "QEMU vCPU probe failed, not advertising SNP guest models; retrying in %ss",
                PROBE_RETRY_SECONDS,
                exc_info=True,
            )
            return _PROBE_FAILED
        capability = _capability_from_facts(facts)
        if capability.supported_vcpu_types:
            _probe_cache.kept = capability
        else:
            # An empty result is a fact about the current QEMU binary, which
            # an operator can upgrade live: retry so the fix is picked up
            # without an agent restart.
            _probe_cache.failed_at = now
            _probe_cache.last_empty = capability
            logger.warning("Not advertising SNP guest models: %s", capability.unavailable_reason)
        return capability


async def get_supported_snp_vcpu_types() -> list[str]:
    """SNP guest CPU models this node can launch; [] when SNP is unsupported
    or the probe fails. We never advertise what we cannot prove."""
    return (await get_snp_launch_capability()).supported_vcpu_types
