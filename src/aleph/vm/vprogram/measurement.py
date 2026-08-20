"""Per-workload SEV-SNP launch measurement.

TRANSIENT: wraps the sev-snp-measure pip package (0.0.12, matching the nix
pin in nix/flake.nix). The intended home for measurement computation is
aleph-rs (the Rust CLI); this module is the stopgap so the publisher can pin
verification.measurements[].registers['launch'] for a message-delivered
workload.

The launch digest is a function of OVMF + kernel + initrd + cmdline + vcpu
count + vcpu type: this wrapper takes exactly those inputs and nothing else,
so it stays a thin, replaceable layer over whatever computes the digest.
"""

from __future__ import annotations

from pathlib import Path

from sevsnpmeasure import guest, vcpu_types, vmm_types
from sevsnpmeasure.sev_mode import SevMode

# CLI default for `sev-snp-measure --guest-features` (see sevsnpmeasure.cli),
# which nix/flake.nix's `measurementFor` also relies on implicitly by never
# overriding it. Keeping it fixed here mirrors that: this wrapper only takes
# the inputs that are actually supposed to vary per workload.
_GUEST_FEATURES = 0x1


def compute_snp_measurement(  # noqa: PLR0913 -- fixed public signature (Task 4 brief)
    *,
    ovmf: Path,
    kernel: Path,
    initrd: Path,
    cmdline: str,
    vcpus: int,
    vcpu_type: str,
) -> str:
    """Compute the SEV-SNP launch measurement (96 lowercase hex chars, a
    SHA-384 digest) for the given OVMF firmware, kernel, initrd, kernel
    command line, vCPU count and vCPU (QEMU CPU model) type."""
    try:
        vcpu_sig = vcpu_types.CPU_SIGS[vcpu_type]
    except KeyError:
        msg = f"unknown vcpu_type {vcpu_type!r}; expected one of {sorted(vcpu_types.CPU_SIGS)}"
        raise ValueError(msg) from None

    digest = guest.calc_launch_digest(
        SevMode.SEV_SNP,
        vcpus,
        vcpu_sig,
        str(ovmf),
        str(kernel),
        str(initrd),
        cmdline,
        _GUEST_FEATURES,
        vmm_type=vmm_types.VMMType.QEMU,
    )
    return digest.hex()
