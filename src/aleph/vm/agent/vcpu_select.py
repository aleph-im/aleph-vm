"""Pick the QEMU CPU model an SEV-SNP guest must launch with.

The launch measurement is a function of the CPU model (it selects the per-vCPU
VMSA contents), so the CRN may only launch a model one of the message's
measurements was computed for. Which of those the host can actually launch
comes from the QEMU probe in ``vcpu_probe`` (the same list the node advertises
as ``properties.tee.sev_snp.supported_vcpu_types``), so selection and
advertisement cannot disagree.

Fails closed: no launchable model means no launch, not a launch that attests
wrong.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from aleph.vm.supervisor_interface.errors import VmSetupError

if TYPE_CHECKING:
    from collections.abc import Iterable
    from typing import Protocol

    class _Measurement(Protocol):
        vcpu_type: str | None


# The model the CRN launched every SNP guest with before the model was
# carried, and the model the aleph-rs tooling measures against by default. An
# untagged measurement can only have been computed for it.
DEFAULT_MEASUREMENT_VCPU_TYPE = "EPYC-v4"


def requested_vcpu_types(measurements: Iterable[_Measurement] | None) -> list[str]:
    """The CPU models a message's launch measurements were computed for, in
    message order, deduplicated case insensitively (first spelling wins)."""
    requested: list[str] = []
    for measurement in measurements or ():
        model = measurement.vcpu_type or DEFAULT_MEASUREMENT_VCPU_TYPE
        if not any(model.lower() == seen.lower() for seen in requested):
            requested.append(model)
    return requested


def select_snp_vcpu_type(requested: list[str], supported: list[str]) -> str:
    """The first requested model this host can launch, spelled the way QEMU
    reported it (``-cpu`` is case sensitive).

    Raises VmSetupError when the intersection is empty, which covers a host
    whose probe failed or which advertises no SNP models at all.
    """
    for model in requested:
        for available in supported:
            if model.lower() == available.lower():
                return available
    msg = (
        f"no SEV-SNP guest CPU model this host can launch matches the message's launch "
        f"measurements: requested {requested or ['(none)']}, host supports {supported or ['(none)']}"
    )
    raise VmSetupError(msg)
