"""The measured confidential-GPU requirement, shared by the two SEV-SNP
launch paths (V-PROGRAM and confidential instance).

A message that declares a confidential GPU binds the requirement into its
launch measurement: the runtime's cmdline template carries `gpu_arch=`,
`gpu_count=` and, when the message narrows the models, `gpu_models=` slots,
and the guest enforces exactly what its measured cmdline states. The aleph
client renders the same tokens before it computes the measurement, so the
rendering here is byte-for-byte the same or the launch mismeasures.

Two products fill those slots differently: a V-PROGRAM's cmdline is derived
by the daemon from sidecars (render_gpu_requirement), while a confidential
instance's cmdline is rendered whole by the agent (render_instance_cmdline).
The checks that decide whether a message and a runtime can be launched
together are the same for both (check_gpu_against_manifest).
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, TypeAlias

from aleph_message.models.execution.environment import (
    CONFIDENTIAL_GPU_DEVICE_ID_PATTERN,
    MAX_CONFIDENTIAL_GPU_MODELS,
    MAX_CONFIDENTIAL_GPUS,
    ConfidentialGpuRequirement,
)

from aleph.vm.supervisor_interface.errors import VmSetupError
from aleph.vm.vprogram.manifest import GpuRuntimeSpec, InstanceGpuRuntimeSpec

if TYPE_CHECKING:
    from aleph_message.models import ItemHash

# A GPU-declaring runtime reserves a fixed IOMMU bounce buffer
# (swiotlb=262144, pinned in the manifest's cmdline template): a VM below this
# floor cannot afford it, so refuse the launch before any staging I/O runs.
GPU_MIN_MEMORY_MIB = 2048

# GPU architectures the measured gpu_arch= token may name.
GPU_ARCHS = frozenset({"hopper", "blackwell"})

# The cmdline slots that make a runtime a GPU runtime: carrying any one of
# them means its measured cmdline states a GPU requirement.
GPU_CMDLINE_SLOTS = ("{gpu_arch}", "{gpu_count}", "{gpu_models}")

# Either product's manifest gpu block: both pin a vendor and a per-arch board
# table, which is all the launch checks read.
ManifestGpu: TypeAlias = GpuRuntimeSpec | InstanceGpuRuntimeSpec


def render_gpu_requirement(arch: str, count: int, models: list[str] | None) -> str:
    """The canonical measured GPU requirement tokens for a message's gpu block.

    The aleph CLI renders the same string into the runtime template's trailing
    slots before it computes the launch measurement, so this must produce it
    byte for byte: `gpu_arch=<arch> gpu_count=<n>`, then, only when the
    message narrows the models, ` gpu_models=<ids>` with the ids lowercase,
    sorted and de-duplicated (the whole token is dropped otherwise, like
    verified_volumes). Raises ValueError on anything the token grammar cannot
    express; the caller turns that into a launch refusal.
    """
    if arch not in GPU_ARCHS:
        msg = f"unknown GPU architecture {arch!r}"
        raise ValueError(msg)
    if isinstance(count, bool) or not isinstance(count, int) or not 1 <= count <= MAX_CONFIDENTIAL_GPUS:
        msg = f"GPU count {count!r} is outside 1..{MAX_CONFIDENTIAL_GPUS}"
        raise ValueError(msg)
    tokens = f"gpu_arch={arch} gpu_count={count}"
    if not models:
        return tokens
    canonical = sorted(set(models))
    if len(canonical) > MAX_CONFIDENTIAL_GPU_MODELS:
        msg = f"{len(canonical)} GPU models named; at most {MAX_CONFIDENTIAL_GPU_MODELS} are supported"
        raise ValueError(msg)
    for model in canonical:
        if not re.fullmatch(CONFIDENTIAL_GPU_DEVICE_ID_PATTERN, model):
            msg = f"GPU model {model!r} is not a lowercase PCI vendor:device id"
            raise ValueError(msg)
    return f"{tokens} gpu_models={','.join(canonical)}"


def check_gpu_against_manifest(  # noqa: C901, PLR0913 -- a linear gate, one parameter per checked input
    *,
    what: str,
    vm_hash: ItemHash,
    runtime_ref: str,
    gpu: ConfidentialGpuRequirement | None,
    manifest_gpu: ManifestGpu | None,
    template: str,
    memory_mib: int,
) -> None:
    """Refuse a GPU message a runtime cannot serve, and a GPU-less message on
    a GPU runtime.

    ``what`` names the product in the refusals ("V-PROGRAM", "SNP instance").
    The count is the capacity resolver's business: every stage below (the
    daemon's per-card gate, the summed MMIO window, the guest's per-card
    device nodes and evidence) takes as many cards as the message names, up
    to the schema's ceiling of eight.
    """
    if gpu is None:
        # Mirror image of the checks below: a GPU runtime measures a GPU
        # requirement, so it has nothing to run a GPU-less workload with. Any
        # one of the slots makes it a GPU runtime, as it does for the client.
        if any(slot in template for slot in GPU_CMDLINE_SLOTS):
            msg = (
                f"{what} {vm_hash} declares no GPU but runtime {runtime_ref} is a GPU runtime "
                "(its cmdline template has a GPU requirement slot)"
            )
            raise VmSetupError(msg)
        return

    if manifest_gpu is None:
        msg = f"{what} {vm_hash} declares a GPU but runtime {runtime_ref} has no gpu block"
        raise VmSetupError(msg)
    if gpu.vendor != manifest_gpu.vendor:
        msg = f"{what} {vm_hash} declares a {gpu.vendor} GPU but the runtime drives {manifest_gpu.vendor}"
        raise VmSetupError(msg)
    if gpu.arch not in manifest_gpu.archs:
        msg = f"{what} {vm_hash} asks for a {gpu.arch} GPU but runtime {runtime_ref} does not drive {gpu.arch}"
        raise VmSetupError(msg)
    if memory_mib < GPU_MIN_MEMORY_MIB:
        msg = (
            f"{what} {vm_hash} declares a GPU with {memory_mib} MiB; the runtime's "
            f"swiotlb reservation needs at least {GPU_MIN_MEMORY_MIB} MiB"
        )
        raise VmSetupError(msg)
    # The guest only enforces a requirement its measured cmdline carries,
    # and the CLI refuses the same way before signing: a runtime whose
    # template has no slot for the tokens cannot run a GPU workload.
    if "{gpu_arch}" not in template or "{gpu_count}" not in template:
        msg = (
            f"{what} {vm_hash} declares a GPU but runtime {runtime_ref} has no " "{gpu_arch}/{gpu_count} cmdline slots"
        )
        raise VmSetupError(msg)
    if gpu.models and "{gpu_models}" not in template:
        msg = (
            f"{what} {vm_hash} narrows its GPU to specific models but runtime "
            f"{runtime_ref} has no {{gpu_models}} cmdline slot"
        )
        raise VmSetupError(msg)
    # A model the runtime lists no board for can never be satisfied: the
    # guest compares the board triple the card signs against this table
    # and powers off. Refuse here rather than burn a launch.
    boards = manifest_gpu.archs[gpu.arch].boards
    for model in gpu.models or []:
        if model not in boards:
            msg = (
                f"{what} {vm_hash} asks for GPU model {model} but runtime "
                f"{runtime_ref} lists no {gpu.arch} board under that id"
            )
            raise VmSetupError(msg)


def render_instance_cmdline(template: str, *, owner: str, gpu: ConfidentialGpuRequirement | None) -> str:
    """The whole measured cmdline of a confidential instance.

    Unlike a V-PROGRAM (whose cmdline the daemon assembles from sidecars), an
    instance's cmdline is rendered here and handed to the daemon verbatim, so
    this is the byte-for-byte counterpart of what the client renders before
    it measures: the template's tokens in order, the `gpu_models=` token
    dropped whole when the message names no model, and the model ids sorted
    and de-duplicated. Raises ValueError when the message and the template
    disagree, or when the requirement cannot be expressed in the tokens.
    """
    tokens = template.split()
    if gpu is None:
        if any(slot in token for token in tokens for slot in GPU_CMDLINE_SLOTS):
            msg = "the runtime template states a GPU requirement but the message declares no GPU"
            raise ValueError(msg)
        arch, count, models = "", "", ""
    else:
        # Reuse the canonical renderer's grammar checks on arch, count and
        # the model ids; only the layout differs here.
        render_gpu_requirement(gpu.arch, gpu.count, gpu.models)
        if "{gpu_arch}" not in template or "{gpu_count}" not in template:
            msg = "the runtime template has no {gpu_arch}/{gpu_count} slot"
            raise ValueError(msg)
        # A narrowing the template cannot render would be measured away, so the
        # guest would admit any card of the arch instead.
        if gpu.models and "{gpu_models}" not in template:
            msg = "the message narrows its GPU to specific models but the runtime template has no {gpu_models} slot"
            raise ValueError(msg)
        arch, count = gpu.arch, str(gpu.count)
        models = ",".join(sorted(set(gpu.models))) if gpu.models else ""
    if not models:
        tokens = [token for token in tokens if "{gpu_models}" not in token]
    return " ".join(token.format(owner=owner, gpu_arch=arch, gpu_count=count, gpu_models=models) for token in tokens)
