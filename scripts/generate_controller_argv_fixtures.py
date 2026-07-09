#!/usr/bin/env python3
"""Generate QEMU argv conformance fixtures from the REAL Python QemuVM.

The Python `QemuVM.start()` (increment A1) and `QemuConfidentialVM.start()`
(increment A2, SEV / SEV-ES) are the argv parity oracles. This script builds a
battery of `QemuVMConfiguration` / `QemuConfidentialVMConfiguration` objects,
instantiates the actual VM class, and captures the argv it would have exec'd by
monkeypatching `asyncio.create_subprocess_exec` to record the args and abort
before spawning.

Two batteries are emitted as JSON files `{name}.json`:

- non-confidential under
  `rust/crates/supervisor-controller/tests/conformance/controller_argv/`:

      {"config_json": <the vm_configuration object>, "expected_argv": [...]}

- confidential under `.../controller_argv_confidential/`, which additionally
  records the FIXED host-CPUID values the Python `secure_encryption_info()` is
  monkeypatched to return (the Rust test injects the identical SevHostInfo, as
  a non-SEV CI host cannot read them from CPUID):

      {"config_json": ..., "expected_argv": [...],
       "sev_host_info": {"cbitpos": .., "reduced_phys_bits": ..}}

`config_json` is the object the Rust `QemuConfig` reader parses; `expected_argv`
is what the Rust `build_argv` / `build_confidential_argv` must reproduce byte
for byte.

Run with the repo venv and the dev stubs on PYTHONPATH:

    PYTHONPATH=$PWD/src:/home/olivier/git/aleph/aleph-vm/.dev-stubs \\
        /home/olivier/git/aleph/aleph-vm/venv/bin/python \\
        scripts/generate_controller_argv_fixtures.py
"""

import asyncio
import json
from pathlib import Path

from aleph.vm.hypervisors.qemu import qemuvm as qemuvm_module
from aleph.vm.hypervisors.qemu.qemuvm import QemuVM
from aleph.vm.hypervisors.qemu_confidential import qemuvm as confidential_module
from aleph.vm.hypervisors.qemu_confidential.qemuvm import QemuConfidentialVM
from aleph.vm.supervisor_interface.configuration import (
    QemuConfidentialVMConfiguration,
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)

OUTPUT_DIR = (
    Path(__file__).resolve().parent.parent / "rust/crates/supervisor-controller/tests/conformance/controller_argv"
)
CONFIDENTIAL_OUTPUT_DIR = (
    Path(__file__).resolve().parent.parent
    / "rust/crates/supervisor-controller/tests/conformance/controller_argv_confidential"
)

# Default host-CPUID values most confidential fixtures pin, injected on the
# Rust side as an identical SevHostInfo. The Rust argv builder takes these by
# injection (a non-SEV CI host cannot read them from CPUID). 51 / 1 are the
# values a real SEV host reports and match the aleph-cvm SNP donor.
DEFAULT_CBITPOS = 51
DEFAULT_REDUCED_PHYS_BITS = 1

# Mutated before each confidential argv capture so the injected cbitpos /
# reduced-phys-bits are load-bearing: at least one case (distinct_sev_host_info)
# uses a DISTINCT pair, so a Rust mutant that hardcodes 51 / 1 in the builder
# (ignoring the injected SevHostInfo) survives every default-pair fixture but
# is killed by that one.
_sev_values = {"cbitpos": DEFAULT_CBITPOS, "reduced_phys_bits": DEFAULT_REDUCED_PHYS_BITS}

_captured: dict[str, list] = {}


class _Abort(Exception):
    """Raised by the fake exec to stop QemuVM.start() before it spawns."""


class _FakeSevInfo:
    """Stand-in for cpuid.features.SecureEncryptionInfo, reading the per-case
    values held in _sev_values (set just before each confidential capture)."""

    @property
    def c_bit_position(self):
        return _sev_values["cbitpos"]

    @property
    def phys_addr_reduction(self):
        return _sev_values["reduced_phys_bits"]


def _fake_secure_encryption_info():
    return _FakeSevInfo()


async def _fake_create_subprocess_exec(*args, **kwargs):
    _captured["args"] = list(args)
    raise _Abort()


def _argv_for(config: QemuVMConfiguration) -> list[str]:
    vm = QemuVM("testhash0000", config)
    try:
        asyncio.run(vm.start())
    except _Abort:
        pass
    return _captured["args"]


def _confidential_argv_for(config: QemuConfidentialVMConfiguration) -> list[str]:
    vm = QemuConfidentialVM("testhash0000", config)
    try:
        asyncio.run(vm.start())
    except _Abort:
        pass
    return _captured["args"]


def _base(**overrides) -> QemuVMConfiguration:
    """A minimal valid QemuVMConfiguration, with per-case overrides."""
    fields = dict(
        qemu_bin_path="/usr/bin/qemu-system-x86_64",
        cloud_init_drive_path=None,
        image_path="/var/lib/aleph/vm/volumes/persistent/testhash/rootfs.qcow2",
        monitor_socket_path=Path("/var/lib/aleph/vm/testhash-monitor.socket"),
        qmp_socket_path=Path("/var/lib/aleph/vm/testhash-qmp.socket"),
        qga_socket_path=Path("/var/lib/aleph/vm/testhash-qga.socket"),
        vcpu_count=2,
        mem_size_mb=2048,
        interface_name=None,
        host_volumes=[],
        gpus=[],
    )
    fields.update(overrides)
    return QemuVMConfiguration(**fields)


def _volume(path: str, read_only: bool) -> QemuVMHostVolume:
    return QemuVMHostVolume(mount="", path_on_host=Path(path), read_only=read_only)


def _cases() -> dict[str, QemuVMConfiguration]:
    data = "/var/lib/aleph/vm/volumes/persistent/testhash"
    return {
        # Minimal: no GPU, no NIC, no cloud-init, no volumes.
        "minimal": _base(),
        # A NIC.
        "with_nic": _base(interface_name="vmtap3"),
        # A cloud-init drive.
        "with_cloud_init": _base(cloud_init_drive_path="/var/lib/aleph/vm/cloud-init-testhash.img"),
        # One read-only host volume.
        "host_volume_ro": _base(host_volumes=[_volume(f"{data}/ro.qcow2", True)]),
        # One read-write host volume.
        "host_volume_rw": _base(host_volumes=[_volume(f"{data}/rw.qcow2", False)]),
        # Multiple host volumes (order preserved).
        "host_volumes_multiple": _base(
            host_volumes=[
                _volume(f"{data}/a.qcow2", False),
                _volume(f"{data}/b.qcow2", True),
            ]
        ),
        # One GPU (supports_x_vga defaults to True).
        "gpu_x_vga": _base(gpus=[QemuGPU(pci_host="0000:01:00.0")]),
        # One GPU that does NOT support x-vga.
        "gpu_no_x_vga": _base(gpus=[QemuGPU(pci_host="0000:01:00.0", supports_x_vga=False)]),
        # Multiple GPUs, mixed x-vga.
        "gpu_multiple": _base(
            gpus=[
                QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True),
                QemuGPU(pci_host="0000:02:00.0", supports_x_vga=False),
            ]
        ),
        # No-GPU kitchen sink: NIC + cloud-init + two volumes (pins ordering of
        # the balloon and the migration-pin second -machine).
        "no_gpu_full": _base(
            interface_name="vmtap5",
            cloud_init_drive_path="/var/lib/aleph/vm/cloud-init-testhash.img",
            host_volumes=[
                _volume(f"{data}/a.qcow2", False),
                _volume(f"{data}/b.qcow2", True),
            ],
        ),
        # Falsy corners that pin the truthiness branches (mutation coverage):
        # qga_socket_path=None renders the literal "path=None" in the qga
        # chardev arg (the known Python f-string wart).
        "qga_socket_none": _base(qga_socket_path=None),
        # interface_name="" is Python-falsy, so the NIC block is skipped (not
        # just for None).
        "interface_empty": _base(interface_name=""),
        # cloud_init_drive_path="" is Python-falsy, so the cloud-init drive is
        # skipped (not just for None).
        "cloud_init_empty": _base(cloud_init_drive_path=""),
        # GPU kitchen sink: NIC + cloud-init + volume + GPUs (pins the q35
        # machine, the absence of the balloon and second -machine, and the
        # GPU args appended last).
        "gpu_full": _base(
            interface_name="vmtap6",
            cloud_init_drive_path="/var/lib/aleph/vm/cloud-init-testhash.img",
            host_volumes=[_volume(f"{data}/data.qcow2", False)],
            gpus=[
                QemuGPU(pci_host="0000:01:00.0", supports_x_vga=True),
                QemuGPU(pci_host="0000:02:00.0", supports_x_vga=False),
            ],
        ),
    }


def _confidential_base(**overrides) -> QemuConfidentialVMConfiguration:
    """A minimal valid QemuConfidentialVMConfiguration, with per-case overrides."""
    fields = dict(
        qemu_bin_path="/usr/bin/qemu-system-x86_64",
        cloud_init_drive_path=None,
        image_path="/var/lib/aleph/vm/volumes/persistent/testhash/rootfs.qcow2",
        monitor_socket_path=Path("/var/lib/aleph/vm/testhash-monitor.socket"),
        qmp_socket_path=Path("/var/lib/aleph/vm/testhash-qmp.socket"),
        qga_socket_path=Path("/var/lib/aleph/vm/testhash-qga.socket"),
        vcpu_count=2,
        mem_size_mb=2048,
        interface_name=None,
        host_volumes=[],
        gpus=[],
        ovmf_path=Path("/opt/aleph-vm/OVMF_CODE.fd"),
        sev_session_file=Path("/var/lib/aleph/vm/testhash/vm_session.b64"),
        sev_dh_cert_file=Path("/var/lib/aleph/vm/testhash/vm_godh.b64"),
        # SEV (0x1) by default; a SEV-ES case (0x5) is added below.
        sev_policy=0x1,
    )
    fields.update(overrides)
    return QemuConfidentialVMConfiguration(**fields)


def _confidential_cases() -> dict[str, tuple[QemuConfidentialVMConfiguration, int, int]]:
    """Confidential cases as (config, cbitpos, reduced_phys_bits). Most pin the
    default 51 / 1 host-CPUID pair; distinct_sev_host_info uses a DISTINCT pair
    so the injected values are load-bearing (see _sev_values)."""
    data = "/var/lib/aleph/vm/volumes/persistent/testhash"
    default = (DEFAULT_CBITPOS, DEFAULT_REDUCED_PHYS_BITS)
    return {
        # Minimal SEV (policy 0x1): no NIC, no cloud-init, no volumes, no GPU.
        "minimal": (_confidential_base(), *default),
        # A NIC (confidential NIC has NO rombar=0).
        "with_nic": (_confidential_base(interface_name="vmtap3"), *default),
        # A cloud-init drive.
        "with_cloud_init": (
            _confidential_base(cloud_init_drive_path="/var/lib/aleph/vm/cloud-init-testhash.img"),
            *default,
        ),
        # One read-only host volume (reuses the base _get_host_volumes_args).
        "host_volume": (_confidential_base(host_volumes=[_volume(f"{data}/ro.qcow2", True)]), *default),
        # A GPU (reuses the base _get_gpu_args; the confidential base already
        # carries a -cpu host,host-phys-bits-limit line, so this repeats it).
        "gpu": (_confidential_base(gpus=[QemuGPU(pci_host="0000:01:00.0")]), *default),
        # SEV-ES policy (0x5): pins the hex() policy rendering for the ES mode.
        "sev_es_policy": (_confidential_base(sev_policy=0x5), *default),
        # sev_policy=0 renders hex(0) == "0x0" (pins the zero-policy corner).
        "sev_policy_zero": (_confidential_base(sev_policy=0x0), *default),
        # DISTINCT injected host-CPUID pair (47 / 2, not the default 51 / 1):
        # this is what makes the injected cbitpos / reduced-phys-bits
        # load-bearing against a hardcoding Rust mutant.
        "distinct_sev_host_info": (_confidential_base(), 47, 2),
    }


def _write_battery(output_dir: Path, cases, argv_fn) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, config in cases.items():
        expected_argv = argv_fn(config)
        config_json = json.loads(config.model_dump_json())
        payload = {"config_json": config_json, "expected_argv": expected_argv}
        out = output_dir / f"{name}.json"
        out.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"wrote {out.relative_to(output_dir.parent.parent.parent.parent.parent)}")


def _write_confidential_battery(output_dir: Path, cases) -> None:
    """Like _write_battery, but sets the injected host-CPUID pair PER case
    (mutating _sev_values, which _FakeSevInfo reads) and records that exact pair
    under sev_host_info so the Rust test injects the identical SevHostInfo."""
    output_dir.mkdir(parents=True, exist_ok=True)
    for name, (config, cbitpos, reduced_phys_bits) in cases.items():
        _sev_values["cbitpos"] = cbitpos
        _sev_values["reduced_phys_bits"] = reduced_phys_bits
        expected_argv = _confidential_argv_for(config)
        config_json = json.loads(config.model_dump_json())
        payload = {
            "config_json": config_json,
            "expected_argv": expected_argv,
            "sev_host_info": {"cbitpos": cbitpos, "reduced_phys_bits": reduced_phys_bits},
        }
        out = output_dir / f"{name}.json"
        out.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"wrote {out.relative_to(output_dir.parent.parent.parent.parent.parent)}")


def main() -> None:
    qemuvm_module.asyncio.create_subprocess_exec = _fake_create_subprocess_exec
    # The plain (non-confidential) battery.
    _write_battery(OUTPUT_DIR, _cases(), _argv_for)

    # The SEV / SEV-ES confidential battery. Monkeypatch the host-CPUID reader
    # so cbitpos / reduced-phys-bits are deterministic (recorded per fixture so
    # the Rust test injects the identical SevHostInfo), and Path.is_file so the
    # godh / session existence guard passes without real files on disk.
    confidential_module.asyncio.create_subprocess_exec = _fake_create_subprocess_exec
    confidential_module.secure_encryption_info = _fake_secure_encryption_info
    original_is_file = Path.is_file
    Path.is_file = lambda self: True  # type: ignore[method-assign]
    try:
        _write_confidential_battery(CONFIDENTIAL_OUTPUT_DIR, _confidential_cases())
    finally:
        Path.is_file = original_is_file  # type: ignore[method-assign]


if __name__ == "__main__":
    main()
