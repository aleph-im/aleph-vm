#!/usr/bin/env python3
"""Generate QEMU argv conformance fixtures from the REAL Python QemuVM.

For increment A1 the Python `QemuVM.start()` is the argv parity oracle. This
script builds a battery of `QemuVMConfiguration` objects, instantiates the
actual `QemuVM`, and captures the argv it would have exec'd by monkeypatching
`asyncio.create_subprocess_exec` to record the args and abort before spawning.

Each case is emitted as a JSON file `{name}.json` under
`rust/crates/supervisor-controller/tests/conformance/controller_argv/`:

    {"config_json": <the vm_configuration object>, "expected_argv": [...]}

`config_json` is the object the Rust `QemuConfig` reader parses; `expected_argv`
is what the Rust `build_argv` must reproduce byte for byte.

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
from aleph.vm.supervisor_interface.configuration import (
    QemuGPU,
    QemuVMConfiguration,
    QemuVMHostVolume,
)

OUTPUT_DIR = (
    Path(__file__).resolve().parent.parent / "rust/crates/supervisor-controller/tests/conformance/controller_argv"
)

_captured: dict[str, list] = {}


class _Abort(Exception):
    """Raised by the fake exec to stop QemuVM.start() before it spawns."""


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


def main() -> None:
    qemuvm_module.asyncio.create_subprocess_exec = _fake_create_subprocess_exec
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    for name, config in _cases().items():
        expected_argv = _argv_for(config)
        # The object the Rust QemuConfig reader parses (mem_size_mb serializes
        # to a plain int MiB via the PlainSerializer).
        config_json = json.loads(config.model_dump_json())
        payload = {"config_json": config_json, "expected_argv": expected_argv}
        out = OUTPUT_DIR / f"{name}.json"
        out.write_text(json.dumps(payload, indent=2) + "\n")
        print(f"wrote {out.relative_to(OUTPUT_DIR.parent.parent.parent.parent.parent)}")


if __name__ == "__main__":
    main()
