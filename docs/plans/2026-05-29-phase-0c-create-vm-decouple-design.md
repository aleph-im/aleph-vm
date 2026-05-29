# Phase 0.C: message-free QEMU config build + agent translator: Design

Status: draft for review. Builds on Phase 0.B (the `Supervisor` ABC, DTOs, in-process clean methods; PR #952). Reference architecture: `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md`. This is the first half of the deferred `create_vm` vertical; the second half (wiring into `InProcessSupervisor.create_vm` + `pool.executions`) is a separate follow-up spec.

## 1. Goal and scope

Build the message-free path that turns a `CreateVmSpec` into a launchable QEMU instance configuration, plus the agent-side translator that produces a `CreateVmSpec` from an Aleph message. Together these prove that a VM can be described and constructed without the hypervisor side ever touching `ExecutableContent`.

Key finding from exploration: `QemuVMConfiguration` (`src/aleph/vm/controllers/configuration.py`) is already a fully message-agnostic chokepoint. It is plain primitives, `Path`s, and the nested `QemuVMHostVolume` / `QemuGPU` models; it serializes to JSON; and the actual launch (`controllers/__main__.py` -> `QemuVM(vm_hash, config)` -> `start()` -> the qemu command line) never reads the message. So 0.C does not rewrite the launch path. It only needs to build that config (and the cloud-init drive it points at) from a `CreateVmSpec` instead of from the message.

In scope (this PR):
- Add `ssh_authorized_keys` to the proto `CreateVmRequest` (regenerate bindings) and to the `CreateVmSpec` dataclass.
- `src/aleph/vm/supervisor/qemu_build.py`: `build_qemu_configuration(spec, vm_id, tap_interface) -> QemuVMConfiguration`, including a message-free cloud-init drive build.
- `src/aleph/vm/supervisor/translate.py`: `build_create_vm_spec(message, ...) -> CreateVmSpec` for QEMU non-confidential instances, running today's `download_all()` to materialize disks.
- Tests for both, with storage download and the `cloud-localds` subprocess stubbed.

Out of scope (later):
- Wiring `InProcessSupervisor.create_vm` and putting a spec-built VM into `pool.executions` (the VmExecution-from-spec question). Separate follow-up spec.
- Firecracker programs and instances; confidential (`QEMU_SEV`, needs firmware + SEV session files).
- GPU assignment (matching `message.requirements.gpu` to available host PCI devices) lands with the pool-integration follow-up; here GPUs are a translator parameter.
- Any boot. 0.C is verified at the configuration layer only.

## 2. Module layout

```
proto/supervisor.proto                       # + ssh_authorized_keys on CreateVmRequest; regenerate _pb
src/aleph/vm/supervisor/types.py             # + CreateVmSpec.ssh_authorized_keys: list[str]
src/aleph/vm/supervisor/qemu_build.py        # NEW
src/aleph/vm/supervisor/translate.py         # NEW
tests/supervisor/test_supervisor_qemu_build.py   # NEW
tests/supervisor/test_supervisor_translate.py    # NEW
```

Reused unchanged: `AlephQemuResources` and its `download_all()`, `create_cloud_init_drive_image`, `QemuVMConfiguration` / `QemuVMHostVolume` / `QemuGPU`, `Configuration`, `save_controller_configuration`, `QemuVM`. The only edits to existing files are the proto contract and the `CreateVmSpec` dataclass.

## 3. Contract change: `ssh_authorized_keys`

`proto/supervisor.proto`, `message CreateVmRequest`: add `repeated string ssh_authorized_keys = 13;` (next free field number). Regenerate the `_pb` bindings via `scripts/generate_proto.py`; the drift check must stay green.

`CreateVmSpec` (dataclass) gains `ssh_authorized_keys: list[str]`. It is the only guest-config field the QEMU cloud-init path needs today (YAGNI; a richer guest-config message can come later). The proto stays the authoritative source so a future Rust supervisor gets the field.

## 4. `build_qemu_configuration(spec, vm_id, tap_interface) -> QemuVMConfiguration`

A pure function (no message, no global pool state) in `qemu_build.py`, mirroring what `AlephQemuInstance.configure()` assembles today but sourced from `spec` + the supervisor-assigned `tap_interface`:

- `image_path`: the host path of the spec disk with `role == DiskRole.ROOTFS` (exactly one expected; raise `InvalidBackendError` / a clear error if missing).
- `host_volumes`: spec disks with `role in {DiskRole.EXTRA, DiskRole.DATA}` -> `QemuVMHostVolume(mount=..., path_on_host=disk.path, read_only=disk.readonly)`. Mount point: the spec disk does not carry a mount string today, so 0.C derives it the way the current code does for unnamed volumes (`/mnt/<name>`); the mount is recorded for completeness. (If mount fidelity matters, it is a small `DiskSpec` field addition; flagged in open questions.)
- `vcpu_count`: `spec.vcpus`. `mem_size_mb`: replicate the live formula verbatim, `str(int(spec.memory_mib / 1024 / 1024 * 1000 * 1000))`, where `spec.memory_mib` carries the same value `AlephQemuInstance` reads from `message.resources.memory`. This is a decouple, not a bugfix, so it preserves observed runtime behavior exactly (whatever the formula's original intent); pinned by a test. Any correction is a separate change.
- `gpus`: `spec.gpus` -> `QemuGPU(pci_host=g.pci_host, supports_x_vga=g.supports_x_vga)`.
- `interface_name`: `tap_interface.device_name` if present else `None`.
- socket paths (`monitor_socket_path`, `qmp_socket_path`, `qga_socket_path`): derived from `vm_id`/`spec.vm_id` exactly as `AlephQemuInstance` does (under `settings.EXECUTION_ROOT`).
- `qemu_bin_path`: `shutil.which("qemu-system-x86_64")`.
- `cloud_init_drive_path`: from the cloud-init build below.

Cloud-init: a message-free helper `build_cloud_init_drive(vm_hash, vm_id, tap_interface, ssh_authorized_keys, is_confidential, has_gpu) -> Path` that calls the existing `create_cloud_init_drive_image(...)` (already fully parameterized) with:
- `hostname = get_hostname_from_hash(vm_hash)`
- `ip / route / ipv6 / ipv6_gateway` from `tap_interface` (`guest_ip.with_prefixlen`, `host_ip` split, `guest_ipv6.with_prefixlen`, `host_ipv6.ip`), matching `interface.py`'s accessors
- `nameservers = settings.DNS_NAMESERVERS`
- `ssh_authorized_keys = spec.ssh_authorized_keys` (the existing code also appends `settings.DEVELOPER_SSH_KEYS` when `USE_DEVELOPER_SSH_KEYS`; preserve that)
- `has_gpu = bool(spec.gpus)`, `is_confidential = spec.backend == Backend.QEMU_SEV` (always `False` in 0.C scope)

This sidesteps the message-coupled `CloudInitMixin._create_cloud_init_drive` (which reads `self.resources.message_content`) without modifying it. Decision: a new additive helper, not a refactor of the mixin, to keep zero risk to the live controller path.

`build_qemu_configuration` does not call `save_controller_configuration`; persisting the JSON and starting systemd belong to the deferred create_vm wiring. It returns the full `Configuration` (wrapping the `QemuVMConfiguration`, plus `vm_id`, `vm_hash`, `settings`, `hypervisor=HypervisorType.qemu`) so the deferred wiring can hand it straight to `save_controller_configuration`; tests assert on `config.vm_configuration`.

## 5. `build_create_vm_spec(message, *, gpus=()) -> CreateVmSpec` (agent translator)

In `translate.py`. For an `InstanceContent` targeting QEMU, non-confidential:
1. Materialize: instantiate `AlephQemuResources(message, namespace=vm_hash)` and `await resources.download_all()`. This reuses all existing download logic (rootfs via `rootfs.parent.ref` + writable volume, plus `download_volumes`).
2. Map to `CreateVmSpec`:
   - `vm_id = str(vm_hash)`, `backend = Backend.QEMU`, `kernel_path = Path("")`, `initrd_path = Path("")`, `persistent = True`.
   - `disks = [DiskSpec(path=resources.rootfs_path, readonly=False, format=DiskFormat.QCOW2, role=DiskRole.ROOTFS)] + [DiskSpec(path=v.path_on_host, readonly=v.read_only, format=DiskFormat.RAW, role=DiskRole.EXTRA) for v in resources.volumes]`.
   - `vcpus = message.resources.vcpus`, `memory_mib = message.resources.memory`.
   - `network = NetworkConfig(internet_access=message.environment.internet, requested_ipv6="", ipv6_prefix_len=0)`.
   - `tee = None`.
   - `gpus = [GpuSpec(pci_host=g.pci_host, supports_x_vga=g.supports_x_vga) for g in gpus]` (the assigned host GPUs, passed by the caller; default empty).
   - `ssh_authorized_keys = list(message.authorized_keys or [])`.
   - `numa_node = None`.
3. Reject out-of-scope input early: a non-instance message, a Firecracker hypervisor, or a confidential instance raises `InvalidBackendError` with a clear message.

The download is a side effect delegated to the resources object, so tests stub `AlephQemuResources.download_all` (and set `rootfs_path`/`volumes`) and assert the mapping. The translator's value is the mapping correctness, exercised without storage access.

## 6. Testing

- `test_supervisor_translate.py`: construct a minimal QEMU `InstanceContent` (or a stand-in with the accessed attributes), monkeypatch `AlephQemuResources.download_all` to set known `rootfs_path` + `volumes`, call `build_create_vm_spec`, and assert every `CreateVmSpec` field (disks/roles/paths, vcpus, memory_mib, network, ssh_authorized_keys, backend, persistent). Add rejection tests (program message, firecracker instance, confidential) raising `InvalidBackendError`.
- `test_supervisor_qemu_build.py`: build a `CreateVmSpec` (rootfs + one extra volume + optional GPU) and a fake `tap_interface` (SimpleNamespace exposing `device_name`, `guest_ip`, `host_ip`, `guest_ipv6`, `host_ipv6`); monkeypatch `create_cloud_init_drive_image` (it shells out to `cloud-localds`) to return a known path; call `build_qemu_configuration`; assert the `QemuVMConfiguration` fields (image_path, host_volumes, vcpu_count, mem_size_mb, gpus, interface_name, cloud_init_drive_path). Pin the MiB->MB conversion with an explicit value. Add a test that a spec with no ROOTFS disk raises a clear error.

Tests run under the project test env; style (ruff/isort) and mypy must pass on the new modules and tests, following 0.B conventions (sibling imports, no `tests/supervisor/__init__.py`).

## 7. Non-goals and risks

Non-goals: no `create_vm` wiring, no `pool.executions` integration, no boot, no agent call-site changes.

Risks:
- The translator's `download_all` hits real storage; only stubbed in tests, exercised for real when the pool-integration follow-up wires create_vm. Acceptable for this phase.
- The MiB->MB memory conversion in the live code looks like it assumes a bytes input. 0.C uses the conversion that yields the correct MB for a MiB input and pins it; if the live formula is intentional we reconcile in review (see open questions).
- Disk mount strings: `DiskSpec` has no mount field, so volume mount points are derived, not carried. Fine for the rootfs-centric QEMU path; revisit if multi-volume mount fidelity is needed.

## 8. Decisions (resolved)

1. Memory conversion: replicate the live formula verbatim to preserve runtime behavior; pin with a test. Not a bugfix.
2. `build_qemu_configuration` returns the full `Configuration` (wrapping `QemuVMConfiguration`).
3. Volume mount fidelity: derive mount points as the current code does; do not add a `mount` field to `DiskSpec` unless a real multi-mount case requires it.
