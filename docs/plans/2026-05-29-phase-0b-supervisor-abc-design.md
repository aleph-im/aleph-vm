# Phase 0.B: the `Supervisor` abstraction (ABC + DTOs + in-process implementation): Design

Status: draft for review. Follows Phase 0.A (the `supervisor.proto` contract and generated bindings, PR #950, renamed in PR #951). Reference architecture: `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md`.

## 1. Goal

Introduce the Python `Supervisor` abstraction inside aleph-vm: the single call path from agent code (HTTP views, orchestrator) into VM-management functionality. It is the seam that a gRPC client (0.D) and eventually a Rust supervisor (Phase 2) drop into without the agent noticing.

This phase delivers the abstraction and a working in-process implementation of the methods that wrap today's `VmPool` / `VmExecution` cleanly. It changes no agent call site (view migration is 0.E) and does not yet implement VM creation (that is a dedicated follow-up, see §2).

## 2. Scope

In scope (this PR):

- `aleph.vm.supervisor` package: `abc.py`, `types.py`, `errors.py`, `inprocess.py`.
- A capability-grouped, async `Supervisor` ABC mirroring the 25 RPCs of `supervisor.proto`.
- Hand-written dataclass DTOs (the agnostic vocabulary), including `CreateVmSpec`, plus the closed `SupervisorError` hierarchy and the internal-exception translation table.
- Real in-process implementations of the 12 methods that wrap existing behavior: `health`, `get_host_info`, `get_vm`, `list_vms`, `delete_vm`, `reboot_vm`, `reinstall_vm`, the three port-forwarding methods, and the two log methods.
- A reusable conformance test suite plus unit tests for the clean methods and the error translation table.

Out of scope (later phases):

- The entire `create_vm` vertical: the `ExecutableContent -> CreateVmSpec` translator, resource materialization, and the spec-driven construction path. Building a VM from a `CreateVmSpec` requires decoupling the resources layer (`AlephQemuResources` and friends, built from the Aleph message today) and the controller constructors (`AlephQemuInstance`, which reads `message.environment` and `message.resources`) from the message. That is a real slice of the §4 detangle and gets its own follow-up PR. In 0.B, `create_vm` raises `NotImplementedSupervisorError` for every backend.
- Backups (6), migration (3), confidential (3): `NotImplementedSupervisorError` in 0.B. The migration proto shape is still provisional (see proto note and design doc open questions).
- The gRPC client implementation (0.D) and migrating `orchestrator/views` + `run.py` onto the abstraction (0.E).
- Real SEV-SNP attestation (Phase 3).

### 2.1 What is functional after this phase

The abstraction is real and test-covered but dormant: no live HTTP path calls it yet (that swap is 0.E). After 0.B:

- 12 of the 25 methods have real implementations behind the abstraction, verified by the conformance and unit tests against a faithful `VmPool`: `health`, `get_host_info`, `get_vm`, `list_vms`, `delete_vm`, `reboot_vm`, `reinstall_vm`, the three port-forwarding methods, and the two log methods.
- The remaining 13 are explicit stubs that raise `NotImplementedSupervisorError`: `create_vm` (all backends), backups (6), migration (3), confidential (3).
- Nothing in `orchestrator/views` or `run.py` is rewired. Production behavior is unchanged.

`CreateVmSpec` ships as a dataclass (part of the contract vocabulary) so the type is available for the follow-up and for 0.D, but nothing produces or consumes it in 0.B.

## 3. Module layout

```
src/aleph/vm/supervisor/
  _pb/            # generated proto bindings (exists, from 0.A + rename)
  errors.py       # closed SupervisorError hierarchy + translation helper
  types.py        # dataclass DTOs + local enums
  abc.py          # capability ABCs + aggregate Supervisor
  inprocess.py    # InProcessSupervisor wrapping VmPool / VmExecution
```

`supervisor` (singular) is the contract boundary. It is distinct from the existing `aleph.vm.hypervisors` (plural), which are the real Firecracker/QEMU launchers and are not touched.

## 4. Capability sub-interfaces (`abc.py`)

Seven ABCs, all methods `async`, 25 methods total, one-to-one with the proto service. A concrete `Supervisor` aggregates them:

```python
class Supervisor(
    HostOps, LifecycleOps, PortForwardingOps,
    LogsOps, BackupOps, MigrationOps, ConfidentialOps, ABC,
):
    ...
```

| ABC | Methods | 0.B |
| --- | --- | --- |
| `HostOps` | `health() -> HealthInfo`, `get_host_info() -> HostInfo` | real |
| `LifecycleOps` | `create_vm(spec: CreateVmSpec) -> VmInfo` | stub |
| | `get_vm(vm_id) -> VmInfo`, `list_vms() -> list[VmInfo]`, `delete_vm(vm_id) -> None`, `reboot_vm(vm_id) -> VmInfo`, `reinstall_vm(vm_id) -> VmInfo` | real |
| `PortForwardingOps` | `add_port_forward(spec) -> PortForwardInfo`, `remove_port_forward(vm_id, host_port, protocol) -> None`, `list_port_forwards(vm_id \| None) -> list[PortForwardInfo]` | real |
| `LogsOps` | `get_logs(vm_id, max_lines, from_tail) -> list[LogChunk]`, `stream_logs(vm_id, include_history) -> AsyncIterator[LogChunk]` | real |
| `BackupOps` | `start_backup`, `get_backup_status`, `list_backups`, `download_backup -> AsyncIterator[BackupChunk]`, `delete_backup`, `restore_backup` | stub |
| `MigrationOps` | `export_vm`, `import_vm`, `get_migration_status` | stub |
| `ConfidentialOps` | `initialize_confidential`, `get_measurement`, `inject_secret` | stub |

VM identity at the boundary is `vm_id: str` (the Aleph `ItemHash` rendered to its string form, matching the proto `string vm_id`). The in-process implementation converts `str -> ItemHash` internally. The agent and any future Rust supervisor never need the `aleph_message` type.

Streaming methods return `AsyncIterator[...]`, so the same signature works for the in-process generator and the gRPC server-stream in 0.D.

## 5. DTOs (`types.py`)

Frozen dataclasses and local enums mirroring the proto messages. Enums use plain `enum.Enum` with the proto's semantic names (without the proto `*_UNSPECIFIED` and prefix noise). The mapping to and from the proto wire enums lives only in the gRPC implementation (0.D), never here.

Enums: `Backend{FIRECRACKER, QEMU, QEMU_SEV}`, `VmStatus{DEFINED, BOOTING, RUNNING, STOPPING, STOPPED, FAILED}`, `DiskFormat{RAW, QCOW2, SQUASHFS}`, `DiskRole{ROOTFS, CODE, RUNTIME, DATA, EXTRA}`, `Protocol{TCP, UDP}`, `LogSource{SERIAL, STDOUT, SYSTEMD}`, `BackupStatus{PENDING, RUNNING, COMPLETE, FAILED}`, `MigrationPhase{PREPARING, EXPORTING, IMPORTING, COMPLETE, FAILED}`, `TeeBackend{NONE, SEV_SNP, TDX, NVIDIA_CC}`, `HealthStatus{OK, DEGRADED}`.

Domain types (`typing.NewType`, zero runtime cost, still `str`/`int` at runtime but distinct to the type checker so call sites must wrap explicitly): `VmId`, `BackupId`, `MigrationId`, `PciAddress` over `str`; `HostPort`, `GuestPort` over `int` (deliberately separate, since a host-side allocated port and an in-guest port are never interchangeable). Paths use `pathlib.Path` for files and `DirectoryPath = NewType(..., Path)` for directories (stdlib has no directory-specific type; this marks intent without runtime validation). The field types below use these where applicable (`vm_id: VmId`, `backup_id: BackupId`, `host_port: HostPort`, `vm_port: GuestPort`, `*_dir: DirectoryPath`, etc.).

Carriers (field set mirrors the proto messages of 0.A):

- `CreateVmSpec`: `vm_id`, `backend`, `kernel_path`, `initrd_path`, `disks: list[DiskSpec]`, `vcpus`, `memory_mib`, `tee: TeeConfig | None`, `network: NetworkConfig`, `gpus: list[GpuSpec]`, `numa_node: int | None`, `persistent`.
- `DiskSpec`: `path`, `readonly`, `format: DiskFormat`, `role: DiskRole`.
- `TeeConfig`: `backend: str`, `policy: str`, `session_dir: str`.
- `NetworkConfig`: `internet_access`, `requested_ipv6`, `ipv6_prefix_len`.
- `GpuSpec`: `pci_host`, `supports_x_vga`.
- `VmInfo`: `vm_id`, `status: VmStatus`, `ipv4`, `ipv6`, `uptime_secs`, `backend`, `numa_node: int | None`, `status_message`.
- `PortForwardSpec` (request) and `PortForwardInfo` (response): `vm_id`, `host_port`, `vm_port`, `protocol`.
- `LogChunk`: `timestamp_ns`, `line`, `source: LogSource`.
- `BackupInfo`: `vm_id`, `backup_id`, `status`, `size_bytes`, `created_at_unix_secs`, `error_message`. `BackupChunk`: `data: bytes`, `offset`.
- `MigrationInfo`: `vm_id`, `migration_id`, `phase`, `bytes_transferred`, `bytes_total`, `error_message`.
- `Measurement`: `vm_id`, `measurement_bytes: bytes`, `tee_backend: str`.
- `HostInfo`, `HealthInfo`: mirror `HostInfo` / `HealthResponse`.

## 6. The VM description layer (`CreateVmSpec`) and the deferred create path

`CreateVmSpec` is the agnostic VM description that will cross the boundary. It mirrors the proto `CreateVmRequest` and contains no Aleph types: disks are host paths with a role and format, resources are plain integers, the TEE config is strings. This is the layer that lets a remote (Rust) supervisor build a VM with no knowledge of Aleph messages. It ships in 0.B as a dataclass so the vocabulary is complete; producing and consuming it is the follow-up.

Recorded decision for the follow-up (do not re-litigate without cause): resource materialization (downloading code/runtime/rootfs/volumes from Aleph storage to host paths) is an agent-side responsibility, consistent with the seam mapping (storage lives on the agent side) and with the proto modeling disks as host paths rather than refs. A remote supervisor cannot fetch Aleph storage, so the descriptor must carry materialized paths. The follow-up adds the `ExecutableContent -> CreateVmSpec` translator (which triggers materialization, reusing the download logic extracted from `VmExecution.prepare`) and a spec-driven construction path that decouples `AlephQemuResources` and `AlephQemuInstance` from the message.

## 7. Error model (`errors.py`)

A closed `SupervisorError` base carrying a `code: ErrorCode`, with one subclass per proto `ErrorCode` value:

`VmNotFoundError`, `VmAlreadyExistsError`, `InsufficientResourcesError`, `ResourceDownloadError`, `FileTooLargeError`, `VmSetupError`, `MicroVMInitError`, `InvalidBackendError`, `TeeUnavailableError`, `PortUnavailableError`, `HostNotFoundError`, `BackupNotFoundError`, `MigrationInProgressError`, `NotImplementedSupervisorError` (maps to `INTERNAL` for now), `InternalSupervisorError`.

These are a new, distinct set in `aleph.vm.supervisor.errors`. They are deliberately not the existing internal exceptions, several of which share names (`InsufficientResourcesError`, `VmSetupError`, `FileTooLargeError`, `ResourceDownloadError`, `HostNotFoundError`, `MicroVMFailedInitError`) and live scattered across `controllers/`, `hypervisors/`, and `resources.py`.

The in-process implementation owns the translation: a `translate_exception(exc) -> SupervisorError` helper catches the internal exceptions raised by `VmPool` / `VmExecution` / controllers and returns the corresponding `SupervisorError`. That table is the wire error vocabulary the architecture doc calls the most underestimated piece of Phase 0. Building it here, in Python, against the real raise sites (Annex A.6 of the design doc) is the entire point of doing it before any gRPC exists. The gRPC server (0.D) reuses the same table to fill `ErrorDetail`; views (0.E) catch `SupervisorError` instead of backend internals.

Initial table (internal -> boundary -> proto code):

| Internal exception | `SupervisorError` | `ErrorCode` |
| --- | --- | --- |
| `InsufficientResourcesError` (`resources.py`) | `InsufficientResourcesError` | `INSUFFICIENT_RESOURCES` |
| `ResourceDownloadError` (`controllers/firecracker/executable.py`) | `ResourceDownloadError` | `RESOURCE_DOWNLOAD_FAILED` |
| `FileTooLargeError` (`controllers/firecracker/program.py`) | `FileTooLargeError` | `FILE_TOO_LARGE` |
| `VmSetupError` (`controllers/firecracker/executable.py`) | `VmSetupError` | `VM_SETUP_FAILED` |
| `MicroVMFailedInitError` (`hypervisors/firecracker/microvm.py`) | `MicroVMInitError` | `MICROVM_INIT_FAILED` |
| `HostNotFoundError` (`utils/__init__.py`) | `HostNotFoundError` | `HOST_NOT_FOUND` |
| any other `Exception` | `InternalSupervisorError` | `INTERNAL` |

`VmNotFoundError` is raised directly by the in-process implementation on a missing `pool.executions` key (not translated from an internal exception).

## 8. In-process implementation (`inprocess.py`)

`InProcessSupervisor(Supervisor)` holds a `VmPool`. Per-capability status in this PR:

| Methods | Status | Mechanism |
| --- | --- | --- |
| `health`, `get_host_info` | real | read pool/system state; assemble `HealthInfo` / `HostInfo` |
| `get_vm`, `list_vms` | real | `pool.executions` lookup, `VmExecution -> VmInfo` mapping (mirrors `views/__init__.py:200-277`) |
| `delete_vm` | real | `pool.stop_vm` + `pool.forget_vm` |
| `reboot_vm`, `reinstall_vm` | real | `systemd_manager.restart` / recreate, mirroring `views/operator.py` |
| `add/remove/list_port_forward` | real | `VmExecution.update_port_redirects` and the `mapped_ports` dict |
| `get_logs`, `stream_logs` | real | `vm.get_log_queue` / `unregister_queue`, yielding `LogChunk` |
| `create_vm` | stub | `NotImplementedSupervisorError`; the create vertical is a follow-up (§6) |
| backups, migration, confidential | stub | `NotImplementedSupervisorError` |

The `VmExecution -> VmInfo` mapping reads: `vm_id = str(execution.vm_hash)`; `status` derived from `execution.times` / persistent systemd state (mirroring the `running_states` logic at `views/__init__.py:200-221`); `ipv4` / `ipv6` from `execution.vm.tap_interface.guest_ip` / `guest_ipv6` when present; `backend` from `execution.hypervisor`; `uptime_secs` from `execution.times.started_at`.

## 9. Testing

- Conformance suite: an abstract `SupervisorContractTests` (pytest, parametrized over a supervisor fixture) asserting the 25 methods exist with the right arity, the stub methods raise `NotImplementedSupervisorError`, and `vm_id` identity is handled as `str`. Written once, reused for the gRPC implementation in 0.D.
- Error translation tests: each internal exception fed to `translate_exception` maps to the expected `SupervisorError` subclass and `ErrorCode`; unknown exceptions map to `InternalSupervisorError` / `INTERNAL`.
- In-process unit tests for the 12 real methods against a faked `VmPool` (a lightweight object exposing `executions`, `systemd_manager`, `stop_vm`, `forget_vm`), asserting DTO output and that a missing VM raises `VmNotFoundError`.
- Style mirrors 0.A's `tests/supervisor/test_proto_bindings.py`. New tests live under `tests/supervisor/`.

## 10. Non-goals and risks

Non-goals: no agent call site changes, no public CRN HTTP API change, no new VM features, no process split, no VM creation.

Risks:

- The `VmExecution -> VmInfo` mapping drifts from the live status view. Mitigation: mirror `views/__init__.py:200-277` exactly and pin the field set with tests; the real convergence happens when that view migrates in 0.E.
- The error translation table is incomplete. Mitigation: it is seeded from the documented raise sites (Annex A.6) and is additive; new mappings are cheap to add when create/backup/migration land.

## 11. Open questions for review

1. `HostInfo` / `HealthInfo` content: how much host detail to populate in 0.B versus stub now and enrich when the host-status view migrates (0.E). Leaning: populate what is trivially available (VM count, basic capacity), defer the rest.
2. Should `reboot_vm` / `reinstall_vm` reuse the eventual `create_vm` spec path, or keep their current systemd-level mechanics? Leaning keep-as-is, since create is deferred anyway.
3. Faked `VmPool` vs a real instance in tests: a real `VmPool()` constructs a `Network` and `SystemDManager` (side effects). Leaning: a small fake exposing only the attributes the methods touch, to keep unit tests hermetic.

## 12. Carry-forward to 0.E (from the 0.B final review)

These are correct-as-built for a dormant phase but become observable when the methods go live behind real views in 0.E. They are recorded here so they are not lost:

1. `get_logs` reads a freshly created live journal queue and drains only what is already buffered, so in production it returns near-empty and ignores `max_lines`/`from_tail`. When it goes live, switch to the history path the current view uses (`get_past_vm_logs()` / `seek_head()`).
2. `stream_logs` is the one real method not wrapped in `translating_errors()` (its `_require` already raises a `SupervisorError`, but errors from `queue.get()` during streaming would escape untranslated). Wrapping an async generator's `yield` in the sync context manager has `aclose`/`GeneratorExit` subtleties, so this was deferred rather than risked in 0.B. Wrap it (carefully, with an explicit per-iteration translate) when it goes live.
3. `add_port_forward` always auto-allocates the host port (the underlying `update_port_redirects` uses `fast_get_available_host_port`), so `spec.host_port` is ignored. Either honor it or document it as auto-only at the agent boundary.
4. `LogChunk.timestamp_ns` is always 0, and `LogSource.SYSTEMD` is never emitted (`_log_source` maps stdout/stderr to STDOUT, else SERIAL). Enrich when the persistent-VM journal path is wired.
5. `reboot_vm` / `reinstall_vm` return a `VmInfo` computed from the pre-restart in-memory execution, so the status can be momentarily stale.
6. The repo configures several `ruff` lint rules (EM, ARG, FBT, S, PLR) but CI's `linting:style` only runs `ruff format` + `isort`, not `ruff check`. The 0.B code carries some of those (unenforced) warnings, consistent with the rest of the tree.
