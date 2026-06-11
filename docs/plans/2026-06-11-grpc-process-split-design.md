# Phase 1 acceleration: gRPC transport, program path, process split

**Date:** 2026-06-11
**Status:** Experimental (dev-accelerate branch)
**Lineage:** follows `2026-05-28-aleph-vm-architecture-backport-design.md` (§6
Phase 1), `2026-06-01-wire-agent-onto-supervisor-design.md`, and the
message-free-supervisor series (#954–#976).

## 1. Goal

Get the agent and the supervisor running as **two separate processes** with
all live VM operations (instances *and* on-demand Firecracker programs)
crossing the boundary through the gRPC contract (`proto/supervisor.proto`).

Exit criteria for this branch:

1. `GrpcSupervisor` (client) and a gRPC server exist and pass the existing
   `SupervisorContractTests` conformance suite over a real UDS channel.
2. The on-demand program path (`run_code_on_request` / `run_code_on_event`)
   no longer touches `pool` / `VmExecution`; programs are created through
   `supervisor.create_vm` and served through agent-owned vsock connections.
3. A supervisor daemon entrypoint (`python -m aleph.vm.supervisor`) owns the
   `VmPool`; the agent, when `ALEPH_VM_SUPERVISOR_GRPC_SOCKET` is set,
   constructs a `GrpcSupervisor` instead of an in-process pool and serves the
   public CRN HTTP API unchanged for the migrated surface.

Out of scope (stay stubbed / in-process-only, consistent with the series):
backups, migration, confidential implementations, GPU instances, the
domains-aggregate networking path, resource admission redesign.

## 2. Stage A — gRPC transport for the existing contract

New modules under `src/aleph/vm/supervisor/`:

- **`proto_convert.py`** — pure DTO ⇄ proto mapping (dataclasses in
  `types.py` ⇄ `_pb.supervisor_pb2`), including the enum tables. No I/O, no
  Aleph imports. Shared by server and client; tested by round-trip unit tests.
- **`grpc_server.py`** — `SupervisorService(SupervisorServicer)` delegating
  every RPC to a wrapped `Supervisor` (the `InProcessSupervisor` in the
  daemon). `SupervisorError` → `context.abort_with_status()` carrying a
  serialized `ErrorDetail` in the `aleph-supervisor-error-bin` trailing
  metadata plus a mapped `grpc.StatusCode`. `serve_unix(supervisor, path)`
  builds and starts a `grpc.aio.server` bound to `unix:<path>`.
- **`grpc_client.py`** — `GrpcSupervisor(Supervisor)` over
  `grpc.aio.insecure_channel("unix:<path>")`. Every call translates
  `grpc.aio.AioRpcError` back into the closed `SupervisorError` vocabulary:
  primary key is the `ErrorDetail.code` trailer; fallback is the gRPC status
  code (`UNIMPLEMENTED` → `NotImplementedSupervisorError`, `NOT_FOUND` →
  `VmNotFoundError`, …).

Status-code table (server side; client falls back on it when the trailer is
absent):

| ErrorCode | grpc.StatusCode |
|---|---|
| VM_NOT_FOUND, BACKUP_NOT_FOUND, HOST_NOT_FOUND | NOT_FOUND |
| VM_ALREADY_EXISTS | ALREADY_EXISTS |
| INSUFFICIENT_RESOURCES | RESOURCE_EXHAUSTED |
| INVALID_BACKEND, FILE_TOO_LARGE | INVALID_ARGUMENT |
| PORT_UNAVAILABLE, TEE_UNAVAILABLE | FAILED_PRECONDITION |
| MIGRATION_IN_PROGRESS | FAILED_PRECONDITION |
| VM_SETUP_FAILED, MICROVM_INIT_FAILED, RESOURCE_DOWNLOAD_FAILED | INTERNAL |
| INTERNAL (incl. NotImplementedSupervisorError → UNIMPLEMENTED) | INTERNAL / UNIMPLEMENTED |

Proto fix folded in: `ReinstallVmRequest.wipe_volumes` becomes
`optional bool` so the server can apply the ABC's `True` default when unset
(the current comment documents the proto3-default wart; `optional` removes
it).

Tests: `tests/supervisor/test_supervisor_conformance_grpc.py` subclasses
`SupervisorContractTests` with a fixture that stands up the real server on a
temp UDS wrapping the same fake-pool `InProcessSupervisor` the in-process
conformance test uses, plus wire-error translation tests (each
`SupervisorError` subclass round-trips class-exact) and a streaming test.

## 3. Stage B — the program (microvm) path

Today `run_code_on_request` drives `pool.create_a_vm` → `VmExecution` →
`execution.run_code()`. All guest I/O is host-side Unix sockets:

- `{vsock}` (`v.sock`): host-initiated; `CONNECT 52` carries the
  Aleph-runtime config push and `run_code` payloads.
- `{vsock}_52`: listener bound by the hypervisor **before boot**; the guest
  init connects to signal readiness and report its runtime config.
- `{vsock}_53`: listener for the guest API HTTP server (host-side process).

The split keeps Aleph program semantics agent-side and VMM mechanics
supervisor-side:

| Concern | Owner after split |
|---|---|
| download code/runtime/data volumes | agent (`AlephProgramResources`) |
| boot the microvm with given disk paths, vsock on | supervisor (`CreateVm`) |
| bind `{vsock}_52`, wait for init signal | supervisor (part of boot; program VM reports RUNNING only after init signaled) |
| runtime config push (`CONNECT 52`), incl. code bytes, entrypoint, variables | agent |
| `run_code` request/response (`CONNECT 52`) | agent |
| guest API process (`{vsock}_53`) | agent |
| idle expiry / update-watch / teardown decision | agent (already migrated) |

Contract additions (regenerated bindings committed; reworked 2026-06-11 to
stay hypervisor- and workload-agnostic — review feedback):

- `CreateVmRequest.guest_channel: GuestChannel { ready_port }` — optional
  host⇄guest control channel (Firecracker vsock today; QEMU could implement
  it with virtio-vsock). When present, the supervisor exposes the channel
  and waits for the guest's ready signal on `ready_port` as part of boot.
  What is spoken over the channel is the client's business. (Replaced the
  earlier `program_mode: bool`, which leaked the program/instance
  distinction onto the wire.)
- `VmInfo.guest_channel_path: string` — host UDS endpoint of the channel;
  empty when the VM has none (QEMU instances).
- `VmInfo.guest_ready_payload: bytes` — the raw bytes the guest sent with
  its ready signal, passed through opaquely; the agent parses the Aleph
  runtime's msgpack version handshake out of it. (Replaced
  `runtime_version`, which required the supervisor to parse the payload.)
- `VmInfo.ipv4_gateway` / `ipv6_gateway` — host-side tap addresses (bare,
  no prefix), the guest's default routes for the agent's config push.
- `DiskRole` collapsed to ROOTFS/EXTRA: workload roles (code/runtime/data)
  are client vocabulary, mapped onto guest devices via disk order.
- `VmInfo.is_instance` removed (field 18 reserved): the instance/program
  distinction is derived agent-side from the registry, with the guest
  channel's presence as the registry-miss fallback for labeling.
- The Aleph runtime's channel conventions (control port 52, guest API port
  53) live in `aleph.vm.utils.runtime_channel`, agent-side.

Supervisor side: `pool.create_vm_from_spec` accepts
`backend=FIRECRACKER, program_mode=True` specs and builds a message-free
Firecracker program controller from the spec's disks (ROOTFS = runtime
squashfs; CODE/DATA/EXTRA preserve order so guest device names are
deterministic).

Agent side: a new `orchestrator/vm/program_client.py` owns config push,
`run_code`, and the guest-API process, keyed by `vm_hash` and driven by
`VmInfo`. `run_code_on_request`/`run_code_on_event` are rewritten on
`supervisor.create_vm` + registry, dropping `pool` entirely.

## 4. Stage C — process split

- **Daemon:** `python -m aleph.vm.supervisor` (new `daemon.py` +
  `__main__.py`): `settings.check()`, `VmPool().setup()`,
  `load_persistent_executions()`, then `serve_unix(InProcessSupervisor(pool),
  settings.SUPERVISOR_GRPC_SOCKET)`. SIGTERM → graceful server stop; VMs keep
  running (reattach on restart, #957 behavior).
- **Agent:** new setting `SUPERVISOR_GRPC_SOCKET: Path | None`. When set,
  `setup_webapp(pool=None)` wires `app["supervisor"] =
  GrpcSupervisor(socket)`; endpoints that still require the in-process pool
  (backups, restore, confidential, migration, recreate_network,
  admission/reservation) return 501 in split mode. The public API for the
  migrated surface (allocations, operator lifecycle, logs, ports, programs,
  about/executions) is unchanged.

The in-process mode remains the default; the flag is the strangler toggle.

## 5. Risks

- The init-ready handshake currently couples runtime-config parsing to the
  hypervisor object; exposing it as `VmInfo.runtime_version` keeps the proto
  Aleph-free (a version string is infra-honest) — to be validated in review.
- Two processes touching nftables: in split mode only the supervisor writes
  nft rules (unchanged invariant from the series); the agent's
  `recreate_network` endpoint is disabled.
- `v.sock_53` ownership moves process: the guest only dials the guest API
  after the config push, so binding it agent-side post-RUNNING is race-free.

## 6. Status (2026-06-11, end of first pass)

Implemented on `dev-accelerate` (stacked on #976):

- Stage A: `proto_convert` + `grpc_server` + `grpc_client` + daemon, with
  conformance/wire-error/streaming tests over a real UDS channel.
- Stage B: program path migrated (spec builder, `SpecFirecrackerProgram`
  supervisor-side, `ProgramGuestClient` agent-side, `run.py` rewritten);
  per-VM creation lock serialises concurrent cold requests.
- Stage C: split mode behind `ALEPH_VM_SUPERVISOR_GRPC_SOCKET`; pool-only
  endpoints 501.

Verified: `tests/supervisor` 716 passed with the same 9 environment-only
failures as the base branch (pyroute2/root/journald); `tests/migration` +
`tests/network` green; mypy error set identical to base; ruff format /
isort / proto-clean gates pass; cross-process smoke (daemon ⇄ agent webapp
over UDS) exercised live.

Known gaps (intentional, follow-ups):

- **In-flight run vs reap:** `VmExecution.run_code` used to count concurrent
  runs so `stop()` waited for them; across the boundary the supervisor has no
  run tracking, so an expiry-fired delete during a long in-flight `run_code`
  kills the connection (the request returns 502). Mitigated by the
  cancel-at-request-start/schedule-at-request-end bracketing; a follow-up
  could track in-flight runs agent-side and defer the reap.
- Persistent programs, backups/restore, confidential, migration, domains/
  HAProxy, GPU reservation and the advisory admission gate stay on the
  in-process pool (501 / skipped in split mode), matching the series' staging.
- **Live e2e (2026-06-11, local, no jailer):** a real program microvm ran
  through the full split — diagnostic-program message loaded from the Aleph
  network, resources downloaded agent-side, `CreateVm` over the UDS gRPC
  contract booted the VM in the daemon process (init handshake, runtime
  2.0.0), the agent pushed the configuration and ran `/` over vsock
  (HTTP 200), `DeleteVm` tore it down cleanly. Recipe: daemon with
  `ALEPH_VM_USE_JAILER=False ALEPH_VM_ALLOW_VM_NETWORKING=False`, agent
  pointed at the daemon socket. The jailered/networked variant remains
  droplet-CI territory (root), as does the legacy fake-data job.

## 7. Protocol review follow-through (2026-06-11, second pass)

A full review of `proto/supervisor.proto` (vocabulary leaks, missing
capabilities, gRPC idiom) was implemented as a commit series on this branch:

**Vocabulary scrubbed off the wire:**

- `DiskConfig.mount` dropped — dead on both backends (Firecracker mounts
  travel over the guest channel; `QemuVM` never consumed the field).
- `BACKEND_QEMU_SEV` dropped — the VMM and the TEE are orthogonal; a
  confidential VM is `backend: QEMU` + a `TeeConfig` (presence selects the
  launch path). The spec path rejects TEE specs explicitly
  (`TeeUnavailableError`) until the confidential configuration is wired.
- Enum-typed wire fields: `HealthStatus`, `Protocol` (port forwarding),
  `TeeBackend` (TeeConfig + Measurement). `is_instance` name reserved.
- `VmInfo` IP fields folded into `IpAssignment {address, network_cidr,
  gateway}` × 2 families (old numbers/names reserved).
- Guest hostname moved into `CreateVmRequest.hostname` — the base32
  item-hash naming convention is computed agent-side now; the supervisor
  falls back to a mechanical vm_id truncation.
- `GuestChannel.ready_timeout_secs` — boot-time policy crosses the wire
  (was supervisor-side `settings.INIT_TIMEOUT` only).
- Same-host invariant (paths by reference over a shared filesystem) is now
  stated in the proto header.

**Capabilities added:**

- `GetVmSpec` — the supervisor returns the spec a live VM was created from
  (UNIMPLEMENTED for legacy message-built executions).
- `CreateVm` idempotent on `vm_id` (same spec → current info; different
  spec or collision with a message-built execution → ALREADY_EXISTS).
- `RebootVm` actually reboots ephemeral spec-created VMs (stop + recreate
  from the held spec).
- `StopVm`/`StartVm` — stop without releasing the definition (persistent
  VMs; the VM stays listed STOPPED, forget-on-stop defused the reinstall
  way; StartVm runs through `restart_persistent_vm`). Ephemeral VMs answer
  UNIMPLEMENTED (their cycle is DeleteVm + CreateVm).
- `WatchEvents` — lifecycle transitions as a server stream (no replay;
  snapshot via ListVms then watch). The split-mode agent runs a
  reconnecting background watcher that drops per-VM agent state (guest API
  process, configured mark, idle timers) when a VM leaves RUNNING — the
  cross-process replacement for the in-process reap hooks.
- Live log chunks are stamped at capture (the `timestamp_ns=0` sentinel
  rendered as the 1970 epoch in clients).
- Client deadlines on every unary RPC (30s queries / 300s lifecycle) via a
  shared `_unary` helper; streams stay deadline-free.

**Verified (second pass):** full suite 769 passed + 3 xfailed with the same
9 environment-only failures; mypy error set identical to base
(line-number-normalized diff); live e2e re-ran clean on the final contract
(`ready_timeout_secs=20` on the wire, HTTP 200, clean DeleteVm).

**Deferred (from the same review, by explicit decision):**

- Resource accounting: allocated-vs-total in `HostInfo`, per-VM
  `GetVmStats` — when admission/metrics migrate to split mode.
- `google.rpc.Status` envelope instead of the custom
  `aleph-supervisor-error-bin` trailer — when external (non-aleph-vm)
  clients appear; the translation layers keep working either way.
- Capabilities/version RPC — when agent and supervisor deploy
  independently.
- Migration contract reshape (directory-based Export/Import is provisional;
  needs streaming or pull-based transport for host-to-host).
- Cloud-init beyond hostname: opaque user-data/meta-data blobs (and
  possibly a two-phase AllocateNetwork → CreateVm so the agent can render
  network-config) — `ssh_authorized_keys`, developer keys and DNS
  nameservers still materialise supervisor-side.
- Spontaneous guest-death detection feeding WatchEvents (no component
  observes VMM process exit today).

## 8. BackupOps + integration suite (2026-06-11, third pass)

**BackupOps wired.** The six `BackupOps` methods were stubs; the gRPC
plumbing (proto RPCs, server handlers, client methods, conversions) already
existed. `InProcessSupervisor` now implements them on top of
`controllers/qemu/backup.py` (the machinery the agent's operator HTTP views
use):

- One async backup job per VM, serialized per-VM against restore;
  idempotent against a running job and against a non-expired archive
  (24h TTL, mirroring the operator endpoint). Optional best-effort guest
  fs-freeze (`quiesce_guest`).
- Backups cover the rootfs disk only — symmetric with what restore can put
  back. Supervisor-issued backup ids use microsecond timestamps (id = tar
  stem; a retry after a failure must get a fresh id).
- Completed archives live on disk as the source of truth; only in-flight
  and failed runs are held in memory. Download streams 1 MiB offset-tagged
  chunks. Restore extracts the rootfs member (member-streamed, no
  extractall), verifies it, stops the VM with forget-on-stop defused, swaps
  the rootfs atomically and restarts; emits down-then-up events.

**Integration suite** (`tests/integration/`, opt-in via `AVM_ITEST=1`):
drives a real supervisor daemon over its UDS gRPC contract, agent-free —
specs built inline from local artifacts. Self-gating: Firecracker tests run
unprivileged (vsock-channel reachability); QEMU tests need root + a cloud
image (IP/SSH reachability, persistent lifecycle via a systemd drop-in that
points `aleph-vm-controller@` at the source tree under test). Covers
creation, management (logs/reboot/events/port-forwards/stop-start),
deletion + resource release (processes, files, TAPs, nftables, units), and
the full backup→mutate→restore cycle.

**Found by the suite:** the pool's forget-on-stop task deleted by hash, not
identity — a reboot (or delete+create) that recreated the VM under the same
vm_id could have its new execution removed from the pool by the old
execution's reap task. Fixed in `_schedule_forget_on_stop`.
