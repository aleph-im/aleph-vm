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

Contract additions (regenerated bindings committed):

- `CreateVmRequest.program_mode: bool` — supervisor uses the program boot
  flow (vsock init handshake, no cloud-init); carries no Aleph vocabulary.
- `VmInfo.control_socket_path: string` — host UDS path of the VM's vsock;
  empty for backends without one.
- `VmInfo.runtime_version: string` — the version string the guest init
  reported during the handshake (the agent needs it to format the config
  push); empty until init signaled / for non-program VMs.
- `VmInfo.ipv4_gateway` / `ipv6_gateway` — host-side tap addresses, needed
  by the agent to fill the guest network config it pushes.

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
