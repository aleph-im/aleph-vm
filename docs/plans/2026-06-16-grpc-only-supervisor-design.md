# gRPC-only supervisor: full process split

**Status:** Design, approved 2026-06-16
**Author:** Olivier Desenfans
**Base branch:** `dev` (after aleph-vm#977)

## Goal

Make the two-process split the only supported deployment: a supervisor daemon
that owns the VM pool and serves the `Supervisor` interface over gRPC, and an
agent/web process that reaches VMs exclusively through that interface and never
holds a `VmPool`. The in-process (monolith) mode disappears from production.

## Background

aleph-vm#977 introduced a dual-mode supervisor:

- `InProcessSupervisor` (`inprocess.py`) is the pool-backed engine that actually
  drives VMs. Despite the name, it is not "the agent's in-process mode": it is
  the implementation that manipulates the pool, controllers, and systemd.
- The supervisor daemon (`python -m aleph.vm.supervisor`, `daemon.py:40`)
  constructs `InProcessSupervisor(pool)` and serves it over gRPC on a Unix
  socket.
- The agent picks its supervisor at `supervisor.py:209-213`: `GrpcSupervisor`
  when `SUPERVISOR_GRPC_SOCKET` is set, otherwise `InProcessSupervisor(pool)`
  in the same process. In-process is the current default.

The agent still reaches around the `Supervisor` interface in several endpoints,
holding the pool directly via `require_vm_pool()`. Those endpoints return HTTP
501 in split mode. This design removes every such bypass, then makes the split
the default and only production path.

## Naming clarification

`InProcessSupervisor` is renamed `LocalSupervisor`: the pool-backed engine that
runs co-located with the pool. The name no longer implies the agent runs it.
`GrpcSupervisor` (the client) keeps its name.

## Target architecture

Two processes in production:

- **Supervisor daemon** (`python -m aleph.vm.supervisor`): owns `VmPool`,
  controllers, systemd supervision, and capacity truth. Serves the `Supervisor`
  interface over gRPC on a Unix socket. Backed by `LocalSupervisor`.
- **Agent / web** (`python -m aleph.vm.orchestrator`): the HTTP API,
  `AgentVmRegistry` (ownership, billing, persistence metadata), expiry,
  update-watcher, and HAProxy/L7 routing. Holds only a `GrpcSupervisor`. Never
  imports or constructs a `VmPool`.

### Core invariant

The agent reaches VMs exclusively through the `Supervisor` interface. That
interface is wired to gRPC in production, or to `LocalSupervisor` directly in
dev and tests (the "embedded" seam). Both are the same interface and the same
agent code path; only the wiring differs.

### Layering: who owns what

- **Supervisor (L3/L4):** network namespaces, nftables, DNAT port-forwards
  (`PortForwardingOps`), VM lifecycle, backup/restore, migration, confidential
  operations, admission/capacity. The supervisor must not know that HAProxy
  exists.
- **Agent (L7):** HAProxy hostname routing, driven entirely by
  `supervisor.list_vms()`. Ownership, billing, persistence, expiry, and update
  watching stay agent-side.

## Interface surface to complete

These capabilities still bypass the `Supervisor` interface and must be routed
through it. Each gets an ABC method, a gRPC RPC (Phase 2), and a
`LocalSupervisor` implementation.

| Capability | Current state | Work |
| --- | --- | --- |
| Backup / restore | ABC + proto methods exist; agent endpoints still use the pool | Rewire endpoints to call the interface; drop pool access |
| Migration export/import/cleanup | agent uses the pool; a provisional directory-based `export_vm`/`import_vm` exists but is unused | Delete the directory-based flow; drive standard lifecycle RPCs from the P2P runner (import builds a spec and calls `create_vm`, restart via `start_vm`, cleanup via `delete_vm(wipe=False)`); keep one `stop_vm_for_export` for the graceful guest powerdown |
| Confidential init/measurement/inject | `LocalSupervisor` raises `NotImplementedSupervisorError`; logic lives in agent endpoints via `QemuVmClient` | Implement in the engine; rewire endpoints |
| Admission + GPU reservation | Agent calls `pool.check_admission()` then `create_vm`; GPU `reserve_resources` is a separate pool call | Fold capacity check and GPU reservation into `create_vm`, atomic, returning typed `InsufficientResources`. Resolve whether the scheduler still needs a standalone pre-create `reserve_resources` RPC |
| `recreate_network` | Agent uses `pool.executions` to re-apply firewall | New supervisor method. Marked for later removal (artifact of a prior design); kept for now because it exists and uses the pool |
| Persistent programs | `_run_code_on_request_legacy` (`run.py:553`) serves them off the pool; 501 in split mode | Route through the spec/supervisor path; retire the legacy path |

On-demand (non-persistent) programs already route through the supervisor
(`run.py:512`, `_ensure_program_vm(supervisor=...)`); no work needed there.

### Admission folded into create_vm

`create_vm` performs the capacity check and GPU reservation atomically inside
the engine and returns a typed `InsufficientResources` error when over
capacity. This removes the cross-process check-then-create TOCTOU race and the
extra round trip. Pre-flight capacity for display or scheduling remains
available through the existing `get_host_info` RPC.

### HAProxy moves fully to the agent

`update_domain_mapping` (`pool.py:1038`) needs only the set of local VM hashes
and their IPs, both available from `supervisor.list_vms()` -> `VmInfo.ipv4`.
HAProxy runs on the same host as the agent and is reached through its admin
socket. The HAProxy logic moves out of `pool.py` into an agent-side HAProxy
manager fed by `list_vms()`. The periodic re-sync (`tasks.py:266,540`) and the
`operate_update` tail (`__init__.py:1169`) become agent-side calls with no pool
or supervisor involvement. An HAProxy resync can no longer be blocked by
supervisor availability.

## Error model

Typed supervisor errors map to gRPC status codes and then to agent HTTP
statuses (for example `VmNotFoundError` -> NOT_FOUND -> 404,
`InsufficientResources` -> RESOURCE_EXHAUSTED -> 409/503). The mapping is
centralized in `grpc_server` and `grpc_client`, extending what exists today.
`NotImplementedSupervisorError` is deleted once the stubs are implemented.

## Packaging (Phase 2)

Production runs two systemd services plus the existing per-VM controller
template:

- `aleph-vm-supervisor.service`: `ExecStart=python -m aleph.vm.supervisor
  --socket /var/lib/aleph/vm/supervisor.sock`. Owns the pool, runs as root.
- `aleph-vm-agent.service` (new): `ExecStart=python -m aleph.vm.orchestrator`,
  with `Environment=ALEPH_VM_SUPERVISOR_GRPC_SOCKET=...` and
  `After=`/`Wants=aleph-vm-supervisor.service`.
- `aleph-vm-controller@.service`: unchanged. Controllers are already separate
  processes, owned by the daemon, which reattaches to running controllers on
  startup.

`postinst` migrates the old single unit into the two new units on upgrade.
The socket is set by default, so production is gRPC-only and the embedded path
never runs there. This is a hard cut with no monolith fallback, acceptable
because the feature is pre-release on `dev`.

## Decomposition

Interface-first, two phases. Each step is a shippable PR. Phase 1 keeps
production single-process; Phase 2 adds the wire protocol and packaging.

### Phase 1: decouple the agent from the pool

The agent stops touching the pool. Everything routes through the `Supervisor`
interface, wired to the embedded `LocalSupervisor`. Tests use the embedded
engine.

- **P1.1** Rename `InProcessSupervisor` -> `LocalSupervisor`. Make the
  embedded-vs-gRPC wiring explicit. No behavior change.
- **P1.2** Rewire backup/restore endpoints to `Supervisor` methods; drop pool
  access.
- **P1.3** Rewire migration export/import/cleanup; add a `cleanup` method if
  missing.
- **P1.4** Implement confidential operations in `LocalSupervisor`; rewire the
  endpoints; remove the agent's `QemuVmClient` use for these.
- **P1.5** Fold admission and GPU reservation into `create_vm`; remove the
  agent-side admission check; resolve the standalone `reserve_resources`
  endpoint.
- **P1.6a** Add `recreate_network` to the supervisor; rewire.
- **P1.6b** Move HAProxy/domain-mapping into an agent-side manager fed by
  `list_vms()`; remove it from `pool.py`.
- **P1.7** Route persistent programs through the spec/supervisor path; retire
  `_run_code_on_request_legacy`; delete `require_vm_pool` and every remaining
  agent pool reference.

End state: the agent has zero `VmPool` references; `require_vm_pool` is gone.

### Phase 2: transport and packaging

- **P2.1** Extend the proto, `grpc_server`, and `grpc_client` for every method
  added in Phase 1; the proto-clean check passes.
- **P2.2** Split packaging into two systemd services with `postinst`
  migration; set the socket by default.
- **P2.3** Flip the production default to gRPC; confine the embedded path to
  dev and tests; validate the two-process deployment on the testnet.

## Testing

- **Unit:** agent endpoints against a fake `Supervisor` (the existing pattern),
  plus `LocalSupervisor` engine unit tests.
- **Integration:** the embedded engine for fast in-process runs, plus a
  gRPC-over-UDS fixture that exercises serialization, plus the Phase 2 testnet
  two-process run.

## Out of scope

- Removing `recreate_network` (tracked separately; it is kept here).
- Multi-host or remote supervisor (the socket is local-only).
- Any change to the per-VM controller process model.

## Open questions

- Does the scheduler still require a standalone pre-create `reserve_resources`
  RPC, or is folding GPU reservation into `create_vm` sufficient? Resolved
  during P1.5 planning.
- Does migration `cleanup` need a dedicated `Supervisor` method, or can it be
  expressed through existing methods? Resolved during P1.3.
