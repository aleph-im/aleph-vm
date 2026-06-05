# Wiring the agent onto the Supervisor abstraction (Phase 0 completion)

**Date:** 2026-06-01
**Status:** Design, approved for planning
**Design doc lineage:** follows `2026-05-28-aleph-vm-architecture-backport-design.md` (§6 Phase 0), `2026-05-29-phase-0b-supervisor-abc-design.md`, `2026-05-29-phase-0c-create-vm-decouple-design.md`, and the `2026-05-29-message-free-supervisor-create-reboot-design.md` plan (PRs #954–#957, merged).

## 1. Goal

Make the agent reach hypervisor functionality **only** through the `Supervisor`
abstraction (`src/aleph/vm/supervisor/abc.py`, in-process impl
`InProcessSupervisor`), starting with the **persistent-instance lifecycle**.
Today the abstraction is fully built and conformance-tested but nothing outside
tests instantiates it: the agent (`orchestrator/run.py`, `orchestrator/views`,
`orchestrator/tasks.py`) still reaches straight into `VmPool` and `VmExecution`
internals (~25 distinct touchpoints; `pool.executions` alone is read in 24
places).

This is the explicit Phase 0 exit criterion from the backport design:

> *"`orchestrator/views` and `orchestrator/run.py` are migrated to call the
> abstraction … every call into hypervisor functionality from agent code goes
> through the abstraction."*

It is also the prerequisite for Phase 1: a call's transport cannot be swapped to
gRPC until the call goes through the boundary.

## 2. Scope

**In scope: persistent-instance lifecycle through the abstraction**

- Create path: `create_vm_execution` (eligible-instance branch) and
  `start_persistent_vm` in `orchestrator/run.py`.
- Operator lifecycle endpoints: stop/delete, reboot, reinstall, logs, and
  port-forward listing/removal in `orchestrator/views` and the deallocation
  path in `orchestrator/tasks.py`.
- A new **agent-side registry** of created VMs (message + original), replacing
  the vestigial `pool.message_cache`.

**Explicitly out of scope:**

- The on-demand program / Firecracker HTTP serving path
  (`run_code_on_request`, `run_code_on_event`), the "hardest entanglement,"
  Phase 1 item #2.
- Resource admission, GPU reservation, domain-mapping, `drain`,
  `setup`/`teardown`, `load_persistent_executions`. These stay on the pool;
  several are agent/scheduler concerns, not hypervisor concerns.
- Backups, migration, confidential, still stubbed on `InProcessSupervisor`
  (deferred: migrate when a carved-out path needs them; confidential is Phase 3).
- Deleting the pool / the in-process implementation. That is the Phase 1 exit
  criterion, not this work.

## 3. Architecture and responsibility split

A single `InProcessSupervisor(pool)` is constructed at app startup and stored in
app state (`app["supervisor"]`), alongside the existing `pool`. The pool remains
for the out-of-scope concerns above; the agent reaches the **hypervisor** only
through the `Supervisor` ABC.

The agent gains a small **agent-side registry**:

```python
@dataclass
class AgentVmRecord:
    message: ExecutableContent
    original: ExecutableContent
```

keyed by `vm_hash`, held in app state. It is populated on **every** create
(both the spec branch and the legacy branch), so owner-auth, billing, and
port-forward resolution have a message source that does not depend on the
hypervisor. It replaces `pool.message_cache` (written once in `run.py`, read
nowhere, effectively dead).

| Concern | Owner |
|---|---|
| create / get / list / delete / reboot / reinstall / logs / port-forward *by `vm_id`*, message-free | **Hypervisor** (`Supervisor`) |
| message translation, aggregate-settings reads, port-forward **resolution**, ownership, billing, the registry, the create→poll orchestration | **Agent** (`orchestrator/run.py` + registry) |

The boundary is gRPC-honest: no `VmExecution` object ever crosses it. Everything
the agent receives back is a `VmInfo` (or a `PortForwardInfo` / `LogChunk` /
…), keyed by `VmId`.

## 4. Create path

Rewrite the eligible-instance branch of `create_vm_execution` plus
`start_persistent_vm`:

```
spec = await build_create_vm_spec(vm_hash, content)          # already present
info = await supervisor.create_vm(spec)                      # VmInfo @ BOOTING
registry[vm_hash] = AgentVmRecord(message=content,
                                  original=original.content)
await _wait_until_running(supervisor, info.vm_id, timeout)   # polls get_vm
forwards = resolve_port_forwards(content)                    # agent-side
for fwd in forwards:
    await supervisor.add_port_forward(fwd)                   # nftables behind the abstraction
```

No `VmExecution` handle crosses the seam.

**Readiness via polling.** `create_vm` returns a `VmInfo` early (status
`BOOTING`); the agent polls `supervisor.get_vm(vm_id)` until status `RUNNING`,
with its own timeout. This replaces the old `await execution.becomes_ready()`.

**Status mapping (no change needed).** An earlier draft proposed redefining
`RUNNING` to mean "guest-ready" rather than "service-active." Tracing the boot
path showed that is both unnecessary and harmful, so the status mapping stays as
it is today. The reasoning: `create_vm_from_spec` awaits `start()` to completion;
for persistent instances `start()` calls `non_blocking_wait_for_boot()` which
blocks until the controller service is active and only then sets `ready_event`.
`becomes_ready` is `ready_event.wait`, and its own docstring states guest-level
readiness (network, user apps) is *not* checked. So `becomes_ready` already
resolves at controller-active, the same coarseness as `_status_of`'s current
`RUNNING` (= systemd service active). Redefining `RUNNING` to key on `ready_event`
would also mis-report reboot-reattached VMs (#957), which are running but never
had `ready_event` set in this process, as stuck in `BOOTING`. The agent therefore
polls `get_vm` until `RUNNING` against the existing mapping; in-process the poll
returns immediately (create already blocked until boot), and across a future gRPC
boundary it does real work. The contract is satisfied without touching
`_status_of` / `_is_running`.

**Port-forward resolution split.** `VmExecution.fetch_port_redirect_config_and_setup`
splits cleanly along the boundary:

- *Agent half (policy)* (`resolve_port_forwards(content)`): read the user
  aggregate settings via `get_user_settings(message.address, "port-forwarding")`,
  compute the requested ports, force `:22`, and produce a list of
  `PortForwardSpec`. The agent decides *what* should be forwarded.
- *Hypervisor half (mechanism + persistence)*: the nftables setup, already
  exposed as `supervisor.add_port_forward(spec)`. The hypervisor applies the
  rules, **persists** the resulting mappings, reports them through
  `list_port_forwards`, and reapplies them on its own reattach / reboot-recovery.
  The agent never reads or recreates persisted mappings.

This realises the backport design's stated freeze: *"Agent owns
aggregate-settings reads; freeze the shape the hypervisor sees (just
`port_forwards`)."* The network policy is translated agent-side; the networking
configuration itself is owned and managed by the hypervisor, which follows the
agent's orders but is the sole writer of nftables state. Consequently the DB-backed
reattach (`get_port_mappings` + `recreate_port_redirect_rules`) becomes a
hypervisor responsibility, not an agent call; `fetch_port_redirect_config_and_setup`
loses that half entirely.

## 5. Operator lifecycle endpoints

The stop/delete, reboot, reinstall, logs, and port-forward listing/removal call
sites in `views/__init__.py`, plus the deallocation path in `tasks.py`, move off
`pool.stop_vm` / `pool.forget_vm` / `pool.get_running_vm` onto
`supervisor.delete_vm / reboot_vm / reinstall_vm / get_logs / list_port_forwards
/ remove_port_forward`, all keyed by `vm_id`. The in-process impl delegates to
the pool, so these cover **all** VMs (instances and programs) uniformly. They
are not instance-only.

**Owner-auth** in those endpoints currently reads `execution.message.address`.
It moves to the registry: `registry[vm_hash].message.address`. Because the
registry is populated on every create, programs are covered too.

**Registry survives agent reboot.** The registry is an in-memory **cache for
messages**, backed by the agent's existing DB, which stores what the agent knows
about each VM. On agent startup the agent **rehydrates** the registry from the
DB, so owner-auth and billing keep working across an agent restart. This is
independent of, and complementary to, the supervisor's message-free config
reattach (#957): the supervisor reattaches the running VMs from on-disk
controller configs, while the agent independently re-learns the messages it
owns. The two recoveries do not share state, which is the point of separating
the lifecycles.

For now the DB is the single source of truth for the agent's known VMs. A later
iteration will add the ability to recreate the agent's state from the network
(fetch the plan from the scheduler, fetch the Aleph messages), at which point the
DB becomes a true cache rather than the authority. That network-recreate path is
out of scope here; keep the DB approach.

## 6. Error handling

`InProcessSupervisor` already wraps internals via `translating_errors()` into
`SupervisorError` subclasses. The agent's
`create_vm_execution_or_raise_http_error` shifts from catching
hypervisor-internal exception types (today's `ResourceDownloadError`,
`VmSetupError`, `MicroVMFailedInitError`, `InsufficientResourcesError`, …) to
catching `SupervisorError` subclasses and mapping them to HTTP responses. This
is the first concrete consumer of the "wire error vocabulary" (backport design
Annex A.6); the mapping table lives agent-side.

`_wait_until_running` enforces a timeout: on expiry the agent calls
`supervisor.delete_vm(vm_id)` to tear down the half-started VM and raises an
HTTP 5xx, mirroring today's failure path.

## 7. Testing

- **Create flow** (extend `tests/supervisor/test_supervisor_run_routing.py`):
  with a fake `Supervisor`, assert `create_vm(spec)` is called, the poll loop
  calls `get_vm` until `RUNNING`, `add_port_forward` is called with the resolved
  specs, and the registry is populated. The timeout path triggers `delete_vm`
  and an error.
- **Poll loop**: `_wait_until_running` returns once `get_vm` reports `RUNNING`,
  and raises (after teardown) on timeout. No change to `_status_of` is made or
  tested; the existing inprocess status tests stand.
- **Operator endpoints**: owner-auth resolves from the registry; an unknown
  `vm_hash` is unauthorized.
- **Gates held throughout:** mypy union-attr gate (`src/aleph/vm/` == 2,
  `src/aleph/vm/controllers/` == 0); the existing `InProcessSupervisor`
  conformance suite; the ~8 environmental-only failures baseline (network /
  pyroute2 / subprocess) and ~540 passing.

## 8. PR breakdown (stacked on `dev`)

1. **App wiring + registry + create path.** Construct `app["supervisor"]` and
   `app["vm_registry"]`; add the `AgentVmRecord` registry (populated on both
   create branches); rewrite `create_vm_execution` so the create flow runs
   through the abstraction (`create_vm` → poll `get_vm` until `RUNNING` →
   `resolve_port_forwards` → `add_port_forward`). The in-process status mapping
   is left unchanged (see §4). This is the decision-heavy PR.

   **Boundary (decided during planning).** No caller uses the return value of
   `create_vm_execution` / `create_vm_execution_or_raise_http_error` /
   `start_persistent_vm`, so the create follow-up (message, port-forward,
   readiness) is fully pure via the registry, `add_port_forward`, and the poll.
   But `start_persistent_vm` still drives the `VmExecution` for three
   un-migrated, create-adjacent concerns: the pre-existing-VM state check, the
   expiry-cancel, and update-watching. PR 1 leaves those on the execution:
   `create_vm_execution` reads the freshly created execution back from
   `pool.executions` **once** (a single, explicitly temporary line) and returns
   it so `start_persistent_vm` is unchanged. That residual `pool.executions`
   read, and the expiry/update-watch ops, migrate in a later PR (see §9). The
   message follow-up itself never re-fetches the execution.
2. **Operator lifecycle endpoints.** Migrate the views / tasks stop, delete,
   reboot, reinstall, logs, and port-forward calls onto the abstraction;
   owner-auth reads from the registry; agent rehydrates the registry on startup
   from its message store; the hypervisor reapplies persisted port forwards on
   reattach (and `fetch_port_redirect_config_and_setup` sheds its DB-reattach half).
3. *(optional)* **Read views.** Move any remaining status/list endpoints onto
   `get_vm` / `list_vms`.

## 9. Open questions / deferred

No open questions remain.

**Future work (out of scope here):**

- *Recreate agent state from the network.* Fetch the plan from the scheduler and
  the Aleph messages to rebuild the agent's known-VM set, demoting the DB from
  authority to cache. This design keeps the DB approach.
- *Migrate expiry-cancel and update-watching off `VmExecution`.* Reimplement
  `cancel_expiration` and `watch_for_updates` as agent-side facilities keyed by
  `vm_hash` (off the registry), removing the residual `pool.executions` read that
  PR 1 leaves in `start_persistent_vm`. This also covers the pre-existing-VM
  state check moving onto `get_vm`.

**Resolved during review (2026-06-01):**

- *Readiness / status mapping.* No change to `_status_of` / `_is_running`. The
  existing `RUNNING` = service-active already matches `becomes_ready` (which does
  not check guest-level readiness), and keying on `ready_event` would break
  reboot-reattached VMs. The agent polls `get_vm` until `RUNNING`. (See §4.)

- *Port-mapping ownership.* Persisted port mappings are **hypervisor-owned**. The
  agent translates API / aggregate-settings into desired forwards and issues
  `add_port_forward` / `remove_port_forward`; the hypervisor applies, persists,
  reports (`list_port_forwards`), and reapplies them on reattach. The agent never
  calls `get_port_mappings` / `recreate_port_redirect_rules`. (See §4, §5.)
- *Owner-auth across agent reboot.* The agent rehydrates its registry (a message
  cache backed by the existing DB) on startup, so there is no owner-auth gap for
  recovered VMs. (See §5.)
