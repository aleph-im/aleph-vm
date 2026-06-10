# Operator owner-auth reads the agent registry

**Status:** design
**Date:** 2026-06-09
**Series:** message-free supervisor (Phase-0 residual cleanup, after #969 expiry, #970 update-watching)
**Stacks on:** `od/wire-supervisor-update-watch` (#970)

## 1. Goal

Stop operator endpoints from reading owner identity off the hypervisor pool
(`pool.executions[vm_hash].message`). After this PR, `execution.message` is read
**nowhere** in `orchestrator/views/operator.py`; owner-auth consults the agent
registry — the agent's own message store — exactly like the already-migrated
`operate_stop` / `operate_reboot` / `operate_erase`.

This is the last of the design docs' named owner-auth residual: *"Operator
owner-auth's `execution.message` reads (~10 sites in `operator.py`) → registry."*

## 2. Background

The message-free-supervisor effort splits the `VmExecution` god-object into an
agent-side concept (message, owner, billing, expiry, update-watching — backed by
the `AgentVmRegistry` + agent DB) and a hypervisor-side `Vm` (process,
networking, status — behind the `Supervisor` boundary). The agent *owns*
messages; the goal is to get message-derived policy off the **hypervisor
object**, not off the agent.

Owner-authorization is agent policy: an operator request is authorized iff the
authenticated sender is the message owner or a delegate. The message it reads is
the agent's own — so it should come from the agent registry, not from a reach
through `pool.executions` into the hypervisor object's `spec.message`.

### What is already migrated (the template)

`operate_stop`, `operate_reboot`, and `operate_erase` already read
`record.message` via the `get_agent_record_or_404(request, vm_hash)` helper
(registry-only, 404 on miss). The logs endpoints use `_logs_auth_message`
(registry first, DB fallback). This PR finishes the same migration for the
remaining endpoints.

```python
def get_agent_record_or_404(request: web.Request, vm_hash: ItemHash) -> AgentVmRecord:
    """Owner identity now comes from the agent registry, not the execution."""
    record = request.app["vm_registry"].get(vm_hash)
    if record is None:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}")
    return record
```

`AgentVmRecord.message` is an `ExecutableContent` — the same type
`is_sender_authorized(authenticated_sender, message)` and the incidental
`message.rootfs.size_mib` reads already expect.

## 3. Scope

### In scope

The remaining `execution.message` reads in `operator.py` — nine functions (one
auth read each), plus two additional `execution.message.rootfs.size_mib` content
reads inside `_do_restore` — in three shapes.

**① Delete (dead code).** `authenticate_websocket_for_vm_or_403` (def at
line 380) reads `execution.message` but has **zero callers** repo-wide
(`grep -rn` across `src/` and `tests/` finds only the definition). Remove the
function (YAGNI) rather than migrate its read. It takes `execution: VmExecution`
as a parameter, so removing it also drops a `VmExecution` dependency from the
module's surface.

**② Become execution-free.** These endpoints use the execution *only* for the
auth check; the `get_execution_or_404` lookup is removed entirely and the auth
message comes from the registry:

- `operate_expire` — otherwise needed only `execution.vm_hash`, which equals the
  `vm_hash` already in scope.
- `operate_backup_status` — otherwise uses only `request.app["backup_state"]`.
- `operate_backup_delete` — otherwise uses only the backup directory on disk.

**③ Auth-only swap.** These genuinely need the execution for the hypervisor
operation (`execution.vm`, `execution.is_running`, `execution.vm.resources`,
`rootfs_path`). The execution lookup stays; only the *message read* moves to the
registry:

- `operate_confidential_initialize` (uses `execution.is_running`,
  `execution.is_confidential`, `execution.vm`)
- `operate_confidential_measurement` (`QemuVmClient(execution.vm)`)
- `operate_confidential_inject_secret` (`QemuVmClient(execution.vm)`)
- `operate_backup` (`execution.is_running`, `execution.vm`)
- `_do_restore` (`execution.vm`, `execution.vm.resources.rootfs_path`) — plus its
  **two** `execution.message.rootfs.size_mib` content reads, which become
  `record.message.rootfs.size_mib` (restore is QEMU-instance-only, guarded by an
  `isinstance(execution.vm, AlephQemuInstance | AlephQemuConfidentialInstance)`
  check, so `.rootfs` is present on the message exactly as before).

### Out of scope (explicit residuals, unchanged)

- **`execution.vm` / `execution.is_running` direct reads in `operator.py`.**
  These are hypervisor-object access that bypasses the `Supervisor` boundary —
  Phase-1 work, not message-coupling. The ③ endpoints keep them.
- **The `create_vm_execution` `save()` readback.** Still deferred (decision
  2026-06-09): agent-owned `ExecutionRecord` persistence.
- **The `VmExecution.message` property itself.** Stays — the hypervisor object's
  own QEMU/Firecracker config build reads `self.spec.message`. This PR removes
  *operator.py's* reads of it, not the property.

## 4. The migration pattern

Per the `operate_stop` precedent, registry-auth runs first, then (for ③) the
execution lookup for the hypervisor op:

```python
# ② execution-free:
record = get_agent_record_or_404(request, vm_hash)
if not await is_sender_authorized(authenticated_sender, record.message):
    return web.Response(status=403, body="Unauthorized sender")
# ... endpoint body uses no execution ...

# ③ auth-only swap:
record = get_agent_record_or_404(request, vm_hash)
if not await is_sender_authorized(authenticated_sender, record.message):
    return web.Response(status=403, body="Unauthorized sender")
execution = get_execution_or_404(vm_hash, pool=pool)   # for execution.vm
# ... endpoint body uses execution.vm / is_running / resources ...
```

### Behavior nuance (deliberate)

For the ③ endpoints the auth check now runs **before** the running-VM lookup
(previously `get_execution_or_404` ran first). Consequences:

- **Unauthorized** request against a **known-but-stopped** VM: now **403**
  (registry has the record) instead of the previous **404** (no running
  execution). This matches the already-migrated endpoints and is arguably more
  correct — authorization precedes VM-state disclosure.
- **Unknown** VM (no registry record): **404**, preserved — `get_agent_record_or_404`
  raises 404 on a registry miss.
- **Authorized** request against a stopped VM: still reaches
  `get_execution_or_404`, which still returns **404** when there is no running
  execution. Unchanged for authorized callers.

This is the design decision approved 2026-06-09: accept the 403-before-404
ordering for consistency with the migrated endpoints, rather than preserving the
exact current ordering by keeping execution-lookup-first.

### Minor cleanup folded in

`get_execution_or_404` carries a stale `# TODO: Check if this should be
execution.message.address or execution.message.content.address?` comment — it
referred to the auth read this PR removes. Delete the comment. The helper itself
stays (the ③ endpoints use it for `execution.vm`).

## 5. Components / files touched

- `src/aleph/vm/orchestrator/views/operator.py` — the nine migrations, the dead
  function deletion, the stale-TODO removal. Imports: drop `VmExecution` if it
  becomes unused after deleting `authenticate_websocket_for_vm_or_403` (verify;
  `get_execution_or_404` is annotated `-> VmExecution`, so the import likely
  stays — confirm during implementation).
- Tests (below).

No wiring changes: `app["vm_registry"]` and `get_agent_record_or_404` already
exist and are used by the migrated endpoints.

## 6. Testing

For each migrated endpoint:

- **Authorized** sender (matching `record.message.address`) → request proceeds
  (past auth; the hypervisor-side outcome may still be a 4xx for non-running VMs,
  asserted as today).
- **Unauthorized** sender → **403**.
- **Registry miss** (`vm_registry.get` returns `None`) → **404**.

Tests stub `request.app["vm_registry"]` with a record whose `message.address` is
the owner. Reuse the existing operator-view test harness.

Cross-cutting guards:

- A test asserting `execution.message` appears **nowhere** in `operator.py`
  (source scan), locking in the migration.
- Confirm the dead-function deletion breaks no imports or route registrations
  (`authenticate_websocket_for_vm_or_403` is referenced only at its definition).

Existing operator tests for the migrated endpoints must continue to pass
(authorized-path behavior is unchanged).

## 7. Out-of-scope residuals after this PR

- `execution.vm` / `execution.is_running` direct hypervisor reads in operator.py
  (Phase-1 Supervisor-boundary work).
- `create_vm_execution` save() readback — agent-owned `ExecutionRecord`
  persistence.
- Recreate-agent-state-from-network (demote DB from authority to cache).
