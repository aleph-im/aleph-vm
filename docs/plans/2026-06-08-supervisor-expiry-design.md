# Wire agent onto Supervisor: agent-side expiry facility

**Status:** Design / spec (approved 2026-06-08)
**Owner:** Olivier Desenfans
**Series:** Message-free supervisor, Phase 0 residual cleanup. First of the
residual PRs that finish detaching the agent from `VmExecution` before the
Phase 1 process split.
**Stacked on:** PR 3 read views (`od/wire-supervisor-read-views`, #967), itself
on `dev`.

## 1. Context

Idle teardown for on-demand programs ("expiry") is agent policy: keep a microVM
warm for `REUSE_TIMEOUT` seconds after a request, then reap it. Today the timer
lives on `VmExecution` (`stop_after_timeout` / `expire` / `cancel_expiration` /
`expire_task`), the god-object Phase 0 is splitting into an agent-side
`Execution` and a hypervisor-side `Vm`. The timer is therefore on the wrong side
of the future boundary, and the agent reaches it by holding the `VmExecution`
instance.

The same coupling shows up on the hypervisor side: `VmPool` itself calls
`cancel_expiration()` in four places, all "do not expire a VM I am handing back
for reuse." Those calls exist only because the timer is a method on the
execution. The pool has no business knowing about an agent idle policy.

This PR lifts expiry into an agent-owned facility keyed by `vm_id`, acting
through the `Supervisor` abstraction, and removes the expiry members from both
`VmExecution` and `VmPool`. When microVM creation later moves behind the
supervisor (Phase 1), nothing in the idle path needs a `VmExecution` anymore.

This is one of three residual cleanups (the others, shipped separately, are
update-watching and the pre-existing-VM state check that together let
`create_vm_execution` stop reading `pool.executions[vm_hash]` back).

## 2. Goals / non-goals

**Goals**
- An `ExpiryManager` agent facility that owns idle timers, decoupled from
  `VmExecution` and `VmPool`.
- All three expiry touch-points migrated: the `run.py` idle-teardown
  `finally:` blocks, `start_persistent_vm`'s cancel, and the `operate_expire`
  operator endpoint.
- `VmExecution` and `VmPool` lose every expiry member and call.
- No observable behavior change: data volumes preserved, same warm-then-reap
  semantics, same "do not expire while serving a request" guarantee.

**Non-goals**
- Update-watching (`watch_for_updates` / `cancel_update` / `update_task`):
  separate PR. The `start_watching_for_updates` calls next to the migrated
  expiry calls stay in place.
- The `pool.executions[vm_hash]` readback at `run.py:223`: separate PR.
- Owner-auth migration. `operate_expire` keeps its execution-based auth check
  (`is_sender_authorized(sender, execution.message)`); only the timer mechanism
  changes.
- Any `stop_vm` addition to the contract. Expiry reaps via the existing
  `delete_vm`.

## 3. Behavior parity (the backward-compat contract)

The reaping action on fire is `supervisor.delete_vm(vm_id, wipe=False)`. This is
behavior-preserving in two ways that were explicitly checked:

1. **Volumes are preserved.** `delete_vm(wipe=False)` never calls
   `erase_volumes()`; volume erasure is gated entirely behind `wipe=True`
   (`inprocess.py:243`). A microVM's persistent data volume survives an idle
   reap, exactly as today. The expiry path always passes `wipe=False`.
2. **Forgetting is not new.** `create_a_vm` always schedules
   `_schedule_forget_on_stop` (`pool.py:398`), so today's
   `expire()` -> `stop()` -> `stop_event` set -> `_forget_task` -> `forget_vm`
   already removes the VM from the pool after idle, asynchronously.
   `delete_vm(wipe=False)` performs the same stop + forget, synchronously.

The "do not expire while serving a request" guarantee is preserved by moving the
cancel-on-reuse from the pool to the agent: when the agent picks up a running VM
to serve a request it calls `expiry.cancel(vm_id)`, and re-arms with
`expiry.schedule(vm_id, REUSE_TIMEOUT)` in the `finally:` block. This is the same
cancel-then-rearm the pool's `get_running_vm` + the execution's
`stop_after_timeout` did together.

## 4. The unit: `ExpiryManager`

New module `src/aleph/vm/orchestrator/expiry.py`.

```python
class ExpiryManager:
    """Agent-owned idle-teardown timers, keyed by vm_id.

    One purpose (own the timers), one dependency (the Supervisor). Independently
    testable with a fake supervisor.
    """

    def __init__(self, supervisor: Supervisor) -> None: ...

    def schedule(self, vm_id: VmId, timeout: float) -> None:
        """Arm (or re-arm, extending) the idle timer for vm_id."""

    def cancel(self, vm_id: VmId) -> bool:
        """Cancel a pending timer. Returns whether one existed."""

    async def cancel_all(self) -> None:
        """Cancel every pending timer (shutdown cleanup)."""

    async def _expire(self, vm_id: VmId, timeout: float) -> None:
        """Sleep, then reap via supervisor.delete_vm; tolerate already-gone."""
```

- State: `_tasks: dict[VmId, asyncio.Task]`.
- `schedule` cancels any existing task for `vm_id` before creating the new one
  (re-arm extends the window, matching `stop_after_timeout`).
- `_expire` sleeps `timeout`, calls `await self.supervisor.delete_vm(vm_id)`
  swallowing `VmNotFoundError` (the VM was already torn down through another
  path), and removes itself from `_tasks` in a `finally`.
- Keyed by `VmId` (= `str(vm_hash)`, the id the supervisor reports), so the
  agent uses one consistent key against both the registry and the manager.

## 5. Wiring

- `supervisor.py` (where `app["supervisor"]` is built, ~line 168):
  `app["expiry"] = ExpiryManager(app["supervisor"])`.
- `tasks.py` (~line 257, where `Reactor(pubsub, pool)` is built next to
  `app["supervisor"]` / `app["vm_registry"]`): pass `app["expiry"]` into the
  `Reactor`, which threads it to `run_code_on_event`.
- `run_code_on_request` reads `request.app["expiry"]`.
- `cli.py` one-shot `check` (`run_code_on_event` at ~line 238) constructs a
  throwaway `ExpiryManager(InProcessSupervisor(pool))`; the process exits after
  the single run, so a long-lived manager is unnecessary there.

In-process the supervisor is a stateless wrapper over the pool, so any
`InProcessSupervisor` over the same pool reaps correctly; only the
`ExpiryManager` itself must be long-lived.

## 6. Call-site migration

**On-demand idle path** (`run_code_on_request`, `run_code_on_event`):
- On picking up a running VM for reuse: `expiry.cancel(vm_id)`.
- Reuse `finally:` branch: `execution.stop_after_timeout(REUSE_TIMEOUT)` ->
  `expiry.schedule(vm_id, REUSE_TIMEOUT)`. (`start_watching_for_updates` stays.)
- Non-reuse `finally:` branch: `await execution.stop(); pool.forget_vm(...)` ->
  `await supervisor.delete_vm(vm_id)`.

**`start_persistent_vm`** (`run.py:496`):
- `execution.cancel_expiration()` -> `expiry.cancel(vm_id)`.

**`operate_expire`** (`operator.py:412`):
- Drop the `execution.persistent = False` hack (only needed because
  `stop_after_timeout` no-ops for persistent VMs; scheduling `delete_vm`
  directly does not need de-persisting).
- `execution.stop_after_timeout(timeout)` -> `expiry.schedule(vm_id, timeout)`.
- Auth check unchanged (still fetches the execution for `is_sender_authorized`).

**Tidy cancel on external teardown:** `operate_stop` / the delete and erase
operator endpoints call `expiry.cancel(vm_id)` so a manual teardown clears any
pending timer. `_expire`'s `VmNotFoundError` swallow is the safety net; this is
just hygiene.

## 7. Removals (the decoupling)

**`VmExecution`** (`models.py`):
- Delete `stop_after_timeout`, `expire`, `cancel_expiration`, and the
  `expire_task` field.
- Drop the `self.cancel_expiration()` call inside `stop()` (~line 841). The
  agent now owns timer cancellation. (`cancel_update()` stays: update-watching
  is the next PR.)

**`VmPool`** (`pool.py`):
- Remove all four `cancel_expiration()` calls: `create_a_vm:327`,
  `create_vm_from_spec:418`, `get_running_or_starting_vm:482`,
  `get_running_vm:491`.
- Fix the two "Disables the VM expiration task" docstrings on `get_running_vm`
  / `get_running_or_starting_vm` (they now just return a running VM or None).
- `get_running_or_starting_vm` has no `src/` callers; left otherwise as-is to
  keep this PR scoped (dead-code removal is unrelated).

## 8. Testing

- New `tests/supervisor/test_expiry.py` against a fake supervisor:
  - `schedule` fires `delete_vm(vm_id, wipe=False)` after the timeout.
  - re-`schedule` replaces the pending timer (extends, does not double-fire).
  - `cancel` returns `True`/`False` and prevents the fire.
  - `_expire` swallows `VmNotFoundError`.
  - `cancel_all` clears everything.
- Update `tests/supervisor/views/test_operator.py:198`: it asserts
  `execution.expire.call_count == 1`; rewrite to assert the `operate_expire`
  endpoint schedules on the `ExpiryManager` instead.
- The existing run/request tests must keep passing (warm-then-reap parity).

## 9. Done criteria

- `grep -rn "stop_after_timeout\|cancel_expiration\|expire_task" src/` returns
  nothing.
- `VmPool` contains no expiry references.
- The idle path reaps via `supervisor.delete_vm(vm_id, wipe=False)`; volumes
  survive; warm-then-reap and "no expiry while serving a request" hold.
- `operate_expire` drives the `ExpiryManager`; its persistent-flag hack is gone.
- mypy / format / isort gates green; full suite at baseline.
