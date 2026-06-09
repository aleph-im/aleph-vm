# Agent-side update-watching + `start_persistent_vm` execution decoupling

**Status:** design
**Date:** 2026-06-09
**Series:** message-free supervisor (Phase-0 residual cleanup, after #969 expiry)
**Stacks on:** `od/wire-supervisor-expiry` (#969)

## 1. Goal

Lift update-watching ("re-deploy on message update") off the `VmExecution`
god-object into an agent-owned `UpdateWatcher`, and make `start_persistent_vm`
execution-free by moving its pre-existing-VM check onto `supervisor.get_vm`.

This is the second half of the design doc's future-work item *"Migrate
expiry-cancel and update-watching off `VmExecution`"* — expiry shipped in #969;
this PR does update-watching and the residual `start_persistent_vm`
`pool.executions` read it named.

## 2. Background

The message-free-supervisor effort splits the current `VmExecution` god-object
into an agent-side concept (knows the message, owner, billing, expiry,
update-watching — backed by the `AgentVmRegistry` + agent DB) and a
hypervisor-side `Vm` (process, networking, status — behind the `Supervisor`
boundary). The agent *owns* messages; the goal is to get message-derived policy
off the **hypervisor object**, not off the agent.

Update-watching is agent policy: it subscribes to the Aleph messages referenced
by a VM's deployment (code / runtime / data / volumes) and, when any is updated,
stops the VM so the next request redeploys it. Today it lives as
`VmExecution.watch_for_updates` / `start_watching_for_updates` / `update_task` /
`cancel_update`, exactly parallel to where expiry lived before #969.

### What #969 established (the template)

- `ExpiryManager` (`orchestrator/expiry.py`): agent-owned timers keyed by
  `vm_id`, one dependency (`Supervisor`), reaping via
  `supervisor.delete_vm(vm_id)` (`wipe=False`). Built as `app["expiry"]`,
  threaded into the request path, the reactor (via `Reactor.__init__`),
  `start_persistent_vm`, and the lifecycle endpoints; `cancel_all()` on
  `on_cleanup`.
- Concurrency discipline: the per-VM task removes only its **own** dict entry in
  `finally` (current-task identity check), swallows `VmNotFoundError`, re-raises
  `CancelledError`.

### Confirmed facts that shape this design

- **`app["pubsub"]` is created late** — in `tasks.py` (`start_watch_for_messages_task`),
  not in `setup_webapp` where the supervisor/expiry singletons are built. The
  watcher therefore cannot hold pubsub from construction; pubsub is passed
  per-`watch()` call (as `ExpiryManager.schedule` takes the timeout per call).
- **Both `create_vm_execution` branches already record to the registry** — the
  spec/instance path and the legacy/program path. Every agent-created VM already
  has its `original` message in the registry, keyed by `vm_hash`. A
  registry-backed watcher needs **no registry-population change**.
- **`create_vm_execution` already waits-until-running** on the spec path
  (`_wait_until_running`). `start_persistent_vm` can use
  `_wait_until_running(supervisor, vm_id)` in place of
  `execution.becomes_ready()`, so it can become fully execution-free.
- **`WATCH_FOR_UPDATES` defaults `True`** — this path is live in production.
- **The reactor builds a throwaway local `AgentVmRegistry`** in
  `run_code_on_event` today. A registry-backed watcher requires the reactor to
  use the app registry singleton instead (a small correctness improvement: one
  registry, not two).

## 3. Scope

### In scope

1. New agent-owned `UpdateWatcher` facility; remove the update machinery from
   `VmExecution`.
2. `start_persistent_vm` execution-free: pre-existing-VM check via
   `supervisor.get_vm` (kills the residual `pool.executions.get(vm_hash)` read),
   readiness via `_wait_until_running`, update-watching via the watcher; returns
   `None`.
3. Wiring symmetric with expiry across request path, reactor, lifecycle
   endpoints, shutdown, and `cli.py`.
4. The reactor adopts the app `vm_registry` singleton (drops the local one).

### Out of scope (explicit residuals, unchanged)

- **The `create_vm_execution` save() readback** (`pool.executions[vm_hash]` →
  `execution.save()`). `save()` persists the full `ExecutionRecord` (message,
  timings, vcpus/memory/gpus, mapped_ports, cpu/io counters) — the agent's
  billing/rehydration record. Moving that onto an agent-owned persistence path
  is deferred (decision 2026-06-09): the `VmExecution` survives this PR anyway,
  and a parallel persistence path carries rehydration round-trip risk for the
  sake of one readback line. It migrates when the rest of the agent's
  record-persistence leaves the execution.
- **Operator owner-auth's `execution.message` reads** (~10 sites in
  `operator.py`). Owner-auth stays exactly as-is; migrating it to read
  `registry.get(vm_hash).message` is separate agent plumbing, not this PR.

## 4. Components

### 4.1 `UpdateWatcher` (`src/aleph/vm/orchestrator/update_watcher.py`)

Agent-owned update-subscription tasks keyed by `vm_id`. Subscription-driven
counterpart to `ExpiryManager`.

**Dependencies:** `Supervisor` + `AgentVmRegistry`.

**State:** `_tasks: dict[VmId, asyncio.Task]`.

**API:**

- `watch(vm_id: VmId, vm_hash: ItemHash, pubsub: PubSub) -> None`
  Look up the record in the registry. If absent or its `original` is not a
  watchable message → **no-op** (preserves today's behavior: spec-built /
  reattached executions, which have no Aleph message to watch, don't schedule a
  task). Otherwise cancel any existing task for `vm_id` and spawn `_watch`.
- `cancel(vm_id: VmId) -> bool` — cancel a pending task; return whether one
  existed.
- `cancel_all() -> None` — cancel every task (shutdown cleanup).

**`_watch(vm_id, refs, pubsub)`:**

```
try:
    await pubsub.msubscribe(*refs)        # blocks until a referenced msg updates
    logger.info("Update received for %s, reaping", vm_id)
    await self.supervisor.delete_vm(vm_id)   # wipe=False
except VmNotFoundError:
    logger.debug("Update-watch: VM %s already gone", vm_id)
except asyncio.CancelledError:
    raise
except Exception:
    logger.exception("Update-watch of %s failed", vm_id)
finally:
    if self._tasks.get(vm_id) is asyncio.current_task():
        del self._tasks[vm_id]
```

**Ref extraction** (moved verbatim from `VmExecution.watch_for_updates`, off the
execution): given `original` and whether it is an instance,

- instance → the `ref` of each volume that has one;
- program → `code.ref`, `runtime.ref`, `data.ref` (if present), plus volume
  refs.

The instance-vs-program decision uses the message type (the same signal
`VmExecution.is_instance` carries), determined from the registry record — not
from a `VmExecution`.

**Why depend on the registry rather than take `original` explicitly:** the
registry is the agent's message store; an agent-owned update facility reading it
is coherent and keeps the 3 call sites trivial (`watch(vm_id, vm_hash, pubsub)`).
The alternative (pass `original` per call) re-spreads the message read across
call sites that would each fetch it from the registry anyway.

### 4.2 `VmExecution` removals (`src/aleph/vm/models.py`)

Delete `watch_for_updates`, `start_watching_for_updates`, `update_task`,
`cancel_update`, and the `self.cancel_update()` call inside `stop()`. The
ref-extraction logic relocates to `UpdateWatcher`.

### 4.3 `start_persistent_vm` (`src/aleph/vm/orchestrator/run.py`)

Becomes execution-free. New shape:

```
async def start_persistent_vm(vm_hash, pubsub, pool, *, supervisor, registry,
                              expiry, update_watcher) -> None:
    vm_id = VmId(str(vm_hash))
    try:
        info = await supervisor.get_vm(vm_id)
    except VmNotFoundError:
        info = None

    if info is not None:
        if info.status == VmStatus.RUNNING:
            pass                                      # already up
        elif info.status in (VmStatus.DEFINED, VmStatus.BOOTING):
            await _wait_until_running(supervisor, vm_id)
        elif info.status == VmStatus.STOPPING:
            await _wait_until_gone(supervisor, vm_id)   # poll get_vm -> NotFound
            info = None
        else:                                         # STOPPED / FAILED
            await supervisor.delete_vm(vm_id)
            info = None

    if info is None:
        logger.info("Starting persistent virtual machine with id: %s", vm_hash)
        await create_vm_execution(vm_hash=vm_hash, pool=pool,
                                  supervisor=supervisor, registry=registry,
                                  persistent=True)
        await _wait_until_running(supervisor, vm_id)

    expiry.cancel(vm_id)        # scheduled long-running: must not idle-expire
    if pubsub and settings.WATCH_FOR_UPDATES:
        update_watcher.watch(vm_id, vm_hash, pubsub)
```

Notes:

- The "stopping → wait for full stop, then recreate" branch previously awaited
  `execution.stop_event`; with no execution it polls `get_vm` until
  `VmNotFoundError`. Same outcome (recreate once stopped), different mechanism.
  `_wait_until_gone` is a small helper alongside `_wait_until_running`.
- `create_vm_execution` still returns a `VmExecution` (it does the deferred
  save() readback internally and `run_code_on_request` still consumes its
  return). `start_persistent_vm` ignores it and returns `None`.
- `VmStatus` members (`supervisor/types.py`): `DEFINED`, `BOOTING`, `RUNNING`,
  `STOPPING`, `STOPPED`, `FAILED`. `get_vm` raises `VmNotFoundError` when the VM
  is absent (the `info = None` path above).

### 4.4 Request + reactor paths (`run.py`)

In `run_code_on_request` and `run_code_on_event`, replace
`execution.start_watching_for_updates(pubsub=...)` with
`update_watcher.watch(vm_id, vm_hash, pubsub)`. Both already receive
`supervisor`/`expiry`; they additionally receive `update_watcher`. The
non-reuse teardown branches that already `expiry.cancel(...)` /
`supervisor.delete_vm(...)` also `update_watcher.cancel(vm_id)`.

`run_code_on_event` stops building a local `AgentVmRegistry`: the `Reactor`
passes the app registry through, so the registry the watcher reads is the same
one the create path records into.

## 5. Wiring (symmetric with expiry)

- `setup_webapp` (`supervisor.py`): `app["update_watcher"] =
  UpdateWatcher(app["supervisor"], app["vm_registry"])` (built after
  `vm_registry`).
- `Reactor.__init__` (`reactor.py`): gains `registry` and `update_watcher`
  (alongside the `supervisor`/`expiry` it already took), passes them into
  `run_code_on_event`.
- `tasks.py` (`start_watch_for_messages_task`): construct
  `Reactor(pubsub, pool, supervisor, app["expiry"], app["update_watcher"], app["vm_registry"])`.
- Lifecycle endpoints (`views/operator.py`): add `update_watcher.cancel(vm_id)`
  next to every existing `expiry.cancel(vm_id)` (stop / reboot / erase).
- `update_allocations` / `notify_allocation` (`views/__init__.py`): pass
  `update_watcher` into `start_persistent_vm`.
- Shutdown (`supervisor.py` `run()`): `app.on_cleanup.append(stop_update_watcher)`
  where `stop_update_watcher` calls `cancel_all()` (mirrors
  `stop_expiry_manager`), ordered before `stop_all_vms`.
- `cli.py`: `benchmark` builds an `UpdateWatcher` into the fake app dict and
  passes it to `run_code_on_event`; `start_instance` passes one into
  `start_persistent_vm`.

## 6. Behavior parity

- Reap-on-update is unchanged: subscribe to the same refs, then stop the VM.
  `delete_vm(wipe=False)` == the old `stop()` (volumes preserved, VM forgotten),
  matching #969's expiry reap.
- The no-op for spec-built / reattached (non-message) VMs is preserved: today
  `start_watching_for_updates` returns early when the spec is not a
  `MessageSpec`; the watcher no-ops when the registry has no watchable `original`.
- `start_persistent_vm`'s state machine preserves the running / starting /
  stopping / unknown / absent outcomes; only the stopping-wait mechanism changes
  (poll vs `stop_event`).

## 7. Testing

- `tests/supervisor/test_update_watcher.py` (mirrors `test_expiry.py`, with a
  `FakePubSub` whose `msubscribe` is awaitable and controllable):
  reaps-on-update; `cancel` prevents reap; re-`watch` replaces the pending task;
  `VmNotFoundError` swallowed; **no-op when the vm is unrecorded / not
  watchable**; `cancel_all` clears every task.
- `start_persistent_vm` precheck-state tests against a fake supervisor:
  absent → create; `RUNNING` → no recreate; `BOOTING` → waits; `STOPPING` →
  waits-gone then recreates; terminal → deletes then recreates.
- A `VmExecution` test asserting the update API (`start_watching_for_updates`
  etc.) is gone.
- Full suite: no new failures vs the #969 base (the 10 pre-existing
  environment failures excluded).

## 8. Risks

- **Reactor registry switch.** Moving the reactor onto the app registry changes
  which registry the reactor's create records into. Mitigation: the app registry
  is the correct shared one; the local registry was a throwaway that nothing
  read across calls.
- **`get_vm` status coverage.** The precheck maps every `VmStatus` member
  explicitly (`RUNNING` / `DEFINED` / `BOOTING` / `STOPPING`); `STOPPED` and
  `FAILED` fall into the terminal `else` (delete + recreate). No status is left
  unhandled.
- **`msubscribe` test ergonomics.** The watcher blocks on `pubsub.msubscribe`;
  tests drive it with a fake pubsub that resolves on demand. Same pattern as the
  expiry timer tests, with an awaitable in place of `asyncio.sleep`.

## 9. Out-of-scope residuals after this PR

- `create_vm_execution` save() readback (#1) — agent-owned `ExecutionRecord`
  persistence.
- Operator owner-auth reads of `execution.message` → registry.
- `operate_expire`'s pre-existing dead route (carried from #969).
