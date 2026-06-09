# Agent-side expiry facility Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift idle-teardown ("expiry") off `VmExecution` into an agent-owned `ExpiryManager` that reaps through `Supervisor.delete_vm`, and remove every expiry member from `VmExecution` and `VmPool`.

**Architecture:** A new `ExpiryManager` (one purpose: own idle timers; one dependency: the `Supervisor`) keyed by `VmId`. It is constructed as an app singleton, threaded into the request path via `request.app["expiry"]` and into the reactor path via the `Reactor`. All three expiry touch-points (the `run.py` idle `finally:` blocks, `start_persistent_vm`, `operate_expire`) migrate to it, then the dead expiry code is deleted from the model and pool.

**Tech Stack:** Python 3.10+, asyncio, aiohttp, pytest + pytest-asyncio.

**Spec:** `docs/plans/2026-06-08-supervisor-expiry-design.md`.

---

## Environment setup (controller does once, before Task 1)

Worktree already created: `.worktrees/wire-supervisor-expiry` on branch
`od/wire-supervisor-expiry` (based on the #967 read-views tip).

Test venv (dbus-python and other system packages cannot build locally; chain
system site-packages):

```bash
cd /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-expiry
python3 -m venv --system-site-packages .testvenv
echo "$PWD/src" > .testvenv/lib/python3*/site-packages/_local_aleph.pth
.testvenv/bin/python -m pip install -q pytest pytest-asyncio pytest-aiohttp pytest-mock
```

Run tests as `.testvenv/bin/python -m pytest <paths> -v`.

Known baseline (neither set blocks): the ~8 environmental-only failures
(root / network / qemu) in `test_execution.py` / `test_instance.py` /
`test_interfaces.py`, and the order-dependent DB-init errors in
`test_port_mappings.py` when run as a subset.

---

## File structure

- Create: `src/aleph/vm/orchestrator/expiry.py` (the `ExpiryManager`).
- Create: `tests/supervisor/test_expiry.py` (unit tests).
- Modify: `src/aleph/vm/orchestrator/supervisor.py` (`app["expiry"]`).
- Modify: `src/aleph/vm/orchestrator/run.py` (both `run_code_on_*`, `start_persistent_vm`).
- Modify: `src/aleph/vm/orchestrator/reactor.py` (thread expiry/supervisor).
- Modify: `src/aleph/vm/orchestrator/tasks.py` (build `Reactor` with deps).
- Modify: `src/aleph/vm/orchestrator/cli.py` (bench `FakeRequest`, one-shot call).
- Modify: `src/aleph/vm/orchestrator/views/operator.py` (`operate_expire`, tidy cancels).
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (`start_persistent_vm` callers).
- Modify: `src/aleph/vm/models.py` (delete expiry members).
- Modify: `src/aleph/vm/pool.py` (delete four `cancel_expiration` calls).
- Modify: `tests/supervisor/views/test_operator.py` (expiry assertion).

---

### Task 1: The `ExpiryManager` unit

**Files:**
- Create: `src/aleph/vm/orchestrator/expiry.py`
- Test: `tests/supervisor/test_expiry.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/supervisor/test_expiry.py`:

```python
import asyncio

import pytest

from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId


class FakeSupervisor:
    def __init__(self, *, raise_not_found: bool = False):
        self.deleted: list[tuple[str, bool]] = []
        self.raise_not_found = raise_not_found

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        self.deleted.append((str(vm_id), wipe))
        if self.raise_not_found:
            raise VmNotFoundError(str(vm_id))


@pytest.mark.asyncio
async def test_schedule_reaps_after_timeout():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.01)
    await asyncio.sleep(0.05)

    assert sup.deleted == [("vm-a", False)]
    assert expiry.cancel(vm_id) is False  # task removed itself after firing


@pytest.mark.asyncio
async def test_cancel_prevents_reap():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.05)
    assert expiry.cancel(vm_id) is True
    await asyncio.sleep(0.1)

    assert sup.deleted == []
    assert expiry.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_reschedule_replaces_pending_timer():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-a")

    expiry.schedule(vm_id, 0.2)
    expiry.schedule(vm_id, 0.01)  # re-arm shorter
    await asyncio.sleep(0.1)

    assert sup.deleted == [("vm-a", False)]  # fired once, on the second timer


@pytest.mark.asyncio
async def test_expire_swallows_vm_not_found():
    sup = FakeSupervisor(raise_not_found=True)
    expiry = ExpiryManager(sup)
    vm_id = VmId("vm-gone")

    expiry.schedule(vm_id, 0.01)
    await asyncio.sleep(0.05)  # must not raise

    assert sup.deleted == [("vm-gone", False)]
    assert expiry.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_cancel_all_clears_every_timer():
    sup = FakeSupervisor()
    expiry = ExpiryManager(sup)

    expiry.schedule(VmId("vm-a"), 0.05)
    expiry.schedule(VmId("vm-b"), 0.05)
    await expiry.cancel_all()
    await asyncio.sleep(0.1)

    assert sup.deleted == []
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_expiry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aleph.vm.orchestrator.expiry'`.

- [ ] **Step 3: Implement `ExpiryManager`**

Create `src/aleph/vm/orchestrator/expiry.py`:

```python
import asyncio
import logging

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId

logger = logging.getLogger(__name__)


class ExpiryManager:
    """Agent-owned idle-teardown timers, keyed by vm_id.

    One purpose (own the timers), one dependency (the Supervisor). Replaces the
    expiry methods that used to live on VmExecution, so the idle policy no
    longer needs a VmExecution instance.
    """

    def __init__(self, supervisor: Supervisor) -> None:
        self.supervisor = supervisor
        self._tasks: dict[VmId, asyncio.Task] = {}

    def schedule(self, vm_id: VmId, timeout: float) -> None:
        """Arm (or re-arm, extending) the idle timer for vm_id."""
        self.cancel(vm_id)
        self._tasks[vm_id] = asyncio.create_task(self._expire(vm_id, timeout), name=f"expire {vm_id}")

    def cancel(self, vm_id: VmId) -> bool:
        """Cancel a pending timer. Returns whether one existed."""
        task = self._tasks.pop(vm_id, None)
        if task is None:
            return False
        task.cancel()
        return True

    async def cancel_all(self) -> None:
        """Cancel every pending timer (shutdown cleanup)."""
        for vm_id in list(self._tasks):
            self.cancel(vm_id)

    async def _expire(self, vm_id: VmId, timeout: float) -> None:
        try:
            await asyncio.sleep(timeout)
            logger.info("Idle timeout reached for %s, reaping", vm_id)
            await self.supervisor.delete_vm(vm_id)
        except VmNotFoundError:
            logger.debug("Expiry: VM %s already gone", vm_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Expiry of %s failed", vm_id)
        finally:
            # Only drop our own entry: a concurrent re-schedule may have already
            # replaced it with a new task under the same key.
            if self._tasks.get(vm_id) is asyncio.current_task():
                del self._tasks[vm_id]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_expiry.py -v`
Expected: all 5 PASS.

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/orchestrator/expiry.py tests/supervisor/test_expiry.py
git commit -m "feat(expiry): agent-owned ExpiryManager keyed by vm_id"
```

---

### Task 2: App wiring + `run_code_on_request` migration + CLI bench

**Files:**
- Modify: `src/aleph/vm/orchestrator/supervisor.py:168` (add `app["expiry"]`)
- Modify: `src/aleph/vm/orchestrator/run.py` (`run_code_on_request`)
- Modify: `src/aleph/vm/orchestrator/cli.py` (`FakeRequest`, `benchmark`)

- [ ] **Step 1: Add the app singleton**

In `src/aleph/vm/orchestrator/supervisor.py`, add the import near the other
orchestrator imports:

```python
from aleph.vm.orchestrator.expiry import ExpiryManager
```

And in `setup_webapp`, right after the `app["supervisor"]` line (currently
line 168):

```python
    app["supervisor"] = InProcessSupervisor(pool)
    app["expiry"] = ExpiryManager(app["supervisor"])
    app["vm_registry"] = AgentVmRegistry()
```

- [ ] **Step 2: Migrate `run_code_on_request`**

In `src/aleph/vm/orchestrator/run.py`, at the top of `run_code_on_request`
(after the docstring), resolve the deps and cancel any pending timer for the VM
being served:

```python
async def run_code_on_request(vm_hash: ItemHash, path: str, pool: VmPool, request: web.Request) -> web.Response:
    """
    Execute the code corresponding to the 'code id' in the path.
    """
    supervisor: Supervisor = request.app["supervisor"]
    expiry: ExpiryManager = request.app["expiry"]
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve

    execution: VmExecution | None = pool.get_running_vm(vm_hash=vm_hash)
```

Replace the `finally:` block (currently lines 392-399):

```python
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                execution.start_watching_for_updates(pubsub=request.app["pubsub"])
            expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        else:
            await supervisor.delete_vm(vm_id)
```

Add the import for `ExpiryManager` at the top of `run.py` (with the other
`aleph.vm.orchestrator` imports):

```python
from aleph.vm.orchestrator.expiry import ExpiryManager
```

(`Supervisor` and `VmId` are already imported in `run.py`.)

- [ ] **Step 3: Give the CLI bench an app with the singletons**

In `src/aleph/vm/orchestrator/cli.py`, add `app` to the `FakeRequest` field
list (class around line 159):

```python
class FakeRequest:
    headers: dict[str, str]
    raw_headers: list[tuple[bytes, bytes]]
    match_info: dict
    method: str
    query_string: str
    read: Callable
    app: dict
```

In `benchmark`, after `pool = VmPool()` / `await pool.setup()`, wire the app
dict (add imports for `InProcessSupervisor` and `ExpiryManager` at the top of
`cli.py` if absent):

```python
    bench_supervisor = InProcessSupervisor(pool)
    fake_request.app = {
        "supervisor": bench_supervisor,
        "expiry": ExpiryManager(bench_supervisor),
        "pubsub": PubSub(),
    }
```

- [ ] **Step 4: Run the affected tests**

Run: `.testvenv/bin/python -m pytest tests/supervisor/ -k "request or run or executions" -v`
Expected: PASS (warm-then-reap parity preserved; new app key present).

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/orchestrator/supervisor.py src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/cli.py
git commit -m "refactor(expiry): run_code_on_request drives the ExpiryManager"
```

---

### Task 3: `run_code_on_event` migration (reactor path)

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (`run_code_on_event`)
- Modify: `src/aleph/vm/orchestrator/reactor.py` (`Reactor` carries deps)
- Modify: `src/aleph/vm/orchestrator/tasks.py:257` (build `Reactor` with deps)
- Modify: `src/aleph/vm/orchestrator/cli.py` (one-shot `run_code_on_event` call)

- [ ] **Step 1: Change `run_code_on_event` signature and body**

In `src/aleph/vm/orchestrator/run.py`, update the signature and the local-build
block (the reactor has no request, so deps are passed in; reuse the passed
supervisor instead of building a throwaway one):

```python
async def run_code_on_event(
    vm_hash: ItemHash,
    event,
    pubsub: PubSub,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    expiry: ExpiryManager,
):
    """
    Execute code in response to an event.
    """
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve

    execution: VmExecution | None = pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        # programs use the legacy create path; the reactor has no agent
        # registry singleton, so build a local one for the create follow-up.
        registry = AgentVmRegistry()
        execution = await create_vm_execution_or_raise_http_error(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
        )
```

Replace the `finally:` block (currently lines 449-455):

```python
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                execution.start_watching_for_updates(pubsub=pubsub)
            expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        else:
            await supervisor.delete_vm(vm_id)
```

(`InProcessSupervisor` may now be an unused import in `run.py` if nothing else
uses it; check and remove only if so.)

- [ ] **Step 2: Carry the deps on the `Reactor`**

In `src/aleph/vm/orchestrator/reactor.py`, add imports and constructor params:

```python
from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.supervisor.abc import Supervisor


class Reactor:
    pubsub: PubSub
    pool: VmPool
    supervisor: Supervisor
    expiry: ExpiryManager
    listeners: list[AlephMessage]

    def __init__(self, pubsub: PubSub, pool: VmPool, supervisor: Supervisor, expiry: ExpiryManager):
        self.pubsub = pubsub
        self.pool = pool
        self.supervisor = supervisor
        self.expiry = expiry
        self.listeners = []
```

And the `trigger` call site:

```python
                    coroutines.append(
                        run_code_on_event(
                            vm_hash, event, self.pubsub, pool=self.pool,
                            supervisor=self.supervisor, expiry=self.expiry,
                        )
                    )
```

- [ ] **Step 3: Build the `Reactor` with deps**

In `src/aleph/vm/orchestrator/tasks.py`, `start_watch_for_messages_task`
(line 257), pass the app singletons:

```python
    supervisor = app["supervisor"]
    registry = app["vm_registry"]
    reactor = Reactor(pubsub, pool, supervisor, app["expiry"])
```

- [ ] **Step 4: Update the one-shot CLI call**

In `src/aleph/vm/orchestrator/cli.py`, the `run_code_on_event` call in
`benchmark` (line 238) reuses the bench supervisor built in Task 2:

```python
    result = await run_code_on_event(
        vm_hash=ref, event=None, pubsub=PubSub(), pool=pool,
        supervisor=bench_supervisor, expiry=fake_request.app["expiry"],
    )
```

- [ ] **Step 5: Run the affected tests**

Run: `.testvenv/bin/python -m pytest tests/supervisor/ -k "reactor or event or run" -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/reactor.py src/aleph/vm/orchestrator/tasks.py src/aleph/vm/orchestrator/cli.py
git commit -m "refactor(expiry): reactor path drives the ExpiryManager"
```

---

### Task 4: `start_persistent_vm` + `operate_expire` migration

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (`start_persistent_vm`)
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (3 callers + `cli.py` caller)
- Modify: `src/aleph/vm/orchestrator/cli.py` (`start_instance` caller)
- Modify: `src/aleph/vm/orchestrator/views/operator.py` (`operate_expire`, tidy cancels)
- Test: `tests/supervisor/views/test_operator.py`

- [ ] **Step 1: Add `expiry` to `start_persistent_vm` and swap the cancel**

In `src/aleph/vm/orchestrator/run.py`:

```python
async def start_persistent_vm(
    vm_hash: ItemHash,
    pubsub: PubSub | None,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    expiry: ExpiryManager,
) -> VmExecution:
```

Replace `execution.cancel_expiration()` (line 496) with:

```python
    # If the VM was already running in lambda mode, it should not expire
    # as long as it is also scheduled as long-running
    expiry.cancel(VmId(str(vm_hash)))
```

- [ ] **Step 2: Update `start_persistent_vm` callers**

In `src/aleph/vm/orchestrator/views/__init__.py`, the three calls (lines ~599,
~613, ~998) each gain `expiry=request.app["expiry"]`, e.g.:

```python
                await start_persistent_vm(
                    vm_hash, pubsub, pool,
                    supervisor=supervisor, registry=registry, expiry=request.app["expiry"],
                )
```

(Apply the same `expiry=request.app["expiry"]` addition to all three call
sites; `instance_item_hash` / `item_hash` is the first arg at the other two.)

In `src/aleph/vm/orchestrator/cli.py`, `start_instance` (line 246) builds a
throwaway:

```python
async def start_instance(item_hash: ItemHash, pubsub: PubSub | None, pool) -> VmExecution:
    """Run an instance from an InstanceMessage."""
    supervisor = InProcessSupervisor(pool)
    registry = AgentVmRegistry()
    expiry = ExpiryManager(supervisor)
    return await start_persistent_vm(
        item_hash, pubsub, pool, supervisor=supervisor, registry=registry, expiry=expiry
    )
```

- [ ] **Step 3: Migrate `operate_expire`**

In `src/aleph/vm/orchestrator/views/operator.py`, rewrite the action lines of
`operate_expire` (currently `execution.persistent = False` /
`execution.stop_after_timeout(timeout=timeout)`):

```python
        logger.info(f"Expiring in {timeout} seconds: {execution.vm_hash}")
        expiry: ExpiryManager = request.app["expiry"]
        expiry.schedule(VmId(str(vm_hash)), timeout)

        return web.Response(status=200, body=f"Expiring VM with ref {vm_hash} in {timeout} seconds")
```

Add the import near the other orchestrator imports in `operator.py`:

```python
from aleph.vm.orchestrator.expiry import ExpiryManager
```

In `operate_stop` and the delete/erase operator endpoints, after the
`supervisor.delete_vm(...)` call, clear any pending timer:

```python
                request.app["expiry"].cancel(vm_id)
```

(Use the `vm_id` already resolved in each handler; in `operate_stop` it is the
`vm_id` passed to `delete_vm`.)

- [ ] **Step 4: Update the operator expiry test**

In `tests/supervisor/views/test_operator.py`, the test currently asserts
`fake_vm_pool["executions"][vm_hash].expire.call_count == 1` (line 198).
`operate_expire` no longer touches the execution; it schedules on the app's
`ExpiryManager`. Replace the assertion so the test installs a spy expiry and
checks it was scheduled. Before `setup_webapp`, build the app with a spy:

```python
    app = setup_webapp(pool=fake_vm_pool)
    scheduled: list[tuple[str, float]] = []
    app["expiry"].schedule = lambda vm_id, timeout: scheduled.append((str(vm_id), timeout))
    client: TestClient = await aiohttp_client(app)
```

And replace the final assertion:

```python
    assert response.status == 200, await response.text()
    assert scheduled == [(vm_hash, 1.0)]
```

- [ ] **Step 5: Run the affected tests**

Run: `.testvenv/bin/python -m pytest tests/supervisor/views/test_operator.py -v`
Expected: PASS (including the rewritten expire test).

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/orchestrator/views/operator.py src/aleph/vm/orchestrator/cli.py tests/supervisor/views/test_operator.py
git commit -m "refactor(expiry): start_persistent_vm and operate_expire drive the ExpiryManager"
```

---

### Task 5: Remove the dead expiry code from `VmExecution` and `VmPool`

**Files:**
- Modify: `src/aleph/vm/models.py`
- Modify: `src/aleph/vm/pool.py`

- [ ] **Step 1: Delete the model members**

In `src/aleph/vm/models.py`:
- Delete the `expire_task: asyncio.Task | None = None` field (line 142).
- Delete the `stop_after_timeout` method (lines 785-796).
- Delete the `expire` method (lines 798-804).
- Delete the `cancel_expiration` method (lines 806-811).
- In `stop()`, delete the `self.cancel_expiration()` line (line 841). Leave the
  adjacent `self.cancel_update()` line in place (update-watching is a later PR).

- [ ] **Step 2: Delete the pool calls and fix docstrings**

In `src/aleph/vm/pool.py`, remove these `cancel_expiration` calls:
- `create_a_vm` (line 327): drop `current_execution.cancel_expiration()`; the
  reuse branch becomes just `return current_execution`.
- `create_vm_from_spec` (line 418): drop `current_execution.cancel_expiration()`;
  becomes `return current_execution`.
- `get_running_or_starting_vm` (line 482): drop the call.
- `get_running_vm` (line 491): drop the call.

Fix the now-stale docstrings on `get_running_vm` and
`get_running_or_starting_vm` (both currently `"""Return a running VM or None.
Disables the VM expiration task."""`) to:

```python
        """Return a running VM or None."""
```

- [ ] **Step 3: Verify no references remain**

Run: `grep -rn "stop_after_timeout\|cancel_expiration\|expire_task\|\.expire(" src/`
Expected: no output.

- [ ] **Step 4: Run the model/pool tests**

Run: `.testvenv/bin/python -m pytest tests/supervisor/ tests/test_pool.py -v`
Expected: PASS (env-only failures from the baseline excepted).

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/models.py src/aleph/vm/pool.py
git commit -m "refactor(expiry): drop expiry members from VmExecution and VmPool"
```

---

### Task 6: Gates and full suite

**Files:** none (verification only)

- [ ] **Step 1: Type check the touched modules**

Run:
```bash
.testvenv/bin/python -m mypy src/aleph/vm/orchestrator/expiry.py src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/reactor.py src/aleph/vm/orchestrator/views/ src/aleph/vm/models.py src/aleph/vm/pool.py --ignore-missing-imports
```
Expected: no NEW errors against the branch baseline.

- [ ] **Step 2: Format and import gates**

Run:
```bash
uvx ruff@0.4.6 format --diff .
uvx isort@5.13.2 --check-only --profile black src tests examples
```
Expected: clean. If `ruff format` reports diffs on touched files, apply
`uvx ruff@0.4.6 format <file>` and `git commit -m "style: ruff format"`.

- [ ] **Step 3: Done-criteria grep**

Run: `grep -rn "stop_after_timeout\|cancel_expiration\|expire_task" src/`
Expected: empty. And `grep -rn "cancel_expiration\|expire" src/aleph/vm/pool.py`
returns nothing.

- [ ] **Step 4: Full suite**

Run: `.testvenv/bin/python -m pytest tests/ -q`
Expected: at baseline (the documented env-only failures only).

- [ ] **Step 5: Final commit (if any format fixes pending)**

```bash
git add -A
git commit -m "test(expiry): gates green, full suite at baseline" || echo "nothing to commit"
```

---

## Self-review notes

- Spec coverage: ExpiryManager (Task 1); wiring (Tasks 2-3); all three
  touch-points (Tasks 2-4); removals from model + pool (Task 5); volume-safe
  reap via `delete_vm(wipe=False)` (Task 1 test + Tasks 2-3); tests (Tasks 1,
  4); gates (Task 6).
- The cancel-on-reuse (`expiry.cancel(vm_id)` at the top of both `run_code_on_*`)
  preserves the "no expiry while serving a request" guarantee the pool's
  `get_running_vm` cancel used to give.
- `cancel_all` is implemented and unit-tested; not yet wired into a shutdown
  hook (no current hook reaches the agent singletons cleanly). Left available;
  wiring it is out of scope per the spec.
