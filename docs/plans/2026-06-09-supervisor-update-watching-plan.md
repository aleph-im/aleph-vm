# Agent-side Update-Watching + Execution-Free `start_persistent_vm` — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Lift update-watching off the `VmExecution` god-object into an agent-owned `UpdateWatcher`, and make `start_persistent_vm` execution-free by moving its pre-existing-VM check onto `supervisor.get_vm`.

**Architecture:** New `UpdateWatcher` (mirror of `ExpiryManager` from #969) holds update-subscription tasks keyed by `vm_id`, reads each VM's message from the `AgentVmRegistry`, subscribes to its code/runtime/data/volume refs via `PubSub.msubscribe`, and reaps via `supervisor.delete_vm` on update. Wired symmetrically with expiry across the request path, reactor, lifecycle endpoints, and shutdown. `start_persistent_vm` drops its `pool.executions` read in favour of `get_vm` + `_wait_until_running`.

**Tech Stack:** Python 3, asyncio, aiohttp, pytest / pytest-asyncio. Design doc: `docs/plans/2026-06-09-supervisor-update-watching-design.md`.

**Stacks on:** `od/wire-supervisor-expiry` (#969).

---

## Environment note (test command)

This worktree has no local `.testvenv`. Run tests through the shared interpreter with this worktree's `src` on the path:

```bash
PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -m pytest <args>
```

In the steps below, `pytest` is shorthand for exactly that invocation. Every `git`/`pytest` command runs from the worktree root `/home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-expiry`. All bash here needs `dangerouslyDisableSandbox: true`.

## File structure

- **Create** `src/aleph/vm/orchestrator/update_watcher.py` — the `UpdateWatcher` class + the `update_refs(original)` pure helper. Sole responsibility: own update-subscription tasks and translate a message into its watch refs.
- **Create** `tests/supervisor/test_update_watcher.py` — unit tests for the watcher and `update_refs`.
- **Modify** `src/aleph/vm/models.py` — delete the update machinery from `VmExecution`.
- **Modify** `src/aleph/vm/orchestrator/run.py` — request/reactor paths use the watcher; `start_persistent_vm` execution-free; add `_wait_until_gone`.
- **Modify** `src/aleph/vm/orchestrator/reactor.py` — `Reactor` gains `registry` + `update_watcher`.
- **Modify** `src/aleph/vm/orchestrator/tasks.py` — construct `Reactor` with the new args.
- **Modify** `src/aleph/vm/orchestrator/supervisor.py` — build `app["update_watcher"]`; `stop_update_watcher` cleanup hook.
- **Modify** `src/aleph/vm/orchestrator/views/operator.py` — `update_watcher.cancel` on stop/reboot/erase.
- **Modify** `src/aleph/vm/orchestrator/views/__init__.py` — pass `update_watcher` into `start_persistent_vm`.
- **Modify** `src/aleph/vm/orchestrator/cli.py` — benchmark + `start_instance` build/pass an `UpdateWatcher`.
- **Modify** `tests/supervisor/test_execution.py` (or a new `test_models_no_update_api.py`) — assert the update API is gone from `VmExecution`.

---

## Task 1: `UpdateWatcher` facility + `update_refs`

**Files:**
- Create: `src/aleph/vm/orchestrator/update_watcher.py`
- Test: `tests/supervisor/test_update_watcher.py`

Reference shape: `src/aleph/vm/orchestrator/expiry.py` (the `ExpiryManager` from #969). The watcher mirrors its `cancel`/`cancel_all`/`finally`-cleanup discipline, but is subscription-driven and **idempotent** (a live watch is not restarted — preserving the old `if not self.update_task` behaviour).

- [ ] **Step 1: Write the failing tests**

Create `tests/supervisor/test_update_watcher.py`:

```python
import asyncio
import json
from types import SimpleNamespace

import pytest
from aleph_message.models import InstanceContent

from aleph.vm.orchestrator.update_watcher import UpdateWatcher, update_refs
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId
from aleph.vm.utils import get_message_executable_content

# Import the existing instance-message builder (instance branch of update_refs).
from test_supervisor_translate import _make_qemu_instance_message


def _program_content():
    # examples/program_message_from_aleph.json is a full message envelope; the
    # helper wants the bare content dict.
    with open("examples/program_message_from_aleph.json") as fd:
        return get_message_executable_content(json.load(fd)["content"])


class FakeSupervisor:
    def __init__(self, *, raise_not_found: bool = False):
        self.deleted: list[tuple[str, bool]] = []
        self.raise_not_found = raise_not_found

    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        self.deleted.append((str(vm_id), wipe))
        if self.raise_not_found:
            raise VmNotFoundError(str(vm_id))


class FakePubSub:
    """msubscribe blocks until the test triggers it, recording the keys."""

    def __init__(self):
        self.event = asyncio.Event()
        self.subscribed: tuple | None = None

    async def msubscribe(self, *keys):
        self.subscribed = tuple(k for k in keys if k is not None)
        await self.event.wait()

    def trigger(self):
        self.event.set()


def _registry_with(vm_hash: str, original):
    registry = AgentVmRegistry()
    registry.record(vm_hash, message=original, original=original, persistent=False)
    return registry


_HASH = "a" * 64


def test_update_refs_instance_uses_volume_refs():
    content = _make_qemu_instance_message()  # volumes=[]
    assert update_refs(content) == []


def test_update_refs_program_uses_code_runtime_data():
    content = _program_content()
    refs = update_refs(content)
    assert content.code.ref in refs
    assert content.runtime.ref in refs


def test_update_refs_program_branch_type():
    # A program message is not an InstanceContent: exercises the else-branch.
    assert not isinstance(_program_content(), InstanceContent)


@pytest.mark.asyncio
async def test_watch_reaps_on_update():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0)          # let the task reach msubscribe
    pubsub.trigger()
    await asyncio.sleep(0.02)

    assert sup.deleted == [(_HASH, False)]
    assert watcher.cancel(vm_id) is False  # task removed itself after firing


@pytest.mark.asyncio
async def test_cancel_prevents_reap():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0)
    assert watcher.cancel(vm_id) is True
    pubsub.trigger()
    await asyncio.sleep(0.02)

    assert sup.deleted == []


@pytest.mark.asyncio
async def test_watch_is_idempotent_keeps_existing_subscription():
    sup, pubsub1, pubsub2 = FakeSupervisor(), FakePubSub(), FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub1)
    await asyncio.sleep(0)
    watcher.watch(vm_id, _HASH, pubsub2)  # second call must NOT restart
    await asyncio.sleep(0)

    assert pubsub1.subscribed is not None   # first subscription is live
    assert pubsub2.subscribed is None       # second was a no-op


@pytest.mark.asyncio
async def test_watch_noop_when_unrecorded():
    sup, pubsub = FakeSupervisor(), FakePubSub()
    watcher = UpdateWatcher(sup, AgentVmRegistry())  # empty registry
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0.01)

    assert watcher.cancel(vm_id) is False   # nothing scheduled
    assert pubsub.subscribed is None


@pytest.mark.asyncio
async def test_watch_swallows_vm_not_found():
    sup = FakeSupervisor(raise_not_found=True)
    pubsub = FakePubSub()
    registry = _registry_with(_HASH, _make_qemu_instance_message())
    watcher = UpdateWatcher(sup, registry)
    vm_id = VmId(_HASH)

    watcher.watch(vm_id, _HASH, pubsub)
    await asyncio.sleep(0)
    pubsub.trigger()
    await asyncio.sleep(0.02)               # must not raise

    assert sup.deleted == [(_HASH, False)]
    assert watcher.cancel(vm_id) is False


@pytest.mark.asyncio
async def test_cancel_all_clears_every_watch():
    sup = FakeSupervisor()
    registry = AgentVmRegistry()
    registry.record("a" * 64, message=_make_qemu_instance_message(),
                    original=_make_qemu_instance_message(), persistent=False)
    registry.record("b" * 64, message=_make_qemu_instance_message(),
                    original=_make_qemu_instance_message(), persistent=False)
    watcher = UpdateWatcher(sup, registry)
    watcher.watch(VmId("a" * 64), "a" * 64, FakePubSub())
    watcher.watch(VmId("b" * 64), "b" * 64, FakePubSub())
    await asyncio.sleep(0)

    await watcher.cancel_all()
    await asyncio.sleep(0.02)

    assert sup.deleted == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/supervisor/test_update_watcher.py -q`
Expected: FAIL — `ModuleNotFoundError: No module named 'aleph.vm.orchestrator.update_watcher'`.

- [ ] **Step 3: Implement `update_watcher.py`**

Create `src/aleph/vm/orchestrator/update_watcher.py`:

```python
import asyncio
import logging

from aleph_message.models import ExecutableContent, InstanceContent, ItemHash

from aleph.vm.orchestrator.pubsub import PubSub
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.errors import VmNotFoundError
from aleph.vm.supervisor.types import VmId

logger = logging.getLogger(__name__)


def update_refs(original: ExecutableContent) -> list[str]:
    """The Aleph message refs whose update should redeploy the VM.

    Moved verbatim from VmExecution.watch_for_updates: instances watch their
    volume refs; programs also watch code / runtime / data.
    """
    volume_refs = [volume.ref for volume in (original.volumes or []) if hasattr(volume, "ref")]
    if isinstance(original, InstanceContent):
        return volume_refs
    data_ref = [original.data.ref] if original.data else []
    return [original.code.ref, original.runtime.ref, *data_ref, *volume_refs]


class UpdateWatcher:
    """Agent-owned 'redeploy on message update' subscriptions, keyed by vm_id.

    Subscription-driven counterpart to ExpiryManager. One dependency pair: the
    Supervisor (to reap) and the AgentVmRegistry (to read the watched message).
    Replaces the update methods that used to live on VmExecution.
    """

    def __init__(self, supervisor: Supervisor, registry: AgentVmRegistry) -> None:
        self.supervisor = supervisor
        self.registry = registry
        self._tasks: dict[VmId, asyncio.Task] = {}

    def watch(self, vm_id: VmId, vm_hash: ItemHash, pubsub: PubSub) -> None:
        """Start watching for updates to vm_hash, unless already watching it.

        Idempotent: a live subscription is kept (matches the old
        ``if not self.update_task`` guard). No-op when the agent has no record
        of the VM (e.g. nothing to watch)."""
        existing = self._tasks.get(vm_id)
        if existing is not None and not existing.done():
            return
        record = self.registry.get(vm_hash)
        if record is None:
            return
        refs = update_refs(record.original)
        self._tasks[vm_id] = asyncio.create_task(self._watch(vm_id, refs, pubsub), name=f"watch {vm_id}")

    def cancel(self, vm_id: VmId) -> bool:
        """Cancel a pending watch. Returns whether one existed."""
        task = self._tasks.pop(vm_id, None)
        if task is None:
            return False
        task.cancel()
        return True

    async def cancel_all(self) -> None:
        """Cancel every pending watch (shutdown cleanup)."""
        for vm_id in list(self._tasks):
            self.cancel(vm_id)

    async def _watch(self, vm_id: VmId, refs: list[str], pubsub: PubSub) -> None:
        try:
            await pubsub.msubscribe(*refs)
            logger.info("Update received for %s, reaping", vm_id)
            await self.supervisor.delete_vm(vm_id)
        except VmNotFoundError:
            logger.debug("Update-watch: VM %s already gone", vm_id)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception("Update-watch of %s failed", vm_id)
        finally:
            # Only drop our own entry: a concurrent re-watch may have replaced it.
            if self._tasks.get(vm_id) is asyncio.current_task():
                del self._tasks[vm_id]
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `pytest tests/supervisor/test_update_watcher.py -q`
Expected: PASS (8 tests).

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/orchestrator/update_watcher.py tests/supervisor/test_update_watcher.py
git commit -m "feat(update-watch): agent-owned UpdateWatcher keyed by vm_id"
```

---

## Task 2: App wiring (`app["update_watcher"]` + shutdown)

**Files:**
- Modify: `src/aleph/vm/orchestrator/supervisor.py`

Reference the expiry wiring already in this file: `app["expiry"] = ExpiryManager(app["supervisor"])` and `stop_expiry_manager`.

- [ ] **Step 1: Add the import and construct the watcher**

In `src/aleph/vm/orchestrator/supervisor.py`, next to the existing expiry import:

```python
from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.orchestrator.update_watcher import UpdateWatcher
```

In `setup_webapp`, immediately after the `vm_registry` line (the watcher needs the registry):

```python
    app["expiry"] = ExpiryManager(app["supervisor"])
    app["vm_registry"] = AgentVmRegistry()
    app["update_watcher"] = UpdateWatcher(app["supervisor"], app["vm_registry"])
```

- [ ] **Step 2: Add the shutdown hook**

After `stop_expiry_manager` in the same file:

```python
async def stop_update_watcher(app: web.Application) -> None:
    """on_cleanup hook: cancel any pending update-watch subscriptions."""
    update_watcher = app.get("update_watcher")
    if update_watcher is not None:
        await update_watcher.cancel_all()
```

In `run()`, register it next to `stop_expiry_manager` (before `stop_all_vms`):

```python
        app.on_cleanup.append(stop_expiry_manager)
        app.on_cleanup.append(stop_update_watcher)
        app.on_cleanup.append(stop_all_vms)
```

- [ ] **Step 3: Verify the app still builds**

Run: `pytest tests/supervisor/test_views.py -q -k system_usage`
Expected: the pre-existing environment failures only (no new import/collection errors). Confirm the module imports:

Run: `PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -c "import aleph.vm.orchestrator.supervisor"`
Expected: no output (clean import).

- [ ] **Step 4: Commit**

```bash
git add src/aleph/vm/orchestrator/supervisor.py
git commit -m "feat(update-watch): build app[\"update_watcher\"] and cancel it on shutdown"
```

---

## Task 3: Request + reactor paths use the watcher

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (`run_code_on_request`, `run_code_on_event`)
- Modify: `src/aleph/vm/orchestrator/reactor.py`
- Modify: `src/aleph/vm/orchestrator/tasks.py`
- Modify: `src/aleph/vm/orchestrator/cli.py` (`benchmark`)

- [ ] **Step 1: `run_code_on_request` — pull the watcher and use it**

In `run_code_on_request` (after the existing `expiry = request.app["expiry"]` lines):

```python
    supervisor: Supervisor = request.app["supervisor"]
    expiry: ExpiryManager = request.app["expiry"]
    update_watcher: UpdateWatcher = request.app["update_watcher"]
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve
```

(Update the imports at the top of `run.py`:)

```python
from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.orchestrator.update_watcher import UpdateWatcher
```

In the `finally` block of `run_code_on_request`, replace the `start_watching_for_updates` call and add a cancel on the teardown branch:

```python
    finally:
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                update_watcher.watch(vm_id, vm_hash, request.app["pubsub"])
            expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        else:
            update_watcher.cancel(vm_id)
            await supervisor.delete_vm(vm_id)
```

Note: update-watch is **not** cancelled at the top of the request (unlike expiry). An update that fires mid-serve must still redeploy; `delete_vm` → `stop_vm` waits for the in-flight run, matching the old `stop()` semantics.

- [ ] **Step 2: `run_code_on_event` — accept and use the watcher**

Change the signature to take `update_watcher`, drop the local registry, and use the passed registry:

```python
async def run_code_on_event(
    vm_hash: ItemHash,
    event,
    pubsub: PubSub,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
    registry: AgentVmRegistry,
):
    """
    Execute code in response to an event.
    """
    vm_id = VmId(str(vm_hash))
    expiry.cancel(vm_id)  # do not reap a VM we are about to serve

    execution: VmExecution | None = pool.get_running_vm(vm_hash=vm_hash)

    if not execution:
        # programs use the legacy create path; the registry is the agent's
        # shared known-VM store (so the watcher reads the same record).
        execution = await create_vm_execution_or_raise_http_error(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
        )
```

In its trailing reuse/teardown block:

```python
        if settings.REUSE_TIMEOUT > 0:
            if settings.WATCH_FOR_UPDATES:
                update_watcher.watch(vm_id, vm_hash, pubsub)
            expiry.schedule(vm_id, settings.REUSE_TIMEOUT)
        else:
            update_watcher.cancel(vm_id)
            await supervisor.delete_vm(vm_id)
```

- [ ] **Step 3: `Reactor` carries the registry + watcher**

In `src/aleph/vm/orchestrator/reactor.py`:

```python
from aleph.vm.orchestrator.expiry import ExpiryManager
from aleph.vm.orchestrator.update_watcher import UpdateWatcher
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.pool import VmPool
from aleph.vm.supervisor.abc import Supervisor
```

```python
class Reactor:
    pubsub: PubSub
    pool: VmPool
    supervisor: Supervisor
    expiry: ExpiryManager
    update_watcher: UpdateWatcher
    registry: AgentVmRegistry
    listeners: list[AlephMessage]

    def __init__(
        self,
        pubsub: PubSub,
        pool: VmPool,
        supervisor: Supervisor,
        expiry: ExpiryManager,
        update_watcher: UpdateWatcher,
        registry: AgentVmRegistry,
    ):
        self.pubsub = pubsub
        self.pool = pool
        self.supervisor = supervisor
        self.expiry = expiry
        self.update_watcher = update_watcher
        self.registry = registry
        self.listeners = []
```

In `Reactor.trigger`, pass them through:

```python
                    coroutines.append(
                        run_code_on_event(
                            vm_hash,
                            event,
                            self.pubsub,
                            pool=self.pool,
                            supervisor=self.supervisor,
                            expiry=self.expiry,
                            update_watcher=self.update_watcher,
                            registry=self.registry,
                        )
                    )
```

- [ ] **Step 4: `tasks.py` constructs the Reactor with the new args**

In `src/aleph/vm/orchestrator/tasks.py`, `start_watch_for_messages_task`:

```python
    reactor = Reactor(pubsub, pool, supervisor, app["expiry"], app["update_watcher"], registry)
```

(`registry` is already bound there as `registry = app["vm_registry"]`.)

- [ ] **Step 5: `cli.py benchmark` passes the watcher**

In `src/aleph/vm/orchestrator/cli.py`:

```python
from aleph.vm.orchestrator.update_watcher import UpdateWatcher
```

In `benchmark`, where the fake app dict and `bench_supervisor` are built:

```python
    bench_supervisor = InProcessSupervisor(pool)
    bench_registry = AgentVmRegistry()
    bench_update_watcher = UpdateWatcher(bench_supervisor, bench_registry)
    fake_request.app = {
        "supervisor": bench_supervisor,
        "expiry": ExpiryManager(bench_supervisor),
        "update_watcher": bench_update_watcher,
        "vm_registry": bench_registry,
        "pubsub": PubSub(),
    }
```

And the `run_code_on_event` call:

```python
    result = await run_code_on_event(
        vm_hash=ref,
        event=None,
        pubsub=PubSub(),
        pool=pool,
        supervisor=bench_supervisor,
        expiry=fake_request.app["expiry"],
        update_watcher=bench_update_watcher,
        registry=bench_registry,
    )
```

- [ ] **Step 6: Run the affected suites**

Run: `pytest tests/supervisor/test_supervisor_run_routing.py -q`
Expected: PASS (the routing tests exercise `run_code_on_event`; update any that construct `run_code_on_event`/`Reactor` directly to pass `update_watcher` + `registry`).

Run: `pytest tests/supervisor/test_update_watcher.py -q`
Expected: PASS (unchanged).

- [ ] **Step 7: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/reactor.py \
        src/aleph/vm/orchestrator/tasks.py src/aleph/vm/orchestrator/cli.py
git commit -m "feat(update-watch): request and reactor paths drive UpdateWatcher; reactor adopts the app registry"
```

---

## Task 4: Execution-free `start_persistent_vm` + lifecycle cancels

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (`start_persistent_vm`, new `_wait_until_gone`)
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (`update_allocations`, `notify_allocation`)
- Modify: `src/aleph/vm/orchestrator/views/operator.py` (`operate_stop`, `operate_reboot`, `operate_erase`)
- Modify: `src/aleph/vm/orchestrator/cli.py` (`start_instance`)
- Test: `tests/supervisor/test_supervisor_run_routing.py` (new `start_persistent_vm` precheck tests)

- [ ] **Step 1: Write the failing precheck tests**

Add to `tests/supervisor/test_supervisor_run_routing.py` (it already has `_info`, `_fake_supervisor`, `_HASH`, and imports `run_module`, `VmStatus`). These drive `start_persistent_vm` against a fake supervisor and assert create-vs-reuse based on `get_vm` status:

```python
@pytest.mark.asyncio
async def test_start_persistent_reuses_running(monkeypatch):
    sup = _fake_supervisor(get_status=VmStatus.RUNNING)
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    result = await run_module.start_persistent_vm(
        ItemHash(_HASH), None, MagicMock(),
        supervisor=sup, registry=AgentVmRegistry(),
        expiry=MagicMock(), update_watcher=MagicMock(),
    )
    assert result is None
    created.assert_not_awaited()  # already running -> no create


@pytest.mark.asyncio
async def test_start_persistent_creates_when_absent(monkeypatch):
    sup = _fake_supervisor()
    sup.get_vm = AsyncMock(side_effect=VmNotFoundError(_HASH))
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    await run_module.start_persistent_vm(
        ItemHash(_HASH), None, MagicMock(),
        supervisor=sup, registry=AgentVmRegistry(),
        expiry=MagicMock(), update_watcher=MagicMock(),
    )
    created.assert_awaited_once()


@pytest.mark.asyncio
async def test_start_persistent_recreates_after_terminal(monkeypatch):
    sup = _fake_supervisor(get_status=VmStatus.STOPPED)
    created = AsyncMock()
    monkeypatch.setattr(run_module, "create_vm_execution", created)
    monkeypatch.setattr(run_module, "_wait_until_running", AsyncMock())

    await run_module.start_persistent_vm(
        ItemHash(_HASH), None, MagicMock(),
        supervisor=sup, registry=AgentVmRegistry(),
        expiry=MagicMock(), update_watcher=MagicMock(),
    )
    sup.delete_vm.assert_awaited_once()  # terminal -> delete then recreate
    created.assert_awaited_once()
```

Ensure these imports are present at the top of the test file (add any missing):
`from unittest.mock import AsyncMock, MagicMock`, `from aleph.vm.orchestrator.vm_registry import AgentVmRegistry`, `from aleph.vm.supervisor.errors import VmNotFoundError`. `_fake_supervisor` must expose `delete_vm`/`get_vm` as `AsyncMock`s — if the existing helper does not, extend it so `delete_vm = AsyncMock()` and `get_vm = AsyncMock(return_value=_info(get_status))`.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `pytest tests/supervisor/test_supervisor_run_routing.py -q -k start_persistent`
Expected: FAIL — `start_persistent_vm` still takes the old signature (no `update_watcher`) and reads `pool.executions`.

- [ ] **Step 3: Add `_wait_until_gone` and rewrite `start_persistent_vm`**

In `src/aleph/vm/orchestrator/run.py`, add next to `_wait_until_running`:

```python
async def _wait_until_gone(
    supervisor: Supervisor,
    vm_id: VmId,
    *,
    timeout: float | None = None,
    interval: float | None = None,
) -> None:
    """Poll get_vm until the VM is gone (VmNotFoundError)."""
    if timeout is None:
        timeout = _START_POLL_TIMEOUT_SECONDS
    if interval is None:
        interval = _START_POLL_INTERVAL_SECONDS
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        try:
            await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            return
        if asyncio.get_running_loop().time() >= deadline:
            msg = f"VM {vm_id} did not stop within {timeout}s"
            raise asyncio.TimeoutError(msg)
        await asyncio.sleep(interval)
```

(Mirrors `_wait_until_running`'s clock and timeout-raise exactly.)

Rewrite `start_persistent_vm`:

```python
async def start_persistent_vm(
    vm_hash: ItemHash,
    pubsub: PubSub | None,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    expiry: ExpiryManager,
    update_watcher: UpdateWatcher,
) -> None:
    vm_id = VmId(str(vm_hash))
    try:
        info: VmInfo | None = await supervisor.get_vm(vm_id)
    except VmNotFoundError:
        info = None

    if info is not None:
        if info.status == VmStatus.RUNNING:
            logger.info(f"{vm_hash} is already running")
        elif info.status in (VmStatus.DEFINED, VmStatus.BOOTING):
            logger.info(f"{vm_hash} is already starting")
            await _wait_until_running(supervisor, vm_id)
        elif info.status == VmStatus.STOPPING:
            logger.info(f"{vm_hash} is stopping, waiting before restart")
            await _wait_until_gone(supervisor, vm_id)
            info = None
        else:  # STOPPED / FAILED
            logger.info(f"{vm_hash} in terminal state {info.status}, recreating")
            await supervisor.delete_vm(vm_id)
            info = None

    if info is None:
        logger.info(f"Starting persistent virtual machine with id: {vm_hash}")
        await create_vm_execution(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry, persistent=True
        )
        await _wait_until_running(supervisor, vm_id)

    # Scheduled long-running: it must not idle-expire.
    expiry.cancel(vm_id)

    if pubsub and settings.WATCH_FOR_UPDATES:
        update_watcher.watch(vm_id, vm_hash, pubsub)
```

Ensure `VmInfo` and `VmStatus` are imported in `run.py`:

```python
from aleph.vm.supervisor.types import VmId, VmInfo, VmStatus
```

- [ ] **Step 4: Run the precheck tests**

Run: `pytest tests/supervisor/test_supervisor_run_routing.py -q -k start_persistent`
Expected: PASS (3 tests).

- [ ] **Step 5: Update `start_persistent_vm` callers**

In `src/aleph/vm/orchestrator/views/__init__.py`, all three call sites (two in `update_allocations`, one in `notify_allocation`) gain `update_watcher`. First bind it next to the existing `expiry = request.app["expiry"]`:

```python
    expiry = request.app["expiry"]
    update_watcher = request.app["update_watcher"]
```

Then each call:

```python
        await start_persistent_vm(
            vm_hash, pubsub, pool, supervisor=supervisor, registry=registry,
            expiry=expiry, update_watcher=update_watcher,
        )
```

(Apply the same `update_watcher=update_watcher` addition to the `instance_item_hash` and `notify_allocation` calls.)

In `src/aleph/vm/orchestrator/cli.py`, `start_instance`:

```python
async def start_instance(item_hash: ItemHash, pubsub: PubSub | None, pool) -> VmExecution:
    """Run an instance from an InstanceMessage."""
    supervisor = InProcessSupervisor(pool)
    registry = AgentVmRegistry()
    expiry = ExpiryManager(supervisor)
    update_watcher = UpdateWatcher(supervisor, registry)
    return await start_persistent_vm(
        item_hash, pubsub, pool, supervisor=supervisor, registry=registry,
        expiry=expiry, update_watcher=update_watcher,
    )
```

Note: `start_persistent_vm` now returns `None`. If `start_instance`'s return value is consumed anywhere, change its annotation to `-> None` and drop the `return`/use; verify with:

Run: `PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -c "import aleph.vm.orchestrator.cli"`
Expected: clean import. (`run_instances` ignores the value today; if mypy/flake flags the `-> VmExecution` annotation, change it to `-> None`.)

- [ ] **Step 6: Lifecycle endpoints cancel the watcher**

In `src/aleph/vm/orchestrator/views/operator.py`, add `request.app["update_watcher"].cancel(vm_id)` next to every existing `request.app["expiry"].cancel(vm_id)`:

`operate_stop` (after the existing expiry cancel):
```python
                await supervisor.delete_vm(vm_id)
                request.app["expiry"].cancel(vm_id)
                request.app["update_watcher"].cancel(vm_id)
                return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
```

`operate_reboot` (the delete-then-recreate branch):
```python
                    await supervisor.delete_vm(vm_id)
                    request.app["expiry"].cancel(vm_id)
                    request.app["update_watcher"].cancel(vm_id)
```

`operate_erase`:
```python
            await supervisor.delete_vm(VmId(str(vm_hash)), wipe=True)
            request.app["expiry"].cancel(VmId(str(vm_hash)))
            request.app["update_watcher"].cancel(VmId(str(vm_hash)))
```

- [ ] **Step 7: Run the views + routing suites**

Run: `pytest tests/supervisor/test_supervisor_run_routing.py tests/supervisor/test_views.py -q`
Expected: no new failures vs the #969 base (the 10 pre-existing environment failures only).

- [ ] **Step 8: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/views/__init__.py \
        src/aleph/vm/orchestrator/views/operator.py src/aleph/vm/orchestrator/cli.py \
        tests/supervisor/test_supervisor_run_routing.py
git commit -m "refactor(update-watch): execution-free start_persistent_vm via get_vm; lifecycle endpoints cancel the watcher"
```

---

## Task 5: Remove the dead update machinery from `VmExecution`

**Files:**
- Modify: `src/aleph/vm/models.py`
- Test: `tests/supervisor/test_execution.py`

By now nothing calls `start_watching_for_updates` / `watch_for_updates` / `cancel_update` (Tasks 3–4 removed every caller).

- [ ] **Step 1: Confirm there are no remaining callers**

Run:
```bash
grep -rn "start_watching_for_updates\|watch_for_updates\|cancel_update\|update_task" src/ tests/
```
Expected: only the definitions in `src/aleph/vm/models.py` (and any tests asserting their absence you are about to add). If a caller remains, migrate it before deleting.

- [ ] **Step 2: Write the failing "API is gone" test**

Append to `tests/supervisor/test_execution.py`:

```python
def test_vm_execution_has_no_update_watch_api():
    # Update-watching moved to the agent-side UpdateWatcher (design 2026-06-09).
    from aleph.vm.models import VmExecution

    for gone in ("start_watching_for_updates", "watch_for_updates", "cancel_update"):
        assert not hasattr(VmExecution, gone), f"{gone} should be removed from VmExecution"
```

- [ ] **Step 3: Run it to verify it fails**

Run: `pytest tests/supervisor/test_execution.py -q -k no_update_watch_api`
Expected: FAIL (the methods still exist).

- [ ] **Step 4: Delete the update machinery**

In `src/aleph/vm/models.py`:
- Remove the `update_task: asyncio.Task | None = None` field.
- Remove `start_watching_for_updates`, `watch_for_updates`, and `cancel_update` methods.
- Remove the `self.cancel_update()` call inside `stop()`.
- If `Task`/`PubSub` imports become unused after this and the expiry removal in #969, drop them. Verify with the import check below.

- [ ] **Step 5: Run the test + import check**

Run: `pytest tests/supervisor/test_execution.py -q -k no_update_watch_api`
Expected: PASS.

Run: `PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python -c "import aleph.vm.models"`
Expected: clean import (no unused-import crash; if `ruff` flags unused imports, remove them).

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/models.py tests/supervisor/test_execution.py
git commit -m "refactor(update-watch): drop update-watching members from VmExecution"
```

---

## Task 6: Whole-branch checks + style gates

**Files:** none (verification only)

- [ ] **Step 1: Run the full supervisor + orchestrator test set**

Run: `pytest tests/supervisor -q`
Expected: no new failures vs the #969 base. Confirm by comparing the failing-set to the known 10 pre-existing environment failures (`/var/lib/aleph` perms). Any failure outside that set must be fixed before proceeding.

- [ ] **Step 2: Style gates (must match CI exactly)**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/update_watcher.py \
    src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/reactor.py \
    src/aleph/vm/orchestrator/tasks.py src/aleph/vm/orchestrator/cli.py \
    src/aleph/vm/orchestrator/supervisor.py src/aleph/vm/orchestrator/views/__init__.py \
    src/aleph/vm/orchestrator/views/operator.py src/aleph/vm/models.py \
    tests/supervisor/test_update_watcher.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/update_watcher.py
```
Expected: no diff. Apply `ruff format` / `isort` (without `--check`/`--diff`) if either reports changes, then re-commit. Remove any `uv.lock` that `uvx` regenerates (`git rm --cached uv.lock` if it appears — it is not tracked).

- [ ] **Step 3: Final commit (only if the gates changed files)**

```bash
git add -A
git commit -m "style(update-watch): ruff/isort formatting"
```

---

## Out-of-scope residuals after this PR (do NOT touch)

- The `create_vm_execution` save() readback (`pool.executions[vm_hash]` → `execution.save()`) — deferred agent-owned `ExecutionRecord` persistence.
- Operator owner-auth's `execution.message` reads (~10 sites in `operator.py`).
- `operate_expire`'s pre-existing dead route (carried from #969).
