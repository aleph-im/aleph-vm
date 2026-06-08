# Wire agent onto Supervisor abstraction: PR 2 (operator lifecycle) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the operator lifecycle endpoints (stop, reboot, erase, reinstall, logs, port-forwards) and the deallocation paths off `pool.stop_vm` / `pool.forget_vm` / `VmExecution` reads onto the `Supervisor` abstraction; move owner-auth onto the agent registry; rehydrate the registry from the agent DB on startup; make port-forward persistence/reapply fully hypervisor-owned.

**Architecture:** Design doc `2026-06-01-wire-agent-onto-supervisor-design.md` §5 (PR 2 of §8). The agent keys every hypervisor call by `VmId`; owner identity and persistence flags come from `AgentVmRegistry` (now persisted via the existing `ExecutionRecord` DB and rehydrated on startup). The Supervisor contract is enriched where the endpoints' real mechanics live hypervisor-side: `delete_vm` gains `wipe`, `reinstall_vm` gains `wipe_volumes` (proto + ABC + in-process disk mechanics), and the logs ops serve journald history in-process. Port-forward reconciliation (aggregate → diff → add/remove) becomes an agent helper; the DB-load half of `fetch_port_redirect_config_and_setup` moves into the hypervisor's create/reattach paths.

**Tech Stack:** Python 3.11, asyncio, aiohttp, pydantic v2, SQLAlchemy async, protobuf (`scripts/generate_proto.py`), pytest / pytest-asyncio. Tests run via `just test <path>` (uses `.testvenv`).

**Design doc:** `docs/plans/2026-06-01-wire-agent-onto-supervisor-design.md` (§5, §8 item 2, §9)

**Worktree:** `.worktrees/wire-supervisor-lifecycle` on branch `od/wire-supervisor-lifecycle`, stacked on `od/wire-supervisor-abstraction` (PR #962). All commands below assume that directory.

---

## Design deltas (resolved 2026-06-04, with Olivier)

The §5 text assumed the existing contract suffices. Mapping it onto the code surfaced gaps; resolutions:

1. **Reinstall/erase mechanics move behind the boundary** (decided: enrich contract now).
   `operate_reinstall` erases rootfs (± data volumes), re-runs `prepare()`, restarts; `operate_erase` deletes data volumes + port mappings. `InProcessSupervisor.reinstall_vm` today just stops/restarts — wiring onto it as-is would boot a VM whose rootfs was deleted. Resolution: `DeleteVmRequest.wipe`, `ReinstallVmRequest.wipe_volumes` in proto + ABC; `_erase_execution_volumes` becomes `VmExecution.erase_volumes()`; `_restart_persistent_vm` becomes `VmPool.restart_persistent_vm()`; the in-process supervisor implements the full mechanics.
2. **Log history is served in-process from journald** (decided: implement now).
   `get_logs` returns journald history (`vm-<hash>-stdout`/`-stderr` identifiers) mapped to `LogChunk`; `stream_logs(include_history=True)` yields history then live queue. New `LOG_SOURCE_STDERR` proto enum value + `LogSource.STDERR` (today stderr is silently folded into STDOUT).
3. **Residuals, explicitly kept (deferred, not forgotten):**
   - `delete_port_mappings` on deallocation stays a direct DB call agent-side (folding it into `delete_vm` would either destroy data on plain stops or need another flag; mappings DB moves hypervisor-side with the gRPC split).
   - `operate_expire` stays execution-based (`stop_after_timeout` has no supervisor op; it is not in the §5 list).
   - `recreate_network`, `regenerate_proxy`, confidential, backup/restore endpoints stay pool/execution-based (out of scope per design §2).
   - The billing/deallocation *decision* logic in `tasks.check_payment` and `update_allocations` keeps reading `pool.get_persistent_executions()` / `pool.get_executions_by_address()`; only the *stop* goes through the supervisor (residual reads migrate per design §9).
4. **Bugs found during planning, fixed here:**
   - Spec-created VMs write **no `ExecutionRecord`** (`save()` no-ops while the spec is still `CreateVmSpec`; the agent re-sources to `MessageSpec` afterward but never saves). Past-logs owner-auth and registry rehydration would miss them. Fix: one `await execution.save()` in the existing TEMPORARY block of `create_vm_execution`.
   - `pool.create_vm_from_spec` does not preload persisted port mappings, so a persistent QEMU instance restarted via allocation gets **new host ports** (the legacy path reuses them via the DB-half of `fetch_port_redirect_config_and_setup`). Fix: hypervisor preloads `mapped_ports` from DB in `create_vm_from_spec` (and explicitly in `create_a_vm` / `recreate_network` once the DB-half is shed).
   - `recreate_network` calls `fetch_port_redirect_config_and_setup()` on reboot-reattached (spec-built) executions, which raises `TypeError` (caught and logged per-VM). Fix: guard with `isinstance(execution.spec, MessageSpec)`; reattached VMs get their DB mappings reapplied without the aggregate re-fetch.

**Known unchanged limitation:** reinstalling a reboot-reattached VM (spec-built, never re-sourced) cannot re-download the rootfs (the message is gone by design). Same failure as today; resolved by the future network-recreate iteration (design §9).

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `proto/supervisor.proto` | `DeleteVmRequest.wipe`, `ReinstallVmRequest.wipe_volumes`, `LOG_SOURCE_STDERR` | Modify |
| `src/aleph/vm/supervisor/_pb/*` | Regenerated bindings | Regenerate |
| `src/aleph/vm/supervisor/types.py` | `LogSource.STDERR` | Modify |
| `src/aleph/vm/supervisor/abc.py` | `delete_vm(vm_id, wipe=False)`, `reinstall_vm(vm_id, wipe_volumes=True)` | Modify |
| `src/aleph/vm/supervisor/inprocess.py` | Wipe/reinstall mechanics; journald-backed `get_logs` / `stream_logs` | Modify |
| `src/aleph/vm/models.py` | `erase_volumes()` method; shed DB-half of `fetch_port_redirect_config_and_setup` | Modify |
| `src/aleph/vm/pool.py` | `restart_persistent_vm()` method; DB preload in `create_a_vm` + `create_vm_from_spec` | Modify |
| `src/aleph/vm/orchestrator/vm_registry.py` | `persistent` field, `items()`, `rehydrate_registry()` | Modify |
| `src/aleph/vm/orchestrator/run.py` | `await execution.save()`; `reconcile_port_forwards()`; pass `persistent` to registry | Modify |
| `src/aleph/vm/orchestrator/supervisor.py` | `_rehydrate_vm_registry` startup hook | Modify |
| `src/aleph/vm/orchestrator/views/operator.py` | stop/reboot/erase/reinstall/logs endpoints onto supervisor + registry auth; drop moved helpers | Modify |
| `src/aleph/vm/orchestrator/views/__init__.py` | `operate_update` reconciliation; dealloc stop loop; `recreate_network` guard | Modify |
| `src/aleph/vm/orchestrator/tasks.py` | `check_payment` dealloc via supervisor; aggregate handler via reconcile | Modify |
| `tests/supervisor/test_supervisor_inprocess_lifecycle.py` | delete-wipe + reinstall mechanics tests | Modify |
| `tests/supervisor/test_supervisor_inprocess_logs.py` | journald history tests | Modify |
| `tests/supervisor/test_agent_vm_registry.py` | persistent flag, `items()`, rehydration tests | Modify |
| `tests/supervisor/test_supervisor_run_helpers.py` | `reconcile_port_forwards` tests | Modify |
| `tests/supervisor/views/test_operator.py` | Endpoint tests updated for registry auth + supervisor calls | Modify |
| `tests/supervisor/test_checkpayment.py` | Dealloc-via-supervisor updates | Modify |

Conformance note: `tests/supervisor/conformance.py` STUB_METHODS is unchanged (no stub is implemented or added); signature-only checks keep passing because parameters are keyword-with-default.

---

## Task 0: Branch + worktree setup

- [ ] **Step 1: Create the stacked worktree**

```bash
cd /home/olivier/git/aleph/aleph-vm
git worktree add .worktrees/wire-supervisor-lifecycle -b od/wire-supervisor-lifecycle od/wire-supervisor-abstraction
cd .worktrees/wire-supervisor-lifecycle
```

- [ ] **Step 2: Commit this plan**

Copy this file into `docs/plans/` of the new worktree if not already present, then:

```bash
git add docs/plans/2026-06-04-wire-agent-supervisor-pr2-plan.md
git commit -m "docs: PR 2 implementation plan (operator lifecycle onto Supervisor abstraction)"
```

---

## Task 1: Contract — proto fields + `LogSource.STDERR` + regenerated bindings

**Files:**
- Modify: `proto/supervisor.proto`
- Modify: `src/aleph/vm/supervisor/types.py:59-62`
- Regenerate: `src/aleph/vm/supervisor/_pb/`
- Test: `tests/supervisor/test_proto_bindings.py` (existing; plus new assertions)

- [ ] **Step 1: Write the failing test**

Append to `tests/supervisor/test_proto_bindings.py`:

```python
def test_delete_vm_request_has_wipe_field():
    from aleph.vm.supervisor._pb import supervisor_pb2

    req = supervisor_pb2.DeleteVmRequest(vm_id="x", wipe=True)
    assert req.wipe is True


def test_reinstall_vm_request_has_wipe_volumes_field():
    from aleph.vm.supervisor._pb import supervisor_pb2

    req = supervisor_pb2.ReinstallVmRequest(vm_id="x", wipe_volumes=True)
    assert req.wipe_volumes is True


def test_log_source_has_stderr():
    from aleph.vm.supervisor._pb import supervisor_pb2

    assert supervisor_pb2.LogChunk.LOG_SOURCE_STDERR == 4

    from aleph.vm.supervisor.types import LogSource

    assert LogSource.STDERR.value == "stderr"
```

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/test_proto_bindings.py`
Expected: FAIL (`ValueError: Protocol message DeleteVmRequest has no "wipe" field`)

- [ ] **Step 3: Edit the proto**

In `proto/supervisor.proto`:

```protobuf
message DeleteVmRequest {
  string vm_id = 1;
  bool wipe = 2;                     // also delete persisted port mappings and writable data volumes
}
```

```protobuf
message ReinstallVmRequest {
  string vm_id = 1;
  bool wipe_volumes = 2;             // false = reset rootfs only, keep writable data volumes
}
```

In `LogChunk.LogSource`:

```protobuf
    LOG_SOURCE_SYSTEMD = 3;          // systemd journal for persistent VM unit
    LOG_SOURCE_STDERR = 4;           // vm-stderr journal identifier
```

- [ ] **Step 4: Update `types.py`**

```python
class LogSource(Enum):
    SERIAL = "serial"
    STDOUT = "stdout"
    STDERR = "stderr"
    SYSTEMD = "systemd"
```

- [ ] **Step 5: Regenerate bindings + verify**

```bash
python scripts/generate_proto.py
bash scripts/check_proto_clean.sh   # expects "proto bindings are up to date."
just test tests/supervisor/test_proto_bindings.py tests/supervisor/test_supervisor_types.py
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add proto/ src/aleph/vm/supervisor/_pb/ src/aleph/vm/supervisor/types.py tests/supervisor/test_proto_bindings.py
git commit -m "feat(supervisor): wipe flags on delete/reinstall + stderr log source in the wire contract"
```

---

## Task 2: `VmExecution.erase_volumes()` + `delete_vm(wipe=)` in-process

**Files:**
- Modify: `src/aleph/vm/models.py` (new method near `record_usage`)
- Modify: `src/aleph/vm/orchestrator/views/operator.py` (delete `_erase_execution_volumes:155-189`, update its 2 call sites)
- Modify: `src/aleph/vm/supervisor/abc.py:52`, `src/aleph/vm/supervisor/inprocess.py:160-164`
- Test: `tests/supervisor/test_supervisor_inprocess_lifecycle.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/supervisor/test_supervisor_inprocess_lifecycle.py` (reuse that file's existing fake-pool/execution helpers; the essence):

```python
@pytest.mark.asyncio
async def test_delete_vm_wipe_erases_data_volumes_and_port_mappings(monkeypatch):
    execution = _make_execution(persistent=True)          # file-backed fake resources
    pool = _make_pool({VM_ID: execution})
    supervisor = InProcessSupervisor(pool)
    deleted = AsyncMock()
    monkeypatch.setattr("aleph.vm.supervisor.inprocess.delete_port_mappings", deleted)
    erased = MagicMock(return_value=1)
    execution.erase_volumes = erased

    await supervisor.delete_vm(VM_ID, wipe=True)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    deleted.assert_awaited_once_with(execution.vm_hash)
    erased.assert_called_once_with()


@pytest.mark.asyncio
async def test_delete_vm_without_wipe_keeps_data(monkeypatch):
    execution = _make_execution(persistent=True)
    pool = _make_pool({VM_ID: execution})
    supervisor = InProcessSupervisor(pool)
    deleted = AsyncMock()
    monkeypatch.setattr("aleph.vm.supervisor.inprocess.delete_port_mappings", deleted)
    execution.erase_volumes = MagicMock()

    await supervisor.delete_vm(VM_ID)

    deleted.assert_not_awaited()
    execution.erase_volumes.assert_not_called()
```

And a `models.py` unit test (e.g. in `tests/supervisor/test_execution.py` or a small new block in the lifecycle file) exercising `erase_volumes` against tmp-path files:

```python
def test_erase_volumes_deletes_rootfs_and_data(tmp_path):
    rootfs = tmp_path / "rootfs.qcow2"; rootfs.touch()
    vol = tmp_path / "data.qcow2"; vol.touch()
    ro = tmp_path / "ro.sqsh"; ro.touch()
    execution = MagicMock(spec=VmExecution)
    execution.resources = SimpleNamespace(
        rootfs_path=rootfs,
        volumes=[SimpleNamespace(read_only=False, path_on_host=vol),
                 SimpleNamespace(read_only=True, path_on_host=ro)],
    )

    deleted = VmExecution.erase_volumes(execution, include_rootfs=True)

    assert deleted == 2
    assert not rootfs.exists() and not vol.exists() and ro.exists()
```

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/test_supervisor_inprocess_lifecycle.py`
Expected: FAIL (`TypeError: delete_vm() got an unexpected keyword argument 'wipe'` / `AttributeError: erase_volumes`)

- [ ] **Step 3: Move `_erase_execution_volumes` into `VmExecution`**

In `models.py`, add (body copied from `operator.py:155-189`, `self` instead of `execution`):

```python
    def erase_volumes(self, *, include_rootfs: bool = False, include_data_volumes: bool = True) -> int:
        """Delete this execution's on-disk volumes.

        Hypervisor mechanism behind Supervisor.delete_vm(wipe=...) and
        reinstall_vm(...). Returns the number of files deleted.
        """
        if self.resources is None:
            return 0
        deleted_count = 0
        if include_rootfs:
            rootfs = self.resources.rootfs_path
            if rootfs.exists():
                logger.info(f"Deleting rootfs {rootfs}")
                rootfs.unlink()
                deleted_count += 1
        if include_data_volumes:
            for volume in self.resources.volumes:
                if not volume.read_only:
                    logger.info(f"Deleting volume {volume.path_on_host}")
                    volume.path_on_host.unlink(missing_ok=True)
                    deleted_count += 1
        return deleted_count
```

Delete `_erase_execution_volumes` from `operator.py`; replace its two uses (`operate_erase:725`, `operate_reinstall:762,774`) with `execution.erase_volumes(...)` (same kwargs). These endpoints migrate fully in Tasks 6–7; this keeps them green meanwhile.

- [ ] **Step 4: ABC + in-process `delete_vm`**

`abc.py`:

```python
    @abstractmethod
    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None: ...
```

`inprocess.py` (import `delete_port_mappings` from `aleph.vm.orchestrator.metrics` — same layering precedent as `pool.py:29`):

```python
    async def delete_vm(self, vm_id: VmId, wipe: bool = False) -> None:
        with translating_errors():
            execution = self._require(vm_id)
            await self.pool.stop_vm(vm_id)
            if execution.vm_hash in self.pool.executions:
                self.pool.forget_vm(vm_id)
            if wipe:
                # Mirrors the old operate_erase semantics exactly: persisted
                # port mappings (persistent VMs keep them across stops) and
                # writable data volumes go; the rootfs stays.
                if execution.persistent:
                    await delete_port_mappings(execution.vm_hash)
                execution.erase_volumes()
```

- [ ] **Step 5: Run tests, fix, run wider**

```bash
just test tests/supervisor/test_supervisor_inprocess_lifecycle.py tests/supervisor/test_supervisor_conformance_inprocess.py tests/supervisor/views/test_operator.py
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A src/ tests/
git commit -m "feat(supervisor): delete_vm(wipe=) erases data volumes and port mappings in-process"
```

---

## Task 3: `reinstall_vm(wipe_volumes=)` mechanics + `pool.restart_persistent_vm`

**Files:**
- Modify: `src/aleph/vm/pool.py` (new method), `src/aleph/vm/orchestrator/views/operator.py` (delete `_restart_persistent_vm:192-233`, restore path calls pool method)
- Modify: `src/aleph/vm/supervisor/abc.py:58`, `src/aleph/vm/supervisor/inprocess.py:176-184`
- Test: `tests/supervisor/test_supervisor_inprocess_lifecycle.py`

- [ ] **Step 1: Write the failing tests**

```python
@pytest.mark.asyncio
async def test_reinstall_persistent_erases_prepares_and_restarts():
    execution = _make_execution(persistent=True)
    execution.erase_volumes = MagicMock()
    execution.prepare = AsyncMock()
    pool = _make_pool({VM_ID: execution})
    pool.restart_persistent_vm = AsyncMock()
    supervisor = InProcessSupervisor(pool)

    await supervisor.reinstall_vm(VM_ID, wipe_volumes=False)

    pool.stop_vm.assert_awaited_once_with(VM_ID)
    execution.erase_volumes.assert_called_once_with(include_rootfs=True, include_data_volumes=False)
    assert execution.resources is None
    execution.prepare.assert_awaited_once()
    pool.restart_persistent_vm.assert_awaited_once_with(execution)


@pytest.mark.asyncio
async def test_reinstall_non_persistent_stops_forgets_and_erases():
    execution = _make_execution(persistent=False)
    execution.erase_volumes = MagicMock()
    pool = _make_pool({VM_ID: execution})
    supervisor = InProcessSupervisor(pool)

    await supervisor.reinstall_vm(VM_ID)

    pool.forget_vm.assert_called_once_with(VM_ID)
    execution.erase_volumes.assert_called_once_with(include_rootfs=True, include_data_volumes=True)
```

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/test_supervisor_inprocess_lifecycle.py`
Expected: FAIL

- [ ] **Step 3: Move `_restart_persistent_vm` to the pool**

In `pool.py`, add (body from `operator.py:192-233`, `self` for `pool`; keep the docstring incl. the duplicate-execution race note; `get_port_mappings` already imported; import `setup_nftables_for_vm` at module level — it is already imported there):

```python
    async def restart_persistent_vm(self, execution: VmExecution) -> None:
        """Re-register a stopped persistent VM and restart it via systemd.

        Re-registers the execution in the pool immediately (before any async
        work) so the periodic allocation loop cannot create a duplicate
        execution with a new vm_id.
        """
        execution.times.stopping_at = None
        execution.times.stopped_at = None
        execution.stop_event = asyncio.Event()
        self.executions[execution.vm_hash] = execution
        self._schedule_forget_on_stop(execution)

        if self.network and execution.vm:
            if not self.network.interface_exists(execution.vm.vm_id):
                await self.network.create_tap(execution.vm.vm_id, execution.vm.tap_interface)
            else:
                # Interface exists but nftables rules may have been flushed —
                # always re-apply them.
                setup_nftables_for_vm(execution.vm.vm_id, interface=execution.vm.tap_interface)
        self.systemd_manager.restart(execution.controller_service)
        # Reload port mappings from DB — stop() clears them in memory
        # but the DB retains them for persistent VMs.
        execution.mapped_ports = await get_port_mappings(execution.vm_hash)
        if execution.mapped_ports:
            await execution.recreate_port_redirect_rules()
        # Re-save so the record survives for registry rehydration.
        execution.record = None
        await execution.save()
```

Delete `_restart_persistent_vm` from `operator.py`; the two remaining callers (`operate_reinstall:769` until Task 7, `_do_restore:1380`) call `await pool.restart_persistent_vm(execution)`.

- [ ] **Step 4: ABC + in-process `reinstall_vm`**

`abc.py`:

```python
    @abstractmethod
    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo: ...
```

`inprocess.py` (replace the old naive body; `import asyncio` at top):

```python
    async def reinstall_vm(self, vm_id: VmId, wipe_volumes: bool = True) -> VmInfo:
        with translating_errors():
            execution = self._require(vm_id)
            await self.pool.stop_vm(vm_id)
            if execution.persistent:
                # Keep the execution registered so the allocation loop cannot
                # create a duplicate while we re-prepare (mirrors the old
                # operate_reinstall persistent branch).
                execution.stop_event = asyncio.Event()
                self.pool.executions[execution.vm_hash] = execution
                execution.erase_volumes(include_rootfs=True, include_data_volumes=wipe_volumes)
                execution.resources = None
                await execution.prepare()
                await self.pool.restart_persistent_vm(execution)
            else:
                if execution.vm_hash in self.pool.executions:
                    self.pool.forget_vm(execution.vm_hash)
                execution.erase_volumes(include_rootfs=True, include_data_volumes=wipe_volumes)
                # The agent re-creates non-persistent VMs through the create
                # path (it owns the message); we return the stopped state.
            return _to_vm_info(execution, _is_running(execution, self.pool))
```

- [ ] **Step 5: Run tests**

```bash
just test tests/supervisor/test_supervisor_inprocess_lifecycle.py tests/supervisor/test_supervisor_conformance_inprocess.py tests/supervisor/views/test_operator.py
```
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add -A src/ tests/
git commit -m "feat(supervisor): reinstall_vm performs erase/prepare/restart in-process; restart helper moves to the pool"
```

---

## Task 4: Journald-backed `get_logs` / `stream_logs` in-process

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py:108-114` (`_log_source`), `:239-268`
- Test: `tests/supervisor/test_supervisor_inprocess_logs.py`

- [ ] **Step 1: Write the failing tests**

```python
def _entries(vm_hash: str):
    base = datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc)
    return [
        {"SYSLOG_IDENTIFIER": f"vm-{vm_hash}-stdout", "MESSAGE": "boot ok", "__REALTIME_TIMESTAMP": base},
        {"SYSLOG_IDENTIFIER": f"vm-{vm_hash}-stderr", "MESSAGE": b"warn\xc3\xa9", "__REALTIME_TIMESTAMP": base},
    ]


@pytest.mark.asyncio
async def test_get_logs_returns_journald_history(monkeypatch):
    pool = _make_pool({})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    chunks = await supervisor.get_logs(VM_ID)

    assert [c.line for c in chunks] == ["boot ok", "warné"]
    assert [c.source for c in chunks] == [LogSource.STDOUT, LogSource.STDERR]
    assert chunks[0].timestamp_ns == int(datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc).timestamp() * 1_000_000_000)


@pytest.mark.asyncio
async def test_get_logs_max_lines_from_tail(monkeypatch):
    pool = _make_pool({})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    chunks = await supervisor.get_logs(VM_ID, max_lines=1, from_tail=True)

    assert [c.line for c in chunks] == ["warné"]


@pytest.mark.asyncio
async def test_stream_logs_with_history_then_live(monkeypatch):
    execution = _make_execution(persistent=True)   # with a fake vm exposing get_log_queue/unregister_queue
    queue = asyncio.Queue()
    queue.put_nowait(("stdout", "live line"))
    execution.vm.get_log_queue = MagicMock(return_value=queue)
    pool = _make_pool({VM_ID: execution})
    supervisor = InProcessSupervisor(pool)
    monkeypatch.setattr(
        "aleph.vm.supervisor.inprocess.get_past_vm_logs",
        lambda out, err: iter(_entries(str(VM_ID))),
    )

    received = []
    async for chunk in supervisor.stream_logs(VM_ID, include_history=True):
        received.append(chunk.line)
        if len(received) == 3:
            break

    assert received == ["boot ok", "warné", "live line"]
```

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/test_supervisor_inprocess_logs.py`
Expected: FAIL (old impl drains the live queue / no journald)

- [ ] **Step 3: Implement**

In `inprocess.py` — imports: `from aleph.vm.utils.logs import get_past_vm_logs`. Replace `_log_source` stderr mapping and the two log methods:

```python
def _log_source(log_type: str) -> LogSource:
    if log_type == "stdout":
        return LogSource.STDOUT
    if log_type == "stderr":
        return LogSource.STDERR
    return LogSource.SERIAL


def _history_chunks(vm_id: VmId) -> list[LogChunk]:
    """Journald history for a VM, mapped to LogChunks.

    Blocking sd-journal read; same behavior as the old views (the agent
    endpoints already read journald inline on the event loop).
    """
    stdout_id = f"vm-{vm_id}-stdout"
    stderr_id = f"vm-{vm_id}-stderr"
    chunks: list[LogChunk] = []
    for entry in get_past_vm_logs(stdout_id, stderr_id):
        source = LogSource.STDOUT if entry["SYSLOG_IDENTIFIER"] == stdout_id else LogSource.STDERR
        message = entry["MESSAGE"]
        if isinstance(message, bytes):
            message = message.decode("utf-8", errors="replace")
        timestamp_ns = int(entry["__REALTIME_TIMESTAMP"].timestamp() * 1_000_000_000)
        chunks.append(LogChunk(timestamp_ns=timestamp_ns, line=message, source=source))
    return chunks
```

```python
    # Logs
    async def get_logs(self, vm_id: VmId, max_lines: int = 0, from_tail: bool = False) -> list[LogChunk]:
        """Journald history for the VM (works for stopped VMs too)."""
        with translating_errors():
            chunks = _history_chunks(vm_id)
            if max_lines:
                chunks = chunks[-max_lines:] if from_tail else chunks[:max_lines]
            return chunks

    async def stream_logs(self, vm_id: VmId, include_history: bool = False) -> AsyncIterator[LogChunk]:
        if include_history:
            for chunk in _history_chunks(vm_id):
                yield chunk
        execution = self.pool.executions.get(vm_id)
        if not execution or not execution.vm:
            return
        queue = execution.vm.get_log_queue()
        try:
            while True:
                log_type, message = await queue.get()
                yield LogChunk(timestamp_ns=0, line=message, source=_log_source(log_type))
                queue.task_done()
        finally:
            execution.vm.unregister_queue(queue)
```

Note: `stream_logs` no longer raises `VmNotFoundError` for unknown VMs — history for stopped VMs is a valid request; it just ends after history. Update any existing test asserting the old behavior.

- [ ] **Step 4: Run tests**

```bash
just test tests/supervisor/test_supervisor_inprocess_logs.py tests/supervisor/test_supervisor_conformance_inprocess.py
```
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A src/ tests/
git commit -m "feat(supervisor): serve journald log history through get_logs/stream_logs in-process"
```

---

## Task 5: Registry — `persistent` flag, `items()`, DB persistence, startup rehydration

**Files:**
- Modify: `src/aleph/vm/orchestrator/vm_registry.py`
- Modify: `src/aleph/vm/orchestrator/run.py:186,207,216` (persistent flag + `save()`)
- Modify: `src/aleph/vm/orchestrator/supervisor.py` (startup hook)
- Test: `tests/supervisor/test_agent_vm_registry.py`, `tests/supervisor/test_supervisor_run_routing.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/supervisor/test_agent_vm_registry.py`:

```python
def test_record_carries_persistent_flag():
    registry = AgentVmRegistry()
    record = registry.record(_HASH, message=MagicMock(), original=MagicMock(), persistent=True)
    assert record.persistent is True
    assert registry.record(_HASH, message=MagicMock(), original=MagicMock()).persistent is False


def test_items_iterates_records():
    registry = AgentVmRegistry()
    record = registry.record(_HASH, message=MagicMock(), original=MagicMock())
    assert list(registry.items()) == [(_HASH, record)]


@pytest.mark.asyncio
async def test_rehydrate_registry_from_db(monkeypatch):
    db_record = SimpleNamespace(
        vm_hash=str(_HASH),
        message='{"address": "0xabc"}',   # parsing is mocked below; content shape is irrelevant
        original_message='{"address": "0xabc"}',
        persistent=True,
    )
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(return_value=[db_record]),
    )
    parsed = MagicMock()
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_message_executable_content",
        MagicMock(return_value=parsed),
    )
    registry = AgentVmRegistry()

    count = await rehydrate_registry(registry)

    assert count == 1
    record = registry.get(_HASH)
    assert record.message is parsed and record.persistent is True


@pytest.mark.asyncio
async def test_rehydrate_skips_messageless_and_duplicate_records(monkeypatch):
    newest = SimpleNamespace(vm_hash=str(_HASH), message='{"k": 1}', original_message=None, persistent=True)
    older = SimpleNamespace(vm_hash=str(_HASH), message='{"k": 2}', original_message=None, persistent=False)
    no_message = SimpleNamespace(vm_hash="ee" * 32, message=None, original_message=None, persistent=True)
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(return_value=[newest, older, no_message]),  # newest-first, as get_execution_records orders
    )
    parsed_newest, parsed_older = MagicMock(), MagicMock()
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_message_executable_content",
        MagicMock(side_effect=[parsed_newest, parsed_older]),
    )
    registry = AgentVmRegistry()

    count = await rehydrate_registry(registry)

    assert count == 1
    assert registry.get(_HASH).message is parsed_newest
    assert ItemHash("ee" * 32) not in registry
```

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/test_agent_vm_registry.py`
Expected: FAIL

- [ ] **Step 3: Implement registry changes**

`vm_registry.py`:

```python
import json
import logging

from aleph.vm.orchestrator.metrics import get_execution_records
from aleph.vm.utils import get_message_executable_content

logger = logging.getLogger(__name__)


@dataclass
class AgentVmRecord:
    """What the agent remembers about one VM: the (updated) message, the
    original message it was derived from, and whether the agent started it
    persistent. Used by agent-only consumers such as operator-API owner-auth,
    billing, and update-watching."""

    message: ExecutableContent
    original: ExecutableContent
    persistent: bool = False


class AgentVmRegistry:
    ...
    def record(
        self,
        vm_hash: ItemHash,
        *,
        message: ExecutableContent,
        original: ExecutableContent,
        persistent: bool = False,
    ) -> AgentVmRecord:
        record = AgentVmRecord(message=message, original=original, persistent=persistent)
        self._records[vm_hash] = record
        return record

    def items(self):
        return self._records.items()


async def rehydrate_registry(registry: AgentVmRegistry) -> int:
    """Refill the registry from the agent DB after a restart.

    ExecutionRecords are the agent's own persisted knowledge (newest first);
    the supervisor's config-reattach is independent (design doc §5).
    """
    count = 0
    for db_record in await get_execution_records():
        if not db_record.message:
            continue
        vm_hash = ItemHash(db_record.vm_hash)
        if vm_hash in registry:
            continue  # newest-first ordering: keep the latest record
        try:
            message = get_message_executable_content(json.loads(db_record.message))
            original = (
                get_message_executable_content(json.loads(db_record.original_message))
                if db_record.original_message
                else message
            )
        except Exception:
            logger.warning("Skipping unparseable execution record for %s", db_record.vm_hash, exc_info=True)
            continue
        registry.record(vm_hash, message=message, original=original, persistent=bool(db_record.persistent))
        count += 1
    return count
```

- [ ] **Step 4: Thread `persistent` + add the missing `save()` in `run.py`**

In `create_vm_execution`: both `registry.record(...)` calls gain `persistent=persistent` — **note** the spec branch is always persistent instances, so pass `persistent=True` there explicitly (the legacy branch passes the function arg). Inside the TEMPORARY block, after `execution.spec = MessageSpec(...)`:

```python
        execution = pool.executions[vm_hash]
        execution.spec = MessageSpec(message=content, original=original_message.content)
        # The spec create path skipped save() (no MessageSpec at start time).
        # Persist the record now: registry rehydration and past-logs owner
        # auth read the message back from the agent DB.
        await execution.save()
        return execution
```

- [ ] **Step 5: Startup hook**

`orchestrator/supervisor.py`, next to `_run_migration_reaper`:

```python
async def _rehydrate_vm_registry(app: web.Application):
    """on_startup hook: refill the agent's message registry from its DB."""
    count = await rehydrate_registry(app["vm_registry"])
    logger.info("Rehydrated %d VM record(s) into the agent registry", count)
```

Register in `run()` right after `app.on_startup.append(_run_migration_reaper)`:

```python
    app.on_startup.append(_rehydrate_vm_registry)
```

(The DB engine + alembic migrations run earlier in `cli.py`, before the web app starts.)

- [ ] **Step 6: Run tests**

```bash
just test tests/supervisor/test_agent_vm_registry.py tests/supervisor/test_supervisor_run_routing.py
```
Expected: PASS (update `test_supervisor_run_routing.py` assertions for the new `registry.record` kwargs and the extra `execution.save()` await — the fake execution in those tests needs `save = AsyncMock()`).

- [ ] **Step 7: Commit**

```bash
git add -A src/ tests/
git commit -m "feat(agent): persist and rehydrate the VM registry across agent restarts"
```

---

## Task 6: `operate_stop` + `operate_reboot` onto supervisor + registry auth

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/operator.py:571-622`
- Test: `tests/supervisor/views/test_operator.py`

- [ ] **Step 1: Add the shared registry-auth helper (failing tests first)**

New helper in `operator.py`:

```python
def get_agent_record_or_404(request: web.Request, vm_hash: ItemHash) -> AgentVmRecord:
    """Owner identity now comes from the agent registry, not the execution."""
    record = request.app["vm_registry"].get(vm_hash)
    if record is None:
        raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}")
    return record
```

Update existing tests `test_operator_stop`, `test_operator_stop_with_delegation_authorized` / `_unauthorized`, `test_reboot_ok`, `test_operator_reboot_with_delegation`: after `app = setup_webapp(pool=FakeVmPool())`, seed the registry and (where lifecycle calls are asserted) replace pool assertions with a fake supervisor:

```python
    app = setup_webapp(pool=fake_pool)
    app["vm_registry"].record(vm_hash, message=fake_message, original=fake_message, persistent=True)
    fake_supervisor = MagicMock(
        get_vm=AsyncMock(return_value=_info(VmStatus.RUNNING)),
        delete_vm=AsyncMock(),
        reboot_vm=AsyncMock(),
    )
    app["supervisor"] = fake_supervisor
    ...
    fake_supervisor.delete_vm.assert_awaited_once()      # stop
    fake_supervisor.reboot_vm.assert_awaited_once()      # reboot, persistent
```

Add new cases: stop of an already-stopped VM (get_vm returns STOPPED → "Already stopped"); reboot of a non-persistent record (delete_vm + `create_vm_execution_or_raise_http_error` mocked, both called); unknown vm_hash → 404.

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/views/test_operator.py`
Expected: FAIL

- [ ] **Step 3: Rewrite the endpoints**

```python
@cors_allow_all
@require_jwk_authentication
async def operate_stop(request: web.Request, authenticated_sender: str) -> web.Response:
    """Stop the virtual machine, smoothly if possible."""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None

        if info.status in (VmStatus.RUNNING, VmStatus.BOOTING):
            logger.info(f"Stopping {vm_hash}")
            await supervisor.delete_vm(vm_id)
            return web.Response(status=200, body=f"Stopped VM with ref {vm_hash}")
        return web.Response(status=200, body="Already stopped, nothing to do")


@cors_allow_all
@require_jwk_authentication
async def operate_reboot(request: web.Request, authenticated_sender: str) -> web.Response:
    """Reboots the virtual machine, smoothly if possible."""
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None

        if info.status in (VmStatus.RUNNING, VmStatus.BOOTING):
            logger.info(f"Rebooting {vm_hash}")
            if record.persistent:
                await supervisor.reboot_vm(vm_id)
            else:
                await supervisor.delete_vm(vm_id)
                await create_vm_execution_or_raise_http_error(
                    vm_hash=vm_hash,
                    pool=request.app["vm_pool"],
                    supervisor=supervisor,
                    registry=request.app["vm_registry"],
                )
            return web.Response(status=200, body=f"Rebooted VM with ref {vm_hash}")
        return web.Response(status=200, body=f"Starting VM (was not running) with ref {vm_hash}")
```

Imports in `operator.py`: `from aleph.vm.supervisor.abc import Supervisor`, `from aleph.vm.supervisor.errors import VmNotFoundError`, `from aleph.vm.supervisor.types import VmId, VmStatus`, `from aleph.vm.orchestrator.vm_registry import AgentVmRecord`.

- [ ] **Step 4: Run tests**

Run: `just test tests/supervisor/views/test_operator.py`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add -A src/ tests/
git commit -m "feat(agent): operate_stop/operate_reboot drive the Supervisor; owner-auth reads the registry"
```

---

## Task 7: `operate_erase` + `operate_reinstall` onto supervisor

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/operator.py:699-786`
- Test: `tests/supervisor/views/test_operator.py`

- [ ] **Step 1: Update/extend tests (failing first)**

`test_operator_erase_with_delegation`, `test_operator_reinstall`, `test_operator_reinstall_unauthorized`: seed registry, fake supervisor with `delete_vm` / `reinstall_vm` AsyncMocks; assert `delete_vm.assert_awaited_once_with(vm_id, wipe=True)` for erase, `reinstall_vm.assert_awaited_once_with(vm_id, wipe_volumes=True)` for reinstall (and `wipe_volumes=False` when `?erase_volumes=false`); erase forgets the registry record; non-persistent reinstall also calls the (mocked) create.

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/views/test_operator.py`
Expected: FAIL

- [ ] **Step 3: Rewrite the endpoints**

```python
@cors_allow_all
@require_jwk_authentication
async def operate_erase(request: web.Request, authenticated_sender: str) -> web.Response:
    """Delete all data stored by a virtual machine.
    Stop the virtual machine first if needed.
    """
    vm_hash = get_itemhash_or_400(request.match_info)
    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Erasing {vm_hash}")
        supervisor: Supervisor = request.app["supervisor"]
        try:
            await supervisor.delete_vm(VmId(str(vm_hash)), wipe=True)
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        request.app["vm_registry"].forget(vm_hash)
        return web.Response(status=200, body=f"Erased VM with ref {vm_hash}")


@cors_allow_all
@require_jwk_authentication
async def operate_reinstall(request: web.Request, authenticated_sender: str) -> web.Response:
    """Reinstall a virtual machine to its initial state. (docstring unchanged)"""
    vm_hash = get_itemhash_or_400(request.match_info)
    rootfs_only = request.query.get("erase_volumes", "true") == "false"

    with set_vm_for_logging(vm_hash=vm_hash):
        record = get_agent_record_or_404(request, vm_hash)
        if not await is_sender_authorized(authenticated_sender, record.message):
            return web.Response(status=403, body="Unauthorized sender")

        logger.info(f"Reinstalling (reset to initial state) {vm_hash}")
        supervisor: Supervisor = request.app["supervisor"]
        try:
            await supervisor.reinstall_vm(VmId(str(vm_hash)), wipe_volumes=not rootfs_only)
        except VmNotFoundError:
            raise web.HTTPNotFound(body=f"No virtual machine with ref {vm_hash}") from None
        if not record.persistent:
            await create_vm_execution_or_raise_http_error(
                vm_hash=vm_hash,
                pool=request.app["vm_pool"],
                supervisor=supervisor,
                registry=request.app["vm_registry"],
            )
        return web.Response(status=200, body=f"Reinstalled VM with ref {vm_hash}")
```

- [ ] **Step 4: Run tests + commit**

```bash
just test tests/supervisor/views/test_operator.py tests/supervisor/test_supervisor_inprocess_lifecycle.py
git add -A src/ tests/
git commit -m "feat(agent): operate_erase/operate_reinstall drive the Supervisor wipe/reinstall ops"
```

---

## Task 8: Logs endpoints onto supervisor

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/operator.py:326-455` (`stream_logs`, `operate_logs_json`)
- Test: `tests/supervisor/views/test_operator.py` (`test_websocket_logs_*`, `test_get_past_logs`)

- [ ] **Step 1: Update/extend tests (failing first)**

Message-source for auth: registry first, DB-record fallback (unchanged contract for past executions). Log payloads now come from a fake supervisor:

```python
    fake_supervisor = MagicMock(
        get_vm=AsyncMock(return_value=_info(VmStatus.RUNNING)),
        get_logs=AsyncMock(return_value=[LogChunk(timestamp_ns=0, line="hello", source=LogSource.STDOUT)]),
        stream_logs=_fake_stream([LogChunk(timestamp_ns=0, line="live", source=LogSource.STDOUT)]),
    )
```

where `_fake_stream(chunks)` is a function returning an async generator. Keep a test for the stopped-VM path: `get_vm` raises `VmNotFoundError` → ws receives past logs (via `get_logs`) then `"VM is not running, past logs sent"`.

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/views/test_operator.py -k "logs"`
Expected: FAIL

- [ ] **Step 3: Rewrite**

`operate_logs_json` — replace the pool/execution read with registry+DB fallback for the auth message, and the journald loop with `supervisor.get_logs`:

```python
        registry = request.app["vm_registry"]
        record = registry.get(vm_hash)
        if record is not None:
            message = record.message
        else:
            db_record = await metrics.get_last_record_for_vm(vm_hash=vm_hash)
            if not db_record:
                raise aiohttp.web_exceptions.HTTPNotFound(body="No execution found for this VM")
            message = get_message_executable_content(json.loads(db_record.message))
        if not await is_sender_authorized(authenticated_sender, message):
            return web.Response(status=403, body="Unauthorized sender")

        supervisor: Supervisor = request.app["supervisor"]
        chunks = await supervisor.get_logs(VmId(str(vm_hash)))

        response = web.StreamResponse()
        response.headers["Transfer-encoding"] = "chunked"
        response.headers["Content-Type"] = "application/json"
        await response.prepare(request)
        await response.write(b"[")
        first = True
        for chunk in chunks:
            if not first:
                await response.write(b",\n")
            first = False
            identifier = f"vm-{vm_hash}-{chunk.source.value}"
            msg = {
                "SYSLOG_IDENTIFIER": identifier,
                "MESSAGE": chunk.line,
                "file": chunk.source.value,
                "__REALTIME_TIMESTAMP": datetime.fromtimestamp(chunk.timestamp_ns / 1e9, tz=timezone.utc),
            }
            await response.write(dumps_for_json(msg).encode())
        await response.write(b"]")
        await response.write_eof()
        return response
```

`stream_logs` (ws) — same auth swap; then:

```python
        supervisor: Supervisor = request.app["supervisor"]
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            info = None

        if info and info.status is VmStatus.RUNNING:
            try:
                async for chunk in supervisor.stream_logs(vm_id):
                    await ws.send_json({"type": chunk.source.value, "message": chunk.line})
            finally:
                await ws.close()
                logger.info(f"connection {ws} closed")
        elif info and info.status is VmStatus.BOOTING:
            await ws.send_json({"type": "system", "message": "VM is starting, try again shortly"})
            await ws.close()
        else:
            for chunk in await supervisor.get_logs(vm_id):
                await ws.send_json({"type": chunk.source.value, "message": chunk.line})
            await ws.send_json({"type": "system", "message": "VM is not running, past logs sent"})
            await ws.close()
            logger.info(f"connection {ws} closed (past logs for stopped VM)")
```

The auth-message lookup in `stream_logs` keeps its DB fallback exactly as `operate_logs_json` (it already had one).

- [ ] **Step 4: Run tests + commit**

```bash
just test tests/supervisor/views/test_operator.py
git add -A src/ tests/
git commit -m "feat(agent): logs endpoints stream through the Supervisor; auth via registry with DB fallback"
```

---

## Task 9: Port-forward reconciliation + hypervisor-owned DB reapply

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (new `reconcile_port_forwards`)
- Modify: `src/aleph/vm/orchestrator/views/__init__.py:1030-1046` (`operate_update`), `:711-723` (`recreate_network` step 5)
- Modify: `src/aleph/vm/orchestrator/tasks.py:187-212` (`_handle_port_forwarding_aggregate`) + thread `supervisor`/`registry` from `start_watch_for_messages_task`
- Modify: `src/aleph/vm/models.py:155-187` (shed DB-half), `src/aleph/vm/pool.py:380-381` + `create_vm_from_spec` (explicit preload)
- Test: `tests/supervisor/test_supervisor_run_helpers.py`, `tests/supervisor/test_port_mappings.py`

- [ ] **Step 1: Write the failing tests**

`test_supervisor_run_helpers.py`:

```python
@pytest.mark.asyncio
async def test_reconcile_adds_missing_and_removes_extra(monkeypatch):
    desired = [
        PortForwardSpec(vm_id=VM_ID, host_port=HostPort(0), vm_port=GuestPort(22), protocol=Protocol.TCP),
        PortForwardSpec(vm_id=VM_ID, host_port=HostPort(0), vm_port=GuestPort(8080), protocol=Protocol.TCP),
    ]
    monkeypatch.setattr(run_module, "resolve_port_forwards", AsyncMock(return_value=desired))
    current = [
        PortForwardInfo(vm_id=VM_ID, host_port=HostPort(24022), vm_port=GuestPort(22), protocol=Protocol.TCP),
        PortForwardInfo(vm_id=VM_ID, host_port=HostPort(24099), vm_port=GuestPort(9999), protocol=Protocol.UDP),
    ]
    supervisor = SimpleNamespace(
        list_port_forwards=AsyncMock(return_value=current),
        add_port_forward=AsyncMock(),
        remove_port_forward=AsyncMock(),
    )

    await run_module.reconcile_port_forwards(supervisor, VM_ID, MagicMock())

    supervisor.remove_port_forward.assert_awaited_once_with(VM_ID, HostPort(24099), Protocol.UDP)
    added = [c.args[0] for c in supervisor.add_port_forward.await_args_list]
    assert [(int(s.vm_port), s.protocol) for s in added] == [(8080, Protocol.TCP)]
```

`test_port_mappings.py` (or the spec-pool test file): `create_vm_from_spec` preloads mapped ports — monkeypatch `aleph.vm.pool.get_port_mappings` to return `{22: {"host": 24022, "tcp": True, "udp": False}}`, fake execution records it and `recreate_port_redirect_rules` is awaited. And `fetch_port_redirect_config_and_setup` no longer reads the DB: monkeypatch `aleph.vm.models.get_port_mappings` to an AsyncMock and assert it is **not** awaited.

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/test_supervisor_run_helpers.py tests/supervisor/test_port_mappings.py`
Expected: FAIL

- [ ] **Step 3: Agent helper in `run.py`**

```python
async def reconcile_port_forwards(supervisor: Supervisor, vm_id: VmId, content) -> None:
    """Drive the hypervisor's forwards to match the aggregate settings.

    Agent policy half of the old fetch_port_redirect_config_and_setup: compute
    the desired set, diff against what the hypervisor reports, and issue
    add/remove calls. The hypervisor owns application and persistence.
    """
    desired = {(int(spec.vm_port), spec.protocol): spec for spec in await resolve_port_forwards(vm_id, content)}
    current = {(int(info.vm_port), info.protocol): info for info in await supervisor.list_port_forwards(vm_id)}
    for key, info in current.items():
        if key not in desired:
            await supervisor.remove_port_forward(vm_id, info.host_port, info.protocol)
    for key, spec in desired.items():
        if key not in current:
            await supervisor.add_port_forward(spec)
```

- [ ] **Step 4: Shed the DB-half of `fetch_port_redirect_config_and_setup`**

In `models.py`, delete lines 159–165 (the `if not self.mapped_ports: ... recreate_port_redirect_rules()` block) and the now-unused `get_port_mappings` import. Docstring note: "Persisted-mapping reload is the creator's job (pool.create_a_vm / create_vm_from_spec / restart_persistent_vm)."

In `pool.create_a_vm` (line 380), preload before the fetch:

```python
                if execution.is_instance:
                    # Reuse persisted host ports across restarts (hypervisor-owned).
                    execution.mapped_ports = await get_port_mappings(vm_hash)
                    if execution.mapped_ports:
                        await execution.recreate_port_redirect_rules()
                    await execution.fetch_port_redirect_config_and_setup()
```

In `pool.create_vm_from_spec`, after `await execution.start(write_config=False)`:

```python
                # Reuse persisted host ports across restarts. The agent then
                # reconciles the aggregate settings through add_port_forward,
                # which merges with these preloaded mappings.
                execution.mapped_ports = await get_port_mappings(vm_hash)
                if execution.mapped_ports:
                    await execution.recreate_port_redirect_rules()
```

In `views/__init__.py` `recreate_network` step 5, replace lines 717–719:

```python
                    # All rules were flushed: reapply from the persisted
                    # mappings, then re-sync message-driven VMs against the
                    # aggregate. Spec-built (reattached) executions have no
                    # message; their persisted mappings are authoritative.
                    execution.mapped_ports = await get_port_mappings(str(vm_info["vm_hash"]))
                    if execution.mapped_ports:
                        await execution.recreate_port_redirect_rules()
                    if isinstance(execution.spec, MessageSpec):
                        await execution.fetch_port_redirect_config_and_setup()
```

(imports: `get_port_mappings` from `aleph.vm.orchestrator.metrics`, `MessageSpec` from `aleph.vm.models`).

- [ ] **Step 5: Migrate `operate_update` and the aggregate handler**

`views/__init__.py`:

```python
async def operate_update(request: web.Request) -> web.Response:
    """Notify that the instance configuration has changed (port-forwarding)."""
    vm_hash = get_itemhash_or_400(request.match_info)
    registry = request.app["vm_registry"]
    record = registry.get(vm_hash)
    if record is None:
        raise HTTPNotFound(reason="VM not found")

    supervisor = request.app["supervisor"]
    vm_id = VmId(str(vm_hash))
    try:
        info = await supervisor.get_vm(vm_id)
    except VmNotFoundError:
        raise HTTPNotFound(reason="VM not found") from None
    if info.status is not VmStatus.RUNNING:
        # Configuration will be fetched when the VM starts; not an error.
        return web.json_response({"status": "ok", "msg": "VM not starting yet"}, dumps=dumps_for_json, status=200)

    await reconcile_port_forwards(supervisor, vm_id, record.message)
    await request.app["vm_pool"].update_domain_mapping()
    return web.json_response({}, dumps=dumps_for_json, status=200)
```

`tasks.py` — `watch_for_messages` and `start_watch_for_messages_task` thread `supervisor` and `registry` (both available on `app`); handler:

```python
async def _handle_port_forwarding_aggregate(message: AggregateMessage, supervisor, registry):
    """Reconcile port forwards for VMs affected by a port-forwarding aggregate change."""
    address = message.content.address
    affected = [
        (vm_hash, record)
        for vm_hash, record in registry.items()
        if isinstance(record.message, InstanceContent) and record.message.address == address
    ]
    if not affected:
        return
    logger.info("Port-forwarding aggregate for %s, updating %d VM(s)", address, len(affected))
    for vm_hash, record in affected:
        vm_id = VmId(str(vm_hash))
        try:
            info = await supervisor.get_vm(vm_id)
        except VmNotFoundError:
            continue
        if info.status is not VmStatus.RUNNING:
            continue
        try:
            await reconcile_port_forwards(supervisor, vm_id, record.message)
        except Exception:
            logger.exception("Failed to update port redirects for %s", vm_hash)
```

(`_handle_domains_aggregate` keeps the pool — domain mapping is out of scope.)

- [ ] **Step 6: Run tests + commit**

```bash
just test tests/supervisor/test_supervisor_run_helpers.py tests/supervisor/test_port_mappings.py tests/supervisor/test_supervisor_spec_pool_create.py tests/supervisor/views/
git add -A src/ tests/
git commit -m "feat(agent): aggregate-driven port forwards reconcile through the Supervisor; DB reapply is hypervisor-owned"
```

---

## Task 10: Deallocation paths onto `delete_vm`

**Files:**
- Modify: `src/aleph/vm/orchestrator/tasks.py:290-437` (`check_payment` + `monitor_payments`)
- Modify: `src/aleph/vm/orchestrator/views/__init__.py:525-543` (`update_allocations` stop loop)
- Test: `tests/supervisor/test_checkpayment.py`, `tests/supervisor/test_views.py`

- [ ] **Step 1: Update tests (failing first)**

`test_checkpayment.py`: `check_payment` gains `supervisor` and `registry` params; the terminal-status dealloc asserts `supervisor.delete_vm` awaited + `delete_port_mappings` awaited + `registry.forget` called; the insufficient-balance/stream/credit stops assert `supervisor.delete_vm` awaited (instead of `pool.stop_vm`).

`test_views.py` (allocation tests): seed `app["supervisor"]` with a fake; the stop loop asserts `delete_vm` + `registry.forget`.

- [ ] **Step 2: Run to verify failure**

Run: `just test tests/supervisor/test_checkpayment.py`
Expected: FAIL

- [ ] **Step 3: Implement**

`monitor_payments(app)` passes `app["supervisor"]`, `app["vm_registry"]` into `check_payment(pool, supervisor, registry)`. In `check_payment`:

- Terminal-status branch (lines 329–331):

```python
            del _terminal_strike_count[key]
            await supervisor.delete_vm(VmId(str(vm_hash)))
            # Residual direct DB call: mapping persistence moves fully
            # hypervisor-side with the gRPC split (plan: Design deltas #3).
            await delete_port_mappings(vm_hash)
            registry.forget(vm_hash)
```

- The three insufficient-funds stops (lines 353, 377, 437): `await supervisor.delete_vm(VmId(str(last_execution.vm_hash)))` (today's `pool.stop_vm` is followed by the scheduled forget-on-stop anyway; `delete_vm` makes it explicit). No `registry.forget` — the VM may be re-paid and re-allocated.

`update_allocations` stop loop (lines 540–542):

```python
                await supervisor.delete_vm(VmId(str(execution.vm_hash)))
                await delete_port_mappings(execution.vm_hash)
                registry.forget(execution.vm_hash)
```

(decision filter on `pool.get_persistent_executions()` is an accepted residual read; design §9.)

- [ ] **Step 4: Run tests + commit**

```bash
just test tests/supervisor/test_checkpayment.py tests/supervisor/test_views.py
git add -A src/ tests/
git commit -m "feat(agent): deallocation paths stop VMs through the Supervisor"
```

---

## Task 11: Gates, full suite, push, PR

- [ ] **Step 1: Style + static gates**

```bash
uvx isort==5.13.2 --profile black src/ tests/ && uvx ruff@0.4.6 check src/ tests/
hatch run linting:typing 2>/dev/null || just mypy   # whichever gate the repo uses locally
```
mypy union-attr gate: `src/aleph/vm/` == 2, `src/aleph/vm/controllers/` == 0 (unchanged budget).

- [ ] **Step 2: Full test suite**

```bash
just test tests/
```
Expected: ~552+ passed, the 8 documented environment-only failures (root/network/qemu), no new failures.

- [ ] **Step 3: Push + open PR**

```bash
git push -u origin od/wire-supervisor-lifecycle
gh pr create --base od/wire-supervisor-abstraction \
  --title "Message-free supervisor (6/N): operator lifecycle through the Supervisor abstraction" \
  --body-file /tmp/pr2-body.md   # summary of Design deltas + task list; written at execution time
```
Base = `od/wire-supervisor-abstraction` while #962 is open; retarget to `dev` after #962 merges.

---

## Done criteria

- Every §5 call site (`operate_stop`, `operate_reboot`, `operate_erase`, `operate_reinstall`, logs endpoints, `operate_update`, aggregate handler, `check_payment` dealloc, `update_allocations` stop loop) reaches the hypervisor only via `Supervisor` methods keyed by `VmId`.
- Owner-auth in migrated endpoints reads `AgentVmRegistry` (DB fallback only in the logs endpoints, as today).
- Registry survives agent restart (rehydrated from `ExecutionRecord`s, incl. spec-created VMs via the new `save()`).
- Port-forward persistence/reapply is hypervisor-owned: spec-created persistent instances reuse host ports across restarts.
- Proto bindings regenerated and clean (`scripts/check_proto_clean.sh`).
- Residuals listed in "Design deltas #3" are the only remaining `pool`/`VmExecution` reaches in migrated code paths, each with a comment.
