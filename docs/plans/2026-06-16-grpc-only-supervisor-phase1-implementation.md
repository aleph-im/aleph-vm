# gRPC-only supervisor, Phase 1 implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Decouple the agent from the `VmPool`: every agent endpoint reaches VMs through the `Supervisor` interface only, never the raw pool. Production stays single-process in Phase 1 (embedded `LocalSupervisor`); Phase 2 adds the gRPC transport and two-service packaging.

**Architecture:** The pool-backed engine (`InProcessSupervisor`, renamed `LocalSupervisor`) implements the `Supervisor` ABC and does all VM work. The agent holds a `Supervisor` (embedded `LocalSupervisor` in dev/tests, `GrpcSupervisor` in prod) and calls only its methods. New capability methods are added to the ABC, implemented for real in `LocalSupervisor`, and stubbed `raise NotImplementedError("wired in Phase 2")` in `GrpcSupervisor` so both subclasses stay concrete. Proto / `grpc_server` / `grpc_client` wire semantics are NOT touched in Phase 1.

**Tech Stack:** Python, aiohttp, pytest (`just test <path>`), grpcio (Phase 2 only).

**Spec:** `docs/plans/2026-06-16-grpc-only-supervisor-design.md`

---

## Decisions (resolved 2026-06-16)

1. **Backup/restore:** enrich the engine, no feature drop. Move the full backup/restore behavior (upload-restore, `volume_ref`, `include_volumes`) into `LocalSupervisor`, growing the `BackupOps` ABC as needed; keep HTTP-only concerns (presigned URLs, multipart parsing, sidecar headers) in the agent.
2. **Migration:** use both layers. The P2P pull protocol stays the agent-side network transport (token-auth disk download between hosts); it drives the supervisor's directory-based `export_vm`/`import_vm` for the disk/VM work. `run_export` asks the supervisor for an export directory then serves it; `run_import` downloads peer disks into a staging dir then calls `supervisor.import_vm(vm_id, staging_dir)`. Add `release_migrated_vm` for cleanup.
3. **Confidential measurement:** preserve the response. Extend the `Measurement` type with the SEV info fields (`enabled, api_major, api_minor, build_id, policy, state, handle`) plus `launch_measure`, so the endpoint returns `{"sev_info": {...}, "launch_measure": ...}` unchanged. `sev_info` is required by the client to verify the launch measurement before injecting the secret. The proto carries these fields in Phase 2; until then `GrpcSupervisor.get_measurement` may return partial data (gRPC is not the prod path in Phase 1).

The original decision write-ups are kept below for context.

## Decisions detail (original write-ups)

These three capabilities involve user-facing contract changes.

1. **Backup/restore contract.** The HTTP endpoints (`operator.py`) implement a richer protocol than the engine's `BackupOps`: client-uploaded QCOW2 restore, `{"volume_ref": ...}` restore, `include_volumes`, presigned download URLs, `BackupState` background tracking, `X-Backup-Checksum`/`X-Source-Size`/`Content-Length` sidecar headers. The engine's methods are rootfs-only, restore-by-backup-id, raw chunk stream.
   - **Recommendation:** enrich the engine to own the VM/disk work (so no feature regresses), keep HTTP-only concerns (signed URLs, multipart parsing) in the agent. This needs the ABC to grow (e.g. an upload-restore method that accepts a staged image path). Confirm "no feature drop" is the goal, or approve dropping upload-restore/`include_volumes` for the narrow contract.

2. **Migration canonical path.** Two parallel systems exist: the live P2P pull protocol (`migration.py` + `migration/runner.py`: `ExportJob`/`ImportJob`, `run_export`/`run_import`, token-authenticated disk download between hosts) vs the engine's directory-based `export_vm`/`import_vm`. The testnet migration test exercises the P2P path.
   - **Recommendation:** treat the P2P pull protocol as canonical; thread the supervisor into the runner (gate via `get_vm`, add `release_migrated_vm` for cleanup, and a supervisor "create from staged disks" method for the import create step). Confirm.

3. **Confidential measurement response shape.** Legacy `get_measurement` returns `{"sev_info": <VmSevInfo>, "launch_measure": <str>}`. The ABC `Measurement` only carries `measurement_bytes` + `tee_backend`.
   - **Recommendation:** extend `Measurement` to carry the SEV info (and the proto in Phase 2) so the response is unchanged, OR confirm the client only needs the launch measure and accept the narrower shape.

## Defaults chosen (no decision needed, recorded for review)

- Over-capacity HTTP status stays **503** (consistent with current `notify_allocation` and `run.py`), not 507.
- **Disk admission is deferred** in the spec path: `DiskSpec` has no `size_mib` today, so `check_spec_admission` enforces memory/vCPU caps only, with a comment. Revisit when `DiskSpec` carries size.
- `inject_secret` returns `{"status": "ok"}` (the void ABC method cannot return the QMP `query-status`); flag if a client depends on the old body.
- New capability methods get a `NotImplementedError("wired in Phase 2")` stub on `GrpcSupervisor`.

---

## P1.1 Foundation: rename + explicit wiring (READY)

No behavior change. The rename must land first so every later task can reference `LocalSupervisor`.

### Task: Rename module inprocess.py to local.py and class InProcessSupervisor to LocalSupervisor

**Files:**
- Move: `src/aleph/vm/supervisor/inprocess.py` -> `src/aleph/vm/supervisor/local.py`
- Modify: `src/aleph/vm/supervisor/local.py` (module docstring; `class InProcessSupervisor(Supervisor)` -> `class LocalSupervisor(Supervisor)`)
- Test: `tests/supervisor/test_rename_smoke.py` (temporary)

- [ ] **Step 1: Write the failing smoke test**

```python
"""Smoke test: the renamed module and class exist (Phase 1 P1.1 rename)."""

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.local import LocalSupervisor


def test_local_supervisor_subclasses_supervisor():
    assert issubclass(LocalSupervisor, Supervisor)
```

- [ ] **Step 2: Run it, expect fail** — `just test tests/supervisor/test_rename_smoke.py`. Expected: `ModuleNotFoundError: No module named 'aleph.vm.supervisor.local'`.
- [ ] **Step 3: Implement** — `git mv src/aleph/vm/supervisor/inprocess.py src/aleph/vm/supervisor/local.py`; rename the class to `LocalSupervisor`; update the module docstring to describe the local pool-backed engine.
- [ ] **Step 4: Run it, expect pass** — `just test tests/supervisor/test_rename_smoke.py`. Expected: 1 passed.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "Rename InProcessSupervisor to LocalSupervisor (module local.py)"`

### Task: Update production references

**Files (verify exact lines with grep before editing):**
- Modify: `src/aleph/vm/orchestrator/supervisor.py` (import + embedded wiring branch)
- Modify: `src/aleph/vm/orchestrator/cli.py` (import + benchmark/test-instance constructions)
- Modify: `src/aleph/vm/supervisor/daemon.py` (import + the `InProcessSupervisor(pool)` the gRPC server wraps)
- Modify: `src/aleph/vm/supervisor/grpc_server.py` (docstring mention)

- [ ] **Step 1: Write the failing test** — add to `tests/supervisor/test_rename_smoke.py`:

```python
def test_no_inprocess_symbol_in_orchestrator_supervisor():
    import aleph.vm.orchestrator.supervisor as orch_sup

    assert not hasattr(orch_sup, "InProcessSupervisor")
    assert hasattr(orch_sup, "LocalSupervisor")
```

- [ ] **Step 2: Run it, expect fail** — `just test tests/supervisor/test_rename_smoke.py::test_no_inprocess_symbol_in_orchestrator_supervisor`. Expected: `ModuleNotFoundError: No module named 'aleph.vm.supervisor.inprocess'` at import.
- [ ] **Step 3: Implement** — replace `from aleph.vm.supervisor.inprocess import InProcessSupervisor` with `from aleph.vm.supervisor.local import LocalSupervisor` and every `InProcessSupervisor(...)` with `LocalSupervisor(...)` in the four files. Use `grep -rn "InProcessSupervisor\|supervisor.inprocess" src/` to find every site.
- [ ] **Step 4: Run it, expect pass** — `just test tests/supervisor/test_rename_smoke.py`.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "Update production references to LocalSupervisor"`

### Task: Update test imports and references

**Files:** every test under `tests/supervisor/` importing `aleph.vm.supervisor.inprocess` or naming `InProcessSupervisor` (find with grep; includes the conformance test class name, subclass bases in `test_supervisor_grpc.py`, and `_to_vm_info` import in `test_inprocess_vm_info.py`). Keep the `test_supervisor_inprocess_*.py` file names as-is.

- [ ] **Step 1: Write the failing test** — none; the existing supervisor suite is the failing test.
- [ ] **Step 2: Run it, expect fail** — `just test tests/supervisor`. Expected: collection errors `ModuleNotFoundError: No module named 'aleph.vm.supervisor.inprocess'`.
- [ ] **Step 3: Implement** — in every file the grep names, replace the import and every `InProcessSupervisor` identifier with `LocalSupervisor`; rename the conformance class `TestInProcessSupervisorConformance` -> `TestLocalSupervisorConformance`; update the `_to_vm_info` import path; rebind any local var named `inprocess`.
- [ ] **Step 4: Run it, expect pass** — `just test tests/supervisor`.
- [ ] **Step 5: Commit** — `git add tests/supervisor && git commit -m "Update supervisor tests to LocalSupervisor"`

### Task: Extract build_supervisor factory

**Files:**
- Modify: `src/aleph/vm/orchestrator/supervisor.py` (add `build_supervisor(settings, pool)` above `setup_webapp`; replace the inline selection)
- Test: `tests/supervisor/test_split_mode.py`

- [ ] **Step 1: Write the failing test**

```python
def test_build_supervisor_factory_selects_path(mocker):
    from aleph.vm.orchestrator.supervisor import build_supervisor

    mocker.patch.object(settings, "SUPERVISOR_GRPC_SOCKET", None)
    pool = SimpleNamespace(executions={})
    assert isinstance(build_supervisor(settings, pool), LocalSupervisor)

    mocker.patch.object(settings, "SUPERVISOR_GRPC_SOCKET", Path("/run/aleph/supervisor.sock"))
    grpc = build_supervisor(settings, pool=None)
    assert isinstance(grpc, GrpcSupervisor)
```

- [ ] **Step 2: Run it, expect fail** — `just test tests/supervisor/test_split_mode.py::test_build_supervisor_factory_selects_path`. Expected: `ImportError: cannot import name 'build_supervisor'`.
- [ ] **Step 3: Implement** — add the factory; it returns `GrpcSupervisor(settings.SUPERVISOR_GRPC_SOCKET)` when the socket is set (production path), else the embedded `LocalSupervisor(pool)` (dev/test). Document that the embedded path is dev/test only. Replace the `if/else` in `setup_webapp` with `app["supervisor"] = build_supervisor(settings, pool)`.
- [ ] **Step 4: Run it, expect pass** — `just test tests/supervisor/test_split_mode.py`.
- [ ] **Step 5: Commit** — `git add -A && git commit -m "Extract build_supervisor factory for explicit agent wiring"`

### Task: Remove the throwaway smoke test

- [ ] `git rm tests/supervisor/test_rename_smoke.py`; `just test tests/supervisor` (expect pass); commit `Remove throwaway rename smoke test`.

---

## P1.6a recreate_network (READY)

Move the firewall-recreation body from the endpoint into the engine; the endpoint becomes a thin delegate.

### Task: Add recreate_network to the Supervisor ABC, implement in LocalSupervisor, stub in GrpcSupervisor

**Files:**
- Modify: `src/aleph/vm/supervisor/abc.py` (new `NetworkOps(ABC)` with `async def recreate_network(self) -> dict`, mixed into `Supervisor`)
- Modify: `src/aleph/vm/supervisor/local.py` (implement; move the body from `views/__init__.py` recreate_network: build `running_vms` from `self.pool.executions`, `remove_all_aleph_chains()`, `initialize_nftables()`, `recreate_network_for_vms()`, the per-instance port-redirect reapply loop; return the summary dict; raise `InternalSupervisorError` on failure instead of building a `web.json_response`)
- Modify: `src/aleph/vm/supervisor/grpc_client.py` (`async def recreate_network(self) -> dict: raise NotImplementedError("wired in Phase 2")`)
- Test: `tests/supervisor/test_abc.py`, `tests/supervisor/test_local_recreate_network.py`, `tests/supervisor/test_grpc_client.py`

- [ ] **Step 1: failing test** — `test_recreate_network_is_abstract` asserts `"recreate_network" in Supervisor.__abstractmethods__` and is a coroutine; engine test builds `LocalSupervisor` with a fake pool holding one running instance execution, patches `remove_all_aleph_chains`/`initialize_nftables`/`recreate_network_for_vms`, and asserts the returned summary dict and that the network helpers got the execution's `vm_id`/`tap_interface`.
- [ ] **Step 2: run, expect fail** — `just test tests/supervisor/test_abc.py tests/supervisor/test_local_recreate_network.py` (AttributeError / missing abstractmethod).
- [ ] **Step 3: implement** — as above; imports in `local.py`: `from aleph.vm.network.firewall import initialize_nftables, recreate_network_for_vms, remove_all_aleph_chains`, plus `MessageSpec` and the port-mapping helper used by the original endpoint.
- [ ] **Step 4: run, expect pass** — same commands.
- [ ] **Step 5: commit** — `Add recreate_network to the Supervisor interface`.

### Task: Rewire the recreate_network endpoint

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (recreate_network endpoint: keep auth + `network_recreation_lock`; `result = await request.app["supervisor"].recreate_network()`; `return web.json_response(result, status=200 if result["success"] else 207)`; map `InternalSupervisorError` -> 500; drop `require_vm_pool` and the inline firewall logic. Keep the `require_vm_pool` import only if other endpoints still use it.)
- Test: `tests/supervisor/views/test_operator.py` (extend `_fake_supervisor` with `recreate_network`; assert delegation and no pool read)

- [ ] **Steps 1-5** as the standard TDD cycle: failing endpoint test asserting 200 + JSON equals the supervisor's dict and `recreate_network` awaited; implement; pass; commit `Route recreate_network endpoint through the supervisor`.

---

## P1.2 backup/restore (BLOCKED on Decision 1)

Drafted task set: rewire `operate_backup`, `operate_backup_status`, `operate_backup_download`, `operate_backup_delete`, `operate_restore` off `require_vm_pool`. The exact target depends on Decision 1 (enrich engine vs adopt narrow contract). If enriching: add upload-restore + metadata methods to `BackupOps`. End with a guard test that the five endpoints contain no `require_vm_pool`/`vm_pool`/`.executions`.

## P1.3 migration (BLOCKED on Decision 2)

Drafted task set: gate `migration_export` via `supervisor.get_vm`; thread the supervisor (not the pool) into `migration/runner.py` (`run_export`/`run_import`); add `MigrationOps.release_migrated_vm(vm_id)` (engine: `stop_vm` + `forget_vm`) for `migration_cleanup`; add a "create from staged disks" supervisor method for the import create step. Drop `require_vm_pool` from all three endpoints.

## P1.4 confidential (initialize + inject_secret READY; measurement BLOCKED on Decision 3)

Drafted task set: move `initialize_confidential`, `get_measurement`, `inject_secret` logic from the endpoints into `LocalSupervisor` (currently `raise NotImplementedSupervisorError`); rewire the three endpoints to delegate; drop `require_vm_pool`/`QemuVmClient` from the agent. `initialize_confidential` (write session/godh files + `systemd_manager.enable_and_start`) and `inject_secret` are ready; `get_measurement` is blocked on Decision 3 (response shape).

## P1.5 admission + GPU into create_vm (READY pending GPU-key check)

Drafted task set: add `check_spec_admission(spec)` and `reserve_spec_gpus(gpus)` to `VmPool`; make `create_vm_from_spec` call both atomically under `creation_lock`, raising the existing `InsufficientResourcesError`; remove the agent-side `pool.check_admission` in `notify_allocation`; add a `reserve_resources` Supervisor method (the `/control/reserve_resources` endpoint is LIVE and tested) and route `operate_reserve_resources` through it. Verify `build_create_vm_spec` resolves the requested GPU `device_id` to a `pci_host` so `reserve_spec_gpus` matching is sound (open item, resolve in implementation).

## P1.7 persistent programs + final pool removal (BLOCKED on P1.2-P1.6)

Drafted task set: let `build_program_create_vm_spec` emit persistent specs; let `_create_firecracker_from_spec` boot persistent programs under systemd; add `Supervisor.run_program_code(vm_id, scope, timeout)` (engine: `becomes_ready()` + `execution.run_code(scope)`); route persistent on-request and on-event programs through the supervisor; retire `_run_code_on_request_legacy`/`_run_code_on_event_legacy`. Then (Part B, after all capabilities land): drop the `pool` param from `run.py` entry points, delete `require_vm_pool`, stop setting `app["vm_pool"]` (move lifecycle-hook pool reads in `supervisor.py` to a private `app["_engine_pool"]`), point `resources.py` at `supervisor.get_host_info()`, and add a guard test that no agent view module references `require_vm_pool`/`app["vm_pool"]`/`.executions`. Note: the `operate_update` restart path (`pool.restart_persistent_vm`) is an unaccounted capability that needs a supervisor restart method before Part B.

## Open items to resolve during implementation

- GPU reservation key: message path uses `device_id`, spec path has `pci_host`. Confirm `build_create_vm_spec` resolution.
- `becomes_ready()` call convention in `run_program_code` (verify against the legacy callsite).
- `resources.py`: confirm `HostInfo` carries GPU inventory + available disk, or add fields.
- `_handle_domains_aggregate` `has_local_instance` check: move to a registry-only check to avoid a residual pool read.
- HAProxy startup seed (`pool.py` load-time force sync) needs an agent startup hook after P1.6b.
