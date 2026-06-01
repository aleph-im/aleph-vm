# Message-free supervisor: create_vm wiring + reboot-recovery — Design

Status: draft for review. Follow-up to Phase 0.C (`docs/plans/2026-05-29-phase-0c-create-vm-decouple-design.md`, PR #953), which built the message-free config build (`build_qemu_configuration`) and the agent translator (`build_create_vm_spec`) but explicitly deferred "wiring into `InProcessSupervisor.create_vm` + `pool.executions`". Reference architecture: `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md`.

## 1. Goal

Make the supervisor's **own machinery message-free**: a VM can be created, prepared, launched, and reattached after a reboot without the supervisor ever reading an Aleph message or downloading anything. Downloads and message translation stay entirely on the agent (orchestrator) side.

Two paths go message-free in this design:
1. **Creation** — `InProcessSupervisor.create_vm(spec)` builds a launchable VM from a `CreateVmSpec` (paths only) and registers it in `pool.executions`.
2. **Reboot-recovery** — the supervisor reattaches to surviving VM controllers from the on-disk controller configs + active systemd units, not from DB-stored messages.

## 2. Key findings (from exploration)

- **`pool.executions[hash]` must be a full `VmExecution`** (~32 consumers; no adapter). So the spec path produces a real `VmExecution`.
- **Restart never re-downloads and never needs a message.** QEMU processes survive a daemon restart under their own `aleph-vm-controller@<hash>.service` units. `pool.py:_restore_running_execution` only rebuilds in-memory state; `prepare()` → `download_all()` is a cache hit on files already on disk. Everything it reads from `self.message` (hypervisor, internet flag, vcpus/memory, gpus, `VmType`) is data the spec carries; the durable artifacts are the files on disk.
- **The on-disk controller config is already a complete, message-free description of a running VM.** `<EXECUTION_ROOT>/<hash>-controller.json` (`controllers/configuration.py:Configuration`) holds image path, sockets, vcpus, `mem_size_mb`, interface, host_volumes, gpus, vm_id, hypervisor, and has a loader `load_controller_configuration()`. The DB `ExecutionRecord.message` column is redundant for reattach — it exists only because `VmExecution` is currently written against `self.message`.
- **The resources object is just a path holder.** `AlephFirecrackerResources` (`controllers/firecracker/executable.py:94`) stores `rootfs_path`, `volumes`, `kernel_image_path`, `gpus`; `download_all()` populates them. The controller interface (`AlephQemuInstance`) reads those attributes, not the message.
- **`VmExecution` already abstracts message access behind properties**: `is_program`, `is_instance`, `is_confidential`, `hypervisor`, `is_stream`, `is_credit` (`models.py:330-367`). These are the seam to re-back with spec-derived data.

## 3. Scope

In scope (delivered as PRs 1-4 below, stacked, each deployable):
- `VmExecution` becomes constructible and operable from a `CreateVmSpec` with no message and no download.
- `InProcessSupervisor.create_vm(spec)` wires a spec-built `VmExecution` into the pool and launches its controller.
- The production creation path (`orchestrator/run.py`) routes through `build_create_vm_spec(message) → create_vm(spec)`, so the agent owns translation and the supervisor receives only a spec.
- Reboot-recovery (`pool.load_persisted_executions` / `_restore_running_execution` / `_restore_network`) reattaches from on-disk controller configs + systemd, message-free.

Out of scope (deliberately deferred):
- **Deleting the `message` field from `VmExecution`.** ~20 reads remain in the Aleph-facing operator API (`orchestrator/views/operator.py`: `is_sender_authorized(sender, execution.message)` owner auth + delegation, `rootfs.size_mib` upload limits) plus `tasks.py`, `run.py` headers. These are agent-side and security-sensitive and need an agent-owned owner/message store. That is a later phase (PR 5, see §8). After this design, `message` survives only as an **agent-owned attribute the supervisor's own logic never reads**.
- Firecracker creation, confidential (`QEMU_SEV`), GPU host-matching beyond passing assigned GPUs through the spec, and VM migration (`migration/runner.py`).
- gRPC transport (Phase 0.D).

## 4. PR 1 — `VmExecution` spec-constructible (message-free internals)

**Files:** `src/aleph/vm/models.py`; a new message-free resources holder (likely `src/aleph/vm/controllers/firecracker/executable.py` or a small new module); tests under `tests/supervisor/`.

- Add an alternate construction path: `VmExecution.from_spec(spec: CreateVmSpec, *, snapshot_manager, systemd_manager)` (or a `spec` kwarg on `__init__`). The execution stores `self.spec`. `message`/`original` remain optional for the agent-side consumers (transition).
- **Re-back the properties** so they work with or without a message: `is_program`/`is_instance` from `spec.backend`, `is_confidential` from `spec.backend == Backend.QEMU_SEV` (and/or `spec.tee`), `hypervisor` from `spec.backend`, `is_stream`/`is_credit` from spec-carried payment flags if present (else preserve message-backed behavior while a message exists). When both a spec and a message are present, the spec is authoritative for the supervisor's machinery.
- **`prepare()` builds a message-free resources holder from the spec** — set `rootfs_path`, `volumes`, `kernel_image_path`, `gpus` directly from `spec.disks`/`spec.kernel_path`/`spec.initrd_path`/`spec.gpus`. **No download.** Introduce a holder that exposes the attributes the controller reads, populated from a spec (a `from_spec` classmethod on the resources class, or a small dataclass with the same attribute surface).
- **`create()` reads spec-derived values**: synthesize `hardware_resources = MachineResources(vcpus=spec.vcpus, memory=spec.memory_mib)`, `enable_networking = spec.network.internet_access`, gpus from `spec.gpus`. For QEMU the launch config is produced by 0.C's `build_qemu_configuration(spec, vm_id, tap_interface)` rather than the message-coupled `configure()`.
- **`prepare_gpus()`** reads `spec.gpus` (already-assigned host GPUs) instead of `message.requirements.gpu`.
- `save()` no longer needs the message for the supervisor path (see §7 persistence).

This PR adds the spec path alongside the message path with **no behavior change** to existing message-driven creation, so it is independently deployable.

## 5. PR 2 — `InProcessSupervisor.create_vm(spec)`

**Files:** `src/aleph/vm/supervisor/inprocess.py`; tests.

Replace the `NotImplementedSupervisorError` stub with:
1. Assign a `vm_id` and create the tap interface (reuse `pool`/`network.prepare_tap` + `create_tap`), deriving `VmType` from `spec.backend` (not from a message).
2. `config = await build_qemu_configuration(spec, vm_id, tap_interface)` (0.C).
3. `save_controller_configuration(spec.vm_id, config)`.
4. Build a spec-based `VmExecution` (PR 1), `prepare()` (no download), `create(vm_id, tap_interface)`, start the controller via the systemd manager, set up nftables/NDP and any port forwards.
5. Register in `pool.executions[hash]`; persist via `save()` (§7).
All exceptions mapped through `translating_errors()` to `SupervisorError`.

## 6. PR 3 — route production creation through the spec

**Files:** `src/aleph/vm/orchestrator/run.py` (the `pool.create_a_vm(message, ...)` call site, run.py:63); tests.

`orchestrator/run.py` is agent territory. Convert it to: `spec = await build_create_vm_spec(message, gpus=<assigned>)` then `await supervisor.create_vm(spec)` (or `pool`-level equivalent during transition). The message stays on the agent side; the supervisor receives only the spec. `create_a_vm(message)` itself is retained for the not-yet-converted callers (migration) but is no longer on the production instance path.

## 7. PR 4 — reboot-recovery from on-disk configs (message-free)

**Files:** `src/aleph/vm/pool.py` (`load_persisted_executions`, `_restore_running_execution`, `_restore_network`); tests.

- Discover survivors by scanning `EXECUTION_ROOT` for `*-controller.json` and checking which `aleph-vm-controller@<hash>.service` units are active (the existing batch `get_services_active_states`), instead of enumerating DB records by stored message.
- Reattach by reconstructing a spec-equivalent from the on-disk `Configuration` (paths, vcpus, `mem_size_mb`, interface, gpus, vm_id) and building a spec-based `VmExecution` (PR 1). `_restore_network` derives `VmType` from the config/backend, not `VmType.from_message_content(execution.message)`.
- **Persistence becomes wipe-friendly.** Reboot no longer depends on the DB `message` column. Per the architecture, the authoritative "what should run" set comes from the agent/scheduler on reboot (VMs migrated or deleted during downtime simply aren't in the allocation, so they are not recreated and their orphan controllers/tap/nft are reaped by the existing `_cleanup_orphan_resources` / `_handle_dead_execution`). The supervisor persists only what it needs to reattach — which the on-disk config already provides — so old DB rows are irrelevant on upgrade; no DB migration of message data is required.
- **Controller-config wire format is preserved.** The memory field stays `mem_size_mb` (typed `MiB`, serialized as a bare int of MiB — see the amended #953), identical to the deployed format. Reattaching to a VM launched by an older binary reads the same JSON shape, so no tolerant loader and no config-format migration are needed. (Deliberate simplification: keeping MiB avoids introducing a cross-version config wrinkle mid-backport.)

### 7.1 The `executions` table is not essential to the supervisor

A review of every `executions`-table access shows it serves only two supervisor-external purposes, neither load-bearing for VM management:

1. **Reboot recovery — "what was running"** (`pool.py:478` `get_execution_records`, `:576` attach). The table's only load-bearing supervisor use, and PR 4 removes it (on-disk configs + scheduler).
2. **Persist-on-start** (`models.py:581` `save()`, `operator.py:231` force-fresh) — exists only to feed (1); vestigial for the supervisor once (1) stops reading the DB.
3. **Resource-usage accounting** (`models.py:709`/`pool.py:604` `record_usage()`) — note this **deletes** the row on stop and writes durable history to a **file** (`EXECUTION_LOG_DIRECTORY`); the table is a live registry, not a history store. Billing/telemetry, agent-side.
4. **Logs/auth for past executions** (`operator.py:340,422` `get_last_record_for_vm`) — Aleph-facing operator API; same owner-auth coupling relocated in PR 5.
5. **Monitoring endpoint** (`views/__init__.py:291` `about_execution_records`) — operational visibility.

End-state: the supervisor keeps **no execution DB** — it discovers running VMs from on-disk configs + systemd, and the agent owns whatever message/owner/billing records it needs. Genuinely stateful data not reconstructable from configs (port forwarding) lives in the separate `port_mappings` table and is re-fetchable from the user-settings service. This design (PR 4) stops the supervisor *reading* the table for recovery; physically dropping it follows in the agent-ownership phase (PR 5).

## 8. Deferred: PR 5 — delete `message` from `VmExecution` (later phase)

Carry the few scalars the agent reads (owner address, `rootfs.size_mib`, program `code.ref`, payment flags) on an agent-owned per-VM record; convert `is_sender_authorized` and the ~20 operator-view auth sites to the agent's owner store; then remove `message`/`original` from `VmExecution` and drop/null the DB `message` columns. Security-sensitive; its own design.

## 9. Testing

Per 0.B/0.C conventions (sibling imports, no `tests/supervisor/__init__.py`, ruff/isort/mypy green):
- PR 1: construct `VmExecution.from_spec`, assert properties (`is_instance`, `hypervisor`, etc.) and that `prepare()` populates the resources holder from spec paths with no download (monkeypatch to assert no network/download call).
- PR 2: `create_vm(spec)` with `build_qemu_configuration`, `save_controller_configuration`, and the systemd start stubbed; assert a `VmExecution` lands in `pool.executions`, the controller config is saved, and the controller is started.
- PR 3: assert `run.py` calls `build_create_vm_spec` then `create_vm`; the message does not reach the supervisor.
- PR 4: write a fake `<hash>-controller.json`, stub systemd active state, assert reattach with no DB/message access.

## 10. Decisions (resolved in brainstorming)

1. Supervisor reads no messages and downloads nothing; paths only (agent owns download + translation).
2. (b) chosen: convert reboot-recovery to on-disk-config-driven now, not just creation.
3. `message` field deletion is deferred to PR 5 (agent-owned owner/message store) because the remaining reads are agent-side, auth-critical operator API.
4. DB is wipe-friendly on upgrade: reattach from on-disk configs, repopulate "what should run" from the scheduler.
