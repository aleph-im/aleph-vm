# Agent / Supervisor package boundary (PR-1: behavior-neutral reorg)

**Status:** IMPLEMENTED (PR #986). Two corrections vs the design below, made
during implementation against the real import graph:

1. **`qemu_build.py` and `cloudinit.py` stay supervisor/controller-side** (the
   design's §3/§4.2 moved them to the agent). Their only importer is the
   supervisor `pool` (`build_qemu_configuration` turns a spec into the controller
   config; `cloudinit` builds the cloud-init drive). Only `translate.py` is agent
   code and moved to `orchestrator/`. `configuration.py` -> `contract/` as
   designed.
2. **The three leaks are documented import-linter residuals, not fixed here.**
   The supervisor->agent edges are the shared port-mappings DB
   (`models`/`pool`/`local`/`daemon` -> `orchestrator.metrics`) and the
   aggregate-settings cache (`pool` -> `orchestrator.utils`); both are entangled
   with the DB-engine / policy layer and are behavior-affecting to extract, so
   they ride with the `VmExecution`/`VmPool` cleave (parent §4). `AMDSEVPolicy`
   stays in `local.py` (third-party `aleph_message`, not an agent-boundary edge).
   The import-linter encodes these as explicit `ignore_imports`, and uses
   `allow_indirect_imports` so only direct edges are enforced (the foundation
   modules `conf`/`resources` themselves leak to `orchestrator`, a separate
   pre-existing tangle).

**Status (original):** Design / approved scope
**Date:** 2026-06-19
**Owner:** Olivier Desenfans
**Repo:** `aleph-im/aleph-vm`
**Parent design:** `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md` (§3 seam map, §4 detangling, §6 phases)

## 1. Context

The gRPC-only-supervisor effort has landed its early pieces on `dev`: the
`Supervisor` ABC + gRPC wire (#980, #981), `ItemHash -> VmId` identity (#982),
a message-free `VmExecution` + `HardwareResources` (#983), and the removal of the
dead in-process QEMU cloud-init path (#984).

What is still missing is a clean, enforced **package boundary** between the two
sides of the system. Today `src/aleph/vm/supervisor/` is three things fused
together:

1. a shared contract (the `Supervisor` ABC, the wire types, the error enum),
2. the supervisor implementation (`local.py`, gRPC client/server, daemon), and
3. agent code that was simply filed in the wrong place (`translate.py`,
   `qemu_build.py`).

And the supervisor reaches back into agent territory in three known spots. There
is nothing stopping the boundary from eroding further, because nothing enforces
it.

This PR establishes the boundary and locks it in with a linter, **without
changing runtime behavior**. It is the "establish the split" step that the
parent design's §4/§6 detangling (the `VmExecution`/`VmPool` cleave, the
download extraction, the wire-error vocabulary) will build on afterwards.

## 2. Goal and non-goals

**Goal.** A three-layer package structure with dependency arrows pointing only
inward, enforced by an import linter:

```
   agent  ───►  contract  ◄───  supervisor
   (Aleph)      (ABC, types,     (local impl, gRPC,
                 error enum)      daemon, hypervisors)
```

Concretely: extract a `contract` layer, move the misfiled agent code out of
`supervisor/`, fix the three back-references, and add an import-linter contract
that fails CI if the boundary is violated again.

**Non-goals (explicitly deferred to the later behavior-changing step, parent §4 + A.6):**

- Cleaving the `VmExecution` / `VmPool` god-objects.
- Splitting the `Resources` classes' dual personality (agent message-downloader
  vs supervisor spec-runtime holder). Volume download is already agent-side
  (`translate.py`); what remains is prising the shared class apart, which is
  behavior-affecting. That is PR-2.
- The wire-error vocabulary that would let `orchestrator/views` stop importing
  controller exception types (also PR-2).
- The physical `orchestrator/` -> `agent/` and `controllers/` ->
  `supervisor/controllers/` moves (PR-3).

**Hard constraint: no runtime behavior change.** Every change in this PR is a
move, a re-export, or an import-direction fix. The existing test suite is the
contract; it must pass unchanged.

## 3. The constraint collision and how it is resolved

The approved direction is "split controllers by concern" (download is agent,
running is supervisor). Most of the controllers package separates cleanly, but
the `Resources` classes are used on **both** sides in a way that cannot be split
behavior-neutrally. They are defined inside the controller modules and
constructed two different ways: the agent's `translate.py` builds them from a
message (`AlephQemuResources(message)` + `download_all()`) to produce the spec,
while the running controller builds them from the resolved spec
(`AlephQemuResources.from_spec(spec)`, no download). Download already lives
agent-side; what remains tangled is the **single class with two personalities**,
and prising those apart is exactly the behavior-changing §4 work.

So this PR does the part that **is** free and defers the `Resources` split:

- `controllers/qemu/cloudinit.py` moves to the agent (post-#984 it is imported
  **only** by agent code: `translate`, `qemu_build`).
- `controllers/configuration.py` moves to `contract/` (it is the on-disk
  config-file schema both daemons share; its only deps are stdlib, pydantic, and
  foundation modules, so the move is clean and it removes the agent
  `qemu_build` -> `controllers` edge).
- `controllers/` is otherwise classified **supervisor-side** (a worker module the
  supervisor daemon imports, not the reverse), with two explicit, documented
  agent residuals: the `Resources` classes and the controller exception types the
  views catch. The import linter forbids `controllers -> {agent, supervisor
  daemon modules}` and ignores those two residuals. Removing them is PR-2; the
  physical move into `supervisor/controllers/` is PR-3.

This is an honest intermediate state: the boundary is enforced, and the
remaining coupling is *marked*, not hidden.

## 4. Target layout

### 4.1 `contract/` (new, shared, depends on neither side)

Moves out of `supervisor/`:

| From                       | To                     | Notes |
| -------------------------- | ---------------------- | ----- |
| `supervisor/abc.py`        | `contract/abc.py`      | The `Supervisor` ABC. |
| `supervisor/types.py`      | `contract/types.py`    | `VmId`, `VmInfo`, `VmStatus`, `Backend`, `ConfidentialMode`, `CreateVmSpec`, `GpuSpec`, `PciAddress`, `ErrorCode`, etc. |
| `SupervisorError` hierarchy from `supervisor/errors.py` | `contract/errors.py` | The error classes only. They already have no backend dependency. |
| `controllers/configuration.py` | `contract/configuration.py` | On-disk controller config-file schema, shared by agent (writes) and controller (reads). Deps are clean (stdlib, pydantic, foundation). |

`errors.py` **splits**: the `SupervisorError` subclasses (the closed
vocabulary, one-to-one with `ErrorCode`) go to `contract/errors.py`; the
mapping (`translate_exception`, `translating_errors`, which import controller
and hypervisor exception types locally) stays supervisor-side as
`supervisor/error_mapping.py`.

`contract/` may import only stdlib, pydantic, and `aleph_message` value types
that are already part of the wire vocabulary (e.g. `AMDSEVPolicy`, see §5.2). It
must not import `agent`, `supervisor`, `controllers`, `pool`, or `models`.

### 4.2 agent side

Lands in the existing agent package (`orchestrator/`, kept under that name this
PR; rename deferred):

| From                          | To (agent)                       | Notes |
| ----------------------------- | -------------------------------- | ----- |
| `supervisor/translate.py`     | `orchestrator/translate.py`      | Pure message -> `CreateVmSpec` translator. Agent code. |
| `supervisor/qemu_build.py`    | `orchestrator/qemu_build.py`     | Builds the controller config + cloud-init from a spec. Agent code. |
| `controllers/qemu/cloudinit.py` | `orchestrator/cloudinit.py`    | Post-#984, only agent code imports it. |

The agent may import `contract` and (as documented residuals only) the
`controllers` `Resources` classes, `pool`, and `models`. It must not import
`supervisor` implementation modules (`local`, `grpc_*`, `daemon`,
`proto_convert`, `_pb`). It already calls the supervisor only through the
`contract.abc.Supervisor` interface and `contract.errors`.

### 4.3 supervisor side

Stays in `supervisor/` (no moves needed beyond the extractions above):
`local.py`, `grpc_server.py`, `grpc_client.py`, `proto_convert.py`, `_pb/`,
`daemon.py`, `__main__.py`, plus the new `error_mapping.py`. It may import
`contract`, `controllers`, `hypervisors`, `network`, `pool`, `models`,
`sevclient`. It must not import `orchestrator` (the three back-references in §5
are the violations this PR removes).

### 4.4 not physically moved this PR

No file movement, but each is *classified* for the linter:

- **Supervisor-side**: `pool.py`, `models.py` (supervisor-owned objects; the
  agent's reach-ins into them are the documented residuals of §6).
  `controllers/` (a supervisor worker module, with the two agent residuals of §3
  until PR-2), `hypervisors/`, `sevclient.py`.
- **Shared base layer** (importable by both, importing neither side):
  `network/`, `migration/`, `storage.py`.
- **Foundation** (importable by everything, importing nothing above it):
  `conf.py`, `vm_type.py`, `resources.py`, `constants.py`, `version.py`,
  `utils/`.

Finer per-module classification (e.g. splitting `network/` policy from infra, or
`migration/`) belongs to the §4 cleave, not here.

## 5. The three back-references to fix

### 5.1 Port-mappings DB read (`supervisor/local.py` -> `orchestrator.metrics`)

`local.py` imports `get_port_mappings` / `delete_port_mappings` from
`orchestrator.metrics`. That is the supervisor reading the agent's persistence
layer. Behavior-neutral fix: relocate the port-mapping persistence helpers to a
neutral module both sides can import (candidate: a `db/` or
`persistence/port_mappings.py` shared module, or `network/` since the data is
host-port state). The SQL and call sites are unchanged; only the import path
moves. Final placement decided in the implementation plan; the test in
`tests/supervisor/test_port_mappings.py` must keep passing with only its import
updated.

### 5.2 `AMDSEVPolicy` (`supervisor/local.py` -> `aleph_message`)

`local.py` imports `AMDSEVPolicy` from `aleph_message`. It is an SEV policy
value, part of the infra vocabulary, not an Aleph message type. Behavior-neutral
fix: it is already a plain enum; either (a) re-export it from `contract/types.py`
as part of the wire vocabulary (the spec already carries TEE fields), or (b)
keep the `aleph_message` import but classify it as an allowed value-type
dependency. Option (a) is preferred since it keeps the supervisor's
`aleph_message` surface at zero. Decided in the implementation plan.

### 5.3 `VmPool` import (`supervisor/daemon.py` -> `pool.VmPool`)

`daemon.py` imports `VmPool` (under `TYPE_CHECKING`). `pool.py` is a supervisor-
owned object, so this is not a *boundary* violation, but it should be expressed
against the supervisor's own view, not reached for as a top-level module. This is
a typing/import-tidy, not a behavior change; the import-linter layering (pool is
supervisor-side) makes it legal. No code movement required beyond confirming the
linter places `pool`/`models` on the supervisor side.

## 6. Enforcement: import-linter

Add `importlinter` as a dev dependency and an `[tool.importlinter]` config
(`pyproject.toml` or `.importlinter`), wired into CI (the existing lint job).
Rather than a single strict "layers" contract (the two top sides are siblings,
not stacked), the boundary is expressed as a set of `forbidden` contracts plus
the documented residual list:

1. **`contract` is the floor**: forbid
   `contract -> {orchestrator, supervisor, controllers, pool, models, network,
   migration, hypervisors}`. It may import only the foundation modules (§4.4).
2. **Supervisor never imports the agent**: forbid `supervisor -> orchestrator`
   (the §5 fixes make this hold).
3. **Controllers are a supervisor worker, not the daemon**: forbid
   `controllers -> {orchestrator, supervisor}` (controllers may import only
   `contract`, the shared base, and foundation).
4. **The shared base never imports either side**: forbid
   `{network, migration} -> {orchestrator, supervisor}`.
5. **Agent never imports the supervisor implementation**: forbid
   `orchestrator -> {supervisor.local, supervisor.grpc_server,
   supervisor.grpc_client, supervisor.daemon, supervisor.proto_convert,
   supervisor._pb, supervisor.error_mapping}`. The agent may import
   `contract` and `supervisor` is otherwise off-limits except via the ABC, which
   now lives in `contract`.
6. **Allowed residuals** (explicit `ignore_imports`, each with a comment
   pointing at the §4 cleave): `orchestrator -> controllers` (the `Resources`
   classes, and the running-controller exception types still caught by views)
   and `orchestrator -> {pool, models}`. These are the seams the next step
   removes; listing them makes the debt visible and prevents *new* ones.

The value is not zero violations today; it is that any *new* violation, or any
regression of a fixed one, fails CI.

## 7. Testing strategy

- **No new behavior, so no new behavioral tests.** The existing suite is the
  oracle. Run the full supervisor test suite (with the known env-only
  exceptions: `test_interfaces`, `test_log`, the `test_qemu_instance` XFAILs)
  and confirm no new failures.
- **Import-graph tests**: `lint-imports` (import-linter) passes in CI. This is
  the new gate that proves the boundary holds.
- **`mypy`**: baseline error count unchanged (no new errors introduced by the
  moves and re-exports).
- **Re-export shims**: if any move would otherwise break a public import path
  used by tests or external tooling, leave a thin re-export at the old location
  with a deprecation comment, rather than editing unrelated call sites. Prefer
  updating call sites where they are in-repo and few.

## 8. Risks

| Risk | Mitigation |
| ---- | ---------- |
| A move silently changes import side effects / ordering | Moves are mechanical; rely on the full suite + a smoke import of the daemons. |
| Import-linter "allowed residual" list becomes a dumping ground | Each ignored import carries a comment referencing the §4 cleave; review rejects new entries. |
| `AMDSEVPolicy` re-export subtly changes typing | Prefer option (a) only if `mypy` baseline is unchanged; else keep the value-type dependency. |
| Scope creep into the §4 cleave | The "no runtime behavior change" constraint is the tripwire: if a change needs a behavioral test, it belongs in the next step, not here. |
| Churn collides with in-flight branches | The diff is moves + import fixes; land it promptly and rebase dependents once. |

## 9. Next steps

This PR is preceded by **PR-0**, the behavior-neutral `vm_hash` -> `vm_id` rename
on the supervisor-side objects (see
`2026-06-19-supervisor-vm-id-rename-design.md`); PR-1 builds on the clarified
names.

1. User review of this design.
2. Implementation plan (writing-plans): the exact file moves, the
   `contract/errors.py` vs `supervisor/error_mapping.py` split, the port-mappings
   relocation target, the `AMDSEVPolicy` decision, the import-linter config and
   its residual-ignore list, and the test run checklist.
3. After this lands: **PR-2** (the `Resources` dual-personality split + wire-error
   vocabulary, see `2026-06-19-controller-split-by-concern-design.md`), then
   **PR-3** (the physical `orchestrator/` -> `agent/` and `controllers/` ->
   `supervisor/controllers/` moves, see
   `2026-06-19-agent-supervisor-code-move-design.md`). The `VmExecution`/`VmPool`
   cleave (parent §4) remains a separate, adjacent effort.
