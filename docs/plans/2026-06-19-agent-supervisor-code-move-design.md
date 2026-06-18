# The code move (PR-3: physical relocation, behavior-neutral)

**Status:** Design / approved scope
**Date:** 2026-06-19
**Owner:** Olivier Desenfans
**Repo:** `aleph-im/aleph-vm`
**Parent design:** `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md`
**Predecessors:** `2026-06-19-agent-supervisor-boundary-design.md` (PR-1),
`2026-06-19-controller-split-by-concern-design.md` (PR-2)

## 1. Context

After PR-1 (contract layer + enforced boundary) and PR-2 (controllers no longer
carry an Aleph-aware personality, views catch only `SupervisorError`), the code
is in the right *layers* but not yet under the right *names and directories*.
The agent still lives in a package called `orchestrator/`; the supervisor-owned
running controller still lives in a neutral-looking top-level `controllers/`.

PR-3 performs the physical move so the directory tree matches the architecture.
It is purely mechanical: renames, file moves, and import updates. No logic
changes, so it is gated on "moves only + green suite", like PR-1.

This is safe to do last precisely because PR-1 and PR-2 already separated the
concerns; moving files around now cannot smuggle in a coupling, because the
import-linter would reject it.

## 2. Moves

### 2.1 `orchestrator/` -> `agent/`

The agent package gets its real name. This is the bulk of the diff (every
internal import of `aleph.vm.orchestrator...` updates), but it is mechanical.

Packaging follow-through (service *names* are unchanged, only module targets):

- `pyproject.toml`: `scripts.aleph-vm = "aleph.vm.agent.cli:main"`.
- `packaging/.../aleph-vm-agent.service`: `ExecStart=python3 -m aleph.vm.agent
  --print-settings`.
- `aleph/vm/agent/__main__.py` (moved) keeps the same CLI surface.

### 2.2 Agent-side downloader -> `agent/`

The message->spec downloader extracted in PR-2 moves into `agent/` next to
`translate.py` / `qemu_build.py` (which PR-1 already placed agent-side).

### 2.3 `controllers/` -> `supervisor/controllers/`

After PR-2, `controllers/` holds only the running controller, the runtime
resource holder (`from_spec`), and management (`QemuVmClient`, `backup`,
`snapshots`). It is the supervisor's execution worker.

**Decision (2026-06-19): move it to `supervisor/controllers/`.** The controller
is spawned by the supervisor (via its `SystemDManager`) and is logically the
supervisor's execution worker; nesting reflects that, keeps the supervisor
subtree together, and lines up with parent-design Phase 2, where the Python
hypervisor and its controllers are swapped for Rust as one unit. Use `git mv` so
rename detection keeps the diff reviewable.

Entry-point follow-through:

- `aleph-vm-controller@.service`: `ExecStart=/usr/bin/python3 -m
  aleph.vm.supervisor.controllers --config=/var/lib/aleph/vm/%i-controller.json`.
  The service *name* and the `%i-controller.json` config path are unchanged, so
  operators and the on-disk config contract are unaffected; only the module
  target moves. The unit file and the module ship in the same `.deb`, so the
  rename is internally consistent within any version (already-running controller
  instances keep running on their old invocation until their next start, which
  uses the new, consistent unit).
- `aleph/vm/supervisor/controllers/__main__.py` (moved) keeps the same
  `--config` CLI surface.

### 2.4 `configuration.py` (already in `contract/` from PR-1)

`controllers/configuration.py`, the on-disk config-file schema (agent
`qemu_build` writes it, the controller reads it, `local.py` removes it), is
**already moved to `contract/configuration.py` in PR-1**. It had to be: once
controllers nests under `supervisor/` here, leaving the schema in
`supervisor/controllers/` would make agent-side `qemu_build` import
`supervisor/controllers`, a forbidden `agent -> supervisor` edge. PR-1 does the
move (its deps are clean: stdlib, pydantic, foundation), so PR-3 has nothing to
do for it beyond confirming the import paths are already `contract.*`.

## 3. Enforcement and cleanup

- Update the import-linter config to the final package names. The only remaining
  documented residual is `agent -> {pool, models}` (the `VmExecution`/`VmPool`
  cleave, a separate adjacent effort). Every other ignore entry from PR-1 is gone
  by now (PR-2 removed the controller ones).
- Optionally leave thin re-export shims at the old `aleph.vm.orchestrator.*`
  paths for one release if any out-of-repo tooling imports them; otherwise a hard
  rename. Recommend a hard rename inside the repo (update all call sites) and
  shims only if a concrete external importer is found.

## 4. Testing strategy

- Behavior-neutral: the existing suite is the oracle, run it green (known
  env-only exceptions excepted).
- **Launch smoke test**: confirm all three entry points still import and start:
  `python -m aleph.vm.agent --print-settings`, `python -m aleph.vm.supervisor`,
  and the controller `python -m aleph.vm.supervisor.controllers --config=<sample>`.
- `mypy` baseline unchanged; import-linter passes under the final names.
- Grep for stale `aleph.vm.orchestrator` references across `packaging/`, docs,
  CI workflows, and tests; none should remain (or only intentional shims).

## 5. Risks

| Risk | Mitigation |
| ---- | ---------- |
| A missed `orchestrator` reference in packaging/CI breaks a service at deploy | §4 grep sweep across packaging, systemd units, CI, and the Makefile; launch smoke test. |
| The rename collides badly with in-flight branches | Land PR-1/PR-2 first; do the rename in one commit; rebase dependents once, immediately. |
| External tooling imports `aleph.vm.orchestrator` | Search for real importers; add re-export shims only if found, with a deprecation note. |
| Reviewers cannot see logic vs move in a huge diff | Keep PR-3 strictly mechanical (no logic edits); use `git mv` so rename detection keeps the diff reviewable. |

## 6. Sequence recap and what remains after

The sequence:

0. **PR-0** (behavior-neutral): rename `vm_hash` -> `vm_id` on the supervisor-side
   objects (`VmExecution`, `VmPool`, `local.py`) and the agent call sites reading
   that attribute. See `2026-06-19-supervisor-vm-id-rename-design.md`.
1. **PR-1** (behavior-neutral): contract layer, misfiled agent code out of
   `supervisor/`, three back-references fixed, import-linter.
2. **PR-2** (behavior-affecting): split the `Resources` dual personality, finish
   the wire-error vocabulary, remove the two `controllers` residuals.
3. **PR-3** (behavior-neutral): `orchestrator/` -> `agent/`, `controllers/` ->
   `supervisor/controllers/`, final import-linter names. (`configuration.py` ->
   `contract/` already happened in PR-1.)

After PR-3 the only remaining cross-boundary coupling is `agent -> {pool,
models}`: the `VmExecution`/`VmPool` cleave from the parent design §4, which is a
separate effort and not part of this sequence. The cosmetic work of this sequence
is then done; the next architectural milestone is that cleave, after which the
Python hypervisor can be swapped for the Rust one (parent design Phase 2).

## 7. Next step

Implementation plan (writing-plans) per PR, authored when its predecessor lands
(PR-2's plan after PR-1 merges, PR-3's after PR-2 merges), since each plan's
exact import edits depend on the prior PR's final state.
