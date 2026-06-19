# Rename vm_hash -> vm_id on the supervisor objects (PR-0: behavior-neutral)

**Status:** BLOCKED (2026-06-19) — needs a naming decision before implementation.

> **Blocker: `vm_id` is already taken by a different concept.** `VmExecution` has
> both `vm_hash: VmId` (the string identity we want to call `vm_id`) **and** a
> `vm_id` property returning `int` (the numeric local VM id from the controller,
> used for TAP/IP). The numeric `vm_id: int` is pervasive: ~11 files across all
> controllers, `network/`, and `hypervisors/`. So `vm_hash -> vm_id` cannot be
> done without first renaming the numeric id (candidate: `vm_id: int` ->
> `vm_index` / `local_vm_id` / `tap_id`), which is (a) a naming choice for the
> owner to make and (b) a large rename that would collide heavily with PR-2/PR-3's
> controller edits if sequenced first.
>
> **Recommendation:** rename numeric `vm_id: int` -> `vm_index` everywhere and
> string `vm_hash` -> `vm_id` (VmId), but sequence this **last**, after PR-3, to
> avoid churn against the controller moves. Awaiting the owner's choice of the
> numeric-id name and confirmation of the expanded (controllers + network) scope.

**Original scope below assumed `vm_id` was free; it is not. Revise per the
blocker before implementing.**

**Status (original):** Design / approved scope
**Date:** 2026-06-19
**Owner:** Olivier Desenfans
**Repo:** `aleph-im/aleph-vm`
**Parent design:** `docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md`
**Sequence:** runs *first*, before
`2026-06-19-agent-supervisor-boundary-design.md` (PR-1).

## 1. Context

Since #982 the VM identity on the supervisor side is a `VmId`
(`NewType("VmId", str)`), and the supervisor wire layer (`abc`, `types`,
`grpc_server`, `grpc_client`, `proto_convert`, `daemon`) already speaks `vm_id`.
But the supervisor-side *objects* still carry the old Aleph-flavoured name:
`VmExecution.vm_hash` (models.py), the `VmPool.executions` keys and params
(pool.py), and the in-process implementation (`supervisor/local.py`). The name
`vm_hash` reads as "an Aleph message hash", which is precisely the concept the
supervisor is supposed to be free of. This step renames the identity to `vm_id`
on those objects so the supervisor code says what it means.

It is a pure, behavior-neutral rename. It runs first because it is independent of
the package reorg (PR-1..PR-3) and clarifies the identity before later PRs move
the code around; isolating it also keeps the rename diff trivially reviewable.

## 2. Scope

End-to-end on the supervisor-side objects:

- `models.py`: `VmExecution.vm_hash` -> `vm_id` (the attribute and all internal
  uses).
- `pool.py`: `VmPool.executions` keys, parameters, and locals named `vm_hash`
  that hold the identity -> `vm_id`.
- `supervisor/local.py`: all `vm_hash` -> `vm_id`.
- Agent call sites that *read the supervisor object's attribute*:
  `orchestrator/run.py`, `orchestrator/custom_logs.py`, `migration/` — update
  `execution.vm_hash` -> `execution.vm_id`.

### What does NOT change

- **Agent-owned `vm_hash` locals that genuinely hold the Aleph `ItemHash`** stay
  `vm_hash`. On the agent side the value *is* the message hash; only references to
  the supervisor object's renamed attribute change. Example in `run.py`: a local
  `vm_hash` parsed from the message keeps its name, while `execution.vm_hash`
  becomes `execution.vm_id`.
- The wire layer (already `vm_id`).
- `translate.py` / `qemu_build.py` (agent code; their `vm_hash` is the ItemHash
  and is correct). PR-1 moves them agent-side unchanged.
- Types and values: `VmId` stays a `NewType` over `str`. The existing
  `VmId(str(execution.vm_id))` normalisation wrappers in `local.py` are left as
  they are; collapsing them (now that the attribute is already a `VmId`) is an
  optional follow-on cleanup, kept out of this rename to keep it purely
  mechanical.

## 3. Testing strategy

- Behavior-neutral: the existing suite is the oracle; run it green (known
  env-only exceptions excepted).
- `mypy` baseline unchanged.
- Grep sweep: no `vm_hash` remains in `supervisor/local.py`, `pool.py`,
  `models.py` except where the value is genuinely an `ItemHash`; no
  `execution.vm_hash` references remain anywhere.
- Use rename-aware edits (IDE/`git`) so the diff is recognisably a rename, not a
  rewrite.

## 4. Risks

| Risk | Mitigation |
| ---- | ---------- |
| Renaming an agent `vm_hash` that is really an ItemHash | Rename only the attribute and its reads; review each agent call site (`run.py`, `custom_logs.py`, `migration/`) individually rather than a blind search-replace. |
| Collides with PR-1's edits to `local.py` (the 3 leak fixes) | Land PR-0 first; PR-1 rebases onto the renamed file (trivial). |
| Hidden string/serialization use of the name `vm_hash` (DB columns, JSON keys) | The DB/port-mapping columns and on-disk config keys are *not* in scope; this renames Python identifiers only. Verify no serialized key literally named `vm_hash` is touched. |

## 5. Next step

Implementation plan (writing-plans), or, given the mechanical nature, a direct
rename PR with the §3 checklist. Then PR-1.
