# Message-free VmExecution and controller layer: design

**Status:** approved for planning
**Date:** 2026-06-17
**Author:** Olivier Desenfans
**Stacks on:** #982 (`od/supervisor-vmid-identity`), which stacks on #981 (`od/grpc-only-supervisor-phase2`).

## Goal

Remove `aleph_message` from `VmExecution` (`src/aleph/vm/models.py`) and the
controller layer completely. After this change the daemon side (the VM pool, the
execution object, and every controller) imports zero `aleph_message` symbols,
including the value types `MachineResources` and `HypervisorType`.

The agent keeps `aleph_message` (it is the message boundary). The shared resource
download classes keep their message constructors (see Boundary below).

## Why this is possible now

Phase 2 already moved all message handling off the execution object:

- The agent keeps its own `VmRegistry`; every agent consumer (operator API,
  billing, port reconciliation, update-watching) reads `record.message` /
  `record.original` from that registry, never from `execution.message`.
- In production every `VmExecution` is built message-free via `from_spec`. There
  is no production `VmExecution(message=...)` construction left in `src/`
  (verified). Only the test suite still builds the message-driven form.

So the message-driven half of `VmExecution` is dead in production and alive only
in tests. This change deletes it and removes the `aleph_message` value types that
leak through the controller constructors.

## Current coupling (the inventory being removed)

`src/aleph/vm/models.py` imports and uses:

| Symbol | Site | Disposition |
| --- | --- | --- |
| `ExecutableContent`/`InstanceContent`/`ProgramContent` | `MessageSpec`, the `spec` union, `.message`/`.original`, message branches in `is_program`/`is_instance`/`is_confidential`/`allocated_*`/`prepare`/`create`/`save` | delete (dead in prod) |
| `GpuProperties` | `prepare_gpus()` (raises for spec execs) | delete (dead in prod) |
| `HypervisorType` | the `hypervisor` property | delete (zero consumers anywhere) |
| `MachineResources` | `create()` builds it on the spec path to pass `hardware_resources=` to controllers | replace with `HardwareResources` DTO |

`MachineResources` is confined to exactly these files (verified, nothing else in
`src/` imports it):

- `controllers/interface.py` (base attr `hardware_resources: MachineResources`)
- `controllers/firecracker/executable.py` (attr + ctor param + default)
- `controllers/firecracker/program.py` (ctor default; reads `.vcpus`/`.memory`/`.seconds`)
- `controllers/firecracker/spec_program.py` (reads `.vcpus`/`.memory`; builds it from the spec)
- `controllers/qemu/instance.py` (attr + ctor default; reads `.vcpus`/`.memory`)
- `controllers/qemu_confidential/instance.py` (attr + ctor default; reads `.vcpus`/`.memory`)
- `models.py` (spec path builds it; message path passes `message.resources`)

`MachineResources` fields actually read by controllers: `vcpus`, `memory` (MiB),
`seconds` (program max-runtime, firecracker `run_code` timeout only). `published_ports`
is never read by any controller.

## The new DTO

A frozen, message-free dataclass in `src/aleph/vm/supervisor/types.py`, mirroring
the three fields controllers read with the same defaults so `HardwareResources()`
is a drop-in for `MachineResources()`:

```python
@dataclass(frozen=True)
class HardwareResources:
    """Message-free hardware sizing handed to controllers.

    Mirrors the three fields the controllers read from aleph_message's
    MachineResources (vcpus, memory in MiB, seconds for the program run
    timeout) so the daemon never imports a message type. Field names match
    MachineResources so controller field access is unchanged.
    """

    vcpus: int = 1
    memory: int = 128  # MiB
    seconds: int = 1
```

Field name `memory` (not `memory_mib`) is kept deliberately: controllers read
`self.hardware_resources.memory`, so keeping the name means the controller swap is
a pure type change with no field-access edits.

## End state of VmExecution

`VmExecution` becomes spec-only:

- `spec: CreateVmSpec` (no union, `MessageSpec` deleted).
- `__init__` loses `message`/`original`; takes `vm_hash`, `vm_spec`,
  `snapshot_manager`, `systemd_manager`, `persistent`. (`from_spec` already the
  only production constructor.)
- Deleted: `.message`, `.original` properties; `prepare_gpus`;
  `fetch_port_redirect_config_and_setup`; the `hypervisor` property; `run_code`
  (message-path on-demand execution; the supervisor runs spec programs via
  `_run_code_over_channel`).
- Simplified to read only the spec: `is_program` (`backend is FIRECRACKER`),
  `is_instance` (`backend is QEMU`), `is_confidential` (`tee is not None`),
  `allocated_memory_mib`/`allocated_vcpus` (spec fields), `prepare` (spec branch
  only), `create` (spec branch only, builds `HardwareResources`).
- `save()`: the message branch is removed. Spec-built executions keep no DB
  record (already the production behaviour: `save()` early-returns for them), so
  `save()` becomes a no-op on the daemon and is removed along with its only
  caller in `start()`. (Confirmed in the plan: nothing else depends on it.)
- Imports: no `aleph_message`.

## Controller changes

Each of the six controller files swaps the `hardware_resources` type
`MachineResources` -> `HardwareResources` (attribute annotation, constructor
parameter, and `MachineResources()` defaults -> `HardwareResources()`). Field
accesses `.vcpus`/`.memory`/`.seconds` are unchanged. No serialization change:
the on-disk controller `Configuration` already uses plain `vcpu_count: int` and
integer memory fields, not `MachineResources`.

`models.create()` builds `HardwareResources(vcpus=spec.vcpus, memory=spec.memory_mib)`
for the QEMU paths; `SpecFirecrackerProgram` already builds its own from the spec
(swap the type there too).

## Dead message-path controllers

After the purge these are constructed only in tests:

- `AlephFirecrackerProgram` (constructed only at the deleted `models.py` message
  branch; the spec program path uses the sibling `SpecFirecrackerProgram`).
- The message-built forms of `AlephQemuInstance` /
  `AlephQemuConfidentialInstance` (but their spec-built forms stay live, so the
  classes stay).

Decision: this change removes the message *construction* from `VmExecution` and
swaps `MachineResources` everywhere, but does NOT delete `AlephFirecrackerProgram`
the class. Deleting that class (and `ProgramVmConfiguration`, its message-coupled
`run_code`, etc.) is a larger, separable cleanup tracked as a follow-up. Rationale:
keep this change focused on the stated goal (message-free `VmExecution` + value-type
purge) and avoid entangling it with controller deletion, which has its own test
surface. The class keeps compiling against `HardwareResources` after the swap.

## Boundary: what stays aleph_message-coupled, by design

`AlephQemuResources` / `AlephProgramResources` (in `controllers/`) keep their
`message` constructors. The agent's `translate.py` uses them to download Aleph
storage (resolve message refs to host paths) before handing the supervisor a
message-free `CreateVmSpec`. They also expose `from_spec`, which is what the
daemon uses. These classes remain message-aware; the daemon only ever calls
`from_spec`. This is the deliberate edge of the purge.

## Risks

1. **Test migration (primary).** ~20 message-built `VmExecution` constructions
   across 8 test files. A legacy test can be the only coverage for a behavior
   that still has a live spec path. Mitigation: per-test triage with a decision
   rule (convert to the spec path if the behavior is still reachable; delete only
   if the behavior is provably message-path-only and therefore being removed).
2. **`save()` removal.** Must confirm no production caller relies on the daemon
   writing a DB record (the agent writes its own via `VmRegistry`). The plan has
   an explicit verification step before removal.
3. **Stack depth 3** (#981 <- #982 <- this). Churn on the lower PRs forces
   rebases here. Accepted for momentum.

## Verification

- `ruff format` + `isort` clean.
- `mypy`: the two pre-existing `trusted_execution`/`policy` union-attr errors in
  `models.py` disappear (their branch is deleted). No new errors.
- Full test suite green except the known environment baseline (jailman `chown`
  subprocess, pyroute2 netlink).
- `grep -rn "aleph_message" src/aleph/vm/models.py src/aleph/vm/controllers/` returns
  only the resources classes' message constructors (the documented boundary), and
  zero `MachineResources` / `HypervisorType`.
