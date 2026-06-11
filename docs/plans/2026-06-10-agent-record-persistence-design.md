# Agent-owned record persistence + message reads off the pool

**Status:** design
**Date:** 2026-06-10
**Series:** message-free supervisor (Phase-0 residual cleanup, after #969 expiry, #970 update-watching, #971 owner-auth)
**Stacks on:** `od/wire-supervisor-owner-auth` (#971)

## 1. Goal

Kill the last agent reach-in on the create path — the `create_vm_execution`
readback (`pool.executions[vm_hash]` → `MessageSpec` attach → `execution.save()`)
— by making the agent persist its own `ExecutionRecord`, and migrate the
remaining agent-side readers of `pool.executions[...].message` to the agent
registry. After this PR, nothing agent-side learns a VM's message by reaching
through the hypervisor's pool object.

## 2. Background

The message-free-supervisor effort splits the `VmExecution` god-object into an
agent-side concept (message, owner, billing, expiry, update-watching — backed by
the `AgentVmRegistry` + agent DB) and a hypervisor-side `Vm` (process,
networking, status). The supervisor's spec create path is already message-free —
but `create_vm_execution` immediately undoes it (run.py:249-254):

```python
execution = pool.executions[vm_hash]                  # reach into the hypervisor's bookkeeping
execution.spec = MessageSpec(message=content, ...)    # glue the message back on
await execution.save()                                # have IT write the agent's DB record
```

The comment on the block says TEMPORARY. It exists for two reasons:

1. **Persistence.** `VmExecution.save()` no-ops unless the spec is a
   `MessageSpec` (models.py:821-825). The attach exists so `save()` writes the
   message into the agent DB — which `rehydrate_registry` and past-logs
   owner-auth read back after an agent restart. Delete `save()` with no
   replacement and the agent forgets spec-created VMs on every reboot.
2. **In-memory readers.** A few agent-side code paths still learn the message by
   reading it off pool executions; the attach is what makes that work for
   spec-created VMs during their first lifetime. (It does NOT survive a restart:
   restored executions are spec-built with no message — these readers already
   silently skip them today.)

### The scheduler context (decision 2026-06-10)

The new scheduler provides allocations for PAYG too; the
`/control/allocations/notify` flow is legacy and will be deprecated. Payment
enforcement is the scheduler's prerogative — agent-side payment checking is on
the deprecation path. Consequences for this design:

- `update_allocations`' reap protection is the allocation set itself; its
  payment-tier guards are transition-window defense, not the primary mechanism.
- `check_payment`'s logic is NOT extended or redesigned here. This PR only moves
  **where its data comes from** (registry instead of pool-message), because the
  transition window is long enough that the checks still matter — including for
  restored VMs, which currently escape them entirely.

## 3. Scope

### In scope

1. **`persist_record` (vm_registry.py)** — the write-side sibling of
   `rehydrate_registry`: the agent writes an `ExecutionRecord` directly from an
   `AgentVmRecord`.
2. **`create_vm_execution` (run.py)** — spec path drops the readback / attach /
   `save()`; calls `persist_record`; returns `None`.
3. **Payment grouping moves to the agent** — `pool.get_executions_by_address`
   is deleted; a registry-sourced `_group_executions_by_payment(pool, registry,
   payment_type)` in tasks.py replaces it at `check_payment`'s three call sites.
4. **`update_allocations` payment guards read the registry** —
   `AgentVmRecord` gains `uses_payment_stream` / `uses_payment_credit`; the
   now-dead `VmExecution.uses_payment_stream` / `uses_payment_credit` properties
   are deleted (no other readers).
5. **`_handle_domains_aggregate` reads the registry** for the owner-address
   check.

### Out of scope (explicit residuals, unchanged)

- **Agent-side payment enforcement itself** — `check_payment`'s balance / credit
  / stream logic and the terminal-status stop loop (liveness, not payment) are
  untouched; the whole apparatus deprecates with the legacy notify flow.
- **Structural `pool.executions` iteration** — grouping and the terminal-status
  loop still iterate pool executions for liveness/structure (`is_running`,
  `is_confidential`, `times`). Replacing that with supervisor list views is
  Phase-1.
- **`update_allocations`' other guards** (`gpus`, `is_confidential`,
  `is_instance`) — structural, spec-safe (they branch on `CreateVmSpec`).
- **The `about_executions` debug endpoint** (raw pool dump residual).
- **`operate_expire`'s dead route, `execution.vm` reads in operator.py** —
  carried residuals from earlier PRs.

## 4. Components

### 4.1 `persist_record` (`src/aleph/vm/orchestrator/vm_registry.py`)

```python
async def persist_record(vm_hash: ItemHash, record: AgentVmRecord) -> None:
    """Persist the agent's knowledge of a VM to the agent DB.

    Write-side sibling of rehydrate_registry: what this writes is exactly what
    rehydrate_registry needs to rebuild the registry after a restart (message,
    original, persistent), carried on the existing ExecutionRecord table.
    """
    now = datetime.now(tz=timezone.utc)
    resources = record.message.resources
    db_record = ExecutionRecord(
        uuid=str(uuid4()),
        vm_hash=str(vm_hash),
        vm_id=None,            # numeric hypervisor id; unknown agent-side (debug-only column)
        time_defined=now,
        time_prepared=now,
        time_started=now,
        time_stopping=None,
        cpu_time_user=None,
        cpu_time_system=None,
        io_read_count=None,
        io_write_count=None,
        io_read_bytes=None,
        io_write_bytes=None,
        vcpus=resources.vcpus,
        memory=resources.memory,
        message=record.message.model_dump_json(),
        original_message=record.original.model_dump_json(),
        persistent=record.persistent,
        gpus=json.dumps([]),   # spec path excludes GPUs (_is_spec_eligible)
        mapped_ports=None,     # the PortMapping table is the authority
    )
    await save_record(db_record)
```

**Field deltas vs. the readback-save** (all consumed only by the
`about/execution/records` debug endpoint; `rehydrate_registry` and the
past-logs owner-auth fallback read only `message` / `original_message` /
`persistent` / `vm_hash`):

| column | readback-save wrote | persist_record writes |
|---|---|---|
| `vm_id` | numeric hypervisor id | `None` |
| `time_*` | execution lifecycle stamps | agent-stamped now |
| `mapped_ports` | `execution.mapped_ports` | `None` (PortMapping table is the authority) |
| `vcpus` / `memory` | `vm.hardware_resources` | `message.resources` (the same values the spec was built from) |

A new record (fresh uuid) per create matches today's behavior; rehydration is
newest-first and keeps the latest record per vm_hash.

### 4.2 `AgentVmRecord` payment helpers (`vm_registry.py`)

```python
@property
def uses_payment_stream(self) -> bool:
    return bool(self.message.payment and self.message.payment.is_stream)

@property
def uses_payment_credit(self) -> bool:
    return bool(self.message.payment and self.message.payment.is_credit)
```

Mirrors of the `VmExecution` properties (models.py:404-412), which are deleted —
`update_allocations` was their only reader.

### 4.3 `create_vm_execution` (`src/aleph/vm/orchestrator/run.py`)

Spec path tail becomes:

```python
        record = registry.record(vm_hash, message=content, original=original_message.content, persistent=True)
        try:
            await _wait_until_running(supervisor, info.vm_id)
            ...
        except Exception:
            ...
            raise
        # Agent persists its own knowledge; the hypervisor object is not touched.
        await persist_record(vm_hash, record)
        return None
```

- Return type: `-> VmExecution | None` (also on
  `create_vm_execution_or_raise_http_error`). Verified callers: the three
  operator endpoints and `start_persistent_vm` discard the return;
  `run_code_on_request` / `run_code_on_event` use it but are program paths —
  `_is_spec_eligible` requires `InstanceContent`, so they can never receive
  `None` from the spec path *by construction*. Each gets an explicit guard
  anyway (clear 400 instead of a deep crash if an instance hash is ever
  submitted to the program path):

  ```python
  if execution is None:
      msg = f"VM {vm_hash} is an instance, not a program"
      raise HTTPBadRequest(reason=msg)
  ```

- The `MessageSpec` import in run.py goes if unused after this.
- Consequence, stated deliberately: spec-created executions now **never** carry
  a `MessageSpec` — `execution.message` is `None` for them in all code paths,
  first lifetime included. Future code reaching for `pool.executions[...].message`
  fails visibly in development rather than working-until-reboot.

### 4.4 Payment grouping (`tasks.py`): `_group_executions_by_payment`

`pool.get_executions_by_address` (pool.py:897-922) is **deleted** — payment
grouping is agent policy and does not belong on the pool. Replacement, private
to tasks.py next to its only consumer `check_payment`:

```python
def _group_executions_by_payment(
    pool: VmPool, registry: AgentVmRegistry, payment_type: PaymentType
) -> dict[str, dict[Chain, list[VmExecution]]]:
    """Group running executions by sender address and chain for one payment type.

    The message (payment tier, owner address) comes from the agent registry;
    the execution supplies only structural facts. Replaces the pool method that
    read the message off the hypervisor object — and thereby skipped spec-built
    and restart-restored VMs entirely.
    """
    executions_by_address: dict[str, dict[Chain, list[VmExecution]]] = {}
    for vm_hash, execution in pool.executions.items():
        record = registry.get(vm_hash)
        if record is None:
            # The agent has no message for this VM (e.g. the diagnostic fake
            # never enters the registry); payment grouping cannot apply.
            continue
        if execution.vm_hash in (settings.CHECK_FASTAPI_VM_ID, settings.LEGACY_CHECK_FASTAPI_VM_ID):
            continue  # diagnostic VM
        if not execution.is_running:
            continue
        payment = record.message.payment if record.message.payment else Payment(chain=Chain.ETH, type=PaymentType.hold)
        if payment.type == payment_type:
            executions_by_address.setdefault(record.message.address, {}).setdefault(payment.chain, []).append(execution)
    return executions_by_address
```

`check_payment`'s three call sites
(`pool.get_executions_by_address(payment_type=...)`, tasks.py:354/381/404)
become `_group_executions_by_payment(pool, registry, ...)`; the registry is
already a `check_payment` parameter. Everything downstream is untouched — the
returned executions are only read structurally (`is_confidential`, `vm_hash`,
`times.started_at`; the `compute_required_*` helpers read `vm_hash`), all
spec-safe.

**Behavior change (intended):** spec-built and restart-restored VMs were
silently excluded from all payment checks (the old method skipped
`message is None`); with the registry as source (rehydrated from the agent DB)
they are now covered. The diagnostic fake VM stays excluded (never recorded in
the registry, plus the explicit hash check).

### 4.5 `update_allocations` guards (`views/__init__.py`)

In the persistent-execution stop loop (views/__init__.py:582-601), the two
`execution.uses_payment_*` reads become registry-record reads. Concretely:

```python
for execution in list(pool.get_persistent_executions()):
    record = registry.get(execution.vm_hash)
    if (
        execution.vm_hash not in allocations
        and execution.is_running
        and not (record and record.uses_payment_stream)
        and not (record and record.uses_payment_credit)
        and not execution.gpus
        and not execution.is_confidential
    ):
        ...
```

(`registry` is already in scope in `update_allocations`.) A VM without a
registry record behaves
as today's message-less execution (`False` / hold-tier). With the registry
rehydrated across restarts, a restored PAYG VM under the legacy notify flow is
no longer reapable as "unallocated hold-tier" — the transition-window hole this
migration closes.

### 4.6 `_handle_domains_aggregate` (`tasks.py`)

Gains a `registry` parameter (in scope at the call site, tasks.py:192):

```python
has_local_instance = any(
    execution.is_instance
    and execution.vm
    and (record := registry.get(execution.vm_hash)) is not None
    and record.message.address == address
    for execution in pool.executions.values()
)
```

Spec-built and restored instances now trigger HAProxy domain-mapping refreshes;
previously they were silently skipped (message-less).

### 4.7 `VmExecution` removals (`src/aleph/vm/models.py`)

Delete `uses_payment_stream` and `uses_payment_credit` (only reader was
`update_allocations`; verify tests). `VmExecution.save()` and the `message` /
`original` properties stay — the legacy (non-spec) create path still uses them.

## 5. Behavior parity / changes

| Surface | Before | After |
|---|---|---|
| Agent restart memory | spec VMs persisted via readback-save | persisted via `persist_record` (same rehydration inputs) |
| Record debug fields | numeric `vm_id`, lifecycle times, mapped_ports | `None` / agent-stamped (debug endpoint only) |
| Payment checks, spec VM first lifetime | covered (via attach) | covered (via registry) |
| Payment checks, restored VMs | **silently escaped** | covered (registry rehydrates) |
| `update_allocations`, restored PAYG under legacy flow | reapable as hold-tier | protected (registry tier) |
| Domains aggregate, spec/restored VMs | silently skipped | covered |
| `pool.executions[...].message` for spec VMs | non-None in first lifetime | always `None` (fails visibly if newly depended on) |
| run_code paths given an instance hash | deep failure | explicit 400 |

## 6. Testing

- `persist_record` → `rehydrate_registry` round-trip (message/original/
  persistent survive; field deltas as specified).
- Routing test (`test_supervisor_run_routing.py`): spec path returns `None`,
  never touches `pool.executions`, and a record lands in the DB (existing test
  asserting the readback updates accordingly).
- `_group_executions_by_payment`: registry-sourced grouping; a message-less
  execution WITH a registry record (the restored-VM scenario) is included; one
  WITHOUT a record is skipped; diagnostic hash excluded; payment default =
  hold.
- `update_allocations`: a persistent execution whose registry record is
  stream-paid is spared even when absent from allocations.
- Domains aggregate: spec VM + registry record triggers the refresh.
- Guard: `pool.py` contains no `.message` read (source scan), mirroring the
  operator.py guard from #971.
- `VmExecution.uses_payment_*` gone (API test), existing suites green.

## 7. Out-of-scope residuals after this PR

- Deletion of agent-side payment enforcement (with the legacy notify flow /
  scheduler transition).
- Structural `pool.executions` iteration in grouping, `check_payment`'s
  terminal loop, and `update_allocations` → supervisor list views (Phase-1).
- `execution.vm` hypervisor reads in operator.py (Phase-1 Supervisor API).
- `about_executions` raw-pool debug endpoint.
- The `create_vm_execution` legacy (non-spec) path — unchanged until the pool
  create path itself is supervisor-routed.
