# Agent-owned record persistence — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Kill the `create_vm_execution` readback (`pool.executions[vm_hash]` → `MessageSpec` attach → `execution.save()`) by making the agent persist its own `ExecutionRecord`, after migrating the remaining agent-side readers of pool-execution messages to the `AgentVmRegistry`.

**Architecture:** Reader migrations land first (payment grouping, `update_allocations` guards, domains aggregate) — each is a pure data-source swap that works with or without the readback. The readback removal lands last, once nothing depends on the glued-on message. A new `persist_record` in `vm_registry.py` is the write-side sibling of `rehydrate_registry`.

**Tech Stack:** Python 3, aiohttp, SQLAlchemy (async), pytest / pytest-asyncio, `mocker` / `monkeypatch`.

**Design doc:** `docs/plans/2026-06-10-agent-record-persistence-design.md`

**Branch:** `od/wire-supervisor-agent-records` (stacked on #971 `od/wire-supervisor-owner-auth`).

---

## Environment notes (read before running anything)

- **Every `Bash` command needs `dangerouslyDisableSandbox: true`** (the repo's seccomp profile blocks sandboxed exec with `apply-seccomp ... Permission denied`).
- **This worktree has no local venv, and `settings.setup()` mkdirs under `/var`** (PermissionError in this sandbox). Run ALL tests as:
  ```bash
  cd /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-expiry
  mkdir -p "$TMPDIR/alephcache" "$TMPDIR/alephlib"
  ALEPH_VM_CACHE_ROOT="$TMPDIR/alephcache" ALEPH_VM_EXECUTION_ROOT="$TMPDIR/alephlib" \
    PYTHONPATH=src /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views/.testvenv/bin/python \
    -m pytest <args> -p no:warnings
  ```
  Later steps abbreviate this as `...pytest <args>`; the env vars are always implied.
- **Style gates (CI):**
  ```bash
  uvx ruff@0.4.6 format --diff <touched files>
  uvx isort==5.13.2 --check-only --profile black <touched files>
  ```
  Apply with `uvx ruff@0.4.6 format <files>` if a diff shows. `uvx` writes an untracked `uv.lock` — **never `git add` it.**
- **Pre-existing environmental failures** in the broader `tests/supervisor` suite (pyroute2/netlink, Firecracker subprocess, `chown` Operation-not-permitted) are NOT regressions; judge against the dev baseline. The targeted files in this plan are fully green with the env overrides.
- **No `Co-Authored-By` trailer in commits.**

## Shared facts

- `AgentVmRecord` / `AgentVmRegistry` / `rehydrate_registry` live in `src/aleph/vm/orchestrator/vm_registry.py`. `AgentVmRecord` is a `@dataclass` with `message: ExecutableContent`, `original: ExecutableContent`, `persistent: bool = False`. `registry.record(...)` RETURNS the `AgentVmRecord`.
- `ExecutionRecord` and `save_record(record)` live in `src/aleph/vm/orchestrator/metrics.py` (`save_record` does a session merge+commit). `vm_registry.py` already imports `get_execution_records` from there.
- The readback being killed is `src/aleph/vm/orchestrator/run.py:243-255` (comment block starting `# TEMPORARY (PR 1 boundary, ...)`).
- `check_payment(pool, supervisor, registry)` in `src/aleph/vm/orchestrator/tasks.py` already receives the registry; its three grouping call sites are lines 354, 381, 404 (`pool.get_executions_by_address(payment_type=...)`).
- `tasks.py` already imports `PaymentType` (from `aleph_message.models`), `settings`, `VmPool`, `AgentVmRegistry`. It does NOT yet import `Payment`, `Chain`, or `VmExecution`.
- `pool.py` line 12 imports `Chain, InstanceContent, ItemHash, Payment, PaymentType` — `Chain`/`Payment`/`PaymentType` are used ONLY inside `get_executions_by_address` (verify before pruning; `InstanceContent`/`ItemHash` are used elsewhere).
- `update_allocations` (`src/aleph/vm/orchestrator/views/__init__.py:545`) already has `registry = request.app["vm_registry"]` in scope (line 572).
- Test-mocking pattern for registry DB functions: `monkeypatch.setattr("aleph.vm.orchestrator.vm_registry.<name>", AsyncMock(...))` (see `tests/supervisor/test_agent_vm_registry.py`).

---

## Task 1: `persist_record` + `AgentVmRecord` payment helpers

**Files:**
- Modify: `src/aleph/vm/orchestrator/vm_registry.py`
- Test: `tests/supervisor/test_agent_vm_registry.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/supervisor/test_agent_vm_registry.py` (file already imports `SimpleNamespace`, `AsyncMock`, `MagicMock`, `pytest`, `ItemHash`, `AgentVmRecord`, `AgentVmRegistry`, `rehydrate_registry`; extend the `vm_registry` import to add `persist_record`):

```python
def test_record_payment_helpers():
    stream = AgentVmRecord(
        message=SimpleNamespace(payment=SimpleNamespace(is_stream=True, is_credit=False)),
        original=MagicMock(),
    )
    credit = AgentVmRecord(
        message=SimpleNamespace(payment=SimpleNamespace(is_stream=False, is_credit=True)),
        original=MagicMock(),
    )
    hold = AgentVmRecord(message=SimpleNamespace(payment=None), original=MagicMock())

    assert stream.uses_payment_stream is True and stream.uses_payment_credit is False
    assert credit.uses_payment_stream is False and credit.uses_payment_credit is True
    assert hold.uses_payment_stream is False and hold.uses_payment_credit is False


@pytest.mark.asyncio
async def test_persist_record_writes_agent_fields(monkeypatch):
    saved = []
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.save_record",
        AsyncMock(side_effect=saved.append),
    )
    message = MagicMock()
    message.resources.vcpus = 2
    message.resources.memory = 1024
    message.model_dump_json.return_value = '{"m": 1}'
    original = MagicMock()
    original.model_dump_json.return_value = '{"o": 1}'

    await persist_record(_HASH, AgentVmRecord(message=message, original=original, persistent=True))

    assert len(saved) == 1
    db = saved[0]
    assert db.vm_hash == str(_HASH)
    assert db.vm_id is None  # numeric hypervisor id unknown agent-side (debug-only column)
    assert db.vcpus == 2 and db.memory == 1024
    assert db.message == '{"m": 1}'
    assert db.original_message == '{"o": 1}'
    assert db.persistent is True
    assert db.mapped_ports is None  # the PortMapping table is the authority
    assert db.time_defined is not None
    assert db.uuid  # fresh uuid per create, matching the old per-execution behavior


@pytest.mark.asyncio
async def test_persist_then_rehydrate_round_trip(monkeypatch):
    """What persist_record writes is exactly what rehydrate_registry needs."""
    saved = []
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.save_record",
        AsyncMock(side_effect=saved.append),
    )
    message = MagicMock()
    message.resources.vcpus = 1
    message.resources.memory = 256
    message.model_dump_json.return_value = '{"address": "0xabc"}'
    original = MagicMock()
    original.model_dump_json.return_value = '{"address": "0xabc"}'
    await persist_record(_HASH, AgentVmRecord(message=message, original=original, persistent=True))

    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_execution_records",
        AsyncMock(return_value=saved),
    )
    parsed = MagicMock()
    monkeypatch.setattr(
        "aleph.vm.orchestrator.vm_registry.get_message_executable_content",
        MagicMock(return_value=parsed),
    )
    registry = AgentVmRegistry()

    count = await rehydrate_registry(registry)

    assert count == 1
    rec = registry.get(_HASH)
    assert rec.message is parsed
    assert rec.persistent is True
```

- [ ] **Step 2: Run, verify they fail**

Run: `...pytest tests/supervisor/test_agent_vm_registry.py -v -p no:warnings`
Expected: ImportError on `persist_record` (and `uses_payment_stream` AttributeError if imports are split).

- [ ] **Step 3: Implement**

In `src/aleph/vm/orchestrator/vm_registry.py`:

Extend the imports:

```python
from datetime import datetime, timezone
from uuid import uuid4

from aleph.vm.orchestrator.metrics import (
    ExecutionRecord,
    get_execution_records,
    save_record,
)
```

(`json` and `logging` are already imported.)

Add the two properties to `AgentVmRecord` (after the dataclass fields):

```python
    @property
    def uses_payment_stream(self) -> bool:
        return bool(self.message.payment and self.message.payment.is_stream)

    @property
    def uses_payment_credit(self) -> bool:
        return bool(self.message.payment and self.message.payment.is_credit)
```

Add at module level (after `rehydrate_registry`):

```python
async def persist_record(vm_hash: ItemHash, record: AgentVmRecord) -> None:
    """Persist the agent's knowledge of a VM to the agent DB.

    Write-side sibling of rehydrate_registry: what this writes is exactly what
    rehydrate_registry needs to rebuild the registry after a restart (message,
    original, persistent), carried on the existing ExecutionRecord table.
    Hypervisor-owned facts are deliberately absent: vm_id (numeric id unknown
    agent-side) and mapped_ports (the PortMapping table is the authority) are
    None; both are read only by the debug records endpoint.
    """
    now = datetime.now(tz=timezone.utc)
    resources = record.message.resources
    db_record = ExecutionRecord(
        uuid=str(uuid4()),
        vm_hash=str(vm_hash),
        vm_id=None,
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
        gpus=json.dumps([]),
        mapped_ports=None,
    )
    await save_record(db_record)
```

- [ ] **Step 4: Run, verify green**

Run: `...pytest tests/supervisor/test_agent_vm_registry.py -v -p no:warnings`
Expected: all PASS (the pre-existing rehydrate tests included).

- [ ] **Step 5: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/vm_registry.py tests/supervisor/test_agent_vm_registry.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/vm_registry.py tests/supervisor/test_agent_vm_registry.py
git add src/aleph/vm/orchestrator/vm_registry.py tests/supervisor/test_agent_vm_registry.py
git commit -m "feat(agent-records): persist_record + AgentVmRecord payment helpers"
```

---

## Task 2: Payment grouping moves to the agent

**Files:**
- Modify: `src/aleph/vm/orchestrator/tasks.py` (new `_group_executions_by_payment`, 3 call-site swaps in `check_payment`)
- Modify: `src/aleph/vm/pool.py` (delete `get_executions_by_address`, prune orphaned imports)
- Create: `tests/supervisor/test_tasks_registry_reads.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/supervisor/test_tasks_registry_reads.py`:

```python
"""Agent-side registry reads in tasks.py: payment grouping and the domains aggregate."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import Chain, ItemHash, Payment, PaymentType

from aleph.vm.conf import settings
from aleph.vm.orchestrator.tasks import _group_executions_by_payment
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry

_HASH = ItemHash("deadbeef" * 8)
_OTHER = ItemHash("cafecafe" * 8)


def _execution(vm_hash: ItemHash, *, is_running: bool = True) -> SimpleNamespace:
    # Message-less, structurally-typed stand-in for a spec-built pool execution.
    return SimpleNamespace(vm_hash=vm_hash, is_running=is_running)


def _registry_with(vm_hash: ItemHash, *, payment: Payment | None, address: str = "0xabc") -> AgentVmRegistry:
    registry = AgentVmRegistry()
    registry.record(
        vm_hash,
        message=SimpleNamespace(payment=payment, address=address),
        original=MagicMock(),
        persistent=True,
    )
    return registry


def test_grouping_sources_message_from_registry():
    """A message-less (spec-built / restored) execution with a registry record is grouped."""
    payment = Payment(chain=Chain.ETH, type=PaymentType.superfluid)
    registry = _registry_with(_HASH, payment=payment)
    pool = SimpleNamespace(executions={_HASH: _execution(_HASH)})

    groups = _group_executions_by_payment(pool, registry, PaymentType.superfluid)

    assert list(groups) == ["0xabc"]
    assert list(groups["0xabc"]) == [Chain.ETH]
    assert groups["0xabc"][Chain.ETH][0].vm_hash == _HASH


def test_grouping_skips_unrecorded_executions():
    """No registry record -> the agent knows no message -> not grouped."""
    pool = SimpleNamespace(executions={_HASH: _execution(_HASH)})

    groups = _group_executions_by_payment(pool, AgentVmRegistry(), PaymentType.superfluid)

    assert groups == {}


def test_grouping_defaults_to_hold_and_filters_by_type():
    registry = _registry_with(_HASH, payment=None)  # no payment -> hold tier
    pool = SimpleNamespace(executions={_HASH: _execution(_HASH)})

    assert _group_executions_by_payment(pool, registry, PaymentType.superfluid) == {}
    hold_groups = _group_executions_by_payment(pool, registry, PaymentType.hold)
    assert hold_groups["0xabc"][Chain.ETH][0].vm_hash == _HASH


def test_grouping_skips_stopped_and_diagnostic_executions():
    payment = Payment(chain=Chain.ETH, type=PaymentType.hold)
    registry = _registry_with(_HASH, payment=payment)
    fake_hash = ItemHash(settings.FAKE_INSTANCE_ID)
    registry.record(
        fake_hash,
        message=SimpleNamespace(payment=payment, address="0xabc"),
        original=MagicMock(),
        persistent=True,
    )
    diag = SimpleNamespace(vm_hash=ItemHash(settings.CHECK_FASTAPI_VM_ID), is_running=True)
    registry.record(
        diag.vm_hash,
        message=SimpleNamespace(payment=payment, address="0xabc"),
        original=MagicMock(),
        persistent=True,
    )
    pool = SimpleNamespace(
        executions={
            _HASH: _execution(_HASH, is_running=False),  # stopped -> skipped
            diag.vm_hash: diag,  # diagnostic -> skipped
        }
    )

    assert _group_executions_by_payment(pool, registry, PaymentType.hold) == {}


def test_pool_has_no_message_reads():
    """pool.py must not learn messages off executions; that is registry territory."""
    import inspect

    from aleph.vm import pool as pool_module

    source = inspect.getsource(pool_module)
    assert "execution.message" not in source
    assert "get_executions_by_address" not in source
```

- [ ] **Step 2: Run, verify they fail**

Run: `...pytest tests/supervisor/test_tasks_registry_reads.py -v -p no:warnings`
Expected: ImportError on `_group_executions_by_payment`; the source-scan test fails on both assertions.

- [ ] **Step 3: Implement `_group_executions_by_payment` in tasks.py**

In `src/aleph/vm/orchestrator/tasks.py`:

Extend imports: the `from aleph_message.models import ...` line gains `Chain` and `Payment` (alongside the existing `PaymentType`); add `from aleph.vm.models import VmExecution` (needed for the annotation; no import cycle — models does not import tasks).

Add the function directly above `check_payment`:

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
            # Ignore the diagnostic VM
            continue
        if not execution.is_running:
            continue
        payment = record.message.payment if record.message.payment else Payment(chain=Chain.ETH, type=PaymentType.hold)
        if payment.type == payment_type:
            executions_by_address.setdefault(record.message.address, {}).setdefault(payment.chain, []).append(
                execution
            )
    return executions_by_address
```

- [ ] **Step 4: Swap the three call sites in `check_payment`**

Replace (tasks.py:354):
```python
    for execution_address, chains in pool.get_executions_by_address(payment_type=PaymentType.hold).items():
```
with:
```python
    for execution_address, chains in _group_executions_by_payment(pool, registry, PaymentType.hold).items():
```

Replace (tasks.py:381):
```python
    for execution_address, chains in pool.get_executions_by_address(payment_type=PaymentType.credit).items():
```
with:
```python
    for execution_address, chains in _group_executions_by_payment(pool, registry, PaymentType.credit).items():
```

Replace (tasks.py:404):
```python
    for execution_address, chains in pool.get_executions_by_address(payment_type=PaymentType.superfluid).items():
```
with:
```python
    for execution_address, chains in _group_executions_by_payment(pool, registry, PaymentType.superfluid).items():
```

- [ ] **Step 5: Delete `pool.get_executions_by_address` and prune imports**

In `src/aleph/vm/pool.py`, delete the whole method (lines 897-922):

```python
    def get_executions_by_address(self, payment_type: PaymentType) -> dict[str, dict[str, list[VmExecution]]]:
        """Return all executions of the given type, grouped by sender and by chain."""
        executions_by_address: dict[str, dict[str, list[VmExecution]]] = {}
        for vm_hash, execution in self.executions.items():
            message = execution.message
            if message is None:
                # Spec-built (supervisor-owned) executions carry no message;
                # payment grouping is an agent concern.
                continue
            if execution.vm_hash in (settings.CHECK_FASTAPI_VM_ID, settings.LEGACY_CHECK_FASTAPI_VM_ID):
                # Ignore Diagnostic VM execution
                continue

            if not execution.is_running:
                # Ignore the execution that is stopping or not running anymore
                continue
            if execution.vm_hash == settings.CHECK_FASTAPI_VM_ID:
                # Ignore Diagnostic VM execution
                continue
            execution_payment = message.payment if message.payment else Payment(chain=Chain.ETH, type=PaymentType.hold)
            if execution_payment.type == payment_type:
                address = message.address
                chain = execution_payment.chain
                executions_by_address.setdefault(address, {})
                executions_by_address[address].setdefault(chain, []).append(execution)
        return executions_by_address
```

Then check whether `Payment`, `PaymentType`, `Chain` are still used anywhere in pool.py (`grep -n "Payment\|Chain" src/aleph/vm/pool.py`); they are expected to be orphaned — trim the line-12 import to `from aleph_message.models import InstanceContent, ItemHash` (keep any name still in use).

- [ ] **Step 6: Run, verify green**

Run: `...pytest tests/supervisor/test_tasks_registry_reads.py tests/supervisor/test_views.py -q -p no:warnings`
Expected: new tests PASS; `test_views.py` stays green (check_payment is not HTTP-exercised there, but the import graph is — a broken pool.py import would fail collection).

- [ ] **Step 7: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/tasks.py src/aleph/vm/pool.py tests/supervisor/test_tasks_registry_reads.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/tasks.py src/aleph/vm/pool.py tests/supervisor/test_tasks_registry_reads.py
git add src/aleph/vm/orchestrator/tasks.py src/aleph/vm/pool.py tests/supervisor/test_tasks_registry_reads.py
git commit -m "refactor(agent-records): payment grouping reads the registry, off the pool"
```

---

## Task 3: `update_allocations` guards read the registry; delete the dead `VmExecution` properties

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/__init__.py:582-590`
- Modify: `src/aleph/vm/models.py` (delete `uses_payment_stream` / `uses_payment_credit`, lines 404-412)
- Test: `tests/supervisor/test_views.py`, `tests/supervisor/test_execution.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/supervisor/test_views.py` (model: `test_update_allocations_stop_loop_uses_supervisor` at line 1170 — reuse its imports and the same `instance_content` shape):

```python
@pytest.mark.asyncio
async def test_update_allocations_spares_payg_via_registry(aiohttp_client, mocker):
    """A message-less execution whose REGISTRY record is stream-paid must be spared
    by the stop loop even when absent from the allocation (the restored-PAYG case)."""
    vm_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    instance_content = {
        "address": "0x101d8D16372dBf5f1614adaE95Ee5CCE61998Fc9",
        "time": 1713874241.800818,
        "allow_amend": False,
        "metadata": None,
        "authorized_keys": None,
        "variables": None,
        "environment": {"reproducible": False, "internet": True, "aleph_api": True, "shared_cache": False},
        "resources": {"vcpus": 1, "memory": 256, "seconds": 30, "published_ports": None},
        "payment": {"type": "superfluid", "chain": "BASE"},
        "requirements": None,
        "replaces": None,
        "rootfs": {
            "parent": {"ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696"},
            "ref": "63f07193e6ee9d207b7d1fcf8286f9aee34e6f12f101d2ec77c1229f92964696",
            "use_latest": True,
            "comment": "",
            "persistence": "host",
            "size_mib": 1000,
        },
    }
    message = InstanceContent.model_validate(instance_content)

    # Message-less, structurally-typed stand-in for a restored spec-built execution:
    # the payment tier is knowable only through the registry.
    execution = SimpleNamespace(
        vm_hash=ItemHash(vm_hash),
        is_running=True,
        gpus=[],
        is_confidential=False,
        is_instance=True,
    )

    class FakeVmPool:
        def get_persistent_executions(self):
            return [execution]

    pool = FakeVmPool()
    app = setup_webapp(pool=pool)
    app["pubsub"] = None
    app["vm_registry"].record(ItemHash(vm_hash), message=message, original=message, persistent=True)

    fake_supervisor = MagicMock(delete_vm=AsyncMock())
    app["supervisor"] = fake_supervisor

    settings.ALLOCATION_TOKEN_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"  # = "test"
    client = await aiohttp_client(app)

    response = await client.post(
        "/control/allocations",
        json={"persistent_vms": []},
        headers={"X-Auth-Signature": "test"},
    )
    assert response.status == 200
    resp_json = await response.json()
    assert vm_hash not in resp_json["stopped"]
    fake_supervisor.delete_vm.assert_not_awaited()
    assert ItemHash(vm_hash) in app["vm_registry"]
```

(If `SimpleNamespace` is not yet imported in test_views.py, add `from types import SimpleNamespace`.)

Append to `tests/supervisor/test_execution.py` (mirroring the `#970` pattern `test_vm_execution_has_no_update_watch_api`):

```python
def test_vm_execution_has_no_payment_api():
    """Payment tier is agent knowledge (AgentVmRecord), not a hypervisor-object concern."""
    assert not hasattr(VmExecution, "uses_payment_stream")
    assert not hasattr(VmExecution, "uses_payment_credit")
```

- [ ] **Step 2: Run, verify they fail**

Run: `...pytest "tests/supervisor/test_views.py::test_update_allocations_spares_payg_via_registry" "tests/supervisor/test_execution.py::test_vm_execution_has_no_payment_api" -v -p no:warnings`
Expected: the views test FAILS — current code reads `execution.uses_payment_stream`, which the `SimpleNamespace` lacks → AttributeError → 500 (or, were a real message-less execution used, `False` → wrongly stopped). The execution test FAILS (properties still exist).

- [ ] **Step 3: Migrate the guard in `update_allocations`**

In `src/aleph/vm/orchestrator/views/__init__.py`, replace (lines 582-590):

```python
        for execution in list(pool.get_persistent_executions()):
            if (
                execution.vm_hash not in allocations
                and execution.is_running
                and not execution.uses_payment_stream
                and not execution.uses_payment_credit
                and not execution.gpus
                and not execution.is_confidential
            ):
```

with:

```python
        for execution in list(pool.get_persistent_executions()):
            # Payment tier comes from the agent registry, not the hypervisor
            # object: spec-built and restart-restored executions carry no
            # message, but their registry record (rehydrated from the agent DB)
            # does. No record behaves as hold-tier, exactly like the old
            # message-less False.
            record = registry.get(execution.vm_hash)
            if (
                execution.vm_hash not in allocations
                and execution.is_running
                and not (record and record.uses_payment_stream)
                and not (record and record.uses_payment_credit)
                and not execution.gpus
                and not execution.is_confidential
            ):
```

- [ ] **Step 4: Delete the dead properties from `VmExecution`**

First verify there are no remaining readers: `grep -rn "uses_payment_stream\|uses_payment_credit" src/ tests/` — expected hits only in `vm_registry.py` (the new record properties), `views/__init__.py` (now via `record.`), and the tests from this plan. Then delete from `src/aleph/vm/models.py` (lines 404-412):

```python
    @property
    def uses_payment_stream(self) -> bool:
        message = self.message
        return bool(message and message.payment and message.payment.is_stream)

    @property
    def uses_payment_credit(self) -> bool:
        message = self.message
        return bool(message and message.payment and message.payment.is_credit)
```

- [ ] **Step 5: Run, verify green (including the pre-existing stop-loop test)**

Run: `...pytest tests/supervisor/test_views.py tests/supervisor/test_execution.py -q -p no:warnings`
Expected: the new tests PASS; `test_update_allocations_stop_loop_uses_supervisor` STAYS green (its registry record is hold-paid → guard still false → VM still stopped). `test_execution.py` has pre-existing environmental failures (`chown` Operation-not-permitted) — only the new test and no NEW failures matter.

- [ ] **Step 6: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/models.py tests/supervisor/test_views.py tests/supervisor/test_execution.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/models.py tests/supervisor/test_views.py tests/supervisor/test_execution.py
git add src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/models.py tests/supervisor/test_views.py tests/supervisor/test_execution.py
git commit -m "refactor(agent-records): update_allocations payment guards read the registry; drop dead VmExecution payment properties"
```

---

## Task 4: `_handle_domains_aggregate` reads the registry

**Files:**
- Modify: `src/aleph/vm/orchestrator/tasks.py:192,224-240`
- Test: `tests/supervisor/test_tasks_registry_reads.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/supervisor/test_tasks_registry_reads.py` (add `_handle_domains_aggregate` to the tasks import):

```python
@pytest.mark.asyncio
async def test_domains_aggregate_triggers_for_registry_recorded_instance():
    """A message-less (spec-built / restored) instance must still trigger the
    HAProxy domain-mapping refresh when its registry record matches the owner."""
    registry = _registry_with(_HASH, payment=None, address="0xowner")
    execution = SimpleNamespace(vm_hash=_HASH, is_instance=True, vm=object())
    pool = SimpleNamespace(
        executions={_HASH: execution},
        update_domain_mapping=AsyncMock(),
    )
    aggregate = SimpleNamespace(content=SimpleNamespace(address="0xowner"))

    await _handle_domains_aggregate(aggregate, pool, registry)

    pool.update_domain_mapping.assert_awaited_once()


@pytest.mark.asyncio
async def test_domains_aggregate_ignores_unrelated_address():
    registry = _registry_with(_HASH, payment=None, address="0xowner")
    execution = SimpleNamespace(vm_hash=_HASH, is_instance=True, vm=object())
    pool = SimpleNamespace(
        executions={_HASH: execution},
        update_domain_mapping=AsyncMock(),
    )
    aggregate = SimpleNamespace(content=SimpleNamespace(address="0xsomeoneelse"))

    await _handle_domains_aggregate(aggregate, pool, registry)

    pool.update_domain_mapping.assert_not_awaited()
```

- [ ] **Step 2: Run, verify they fail**

Run: `...pytest tests/supervisor/test_tasks_registry_reads.py -k domains -v -p no:warnings`
Expected: TypeError (the function takes 2 positional args today) — and were the signature already extended, the first test would fail because current code reads `execution.message` (absent on the `SimpleNamespace`).

- [ ] **Step 3: Implement**

In `src/aleph/vm/orchestrator/tasks.py`, change the signature and the check (lines 224-240):

```python
async def _handle_domains_aggregate(message: AggregateMessage, pool: VmPool, registry: AgentVmRegistry):
    """Update HAProxy domain mapping when a domains aggregate changes.

    The aggregate content maps domain names to instance configs:
    {"testd.example.com": {"message_id": "<item_hash>", "type": "instance"}}

    Only trigger if any referenced message_id matches a locally running instance.
    """
    address = message.content.address

    # Trigger if the address owns any running instance on this node. The owner
    # address comes from the agent registry, not the hypervisor object —
    # spec-built and restored executions carry no message.
    # This covers both additions (new domain pointing to local instance)
    # and deletions (domain removed — need to clean up the map).
    has_local_instance = any(
        execution.is_instance
        and execution.vm
        and (record := registry.get(execution.vm_hash)) is not None
        and record.message.address == address
        for execution in pool.executions.values()
    )
    if not has_local_instance:
        return
```

(the `logger.info` / `try: await pool.update_domain_mapping()` tail is unchanged.)

Update the caller (tasks.py:192):

```python
                elif key == "domains":
                    await _handle_domains_aggregate(message, pool, registry)
```

(`registry` is already in scope in `watch_for_messages` — it is passed to the port-forwarding handler two lines above.)

- [ ] **Step 4: Run, verify green**

Run: `...pytest tests/supervisor/test_tasks_registry_reads.py -v -p no:warnings`
Expected: all PASS.

- [ ] **Step 5: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/tasks.py tests/supervisor/test_tasks_registry_reads.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/tasks.py tests/supervisor/test_tasks_registry_reads.py
git add src/aleph/vm/orchestrator/tasks.py tests/supervisor/test_tasks_registry_reads.py
git commit -m "refactor(agent-records): domains aggregate reads the owner address from the registry"
```

---

## Task 5: Kill the `create_vm_execution` readback

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (spec-path tail, signatures, None-guards, imports)
- Test: `tests/supervisor/test_supervisor_run_routing.py`

- [ ] **Step 1: Update the routing test (red)**

In `tests/supervisor/test_supervisor_run_routing.py`, rewrite `test_eligible_instance_routed_through_supervisor` (lines 85-122) as:

```python
@pytest.mark.asyncio
async def test_eligible_instance_routed_through_supervisor(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    original_content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    original_message = MagicMock(content=original_content)
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    spec = _spec()
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=spec))
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    persist = AsyncMock()
    monkeypatch.setattr(run_module, "persist_record", persist)

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()
    # An EMPTY pool: the spec path must never read pool.executions (the old
    # readback would KeyError here).
    pool = SimpleNamespace(executions={}, create_a_vm=AsyncMock())

    execution = await run_module.create_vm_execution(
        _HASH, pool, supervisor=supervisor, registry=registry, persistent=True
    )

    supervisor.create_vm.assert_awaited_once_with(spec)
    pool.create_a_vm.assert_not_awaited()
    # The message is recorded in the agent registry, not on the execution.
    record = registry.get(_HASH)
    assert record.message is content
    assert record.original is original_content
    assert record.persistent is True
    # The agent persists its own record; the hypervisor object is never touched.
    persist.assert_awaited_once_with(_HASH, record)
    # SSH port-forward applied through the abstraction.
    assert supervisor.add_port_forward.await_count >= 1
    # Spec path returns None: no caller consumes a hypervisor object from it.
    assert execution is None
    supervisor.delete_vm.assert_not_awaited()
```

Also remove the now-unused `from aleph.vm.models import MessageSpec` import at the top of the test file (line 20) — it was used only by the deleted assertion (verify with a grep within the file before removing).

- [ ] **Step 2: Run, verify it fails**

Run: `...pytest tests/supervisor/test_supervisor_run_routing.py -v -p no:warnings`
Expected: `test_eligible_instance_routed_through_supervisor` FAILS — current code does `pool.executions[vm_hash]` → KeyError on the empty pool (and `run_module.persist_record` does not exist yet for the monkeypatch → AttributeError; either way red).

- [ ] **Step 3: Implement in run.py**

In `src/aleph/vm/orchestrator/run.py`:

Imports: extend the registry import to `from aleph.vm.orchestrator.vm_registry import AgentVmRegistry, persist_record`. Check remaining uses of `MessageSpec` in the file (`grep -n "MessageSpec" src/aleph/vm/orchestrator/run.py`); after this change the attach is gone — if no use remains, trim line 26 to `from aleph.vm.models import VmExecution`.

Signature (line 209-216): change the return annotation:

```python
async def create_vm_execution(
    vm_hash: ItemHash,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    persistent: bool = False,
) -> VmExecution | None:
```

Capture the record (line 229):

```python
        record = registry.record(vm_hash, message=content, original=original_message.content, persistent=True)
```

Replace the readback tail (lines 243-255):

```python
        # TEMPORARY (PR 1 boundary, design doc sections 5/8): the operator
        # endpoints, billing and update-watching still read owner identity and
        # the message off the VmExecution, and start_persistent_vm drives it for
        # the pre-existing check and expiry-cancel. Re-source the message-free
        # execution as message-driven and hand it back unchanged. This goes away
        # when those consumers read the registry instead.
        execution = pool.executions[vm_hash]
        execution.spec = MessageSpec(message=content, original=original_message.content)
        # The spec create path skipped save() (no MessageSpec at start time).
        # Persist the record now: registry rehydration and past-logs owner
        # auth read the message back from the agent DB.
        await execution.save()
        return execution
```

with:

```python
        # Agent persists its own knowledge; the hypervisor object is not
        # touched. Registry rehydration and past-logs owner-auth read the
        # message back from the agent DB.
        await persist_record(vm_hash, record)
        return None
```

`create_vm_execution_or_raise_http_error` (line 267-273): return annotation becomes `-> VmExecution | None`.

None-guards in the two program paths — in `run_code_on_request`, after the create call (lines 337-339):

```python
        execution = await create_vm_execution_or_raise_http_error(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
        )
        if execution is None:
            # Spec-eligible messages are instances; they cannot serve code requests.
            raise HTTPBadRequest(reason=f"VM {vm_hash} is an instance, not a program")
```

and identically in `run_code_on_event` after its create call (lines 455-457):

```python
        execution = await create_vm_execution_or_raise_http_error(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
        )
        if execution is None:
            # Spec-eligible messages are instances; they cannot serve code requests.
            raise HTTPBadRequest(reason=f"VM {vm_hash} is an instance, not a program")
```

(`HTTPBadRequest` is already imported in run.py.)

- [ ] **Step 4: Run, verify green**

Run: `...pytest tests/supervisor/test_supervisor_run_routing.py tests/supervisor/test_views.py tests/supervisor/views/test_operator.py -q -p no:warnings`
Expected: all PASS — the routing file's teardown tests (`timeout_tears_down`, `port_forward_failure_tears_down`) already use `executions={}` pools and never reach the tail; operator/views suites prove the three discard-return callers and `start_persistent_vm` are unaffected.

- [ ] **Step 5: Style + commit**

```bash
uvx ruff@0.4.6 format --diff src/aleph/vm/orchestrator/run.py tests/supervisor/test_supervisor_run_routing.py
uvx isort==5.13.2 --check-only --profile black src/aleph/vm/orchestrator/run.py tests/supervisor/test_supervisor_run_routing.py
git add src/aleph/vm/orchestrator/run.py tests/supervisor/test_supervisor_run_routing.py
git commit -m "refactor(agent-records): create_vm_execution persists agent-side; drop the pool readback"
```

---

## Task 6: Whole-branch verification

**Files:** none (verification only)

- [ ] **Step 1: Source-scan invariants**

```bash
grep -n "execution.message" src/aleph/vm/pool.py src/aleph/vm/orchestrator/views/operator.py
grep -rn "get_executions_by_address\|uses_payment_stream\|uses_payment_credit" src/aleph/vm/pool.py src/aleph/vm/models.py
grep -n "pool.executions\[" src/aleph/vm/orchestrator/run.py
```
Expected: no output from any of the three.

- [ ] **Step 2: Run the touched test files**

Run: `...pytest tests/supervisor/test_agent_vm_registry.py tests/supervisor/test_tasks_registry_reads.py tests/supervisor/test_supervisor_run_routing.py tests/supervisor/test_views.py tests/supervisor/views/test_operator.py -q -p no:warnings`
Expected: all PASS.

- [ ] **Step 3: Baseline check on the broader supervisor suite**

Run: `...pytest tests/supervisor -q -p no:warnings 2>&1 | tail -10`
Expected: the failing set matches the pre-existing environmental baseline (pyroute2/netlink, Firecracker subprocess/`chown`); no NEW failures in registry/payment/views/run files. If a failure looks new, check the same test against the branch base (`git stash` is NOT sufficient for committed work — check out the base commit) before attributing it.

- [ ] **Step 4: Final style gate + commit (only if anything changed)**

```bash
uvx ruff@0.4.6 format --diff $(git diff --name-only od/wire-supervisor-owner-auth..HEAD -- 'src/*.py' 'tests/*.py')
uvx isort==5.13.2 --check-only --profile black $(git diff --name-only od/wire-supervisor-owner-auth..HEAD -- 'src/*.py' 'tests/*.py')
git status --porcelain   # must NOT list uv.lock as staged
```

---

## Done criteria

- `create_vm_execution`'s spec path never touches `pool.executions`; the agent persists its own `ExecutionRecord` (`persist_record`), and the path returns `None`.
- `pool.py` contains no message reads and no `get_executions_by_address` (guard test).
- Payment grouping, `update_allocations` guards, and the domains aggregate read the registry; restored/spec VMs are covered by all three (tests).
- `VmExecution.uses_payment_stream` / `uses_payment_credit` are gone (API test).
- Touched test files green; broader suite matches the environmental baseline.
- Style gates clean; no `uv.lock` staged; no `Co-Authored-By` trailer.

## Out of scope (design §7)

- `check_payment`'s balance/credit/stream logic and terminal-status loop (deprecates with the legacy notify flow).
- Structural `pool.executions` iteration (Phase-1 supervisor list views).
- `execution.vm` reads in operator.py; the `about_executions` debug endpoint; the legacy (non-spec) create path.
