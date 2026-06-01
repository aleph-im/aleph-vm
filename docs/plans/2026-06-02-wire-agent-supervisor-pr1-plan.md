# Wire agent onto Supervisor abstraction: PR 1 (create path) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Route the agent's persistent-instance create path (`orchestrator/run.py:create_vm_execution`) through the `Supervisor` abstraction instead of reaching into the pool, with the message follow-up handled purely via an agent-side registry, `add_port_forward`, and a `get_vm` readiness poll.

**Architecture:** A single `InProcessSupervisor(pool)` and an `AgentVmRegistry` are constructed at app startup (`app["supervisor"]`, `app["vm_registry"]`) and injected into the run.py create functions. The eligible-instance branch builds a `CreateVmSpec`, calls `supervisor.create_vm(spec)`, records the message in the registry, polls `supervisor.get_vm` until `RUNNING`, resolves desired port-forwards from aggregate settings (agent policy), and applies them through `supervisor.add_port_forward`. No `VmExecution` crosses the boundary for the follow-up; the execution is read back from `pool.executions` exactly once (an explicitly temporary line, see design §8) so the unchanged `start_persistent_vm` can keep driving the residual expiry/update-watch ops.

**Tech Stack:** Python 3.11, asyncio, pydantic v2, pytest / pytest-asyncio. Test conventions per `tests/supervisor/`: sibling imports (no `__init__.py`), `monkeypatch`, ruff/isort/mypy green.

**Design doc:** `docs/plans/2026-06-01-wire-agent-onto-supervisor-design.md`

**Worktree:** `.worktrees/wire-supervisor-abstraction` on branch `od/wire-supervisor-abstraction` (off `dev`). All commands below assume that directory; the local venv is `.testvenv` and tests run with `ALEPH_VM_CACHE_ROOT`/`ALEPH_VM_EXECUTION_ROOT` redirected and `-p no:cacheprovider`.

---

## File Structure

| File | Responsibility | Change |
|------|----------------|--------|
| `src/aleph/vm/orchestrator/vm_registry.py` | Agent-side message cache (`AgentVmRecord` + `AgentVmRegistry`) | **Create** |
| `src/aleph/vm/orchestrator/run.py` | Create path: helpers + rewritten `create_vm_execution`; thread `supervisor`/`registry` through `create_vm_execution_or_raise_http_error` + `start_persistent_vm` | Modify |
| `src/aleph/vm/pool.py` | Remove vestigial `message_cache` | Modify (`:68`, `:81`) |
| `src/aleph/vm/orchestrator/supervisor.py` | App wiring: `app["supervisor"]`, `app["vm_registry"]` | Modify (`:165`) |
| `src/aleph/vm/orchestrator/views/__init__.py` | Pass `supervisor`/`registry` into `start_persistent_vm` (3 sites) | Modify |
| `src/aleph/vm/orchestrator/views/operator.py` | Pass `supervisor`/`registry` into `create_vm_execution_or_raise_http_error` (2 sites) | Modify |
| `src/aleph/vm/orchestrator/cli.py` | Build `InProcessSupervisor`/`AgentVmRegistry` locally for the standalone path (1 site) | Modify |
| `tests/supervisor/test_agent_vm_registry.py` | Registry unit tests | **Create** |
| `tests/supervisor/test_supervisor_run_helpers.py` | `resolve_port_forwards` + `_wait_until_running` unit tests | **Create** |
| `tests/supervisor/test_supervisor_run_routing.py` | Rewritten routing tests (new signature + registry) | Modify |

---

## Task 1: `AgentVmRegistry` (agent-side message cache)

**Files:**
- Create: `src/aleph/vm/orchestrator/vm_registry.py`
- Test: `tests/supervisor/test_agent_vm_registry.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_agent_vm_registry.py`:

```python
"""AgentVmRegistry: the agent-side message cache keyed by vm_hash."""

from __future__ import annotations

from unittest.mock import MagicMock

from aleph_message.models import ItemHash

from aleph.vm.orchestrator.vm_registry import AgentVmRecord, AgentVmRegistry

_HASH = ItemHash("deadbeef" * 8)


def test_record_and_get():
    registry = AgentVmRegistry()
    message, original = MagicMock(), MagicMock()

    record = registry.record(_HASH, message=message, original=original)

    assert record == AgentVmRecord(message=message, original=original)
    assert registry.get(_HASH) is record
    assert _HASH in registry
    assert len(registry) == 1


def test_get_unknown_returns_none():
    assert AgentVmRegistry().get(_HASH) is None
    assert _HASH not in AgentVmRegistry()


def test_forget_is_idempotent():
    registry = AgentVmRegistry()
    registry.record(_HASH, message=MagicMock(), original=MagicMock())

    registry.forget(_HASH)
    assert registry.get(_HASH) is None
    assert _HASH not in registry

    registry.forget(_HASH)  # forgetting an unknown hash must not raise
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_agent_vm_registry.py -p no:cacheprovider -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aleph.vm.orchestrator.vm_registry'`

- [ ] **Step 3: Create the module**

Create `src/aleph/vm/orchestrator/vm_registry.py`:

```python
"""Agent-side registry of VMs the agent knows about.

An in-memory cache for messages, keyed by vm_hash. The agent owns this; the
supervisor (hypervisor) never sees it. It replaces the vestigial
``pool.message_cache``. For now it is populated on create; a later iteration
rehydrates it from the agent DB on startup and, eventually, from the network
(scheduler plan + Aleph messages). See the design doc, sections 3 and 9.
"""

from __future__ import annotations

from dataclasses import dataclass

from aleph_message.models import ExecutableContent, ItemHash


@dataclass
class AgentVmRecord:
    """What the agent remembers about one VM: the (updated) message and the
    original message it was derived from. Used by agent-only consumers such as
    operator-API owner-auth, billing, and update-watching."""

    message: ExecutableContent
    original: ExecutableContent


class AgentVmRegistry:
    """In-memory cache of AgentVmRecord, keyed by vm_hash."""

    def __init__(self) -> None:
        self._records: dict[ItemHash, AgentVmRecord] = {}

    def record(
        self, vm_hash: ItemHash, *, message: ExecutableContent, original: ExecutableContent
    ) -> AgentVmRecord:
        record = AgentVmRecord(message=message, original=original)
        self._records[vm_hash] = record
        return record

    def get(self, vm_hash: ItemHash) -> AgentVmRecord | None:
        return self._records.get(vm_hash)

    def forget(self, vm_hash: ItemHash) -> None:
        self._records.pop(vm_hash, None)

    def __contains__(self, vm_hash: object) -> bool:
        return vm_hash in self._records

    def __len__(self) -> int:
        return len(self._records)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_agent_vm_registry.py -p no:cacheprovider -v`
Expected: PASS (3 passed)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/orchestrator/vm_registry.py tests/supervisor/test_agent_vm_registry.py
git commit -m "feat(agent): AgentVmRegistry message cache"
```

---

## Task 2: `resolve_port_forwards` (agent-side port-forward policy)

Extracts the agent half of `VmExecution.fetch_port_redirect_config_and_setup`: read the user aggregate settings, compute the requested ports, force SSH, and produce a list of `PortForwardSpec`. No nftables here; the supervisor applies them.

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (imports + new function)
- Test: `tests/supervisor/test_supervisor_run_helpers.py`

- [ ] **Step 1: Write the failing test**

Create `tests/supervisor/test_supervisor_run_helpers.py`:

```python
"""Unit tests for the run.py create-path helpers (no pool, no I/O)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from aleph_message.models import ItemHash

from aleph.vm.orchestrator import run as run_module
from aleph.vm.supervisor.types import Protocol, VmId, VmStatus

_HASH = ItemHash("deadbeef" * 8)
_VM_ID = VmId(str(_HASH))


@pytest.mark.asyncio
async def test_resolve_port_forwards_always_forces_ssh(monkeypatch):
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value={}))
    content = SimpleNamespace(address="0xabc")

    forwards = await run_module.resolve_port_forwards(_VM_ID, content)

    assert (22, Protocol.TCP) in {(f.vm_port, f.protocol) for f in forwards}
    assert all(f.host_port == 0 and f.vm_id == _VM_ID for f in forwards)


@pytest.mark.asyncio
async def test_resolve_port_forwards_reads_settings(monkeypatch):
    payload = {str(_HASH): {"ports": {"80": {"tcp": True, "udp": False}, "53": {"tcp": False, "udp": True}}}}
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(return_value=payload))
    content = SimpleNamespace(address="0xabc")

    pairs = {(f.vm_port, f.protocol) for f in await run_module.resolve_port_forwards(_VM_ID, content)}

    assert (80, Protocol.TCP) in pairs
    assert (53, Protocol.UDP) in pairs
    assert (80, Protocol.UDP) not in pairs
    assert (22, Protocol.TCP) in pairs  # SSH still forced


@pytest.mark.asyncio
async def test_resolve_port_forwards_tolerates_settings_error(monkeypatch):
    monkeypatch.setattr(run_module, "get_user_settings", AsyncMock(side_effect=RuntimeError("boom")))
    content = SimpleNamespace(address="0xabc")

    forwards = await run_module.resolve_port_forwards(_VM_ID, content)

    assert [(f.vm_port, f.protocol) for f in forwards] == [(22, Protocol.TCP)]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_helpers.py -p no:cacheprovider -v`
Expected: FAIL with `AttributeError: module 'aleph.vm.orchestrator.run' has no attribute 'resolve_port_forwards'` (and `get_user_settings`)

- [ ] **Step 3: Add imports to `run.py`**

In `src/aleph/vm/orchestrator/run.py`, after the existing `from aleph.vm.supervisor.translate import build_create_vm_spec` import (line 29), add:

```python
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.types import (
    GuestPort,
    HostPort,
    PortForwardSpec,
    Protocol,
    VmId,
    VmInfo,
    VmStatus,
)
from aleph.vm.utils.aggregate import get_user_settings
```

- [ ] **Step 4: Add the helper**

In `src/aleph/vm/orchestrator/run.py`, add after `_is_spec_eligible` (around line 77) and before `create_vm_execution`:

```python
async def resolve_port_forwards(vm_id: VmId, content) -> list[PortForwardSpec]:
    """Agent-side policy: translate the user's port-forwarding aggregate settings
    into the set of forwards the hypervisor should apply.

    This is the agent half of the old VmExecution.fetch_port_redirect_config_and_setup.
    Nothing here touches nftables; the caller applies each spec through
    supervisor.add_port_forward. host_port is left 0; the hypervisor assigns it.
    """
    ports_requests: dict[int, dict[str, bool]] = {}
    try:
        settings_for_user = await get_user_settings(content.address, "port-forwarding")
        vm_port_forwarding = settings_for_user.get(str(vm_id), {}) or {}
        fetched = vm_port_forwarding.get("ports", {})
        ports_requests = {int(port): flags for port, flags in fetched.items()}
    except Exception:
        logger.info("Could not fetch port redirect settings for %s", content.address, exc_info=True)

    # Always forward SSH.
    ports_requests.setdefault(22, {"tcp": True, "udp": False})

    forwards: list[PortForwardSpec] = []
    for vm_port, flags in ports_requests.items():
        for protocol in (Protocol.TCP, Protocol.UDP):
            if flags.get(protocol.value):
                forwards.append(
                    PortForwardSpec(
                        vm_id=vm_id,
                        host_port=HostPort(0),
                        vm_port=GuestPort(int(vm_port)),
                        protocol=protocol,
                    )
                )
    return forwards
```

- [ ] **Step 5: Run test to verify it passes**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_helpers.py -p no:cacheprovider -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py tests/supervisor/test_supervisor_run_helpers.py
git commit -m "feat(agent): resolve_port_forwards from aggregate settings"
```

---

## Task 3: `_wait_until_running` (readiness poll)

Replaces `await execution.becomes_ready()`. Polls `get_vm` until `RUNNING`; raises on terminal status or timeout.

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py` (constants + new function)
- Test: `tests/supervisor/test_supervisor_run_helpers.py` (extend)

- [ ] **Step 1: Write the failing test**

Append to `tests/supervisor/test_supervisor_run_helpers.py`:

```python
@pytest.mark.asyncio
async def test_wait_until_running_returns_on_running(monkeypatch):
    booting = SimpleNamespace(status=VmStatus.BOOTING)
    running = SimpleNamespace(status=VmStatus.RUNNING)
    supervisor = SimpleNamespace(get_vm=AsyncMock(side_effect=[booting, running]))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    info = await run_module._wait_until_running(supervisor, _VM_ID, timeout=10, interval=0)

    assert info.status is VmStatus.RUNNING
    assert supervisor.get_vm.await_count == 2


@pytest.mark.asyncio
async def test_wait_until_running_raises_on_terminal_status(monkeypatch):
    supervisor = SimpleNamespace(get_vm=AsyncMock(return_value=SimpleNamespace(status=VmStatus.FAILED)))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    with pytest.raises(RuntimeError):
        await run_module._wait_until_running(supervisor, _VM_ID, timeout=10, interval=0)


@pytest.mark.asyncio
async def test_wait_until_running_times_out(monkeypatch):
    supervisor = SimpleNamespace(get_vm=AsyncMock(return_value=SimpleNamespace(status=VmStatus.BOOTING)))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())

    with pytest.raises(asyncio.TimeoutError):
        await run_module._wait_until_running(supervisor, _VM_ID, timeout=0, interval=0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_helpers.py -k wait_until_running -p no:cacheprovider -v`
Expected: FAIL with `AttributeError: module 'aleph.vm.orchestrator.run' has no attribute '_wait_until_running'`

- [ ] **Step 3: Add constants + the poll**

In `src/aleph/vm/orchestrator/run.py`, add module-level constants just below `logger = logging.getLogger(__name__)` (around line 35):

```python
# Readiness poll for the spec create path (replaces execution.becomes_ready()).
_START_POLL_TIMEOUT_SECONDS = 120.0
_START_POLL_INTERVAL_SECONDS = 0.5
```

Add the function immediately after `resolve_port_forwards`:

```python
async def _wait_until_running(
    supervisor: Supervisor,
    vm_id: VmId,
    *,
    timeout: float = _START_POLL_TIMEOUT_SECONDS,
    interval: float = _START_POLL_INTERVAL_SECONDS,
) -> VmInfo:
    """Poll get_vm until the VM reports RUNNING.

    In-process the first poll already reports RUNNING (create_vm blocked until
    boot); across a future gRPC boundary this does real work. Raises on a
    terminal status or after `timeout` seconds.
    """
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        info = await supervisor.get_vm(vm_id)
        if info.status is VmStatus.RUNNING:
            return info
        if info.status in (VmStatus.STOPPED, VmStatus.FAILED):
            msg = f"VM {vm_id} entered status {info.status.value} while waiting to start"
            raise RuntimeError(msg)
        if asyncio.get_running_loop().time() >= deadline:
            msg = f"VM {vm_id} did not reach RUNNING within {timeout}s"
            raise asyncio.TimeoutError(msg)
        await asyncio.sleep(interval)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_helpers.py -p no:cacheprovider -v`
Expected: PASS (6 passed)

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py tests/supervisor/test_supervisor_run_helpers.py
git commit -m "feat(agent): _wait_until_running readiness poll via get_vm"
```

---

## Task 4: Rewrite `create_vm_execution` to route through the abstraction

The eligible-instance branch now: build spec → `supervisor.create_vm` → `registry.record` → poll → resolve + apply port-forwards → return the execution read back from the pool once. The legacy branch also records the message. The vestigial `pool.message_cache` write is removed.

**Files:**
- Modify: `src/aleph/vm/orchestrator/run.py:80-108` (`create_vm_execution`)
- Modify: `src/aleph/vm/pool.py:68,81` (remove `message_cache`)
- Test: `tests/supervisor/test_supervisor_run_routing.py` (rewrite)

- [ ] **Step 1: Rewrite the routing test file**

Replace the entire contents of `tests/supervisor/test_supervisor_run_routing.py` with:

```python
"""run.create_vm_execution routes eligible QEMU instances through the Supervisor."""

from __future__ import annotations

import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from aleph_message.models import ItemHash, ProgramContent
from aleph_message.models.execution.environment import (
    GpuProperties,
    HostRequirements,
    HypervisorType,
    TrustedExecutionEnvironment,
)
from test_supervisor_translate import _make_qemu_instance_message

from aleph.vm.orchestrator import run as run_module
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.types import (
    Backend,
    CreateVmSpec,
    DiskFormat,
    DiskRole,
    DiskSpec,
    NetworkConfig,
    VmId,
    VmInfo,
    VmStatus,
)

_HASH = ItemHash("deadbeef" * 8)


def _spec() -> CreateVmSpec:
    return CreateVmSpec(
        vm_id=VmId(str(_HASH)),
        backend=Backend.QEMU,
        kernel_path=Path(""),
        initrd_path=Path(""),
        disks=[
            DiskSpec(
                path=Path("/data/rootfs.qcow2"),
                readonly=False,
                format=DiskFormat.QCOW2,
                role=DiskRole.ROOTFS,
            )
        ],
        vcpus=2,
        memory_mib=1024,
        tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[],
        numa_node=None,
        persistent=True,
    )


def _info(status: VmStatus = VmStatus.RUNNING) -> VmInfo:
    return VmInfo(
        vm_id=VmId(str(_HASH)),
        status=status,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )


def _fake_supervisor(*, create_status: VmStatus = VmStatus.RUNNING, get_status: VmStatus = VmStatus.RUNNING):
    return SimpleNamespace(
        create_vm=AsyncMock(return_value=_info(create_status)),
        get_vm=AsyncMock(return_value=_info(get_status)),
        add_port_forward=AsyncMock(),
        delete_vm=AsyncMock(),
    )


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

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()
    created = SimpleNamespace()
    pool = SimpleNamespace(executions={_HASH: created}, create_a_vm=AsyncMock())

    execution = await run_module.create_vm_execution(
        _HASH, pool, supervisor=supervisor, registry=registry, persistent=True
    )

    supervisor.create_vm.assert_awaited_once_with(spec)
    pool.create_a_vm.assert_not_awaited()
    # The message is recorded in the agent registry, not on the execution.
    assert registry.get(_HASH).message is content
    assert registry.get(_HASH).original is original_content
    # SSH port-forward applied through the abstraction.
    assert supervisor.add_port_forward.await_count >= 1
    # The execution is read back from the pool once for start_persistent_vm.
    assert execution is created
    supervisor.delete_vm.assert_not_awaited()


@pytest.mark.asyncio
async def test_eligible_instance_timeout_tears_down(monkeypatch):
    content = _make_qemu_instance_message(hypervisor=HypervisorType.qemu)
    message = MagicMock(content=content)
    monkeypatch.setattr(
        run_module, "load_updated_message", AsyncMock(return_value=(message, MagicMock(content=content)))
    )
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock(return_value=_spec()))
    monkeypatch.setattr(run_module.asyncio, "sleep", AsyncMock())
    monkeypatch.setattr(run_module, "_START_POLL_TIMEOUT_SECONDS", 0)

    supervisor = _fake_supervisor(get_status=VmStatus.BOOTING)  # never RUNNING
    registry = AgentVmRegistry()
    pool = SimpleNamespace(executions={}, create_a_vm=AsyncMock())

    with pytest.raises(asyncio.TimeoutError):
        await run_module.create_vm_execution(
            _HASH, pool, supervisor=supervisor, registry=registry, persistent=True
        )

    supervisor.delete_vm.assert_awaited_once_with(VmId(str(_HASH)))
    assert registry.get(_HASH) is None  # forgotten on failure


async def _assert_routed_to_legacy(monkeypatch, content) -> None:
    """An ineligible message takes create_a_vm, never touches the spec path, and is still recorded."""
    message = MagicMock(content=content)
    original_message = MagicMock(content=_make_qemu_instance_message())
    monkeypatch.setattr(run_module, "load_updated_message", AsyncMock(return_value=(message, original_message)))
    monkeypatch.setattr(run_module, "build_create_vm_spec", AsyncMock())

    supervisor = _fake_supervisor()
    registry = AgentVmRegistry()
    legacy = SimpleNamespace()
    pool = SimpleNamespace(executions={}, create_a_vm=AsyncMock(return_value=legacy))

    execution = await run_module.create_vm_execution(
        _HASH, pool, supervisor=supervisor, registry=registry, persistent=False
    )

    pool.create_a_vm.assert_awaited_once()
    supervisor.create_vm.assert_not_awaited()
    run_module.build_create_vm_spec.assert_not_awaited()
    assert execution is legacy
    assert registry.get(_HASH) is not None  # legacy path records the message too


@pytest.mark.asyncio
async def test_non_instance_falls_back_to_legacy(monkeypatch):
    await _assert_routed_to_legacy(monkeypatch, MagicMock(spec=ProgramContent))


@pytest.mark.asyncio
async def test_confidential_instance_falls_back_to_legacy(monkeypatch):
    content = _make_qemu_instance_message(trusted_execution=TrustedExecutionEnvironment())
    await _assert_routed_to_legacy(monkeypatch, content)


@pytest.mark.asyncio
async def test_gpu_instance_falls_back_to_legacy(monkeypatch):
    content = _make_qemu_instance_message().model_copy(
        update={
            "requirements": HostRequirements(
                gpu=[
                    GpuProperties(
                        vendor="NVIDIA",
                        device_name="RTX",
                        device_class="0300",
                        device_id="10de:1234",
                    )
                ]
            )
        }
    )
    await _assert_routed_to_legacy(monkeypatch, content)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_routing.py -p no:cacheprovider -v`
Expected: FAIL. `create_vm_execution` has no `supervisor`/`registry` keyword and still calls `pool.create_vm_from_spec`.

- [ ] **Step 3: Rewrite `create_vm_execution`**

In `src/aleph/vm/orchestrator/run.py`, replace the whole `create_vm_execution` function (currently lines 80-108) with:

```python
async def create_vm_execution(
    vm_hash: ItemHash,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
    persistent: bool = False,
) -> VmExecution:
    message, original_message = await load_updated_message(vm_hash)

    logger.debug(f"Message: {json.dumps(message.model_dump(exclude_none=True), indent=4, sort_keys=True, default=str)}")

    content = message.content
    if _is_spec_eligible(content):
        spec = await build_create_vm_spec(vm_hash, content)
        info = await supervisor.create_vm(spec)
        # Agent territory: record the message for the agent's own consumers
        # (operator API owner-auth, billing, update-watching). The supervisor
        # machinery that created the VM never reads it.
        registry.record(vm_hash, message=content, original=original_message.content)
        try:
            await _wait_until_running(supervisor, info.vm_id)
            for forward in await resolve_port_forwards(info.vm_id, content):
                await supervisor.add_port_forward(forward)
        except Exception:
            # Readiness or port-forward setup failed: tear the half-started VM down.
            registry.forget(vm_hash)
            await supervisor.delete_vm(info.vm_id)
            raise
        # TEMPORARY (PR 1 boundary, design doc section 8): start_persistent_vm
        # still drives the VmExecution for the pre-existing check, expiry-cancel
        # and update-watching. Read it back once so that caller is unchanged.
        # This line goes away when those ops migrate off VmExecution.
        return pool.executions[vm_hash]

    execution = await pool.create_a_vm(
        vm_hash=vm_hash,
        message=content,
        original=original_message.content,
        persistent=persistent,
    )
    registry.record(vm_hash, message=content, original=original_message.content)
    return execution
```

- [ ] **Step 4: Remove the vestigial `message_cache` from the pool**

In `src/aleph/vm/pool.py`, delete the class attribute declaration (line 68):

```python
    message_cache: dict[str, ExecutableMessage]
```

and the initialisation in `__init__` (line 81):

```python
        self.message_cache = {}
```

- [ ] **Step 5: Run the routing tests to verify they pass**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m pytest tests/supervisor/test_supervisor_run_routing.py -p no:cacheprovider -v`
Expected: PASS (5 passed)

- [ ] **Step 6: Fix any now-unused import in `pool.py`**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/ruff check src/aleph/vm/pool.py src/aleph/vm/orchestrator/run.py`
If ruff reports `ExecutableMessage` imported but unused in `pool.py`, remove it from that import line. Re-run ruff until clean. Expected end state: no errors.

- [ ] **Step 7: Commit**

```bash
git add src/aleph/vm/orchestrator/run.py src/aleph/vm/pool.py tests/supervisor/test_supervisor_run_routing.py
git commit -m "feat(agent): route create_vm_execution through the Supervisor abstraction"
```

---

## Task 5: App wiring + thread `supervisor`/`registry` through callers

Construct the singletons at startup and inject them into `create_vm_execution_or_raise_http_error` and `start_persistent_vm`, then update every call site.

**Files:**
- Modify: `src/aleph/vm/orchestrator/supervisor.py:165`
- Modify: `src/aleph/vm/orchestrator/run.py` (`create_vm_execution_or_raise_http_error`, `start_persistent_vm`)
- Modify: `src/aleph/vm/orchestrator/views/operator.py:614,774`
- Modify: `src/aleph/vm/orchestrator/views/__init__.py:564,578,954`
- Modify: `src/aleph/vm/orchestrator/cli.py:240-242`

- [ ] **Step 1: Wire the singletons into app state**

In `src/aleph/vm/orchestrator/supervisor.py`, add near the top-level imports:

```python
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.inprocess import InProcessSupervisor
```

Then, immediately after `app["vm_pool"] = pool` (line 165), add:

```python
    app["supervisor"] = InProcessSupervisor(pool)
    app["vm_registry"] = AgentVmRegistry()
```

- [ ] **Step 2: Thread the parameters through the run.py wrappers**

In `src/aleph/vm/orchestrator/run.py`, change `create_vm_execution_or_raise_http_error` (currently `async def create_vm_execution_or_raise_http_error(vm_hash, pool)`) to accept and forward the new keyword args. Update the signature and the single inner call:

```python
async def create_vm_execution_or_raise_http_error(
    vm_hash: ItemHash,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
) -> VmExecution:
    try:
        return await create_vm_execution(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
        )
```

(leave the entire `except ...` chain unchanged.)

And change `start_persistent_vm` (currently `async def start_persistent_vm(vm_hash, pubsub, pool)`) signature and its inner `create_vm_execution` call:

```python
async def start_persistent_vm(
    vm_hash: ItemHash,
    pubsub: PubSub | None,
    pool: VmPool,
    *,
    supervisor: Supervisor,
    registry: AgentVmRegistry,
) -> VmExecution:
```

and inside it, the create call becomes:

```python
        execution = await create_vm_execution(
            vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry, persistent=True
        )
```

(everything else in `start_persistent_vm` stays as-is: the pre-existing-execution checks, `becomes_ready`, `cancel_expiration`, `start_watching_for_updates`.)

- [ ] **Step 3: Update `operator.py` call sites**

In `src/aleph/vm/orchestrator/views/operator.py`, both handlers already bind `pool: VmPool = request.app["vm_pool"]`. In each of the two handlers containing the calls at lines 614 and 774, add right after that `pool` assignment:

```python
        supervisor = request.app["supervisor"]
        registry = request.app["vm_registry"]
```

and pass them to the call. Line 614 becomes:

```python
                await create_vm_execution_or_raise_http_error(
                    vm_hash=vm_hash, pool=pool, supervisor=supervisor, registry=registry
                )
```

Line 774 becomes:

```python
            await create_vm_execution_or_raise_http_error(
                vm_hash=vm_hash,
                pool=pool,
                supervisor=supervisor,
                registry=registry,
            )
```

- [ ] **Step 4: Update `views/__init__.py` call sites**

In `src/aleph/vm/orchestrator/views/__init__.py`, the two functions containing the calls at lines 564/578 and at 954 each already have `pool` and `pubsub` in scope from `request.app`/`app`. In each, add `supervisor = app["supervisor"]` and `registry = app["vm_registry"]` (use the same `app` handle already used to obtain `pool`/`pubsub` in that function), and pass them. Each `await start_persistent_vm(<hash>, pubsub, pool)` becomes:

```python
                await start_persistent_vm(
                    vm_hash, pubsub, pool, supervisor=supervisor, registry=registry
                )
```

(matching the actual hash variable at each site: `vm_hash` at 564, `instance_item_hash` at 578, `item_hash` at 954).

- [ ] **Step 5: Update the standalone `cli.py` path**

In `src/aleph/vm/orchestrator/cli.py`, `start_instance` runs without an aiohttp app, so it constructs the singletons locally. Add imports at the top of the module:

```python
from aleph.vm.orchestrator.vm_registry import AgentVmRegistry
from aleph.vm.supervisor.inprocess import InProcessSupervisor
```

and rewrite `start_instance` (lines 240-242):

```python
async def start_instance(item_hash: ItemHash, pubsub: PubSub | None, pool) -> VmExecution:
    """Run an instance from an InstanceMessage."""
    supervisor = InProcessSupervisor(pool)
    registry = AgentVmRegistry()
    return await start_persistent_vm(
        item_hash, pubsub, pool, supervisor=supervisor, registry=registry
    )
```

- [ ] **Step 6: Type-check the touched modules**

Run: `cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m mypy src/aleph/vm/orchestrator/run.py src/aleph/vm/orchestrator/supervisor.py src/aleph/vm/orchestrator/cli.py src/aleph/vm/orchestrator/views/operator.py src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/pool.py`
Expected: no new errors versus baseline.

- [ ] **Step 7: Run the full suite + gates**

Run: `cd .worktrees/wire-supervisor-abstraction && ALEPH_VM_CACHE_ROOT=$(mktemp -d) ALEPH_VM_EXECUTION_ROOT=$(mktemp -d) .testvenv/bin/python -m pytest tests/ -p no:cacheprovider -q`
Expected: ~545 passed (the 8 new helper/registry tests added), the same ~8 environmental-only failures (test_execution x4, test_instance::test_create_firecracker_instance, test_interfaces x3), 1 skipped, 3 xfailed.

Run the mypy union-attr gates:
`cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m mypy src/aleph/vm/ 2>&1 | grep -c 'Item "None".*union-attr'`
Expected: `2`
`cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/python -m mypy src/aleph/vm/controllers/ 2>&1 | grep -c 'Item "None".*union-attr'`
Expected: `0`

Run lint/format:
`cd .worktrees/wire-supervisor-abstraction && .testvenv/bin/ruff check src/aleph/vm/orchestrator/ src/aleph/vm/pool.py tests/supervisor/test_agent_vm_registry.py tests/supervisor/test_supervisor_run_helpers.py tests/supervisor/test_supervisor_run_routing.py && .testvenv/bin/isort --check-only --profile black tests/supervisor/test_agent_vm_registry.py tests/supervisor/test_supervisor_run_helpers.py tests/supervisor/test_supervisor_run_routing.py`
Expected: clean.

- [ ] **Step 8: Commit**

```bash
git add src/aleph/vm/orchestrator/supervisor.py src/aleph/vm/orchestrator/run.py \
  src/aleph/vm/orchestrator/cli.py src/aleph/vm/orchestrator/views/operator.py \
  src/aleph/vm/orchestrator/views/__init__.py
git commit -m "feat(agent): construct and inject Supervisor + AgentVmRegistry app-wide"
```

---

## Done criteria

- The eligible-instance create path calls `supervisor.create_vm` / `get_vm` / `add_port_forward`; it touches `pool.executions` exactly once (the flagged read-back) and never calls `pool.create_vm_from_spec` directly.
- The message lives only in the `AgentVmRegistry`; `pool.message_cache` is gone.
- `start_persistent_vm` is behaviourally unchanged for callers.
- Full suite green except the known ~8 environmental failures; mypy gate `2 / 0`; ruff/isort clean.
