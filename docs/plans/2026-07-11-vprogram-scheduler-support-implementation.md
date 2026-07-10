# V-PROGRAM Scheduler Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let the scheduler command aleph-vm nodes to run V-PROGRAM messages (accept `v_programs` in `POST /control/allocations`, thread the type through the agent, no payment checks, clean launch failure) and advertise supported SNP guest vCPU models so the scheduler matches truly compatible nodes.

**Architecture:** Python agent (src/aleph/vm/agent/) drives VMs through the `Supervisor` boundary; V-PROGRAM launch stays out of scope (fails cleanly at create with `VmSetupError`). Capability advertising adds a `properties.tee` block to `/about/usage/system` populated by a QEMU QMP probe. Scheduler follow-up (aleph-vm-scheduler, PR #193 branch) renames the allocation bucket to `v_programs` and matches measurement `vcpu_type` against the advertised models.

**Tech Stack:** Python 3.12+ (aiohttp, pydantic), aleph-message (git pin, PR #158), pytest; Rust (scheduler repo).

**Design doc:** `docs/plans/2026-07-11-vprogram-scheduler-support-design.md`

## Global Constraints

- Branch `od/vprogram-scheduler-support` off `origin/dev`, worktree `/home/olivier/git/aleph/aleph-vm/.worktrees/vprogram-scheduler` (referred to as `$WT`).
- aleph-message pinned to git ref `bc9c0f86958a746faeecbd6c6f96cc6f5b4538de` (PR #158 head). **MERGE GATE: swap for a released aleph-message before merging.**
- Local test invocation (venv is py3.14 with C-module stubs; aleph-message checkout provides the pinned version):
  `PYTHONPATH="$WT/src:/home/olivier/git/aleph/aleph-message:/home/olivier/git/aleph/aleph-vm/.dev-stubs" ALEPH_VM_CACHE_ROOT=$HOME/.cache/aleph-vm-tests ALEPH_VM_EXECUTION_ROOT=$HOME/.cache/aleph-vm-exec /home/olivier/git/aleph/aleph-vm/venv/bin/python -m pytest -p no:cacheprovider`
- Local gates before push: pytest (baseline = ~9 environment-only failures), `mypy` (1.8.0, project config), ruff/black/isort, `lint-imports` (agent must not import supervisor side).
- No em-dashes in prose/comments/commit messages. No Co-Authored-By trailer.
- Message type enum member is `MessageType.v_program` (wire value `"V-PROGRAM"`); content class `VerifiableProgramContent`; message class `VerifiableProgramMessage`.
- Node-side `VmType` member is named `v_program` so `.name` matches the scheduler's `"v_program"` string.
- IPv6 type value for v-programs: **4** (mirrors scheduler-events `VmType::ipv6_value()`).

---

## Part A: aleph-vm

### Task A0: Commit design doc + plan

**Files:**
- Add: `docs/plans/2026-07-11-vprogram-scheduler-support-design.md` (copy from main checkout)
- Add: `docs/plans/2026-07-11-vprogram-scheduler-support-implementation.md` (this file)

**Steps:**
- [ ] Copy the design doc from the main checkout into `$WT/docs/plans/`, remove it from the main checkout (it was untracked there).
- [ ] `git add docs/plans/2026-07-11-vprogram-scheduler-support-*.md && git commit -m "docs: v-program scheduler support design + implementation plan"`

### Task A1: Pin aleph-message and add the canonical fixture

**Files:**
- Modify: `pyproject.toml:38`
- Create: `tests/supervisor/fixtures/vprogram_message.json` (copy of aleph-message `aleph_message/tests/messages/vprogram_machine.json`)

**Interfaces:**
- Produces: importable `aleph_message.models.VerifiableProgramContent`, `VerifiableProgramMessage`, `MessageType.v_program`; fixture path used by all later tests.

**Steps:**
- [ ] **Edit pyproject.toml line 38:**
```toml
  # MERGE GATE: replace the git pin with a released aleph-message version.
  "aleph-message @ git+https://github.com/aleph-im/aleph-message@bc9c0f86958a746faeecbd6c6f96cc6f5b4538de",
```
- [ ] **Copy fixture:** `cp /home/olivier/git/aleph/aleph-message/aleph_message/tests/messages/vprogram_machine.json tests/supervisor/fixtures/vprogram_message.json` (create the fixtures dir if tests/supervisor has none; if one already exists under another name, use it).
- [ ] **Sanity check the pinned types import:** run a python one-liner with the test PYTHONPATH asserting `MessageType.v_program.value == "V-PROGRAM"` and `parse_message` on the fixture returns a `VerifiableProgramMessage`.
- [ ] Commit: `build: pin aleph-message to the V-PROGRAM schema ref (merge-gated)`

### Task A2: Accept V-PROGRAM messages in storage + type map + IPv6 prefix

**Files:**
- Modify: `src/aleph/vm/storage.py:205,231`
- Modify: `src/aleph/vm/vm_type.py`
- Modify: `src/aleph/vm/network/hostnetwork.py:50-54`
- Test: `tests/supervisor/test_vprogram.py` (new), `tests/supervisor/test_ipv6_allocator.py`

**Interfaces:**
- Produces: `VmType.v_program` (value 4); `get_message` returning `VerifiableProgramMessage`; IPv6 prefix "4".

**Steps:**
- [ ] **Failing tests** in `tests/supervisor/test_vprogram.py`:
```python
import json
from pathlib import Path

import pytest
from aleph_message.models import VerifiableProgramContent, VerifiableProgramMessage, parse_message

from aleph.vm.vm_type import VmType

FIXTURE = Path(__file__).parent / "fixtures" / "vprogram_message.json"


def load_vprogram_message() -> VerifiableProgramMessage:
    message = parse_message(json.loads(FIXTURE.read_text()))
    assert isinstance(message, VerifiableProgramMessage)
    return message


def test_vm_type_v_program():
    message = load_vprogram_message()
    assert isinstance(message.content, VerifiableProgramContent)
    assert VmType.from_message_content(message.content) == VmType.v_program
    assert VmType.v_program.name == "v_program"
```
   and in `tests/supervisor/test_ipv6_allocator.py` (mirror the existing static-allocator test style):
```python
def test_static_allocator_v_program_prefix():
    allocator = StaticIPv6Allocator(ipv6_range=IPv6Network("2a01:240:ad00:2500::/64"), subnet_prefix=124)
    subnet = allocator.allocate_vm_ipv6_subnet(
        vm_id=3,
        vm_hash=ItemHash("cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"),
        vm_type=VmType.v_program,
    )
    # 16-bit VM-type field = 4: must mirror scheduler-events VmType::ipv6_value()
    assert subnet == IPv6Network("2a01:240:ad00:2500:4:cafe:cafe:caf0/124")
```
- [ ] Run both, expect FAIL (no `v_program` member / KeyError in prefix map).
- [ ] **Implement** `src/aleph/vm/vm_type.py`:
```python
from enum import Enum

from aleph_message.models import (
    ExecutableContent,
    InstanceContent,
    ProgramContent,
    VerifiableProgramContent,
)


class VmType(Enum):
    microvm = 1
    persistent_program = 2
    instance = 3
    v_program = 4

    @staticmethod
    def from_message_content(content: ExecutableContent) -> "VmType":
        if isinstance(content, InstanceContent):
            return VmType.instance
        elif isinstance(content, VerifiableProgramContent):
            return VmType.v_program
        elif isinstance(content, ProgramContent):
            if content.on.persistent:
                return VmType.persistent_program
            return VmType.microvm

        msg = f"Unexpected message content type: {type(content)}"
        raise TypeError(msg)
```
   `src/aleph/vm/network/hostnetwork.py` VM_TYPE_PREFIX:
```python
    VM_TYPE_PREFIX = {
        VmType.microvm: "1",
        VmType.persistent_program: "2",
        VmType.instance: "3",
        # Must match the scheduler's VmType::ipv6_value() (scheduler-events)
        VmType.v_program: "4",
    }
```
   `src/aleph/vm/storage.py`: import `VerifiableProgramMessage`, signature `-> ProgramMessage | InstanceMessage | VerifiableProgramMessage`, assert `isinstance(result, InstanceMessage | ProgramMessage | VerifiableProgramMessage)`.
   Add a storage-level test (same test file, monkeypatching the message cache dir or using `parse_message` directly if `get_message` needs network; minimal: assert the widened assert accepts the fixture message object type).
- [ ] Run tests, expect PASS.
- [ ] Commit: `feat(agent): parse V-PROGRAM messages, map VmType.v_program, IPv6 type 4`

### Task A3: update_message immutability branch

**Files:**
- Modify: `src/aleph/vm/agent/messages.py:54-68`
- Test: `tests/supervisor/test_vprogram.py`

**Steps:**
- [ ] **Failing test:**
```python
@pytest.mark.asyncio
async def test_update_message_vprogram_is_noop():
    message = load_vprogram_message()
    # Must not attempt any amend resolution (no network): v-programs are immutable
    await update_message(message)
```
- [ ] **Implement** in `update_message`:
```python
    if message.type == MessageType.program:
        ...existing...
    elif message.type == MessageType.v_program:
        # V-Programs are immutable (allow_amend is schema-rejected) and every
        # reference is pinned by exact hash, so there are no amends to resolve.
        return
    else:
        assert message.type == MessageType.instance
        ...existing...
```
- [ ] Run test, expect PASS. Commit: `feat(agent): no amend resolution for immutable V-PROGRAM messages`

### Task A4: AgentVmRecord.is_vprogram

**Files:**
- Modify: `src/aleph/vm/agent/vm_registry.py`
- Test: `tests/supervisor/test_agent_vm_registry.py`

**Interfaces:**
- Produces: `AgentVmRecord.is_vprogram: bool` (consumed by A5 stop-guard and A7 payment sweep).

**Steps:**
- [ ] **Failing test** (in test_agent_vm_registry.py, using the fixture loader from test_vprogram.py or a local copy):
```python
def test_record_is_vprogram():
    message = load_vprogram_message()
    record = AgentVmRecord(message=message.content, original=message.content, persistent=True)
    assert record.is_vprogram
    assert record.uses_payment_credit  # schema enforces credit; sweep exclusion is explicit
```
- [ ] **Implement:**
```python
    @property
    def is_vprogram(self) -> bool:
        return isinstance(self.message, VerifiableProgramContent)
```
- [ ] Run, PASS. Commit: `feat(agent): AgentVmRecord.is_vprogram`

### Task A5: Allocation.v_programs + update_allocations wiring

**Files:**
- Modify: `src/aleph/vm/agent/resources.py:274-291` (Allocation model)
- Modify: `src/aleph/vm/agent/views/__init__.py:575,585-603,647-666`
- Test: `tests/supervisor/test_views.py` (mirror `test_update_allocations_stop_loop_uses_supervisor` at :1278 and `test_update_allocations_spares_payg_via_registry` at :1466)

**Steps:**
- [ ] **Failing tests:** (a) POST /control/allocations with `{"v_programs": ["<fixture hash>"]}` parses and reaches the start loop (assert `start_persistent_vm` called via mock, or scheduling error surfaces in `errors`); (b) a running v-program execution (registry record from fixture content, persistent, RUNNING, confidential) absent from the allocation IS stopped despite `uses_payment_credit`; (c) old payloads without the key still validate.
- [ ] **Implement** Allocation:
```python
    v_programs: set[ItemHash] = Field(default_factory=set)
```
   `update_allocations`: line 575 `allocations = allocation.persistent_vms | allocation.instances | allocation.v_programs`; stop-guard becomes:
```python
            if (
                record is not None
                and record.persistent
                and vm_hash not in allocations
                and info.status is VmStatus.RUNNING
                and (
                    # The scheduler is the single source of truth for
                    # v-programs: absence from the allocation stops them,
                    # even though they are credit-paid and confidential.
                    record.is_vprogram
                    or (
                        not record.uses_payment_stream
                        and not record.uses_payment_credit
                        and not info.gpus
                        and info.confidential_mode is ConfidentialMode.NONE
                    )
                )
            ):
```
   and a start loop after the instances loop, identical in shape to the instances loop but iterating `allocation.v_programs`.
- [ ] Run tests, PASS. Commit: `feat(agent): accept v_programs bucket in /control/allocations`

### Task A6: create dispatch failure + on-demand rejection

**Files:**
- Modify: `src/aleph/vm/agent/run.py` (`create_vm_execution` before the final raise at :344; `run_code_on_request` :578; `run_code_on_event` :658)
- Test: `tests/supervisor/test_vprogram.py`, `tests/supervisor/views/test_run_code.py`

**Steps:**
- [ ] **Failing tests:** (a) `create_vm_execution` with a v-program message raises `VmSetupError` mentioning SEV-SNP; (b) on-demand run path returns 400 with a scheduler-controlled message for a v-program hash.
- [ ] **Implement** in `create_vm_execution` (before the final `raise HTTPBadRequest`):
```python
    if isinstance(content, VerifiableProgramContent):
        # Scheduler wiring for V-Programs lands before the launch path: the
        # allocation is accepted, but building a CreateVmSpec for an SNP
        # guest (runtime manifest fetch, measured cmdline, verified volumes)
        # is not implemented yet. Fail with the create-path vocabulary so
        # update_allocations reports it per-VM and the scheduler can react.
        msg = f"V-PROGRAM {vm_hash} accepted, but this CRN does not implement the SEV-SNP launch path yet"
        raise VmSetupError(msg)
```
   In `run_code_on_request` (and `run_code_on_event`), before the existing non-program rejection:
```python
    if isinstance(content, VerifiableProgramContent):
        raise HTTPBadRequest(reason=f"VM {vm_hash} is a V-PROGRAM: executions are scheduler-controlled")
```
- [ ] Run tests, PASS. Commit: `feat(agent): v-program create fails cleanly, on-demand endpoints reject`

### Task A7: Exclude v-programs from the payment sweep

**Files:**
- Modify: `src/aleph/vm/agent/tasks.py:329-351` (`_group_executions_by_payment`)
- Test: `tests/supervisor/test_checkpayment.py`

**Steps:**
- [ ] **Failing test:** a RUNNING v-program execution with zero credit balance is NOT stopped by `check_payment` (mirror the existing credit-sweep test setup).
- [ ] **Implement** in `_group_executions_by_payment`, right after the `record is None` skip:
```python
        if record.is_vprogram:
            # V-Programs are not payment-checked on the node: the CCN and
            # the scheduler already enforce their credit budget, node-side
            # duplication adds nothing.
            continue
```
- [ ] Run test, PASS (also confirm the terminal-status stop loop is untouched: forgotten/rejected v-program messages still stop). Commit: `feat(agent): no node-side payment checks for v-programs`

### Task A8: SNP detection fix, QMP vCPU probe, tee advertising

**Files:**
- Modify: `src/aleph/vm/utils/__init__.py:175-182` (`check_amd_sev_snp_supported`)
- Create: `src/aleph/vm/agent/vcpu_probe.py`
- Modify: `src/aleph/vm/agent/resources.py` (models + `get_machine_properties` + `get_machine_capability`)
- Test: `tests/supervisor/test_vprogram_probe.py` (new), `tests/supervisor/test_resources.py`, `tests/supervisor/test_utils.py`

**Interfaces:**
- Produces: `get_supported_snp_vcpu_types() -> list[str]` (async, cached); `/about/usage/system` JSON gains `properties.tee.sev_snp.supported_vcpu_types` when non-empty, absent otherwise.

**Steps:**
- [ ] **Failing tests:**
```python
def test_filter_snp_vcpu_types():
    definitions = [
        {"name": "EPYC-v4", "unavailable-features": []},
        {"name": "EPYC-Genoa", "unavailable-features": ["some-feature"]},
        {"name": "EPYC", "unavailable-features": []},
        {"name": "Skylake-Server", "unavailable-features": []},
    ]
    assert filter_snp_vcpu_types(definitions) == ["EPYC", "EPYC-v4"]

@pytest.mark.asyncio
async def test_get_supported_snp_vcpu_types_no_snp(mocker):
    mocker.patch("aleph.vm.agent.vcpu_probe.check_amd_sev_snp_supported", return_value=False)
    probe = mocker.patch("aleph.vm.agent.vcpu_probe.query_cpu_definitions")
    assert await get_supported_snp_vcpu_types.__wrapped__() == []
    probe.assert_not_called()

@pytest.mark.asyncio
async def test_get_supported_snp_vcpu_types_probe_failure(mocker):
    mocker.patch("aleph.vm.agent.vcpu_probe.check_amd_sev_snp_supported", return_value=True)
    mocker.patch("aleph.vm.agent.vcpu_probe.query_cpu_definitions", side_effect=OSError("no qemu"))
    assert await get_supported_snp_vcpu_types.__wrapped__() == []
```
   plus a `/about/usage/system` test asserting the tee block appears with a mocked probe and is absent when it returns [] (mirror existing test_resources.py style, resetting the async_cache), and a `check_amd_sev_snp_supported` test asserting it requires `/dev/sev`.
- [ ] **Implement** `src/aleph/vm/agent/vcpu_probe.py`:
```python
"""Probe QEMU for the SNP guest CPU models this host can actually launch.

The scheduler matches a v-program's launch-measurement vcpu_type against the
models advertised here, so the source of truth must be QEMU itself (this
exact QEMU build + host kernel + silicon), not a static CPUID table.
"""

import asyncio
import json
import logging

from aleph.vm.utils import async_cache, check_amd_sev_snp_supported

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 15.0


async def _read_qmp_response(stdout: asyncio.StreamReader) -> dict:
    """Read the next QMP response, skipping asynchronous events."""
    while True:
        line = await stdout.readline()
        if not line:
            msg = "QMP stream closed before a response arrived"
            raise RuntimeError(msg)
        message = json.loads(line)
        if "event" in message:
            continue
        return message


async def query_cpu_definitions() -> list[dict]:
    """Ask a KVM-accelerated QEMU which CPU models it can launch on this host."""
    process = await asyncio.create_subprocess_exec(
        "qemu-system-x86_64",
        "-machine", "none",
        "-accel", "kvm",
        "-display", "none",
        "-nodefaults",
        "-qmp", "stdio",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        async with asyncio.timeout(PROBE_TIMEOUT_SECONDS):
            greeting = await _read_qmp_response(process.stdout)
            if "QMP" not in greeting:
                msg = f"Unexpected QMP greeting: {greeting}"
                raise RuntimeError(msg)
            definitions: list[dict] | None = None
            for command in ("qmp_capabilities", "query-cpu-definitions", "quit"):
                process.stdin.write(json.dumps({"execute": command}).encode() + b"\n")
                await process.stdin.drain()
                response = await _read_qmp_response(process.stdout)
                if command == "query-cpu-definitions":
                    definitions = response["return"]
            await process.wait()
    finally:
        if process.returncode is None:
            process.kill()
    assert definitions is not None
    return definitions


def filter_snp_vcpu_types(definitions: list[dict]) -> list[str]:
    """Keep the EPYC-family models QEMU reports as runnable on this host."""
    return sorted(
        definition["name"]
        for definition in definitions
        if definition["name"].startswith("EPYC") and not definition.get("unavailable-features")
    )


@async_cache
async def get_supported_snp_vcpu_types() -> list[str]:
    """SNP guest CPU models this node can launch; [] when SNP is unsupported
    or the probe fails (we never advertise what we cannot prove)."""
    if not check_amd_sev_snp_supported():
        return []
    try:
        definitions = await query_cpu_definitions()
    except Exception:
        logger.warning("QEMU vCPU probe failed, not advertising SNP guest models", exc_info=True)
        return []
    return filter_snp_vcpu_types(definitions)
```
   (If `async_cache` does not expose `__wrapped__`, test the uncached internals instead; adapt at implementation time.)
   `src/aleph/vm/utils/__init__.py`:
```python
def check_amd_sev_snp_supported() -> bool:
    """..."""
    return (check_system_module("kvm_amd/parameters/sev_snp") == "Y") and Path("/dev/sev").exists()
```
   `src/aleph/vm/agent/resources.py`:
```python
class SevSnpProperties(BaseModel):
    supported_vcpu_types: list[str] = Field(
        description="QEMU SNP guest CPU models this host can launch (e.g. EPYC-v4)"
    )


class TeeProperties(BaseModel):
    sev_snp: SevSnpProperties | None = None


class MachineProperties(BaseModel):
    cpu: CpuProperties
    tee: TeeProperties | None = None
```
   In `get_machine_properties` (and `get_machine_capability` for `/about/capability`, adding `tee` to `MachineCapability` too):
```python
    snp_vcpu_types = await get_supported_snp_vcpu_types()
    tee = (
        TeeProperties(sev_snp=SevSnpProperties(supported_vcpu_types=snp_vcpu_types)) if snp_vcpu_types else None
    )
```
- [ ] Run tests, PASS. Commit: `feat(agent): advertise SNP guest vCPU models via QEMU QMP probe`

### Task A9: Full local gates

- [ ] Full pytest run with the invocation from Global Constraints; compare against the dev baseline (run baseline on a clean `origin/dev` checkout of the same worktree BEFORE the first code task if not already done; only environment-only failures allowed).
- [ ] `mypy` from `$WT` root on the project config; `ruff check src tests`, `black --check`, `isort --check` (match `hatch run linting:style` set); `lint-imports`.
- [ ] Fix anything found; amend or add fixup commits per logical change.

### Task A10: Push, PR, CI loop

- [ ] `git push -u origin od/vprogram-scheduler-support`
- [ ] `gh pr create --draft --base dev` with a body summarizing the design (link the design doc, note the aleph-message merge gate).
- [ ] Watch CI (`gh pr checks --watch` or poll via ScheduleWakeup ~270s); fix failures and push until green. Expect the pinned git dependency to be exercised by both the pytest workflow and the deb/droplet workflow.

## Part B: aleph-vm-scheduler (repo /home/olivier/git/aleph/aleph-vm-scheduler)

### Task B1: Rename persistent_programs to v_programs (on `od/vprogram-scheduling`, PR #193)

**Files:**
- Modify: `scheduler-rs/src/models.rs` (Allocation field + all uses: is_empty/item_hashes/contains/find_vm_type/add_vm/all_vms + tests)
- Modify: `scheduler-api/src/routes/v0.rs` (NodePlan field + bucketing + tests)
- Modify: `scheduler-rs/src/actors/dispatcher.rs` (per-node Allocation rebuild)

**Steps:**
- [ ] `git -C /home/olivier/git/aleph/aleph-vm-scheduler switch od/vprogram-scheduling && git pull`
- [ ] Rename the field and serde key `persistent_programs` -> `v_programs` everywhere it was added by PR #193 (`grep -rn persistent_programs`); keep `#[serde(default)]`. Update test JSON assertions.
- [ ] `cargo fmt && cargo clippy --locked --all-targets -- -D warnings && cargo test`
- [ ] Commit: `refactor: rename allocation bucket persistent_programs to v_programs` and push (updates PR #193).

### Task B2: Parse the node tee block

**Files:**
- Modify: `scheduler-rs/src/crn_client.rs` (MachineUsage properties struct: add optional `tee` with `sev_snp.supported_vcpu_types`)
- Modify: `scheduler-rs/src/nodes.rs` (NodeSnapshot: `snp_vcpu_types: Vec<String>`)
- Modify: `scheduler-rs/src/actors/node_watcher.rs:104-189` (populate from usage properties)

**Steps:**
- [ ] Failing test: deserialize a MachineUsage JSON with and without the tee block; snapshot carries the list (empty when absent).
- [ ] Implement structs (`#[serde(default)]` throughout so old nodes parse), thread into NodeSnapshot.
- [ ] `cargo test`, PASS. Commit: `feat: read SNP guest vCPU models from CRN usage properties`

### Task B3: Match measurement vcpu_type in can_vm_run_on_node

**Files:**
- Modify: `scheduler-rs/src/actors/message_watcher.rs` (extract per-VM required vcpu_types from `content.verification.measurements[].vcpu_type`, default `"EPYC"` for untagged measurements)
- Modify: `scheduler-rs/src/scheduling.rs:57-113` (`can_vm_run_on_node`)

**Steps:**
- [ ] Failing tests: (a) v-program with `vcpu_type: "EPYC-v4"` lands only on a node advertising `EPYC-v4` (case-insensitive); (b) node without the tee block (empty `snp_vcpu_types`) never receives v-programs even with the `sev_snp` feature flag; (c) an untagged measurement matches a node advertising `EPYC`; (d) non-v-program VMs are unaffected by empty `snp_vcpu_types`.
- [ ] Implement: for v-programs require `!node.snapshot.snp_vcpu_types.is_empty()` AND any required vcpu_type (measurement vcpu_type or `"EPYC"` default) present in the node set, case-insensitive.
- [ ] `cargo fmt && cargo clippy --locked --all-targets -- -D warnings && cargo test`, PASS. Commit: `feat: match v-program launch-measurement vcpu_type against node SNP models`

### Task B4: Push + CI

- [ ] Push `od/vprogram-scheduling`; watch PR #193 CI until green.

## Self-Review Notes

- Spec coverage: allocation bucket (A5), type threading (A2/A3/A4), on-demand rejection (A6), payment (A7), advertising + probe + /dev/sev fix (A8), IPv6 type 4 (A2), scheduler rename (B1), snapshot + matching + strict gate + EPYC default (B2/B3), clean launch failure (A6), testing (each task + A9/A10/B4).
- Deliberately deferred (recorded in design): the spec-create IPv6 path (`pool.py:239` hardcodes `VmType.instance`) only matters once v-program launch is wired; the launch increment must pass the vm type through `CreateVmSpec`.
- `notify_allocation` needs no change: its `message.type != MessageType.instance` gate already rejects v-programs.
