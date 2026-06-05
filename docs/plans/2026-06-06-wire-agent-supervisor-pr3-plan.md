# Wire agent onto Supervisor — PR 3: read views (list endpoints)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate the execution list endpoints (`/about/executions/list`, `/v2/about/executions/list`) off `pool.executions` onto `supervisor.list_vms()` / `list_port_forwards()` / `get_host_info()`, enriching the contract (`VmInfo`, `HostInfo`) with the fields those views need.

**Architecture:** Design doc `docs/plans/2026-06-01-wire-agent-onto-supervisor-design.md` §8 item 3 ("Read views"). PR 3 of the series, stacked on PR 2 (#965, branch `od/wire-supervisor-lifecycle`). The contract gains tap networks, lifecycle timestamps and the host IPv4; the in-process impl fills them and batches its systemd query; the two list views are rewritten agent-side on `VmInfo` + the `AgentVmRegistry`, byte-compatible with today's output.

**Tech Stack:** Python 3.12+, aiohttp, protobuf (proto3, bindings via `scripts/generate_proto.py`), pytest + pytest-asyncio.

---

## Design deltas (decisions made 2026-06-06, user-approved)

1. **VmInfo enrichment — networks + full lifecycle times.** `VmInfo` (proto + dataclass) gains `ipv4_network` / `ipv6_network` (CIDR strings, empty until the tap exists) and the 7 lifecycle timestamps (`defined/preparing/prepared/starting/started/stopping/stopped`, `uint64` unix-ns UTC, 0 = stage not reached). Rationale: libvirt-style lifecycle timestamps are a natural hypervisor contract; lets the v2 endpoint keep its exact output shape.
2. **HostInfo gains `host_ipv4`.** The v2 endpoint exposes the host's external IPv4, owned by the hypervisor's `pool.network`. The gRPC-honest source is `get_host_info()`. Empty string when host networking is disabled.
3. **`/about/executions/details` (`about_executions`) stays a residual.** It dumps raw `VmExecution` internals, which cannot cross the boundary; nobody is known to use it. Documented in-code; dies (or moves to the hypervisor's own debug surface) with the in-process pool in Phase 1.
4. **Batch systemd query moves into the in-process supervisor.** The views' `_get_executions_running_states` (one D-Bus call for all persistent VMs) is deleted; `InProcessSupervisor.list_vms` gets the same batching via a `_running_states(pool)` helper, so migrating the views does not regress D-Bus round-trips. `get_vm` keeps the per-VM `_is_running`.
5. **vm_type resolution moves agent-side.** Registry hit → `VmType.from_message_content(record.message)`. Registry miss (spec-created or reattached VM) → infer from `VmInfo.backend` (`QEMU`/`QEMU_SEV` → `instance`, `FIRECRACKER` → `microvm`) — exactly what `execution.is_instance` computes for spec executions today.

### Behavior notes (reviewer-facing)

- v2 `"status"` datetimes are reconstructed from unix-ns. All execution times are tz-aware UTC with µs precision, and the ns composition is lossless (`int(ts.timestamp()) * 1e9 + µs * 1000`, same pattern as the log timestamps), so `str()` output is byte-identical.
- v2 `mapped_ports` is rebuilt from `list_port_forwards()`. Entries with `host=None` or no enabled protocol are no longer emitted — such entries cannot exist after PR 2's ghost-entry fix, so no observable change.
- The "running" flag derives from `VmInfo.status is RUNNING`; the in-process `_is_running` logic is identical to the deleted views helper (systemd for persistent VMs, times otherwise).
- `registry.get` is widened to accept `ItemHash | str` so views can pass `VmId` (a `str` NewType) without an unsafe `ItemHash()` re-validation of hypervisor-issued ids.

### Existing tests as parity proof

`tests/supervisor/test_views.py::test_v2_executions_list_one_vm`, `::test_v2_executions_list_vm_network`, `::test_v2_executions_list_empty` assert the full v2 JSON byte-for-byte (including the times dict and `host_ipv4`). They must pass **unchanged** after the migration — they are the proof the output shape survived.

---

## Branch / environment setup (controller does this once, before Task 1)

- Worktree: `git -C /home/olivier/git/aleph/aleph-vm worktree add .worktrees/wire-supervisor-read-views -b od/wire-supervisor-read-views od/wire-supervisor-lifecycle`
- Test venv (dbus-python cannot build locally; chain site-packages instead):
  ```bash
  cd /home/olivier/git/aleph/aleph-vm/.worktrees/wire-supervisor-read-views
  python3 -m venv --system-site-packages .testvenv
  echo "$PWD/src" > .testvenv/lib/python3*/site-packages/_local_aleph.pth
  echo "/home/olivier/git/aleph/aleph-vm/.worktrees/supervisor-create/.testvenv/lib/python3.14/site-packages" >> .testvenv/lib/python3*/site-packages/_local_aleph.pth
  ```
- Commit this plan file as the first commit on the branch.
- Tests run as `.testvenv/bin/python -m pytest <paths> -v` (or `just test`). Proto regen needs `PATH=$PWD/.testvenv/bin:$PATH` (the scripts call bare `python`).
- Known baseline: 8 environmental-only failures (root/network/qemu) in `test_execution.py`/`test_instance.py`/`test_interfaces.py`; 4 order-dependent DB-init errors in `test_port_mappings.py` when run as a subset. Neither set blocks.

---

### Task 1: Contract enrichment — proto + dataclasses + regenerated bindings

**Files:**
- Modify: `proto/supervisor.proto` (messages `VmInfo`, `HostInfo`)
- Modify: `src/aleph/vm/supervisor/types.py` (`VmInfo`, `HostInfo`)
- Regenerate: `src/aleph/vm/supervisor/_pb/` (via `scripts/generate_proto.py`)
- Test: `tests/supervisor/test_proto_bindings.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/supervisor/test_proto_bindings.py` (follow the existing import style in that file):

```python
def test_vm_info_network_and_lifecycle_fields_default():
    info = supervisor_pb2.VmInfo()
    assert info.ipv4_network == ""
    assert info.ipv6_network == ""
    for field in (
        "defined_at_ns",
        "preparing_at_ns",
        "prepared_at_ns",
        "starting_at_ns",
        "started_at_ns",
        "stopping_at_ns",
        "stopped_at_ns",
    ):
        assert getattr(info, field) == 0


def test_host_info_host_ipv4_defaults_empty():
    host = supervisor_pb2.HostInfo()
    assert host.host_ipv4 == ""


def test_vm_info_dataclass_new_fields_default():
    from aleph.vm.supervisor.types import Backend, VmId, VmInfo, VmStatus

    info = VmInfo(
        vm_id=VmId("x"),
        status=VmStatus.RUNNING,
        ipv4="",
        ipv6="",
        uptime_secs=0,
        backend=Backend.QEMU,
        numa_node=None,
        status_message="",
    )
    assert info.ipv4_network == ""
    assert info.defined_at_ns == 0
    assert info.stopped_at_ns == 0


def test_host_info_dataclass_host_ipv4_defaults_empty():
    from aleph.vm.supervisor.types import HostInfo

    assert HostInfo().host_ipv4 == ""
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_proto_bindings.py -v -k "network_and_lifecycle or host_ipv4 or new_fields"`
Expected: FAIL (`AttributeError: ipv4_network` on the pb2 message / unexpected dataclass attribute).

- [ ] **Step 3: Edit the proto**

In `proto/supervisor.proto`, extend `message VmInfo` (fields 1–8 exist; add 9–17):

```proto
message VmInfo {
  string vm_id = 1;
  VmStatus status = 2;
  string ipv4 = 3;
  string ipv6 = 4;
  uint64 uptime_secs = 5;
  Backend backend = 6;
  optional uint32 numa_node = 7;     // effective placement (0-indexed). Unset until status is BOOTING/RUNNING.
  string status_message = 8;         // human-readable, optional

  // Tap networks (CIDR strings, e.g. "172.16.3.0/24"). Empty until the tap device exists.
  string ipv4_network = 9;
  string ipv6_network = 10;

  // Lifecycle timestamps, unix nanoseconds UTC. 0 = stage not reached.
  uint64 defined_at_ns = 11;
  uint64 preparing_at_ns = 12;
  uint64 prepared_at_ns = 13;
  uint64 starting_at_ns = 14;
  uint64 started_at_ns = 15;
  uint64 stopping_at_ns = 16;
  uint64 stopped_at_ns = 17;
}
```

In `message HostInfo` (fields 1–16 used; add 17 in the Identity block):

```proto
  // Identity
  string hostname = 7;
  string kernel_version = 8;

  // Networking
  string host_ipv4 = 17;             // primary external IPv4 of the host; empty when host networking is disabled
```

- [ ] **Step 4: Regenerate bindings**

```bash
PATH=$PWD/.testvenv/bin:$PATH .testvenv/bin/python scripts/generate_proto.py
PATH=$PWD/.testvenv/bin:$PATH bash scripts/check_proto_clean.sh
```
Expected: clean regeneration; `git status` shows changes under `src/aleph/vm/supervisor/_pb/`. Commit **all** regenerated files (these are real field additions, unlike env-drift churn).

- [ ] **Step 5: Edit the dataclasses**

In `src/aleph/vm/supervisor/types.py`, extend `VmInfo`:

```python
@dataclass(frozen=True)
class VmInfo:
    vm_id: VmId
    status: VmStatus
    ipv4: str
    ipv6: str
    uptime_secs: int
    backend: Backend
    numa_node: int | None
    status_message: str
    # Tap networks (CIDR strings); empty until the tap device exists.
    ipv4_network: str = ""
    ipv6_network: str = ""
    # Lifecycle timestamps, unix nanoseconds UTC; 0 = stage not reached.
    defined_at_ns: int = 0
    preparing_at_ns: int = 0
    prepared_at_ns: int = 0
    starting_at_ns: int = 0
    started_at_ns: int = 0
    stopping_at_ns: int = 0
    stopped_at_ns: int = 0
```

And `HostInfo` gains one field (all its fields already have defaults; add after `hostname`):

```python
    hostname: str = ""
    host_ipv4: str = ""  # primary external IPv4; empty when host networking is disabled
```

- [ ] **Step 6: Run the tests**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_proto_bindings.py -v`
Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb/ src/aleph/vm/supervisor/types.py tests/supervisor/test_proto_bindings.py
git commit -m "feat(supervisor): VmInfo networks + lifecycle timestamps, HostInfo host_ipv4"
```

---

### Task 2: InProcessSupervisor fills the new fields; list_vms batches systemd

**Files:**
- Modify: `src/aleph/vm/supervisor/inprocess.py` (`_to_vm_info`, new `_ns` + `_running_states` helpers, `list_vms`, `get_host_info`)
- Test: `tests/supervisor/test_supervisor_inprocess_query.py`

- [ ] **Step 1: Update the test fixture and write the failing tests**

In `tests/supervisor/test_supervisor_inprocess_query.py`, update `make_execution` — the `times` namespace gains the two missing stages and the tap gains networks:

```python
    times = SimpleNamespace(
        defined_at=started,
        preparing_at=None,
        prepared_at=None,
        starting_at=started,
        started_at=started if running else None,
        stopping_at=None,
        stopped_at=None,
    )
    tap = SimpleNamespace(
        guest_ip=SimpleNamespace(ip="10.0.0.2"),
        guest_ipv6=SimpleNamespace(ip="fd00::2"),
        ip_network="172.16.3.0/24",
        ipv6_network="fc00:1:2:3::/64",
    )
```

Append the new tests:

```python
@pytest.mark.asyncio
async def test_get_vm_reports_networks_and_lifecycle_timestamps():
    execution = make_execution(running=True)
    pool = FakePool(
        executions={"itemhash123": execution},
        systemd=FakeSystemd({"aleph-vm-controller@itemhash123.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)

    info = await sup.get_vm(VmId("itemhash123"))

    assert info.ipv4_network == "172.16.3.0/24"
    assert info.ipv6_network == "fc00:1:2:3::/64"
    started = execution.times.started_at
    assert info.started_at_ns == int(started.timestamp()) * 1_000_000_000 + started.microsecond * 1_000
    assert info.preparing_at_ns == 0
    assert info.stopped_at_ns == 0


@pytest.mark.asyncio
async def test_get_vm_without_tap_reports_empty_networks():
    execution = make_execution(running=False, with_ip=False)
    pool = FakePool(executions={"itemhash123": execution})
    sup = InProcessSupervisor(pool=pool)

    info = await sup.get_vm(VmId("itemhash123"))

    assert info.ipv4_network == ""
    assert info.ipv6_network == ""


@pytest.mark.asyncio
async def test_list_vms_batches_the_systemd_query():
    calls: list[list[str]] = []

    class CountingSystemd(FakeSystemd):
        def get_services_active_states(self, services):
            calls.append(list(services))
            return super().get_services_active_states(services)

    pool = FakePool(
        executions={"hash-a": make_execution(vm_hash="hash-a"), "hash-b": make_execution(vm_hash="hash-b")},
        systemd=CountingSystemd({"aleph-vm-controller@hash-a.service": True}),
    )
    sup = InProcessSupervisor(pool=pool)

    infos = await sup.list_vms()

    assert len(calls) == 1
    assert sorted(calls[0]) == [
        "aleph-vm-controller@hash-a.service",
        "aleph-vm-controller@hash-b.service",
    ]
    by_id = {i.vm_id: i for i in infos}
    assert by_id["hash-a"].status is VmStatus.RUNNING
    assert by_id["hash-b"].status is not VmStatus.RUNNING


@pytest.mark.asyncio
async def test_get_host_info_reports_host_ipv4():
    pool = FakePool()
    pool.network = SimpleNamespace(host_ipv4="10.0.5.201")
    sup = InProcessSupervisor(pool=pool)
    assert (await sup.get_host_info()).host_ipv4 == "10.0.5.201"


@pytest.mark.asyncio
async def test_get_host_info_empty_host_ipv4_without_network():
    sup = InProcessSupervisor(pool=FakePool())
    assert (await sup.get_host_info()).host_ipv4 == ""
```

- [ ] **Step 2: Run them to verify they fail**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_supervisor_inprocess_query.py -v`
Expected: the 5 new tests FAIL (`ipv4_network == ""` mismatches, missing batch, `host_ipv4 == ""`); the existing 5 still PASS.

- [ ] **Step 3: Implement in `inprocess.py`**

Add a `_ns` helper next to `_uptime_secs`:

```python
def _ns(dt: datetime | None) -> int:
    """Unix nanoseconds for an aware datetime; 0 for None.

    Same lossless composition as the log timestamps: whole seconds plus the
    integer microsecond field (datetimes carry µs precision, so this
    roundtrips exactly; float multiplication would not).
    """
    if dt is None:
        return 0
    return int(dt.timestamp()) * 1_000_000_000 + dt.microsecond * 1_000
```

Rewrite `_to_vm_info`:

```python
def _to_vm_info(execution, running: bool) -> VmInfo:
    tap = execution.vm.tap_interface if execution.vm else None
    times = execution.times
    return VmInfo(
        vm_id=VmId(str(execution.vm_hash)),
        status=_status_of(execution, running),
        ipv4=str(tap.guest_ip.ip) if tap else "",
        ipv6=str(tap.guest_ipv6.ip) if tap else "",
        uptime_secs=_uptime_secs(execution, running),
        backend=_backend_of(execution),
        numa_node=None,
        status_message="",
        ipv4_network=str(tap.ip_network) if tap else "",
        ipv6_network=str(tap.ipv6_network) if tap else "",
        defined_at_ns=_ns(times.defined_at),
        preparing_at_ns=_ns(times.preparing_at),
        prepared_at_ns=_ns(times.prepared_at),
        starting_at_ns=_ns(times.starting_at),
        started_at_ns=_ns(times.started_at),
        stopping_at_ns=_ns(times.stopping_at),
        stopped_at_ns=_ns(times.stopped_at),
    )
```

Add `_running_states` next to `_is_running` (same logic, one D-Bus round-trip):

```python
def _running_states(pool) -> dict[str, bool]:
    """Running flag for every execution with one batched systemd query.

    Same semantics as _is_running, but a single D-Bus call covers all
    persistent VMs instead of one call each.
    """
    persistent_services: dict[str, str] = {}
    for vm_hash, execution in pool.executions.items():
        if execution.persistent and getattr(execution, "systemd_manager", None):
            persistent_services[execution.controller_service] = str(vm_hash)

    service_states: dict[str, bool] = {}
    if persistent_services and getattr(pool, "systemd_manager", None):
        service_states = pool.systemd_manager.get_services_active_states(list(persistent_services.keys()))

    states: dict[str, bool] = {}
    for vm_hash, execution in pool.executions.items():
        if execution.persistent and getattr(execution, "systemd_manager", None):
            states[str(vm_hash)] = service_states.get(execution.controller_service, False)
        else:
            times = execution.times
            states[str(vm_hash)] = bool(times.starting_at and not times.stopping_at)
    return states
```

Rewrite `list_vms` to use it:

```python
    async def list_vms(self) -> list[VmInfo]:
        with translating_errors():
            running = _running_states(self.pool)
            return [
                _to_vm_info(execution, running[str(vm_hash)])
                for vm_hash, execution in self.pool.executions.items()
            ]
```

In `get_host_info`, add the host IPv4 (FakePool has no `.network`, so use getattr):

```python
            network = getattr(self.pool, "network", None)
            return HostInfo(
                cpu_count=os.cpu_count() or 0,
                memory_mib=int(psutil.virtual_memory().total / (1024 * 1024)),
                kernel_version=os.uname().release,
                hostname=os.uname().nodename,
                host_ipv4=network.host_ipv4 if network else "",
            )
```

- [ ] **Step 4: Run the file, then the supervisor suite**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_supervisor_inprocess_query.py tests/supervisor/test_supervisor_inprocess_lifecycle.py tests/supervisor/test_supervisor_inprocess_ports.py tests/supervisor/test_supervisor_inprocess_logs.py -v`
Expected: all PASS (other inprocess test files use their own fakes; if one trips on the new `times` attributes, extend its fake the same way as Step 1).

- [ ] **Step 5: Commit**

```bash
git add src/aleph/vm/supervisor/inprocess.py tests/supervisor/test_supervisor_inprocess_query.py
git commit -m "feat(supervisor): fill VmInfo networks/timestamps, batch systemd in list_vms, host_ipv4"
```

---

### Task 3: Migrate `list_executions` and `list_executions_v2` onto the supervisor

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (both views, new helpers, delete `_get_executions_running_states`)
- Modify: `src/aleph/vm/orchestrator/vm_registry.py` (widen `get` annotation)
- Test: `tests/supervisor/test_views.py`

- [ ] **Step 1: Widen the registry lookup annotation**

In `src/aleph/vm/orchestrator/vm_registry.py`, `VmId` is a plain `str` NewType, not an `ItemHash`; the views pass hypervisor-issued ids straight through:

```python
    def get(self, vm_hash: ItemHash | str) -> AgentVmRecord | None:
```

(Dict lookup with a `str` works because `ItemHash` is a `str` subclass; this is an annotation widening only.)

- [ ] **Step 2: Write the failing tests**

Append to `tests/supervisor/test_views.py` (reuse the existing imports — `VmExecution`, `InstanceContent`, `settings` are already imported there; add `from datetime import datetime, timezone` and `from aleph_message.models import ItemHash` if missing):

```python
@pytest.mark.asyncio
async def test_executions_list_only_running(aiohttp_client, mocker, mock_app_with_pool, mock_instance_content):
    """/about/executions/list keeps its shape: running VMs only, networks + vm_type."""
    web_app = await mock_app_with_pool
    pool = web_app["vm_pool"]
    registry = web_app["vm_registry"]
    message = InstanceContent.model_validate(mock_instance_content)

    running_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"
    stopped_hash = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe"

    running = VmExecution(
        vm_hash=running_hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )
    running.times.starting_at = datetime.now(tz=timezone.utc)
    running.vm = mocker.Mock()
    running.vm.tap_interface = mocker.Mock(
        ip_network="172.16.3.0/24",
        ipv6_network="fc00:1:2:3::/64",
        guest_ip=mocker.Mock(ip="172.16.3.2"),
        guest_ipv6=mocker.Mock(ip="fc00:1:2:3::2"),
    )
    registry.record(ItemHash(running_hash), message=message, original=message, persistent=False)

    stopped = VmExecution(
        vm_hash=stopped_hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )

    pool.executions = {running_hash: running, stopped_hash: stopped}
    client = await aiohttp_client(web_app)
    response = await client.get("/about/executions/list")
    assert response.status == 200
    assert await response.json() == {
        running_hash: {
            "networking": {"ipv4": "172.16.3.0/24", "ipv6": "fc00:1:2:3::/64"},
            "vm_type": "instance",
        }
    }


@pytest.mark.asyncio
async def test_v2_executions_list_mapped_ports(aiohttp_client, mocker, mock_app_with_pool, mock_instance_content):
    """v2 rebuilds the legacy mapped_ports shape from list_port_forwards."""
    web_app = await mock_app_with_pool
    pool = web_app["vm_pool"]
    message = InstanceContent.model_validate(mock_instance_content)
    vm_hash = "decadecadecadecadecadecadecadecadecadecadecadecadecadecadecadeca"

    execution = VmExecution(
        vm_hash=vm_hash,
        message=message,
        original=message,
        persistent=False,
        snapshot_manager=None,
        systemd_manager=None,
    )
    execution.vm = mocker.Mock()
    execution.vm.tap_interface = mocker.Mock(
        ip_network="172.16.3.0/24",
        ipv6_network="fc00:1:2:3::/64",
        guest_ip=mocker.Mock(ip="172.16.3.2"),
        guest_ipv6=mocker.Mock(ip="fc00:1:2:3::2"),
    )
    execution.mapped_ports = {22: {"host": 24000, "tcp": True, "udp": False}}

    pool.executions = {vm_hash: execution}
    client = await aiohttp_client(web_app)
    response = await client.get("/v2/about/executions/list")
    assert response.status == 200
    body = await response.json()
    assert body[vm_hash]["networking"]["mapped_ports"] == {"22": {"host": 24000, "tcp": True, "udp": False}}
```

- [ ] **Step 3: Run them to verify the new tests fail**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_views.py -v -k "executions_list"`
Expected: `test_executions_list_only_running` FAILS (old code calls `execution.vm.tap_interface.ip_network` on a Mock → Mock repr in JSON, or registry not consulted). `test_v2_executions_list_mapped_ports` may PASS against the old code (it reads `execution.mapped_ports` directly) — that is fine, it pins the parity target. The three existing `test_v2_executions_list_*` tests must PASS.

- [ ] **Step 4: Implement the migration in `views/__init__.py`**

Add imports (top of file, in the existing groups):

```python
from datetime import datetime, timezone

from aleph.vm.orchestrator.vm_registry import AgentVmRecord, AgentVmRegistry
from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.types import Backend, PortForwardInfo, VmInfo, VmStatus
```

(Check which of these are already imported — PR 2 added some; do not duplicate. `VmType` and `ItemHash` are already imported.)

Add three helpers where `_get_executions_running_states` currently lives, then **delete `_get_executions_running_states`** (these two views were its only callers):

```python
def _vm_type_name(record: AgentVmRecord | None, info: VmInfo) -> str:
    """vm_type label: from the agent's message when known, otherwise inferred
    from the hypervisor backend (spec-created / reattached VMs without a
    registry record) — the same inference VmExecution.is_instance used."""
    if record is not None:
        return VmType.from_message_content(record.message).name
    if info.backend in (Backend.QEMU, Backend.QEMU_SEV):
        return VmType.instance.name
    return VmType.microvm.name


def _datetime_from_ns(ns: int) -> datetime | None:
    """Inverse of the supervisor's ns composition; lossless at µs precision."""
    if not ns:
        return None
    return datetime.fromtimestamp(ns // 1_000_000_000, tz=timezone.utc).replace(
        microsecond=(ns % 1_000_000_000) // 1_000
    )


def _times_dict(info: VmInfo) -> dict[str, datetime | None]:
    """The VmExecutionTimes-shaped dict the v2 endpoint has always served."""
    return {
        "defined_at": _datetime_from_ns(info.defined_at_ns),
        "preparing_at": _datetime_from_ns(info.preparing_at_ns),
        "prepared_at": _datetime_from_ns(info.prepared_at_ns),
        "starting_at": _datetime_from_ns(info.starting_at_ns),
        "started_at": _datetime_from_ns(info.started_at_ns),
        "stopping_at": _datetime_from_ns(info.stopping_at_ns),
        "stopped_at": _datetime_from_ns(info.stopped_at_ns),
    }


def _group_port_forwards(forwards: list[PortForwardInfo]) -> dict[str, dict[int, dict]]:
    """{vm_id: {vm_port: {"host", "tcp", "udp"}}} — the legacy mapped_ports
    shape, rebuilt from the supervisor's flat port-forward list."""
    grouped: dict[str, dict[int, dict]] = {}
    for fwd in forwards:
        entry = grouped.setdefault(str(fwd.vm_id), {}).setdefault(
            int(fwd.vm_port), {"host": int(fwd.host_port), "tcp": False, "udp": False}
        )
        entry[fwd.protocol.value] = True
    return grouped
```

Rewrite the two views:

```python
@cors_allow_all
async def list_executions(request: web.Request) -> web.Response:
    supervisor: Supervisor = request.app["supervisor"]
    registry: AgentVmRegistry = request.app["vm_registry"]
    infos = await supervisor.list_vms()
    return web.json_response(
        {
            info.vm_id: {
                "networking": {
                    "ipv4": info.ipv4_network,
                    "ipv6": info.ipv6_network,
                },
                "vm_type": _vm_type_name(registry.get(info.vm_id), info),
            }
            for info in infos
            if info.status is VmStatus.RUNNING
        },
        dumps=dumps_for_json,
    )


@cors_allow_all
async def list_executions_v2(request: web.Request) -> web.Response:
    """List all executions. Returning their status and ip"""
    supervisor: Supervisor = request.app["supervisor"]
    registry: AgentVmRegistry = request.app["vm_registry"]
    infos = await supervisor.list_vms()
    host_info = await supervisor.get_host_info()
    mapped_ports = _group_port_forwards(await supervisor.list_port_forwards())
    return web.json_response(
        {
            info.vm_id: {
                "networking": (
                    {
                        "ipv4_network": info.ipv4_network,
                        "host_ipv4": host_info.host_ipv4,
                        "ipv6_network": info.ipv6_network,
                        "ipv6_ip": info.ipv6,
                        "ipv4_ip": info.ipv4,
                        "mapped_ports": mapped_ports.get(info.vm_id, {}),
                    }
                    if info.ipv4_network
                    else {}
                ),
                "status": _times_dict(info),
                "running": info.status is VmStatus.RUNNING,
                "vm_type": _vm_type_name(registry.get(info.vm_id), info),
            }
            for info in infos
        },
        dumps=dumps_for_json,
    )
```

Note the parity pivots: the old v2 emitted `networking: {}` when `execution.vm`/`tap_interface` was missing — that is exactly `ipv4_network == ""` now. The old `"running"` came from the deleted batch helper — that is exactly `status is RUNNING` now.

- [ ] **Step 5: Run the view tests**

Run: `.testvenv/bin/python -m pytest tests/supervisor/test_views.py -v`
Expected: all PASS — including the three pre-existing `test_v2_executions_list_*` byte-parity tests, **unchanged**.

- [ ] **Step 6: Commit**

```bash
git add src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/orchestrator/vm_registry.py tests/supervisor/test_views.py
git commit -m "refactor(views): list endpoints read the supervisor, not the pool"
```

---

### Task 4: Residual marker, gates, full suite

**Files:**
- Modify: `src/aleph/vm/orchestrator/views/__init__.py` (`about_executions` comment, import cleanup)

- [ ] **Step 1: Mark `about_executions` as a residual**

```python
async def about_executions(request: web.Request) -> web.Response:
    "/about/executions/details Debugging endpoint with full execution details."
    # RESIDUAL (wire-agent design §8.3, decided 2026-06-06): dumps raw
    # VmExecution internals, which cannot cross the Supervisor boundary, and
    # has no known consumers. It dies — or moves to the hypervisor's own debug
    # surface — when the in-process pool goes away in Phase 1.
    authenticate_request(request)
```

- [ ] **Step 2: Import hygiene**

`_get_executions_running_states` is gone; check whether `VmPool` is still referenced in `views/__init__.py` (it is — `update_allocations`, `recreate_network`, etc. — keep it). Remove only imports that became unused. Run:

```bash
.testvenv/bin/python -m mypy src/aleph/vm/orchestrator/views/__init__.py src/aleph/vm/supervisor/ src/aleph/vm/orchestrator/vm_registry.py --ignore-missing-imports
```
Expected: no NEW errors against the branch baseline.

- [ ] **Step 3: Full gates**

```bash
uvx ruff@0.4.6 format --diff .
uvx isort==5.13.2 --check-only --profile black src tests examples
.testvenv/bin/python -m pytest tests/ -x -q
```
Expected: format/isort clean; test suite at baseline (594+ passed; only the 8 documented env-only failures).

- [ ] **Step 4: Commit**

```bash
git add src/aleph/vm/orchestrator/views/__init__.py
git commit -m "docs(views): mark about_executions as a phase-1 residual"
```

---

## Done criteria

- `list_executions` / `list_executions_v2` contain no `pool.` references; `_get_executions_running_states` is deleted.
- The three pre-existing `test_v2_executions_list_*` tests pass without modification (byte-parity proof).
- `InProcessSupervisor.list_vms` issues exactly one `get_services_active_states` call regardless of VM count.
- Proto bindings regenerate clean (`scripts/check_proto_clean.sh`); `VmInfo`/`HostInfo` dataclass and pb2 defaults match.
- mypy/format/isort gates green; full suite at baseline.
- `about_executions` carries the residual comment and is otherwise untouched.
