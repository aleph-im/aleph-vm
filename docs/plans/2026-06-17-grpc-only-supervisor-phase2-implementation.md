# gRPC-only Supervisor Phase 2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Complete the supervisor wire protocol (every Phase 1 method/field crosses gRPC), then make the two-process split the default production deployment with the embedded path confined to dev and tests.

**Architecture:** Phase 1 left the agent fully decoupled from the pool through the `Supervisor` interface, wired to the embedded `LocalSupervisor`. Phase 2 finishes the `GrpcSupervisor` client + `SupervisorService` server so the same interface works over a Unix socket, removes the orphan migration RPCs, then ships two systemd units (a supervisor daemon owning the pool, an agent holding only a gRPC client) and flips production to gRPC.

**Tech Stack:** Python 3, protobuf3 + grpcio + grpcio-tools (+ mypy-protobuf), frozen dataclasses (`types.py`), Debian packaging (`.deb` + systemd units).

**Base branch:** `od/grpc-only-supervisor` (PR #980, into `dev`). Phase 2 continues on the same branch or a follow-up branch `od/grpc-only-supervisor-phase2` cut from it.

---

## Background: exact current state

Phase 1 already built most of the transport. The gaps Phase 2 closes are precise and enumerated below; do not re-derive them.

**Four `GrpcSupervisor` methods are stubs** (`src/aleph/vm/supervisor/grpc_client.py`), each `raise NotImplementedError("wired in Phase 2")`:
- `run_program_code` (line 206-207)
- `restore_from_image` (line 316-319)
- `recreate_network` (line 343-344)
- `reserve_resources` (line 347-348)

None of these four has a proto RPC yet, nor a `SupervisorService` handler.

**Eight dataclass fields are silently dropped over the wire** (present in `types.py`, ignored by `proto_convert.py`, defaulted on round-trip):
1. `TeeConfig.firmware_path` (`types.py:145`)
2. `GpuSpec.device_id` (`types.py:176`)
3. `GpuSpec.model` (`types.py:177`)
4. `CreateVmSpec.owner_address` (`types.py:214`)
5. `Measurement.sev_info` (`types.py:385`, a `SevInfo` with 7 fields, `types.py:361`)
6. `Measurement.launch_measure` (`types.py:386`)
7. `BackupInfo.checksum` / `.volumes` / `.source_sizes` (`types.py:340-342`)
8. `StartBackupRequest.include_volumes` parameter (`grpc_client.py:266`, noqa ARG002)

**HostInfo is asymmetric.** The proto has `cpu_frequency_mhz=12`, `memory_type=13`, `memory_clock_mhz=14` (`proto/supervisor.proto:109,113,114`) that the dataclass and `proto_convert` ignore; the dataclass has `available_disk_bytes`, `gpu_inventory`, `available_gpus` (`types.py:432-434`) that the proto lacks. In split mode the agent's `/about` endpoints lose disk/GPU inventory.

**Three orphan migration RPCs** remain (`proto/supervisor.proto:76-78`, request messages at `:504-517`), with a "drop in the Phase 2 proto pass" comment at `grpc_server.py:235-239`. Phase 1 collapsed migration onto lifecycle RPCs; these have no handlers.

**Packaging is single-unit.** `packaging/aleph-vm/etc/systemd/system/aleph-vm-supervisor.service` runs `python3 -m aleph.vm.orchestrator` (the agent, monolith mode, embedded pool). The daemon entrypoint (`src/aleph/vm/supervisor/daemon.py`, `python -m aleph.vm.supervisor --socket PATH`), the `build_supervisor()` factory (`orchestrator/supervisor.py:195-206`), and the `SUPERVISOR_GRPC_SOCKET` setting (`conf.py:133-139`, default `None`) all already exist. `supervisor.env` does not set the socket, so production runs embedded.

**Proto generation:** `python scripts/generate_proto.py` (emits `supervisor_pb2.py`, `supervisor_pb2_grpc.py`, `supervisor_pb2.pyi` into `src/aleph/vm/supervisor/_pb/`; rewrites the grpc import to relative). Requires `grpcio-tools` and `mypy-protobuf` in the venv. Run it after every `.proto` edit.

**Test command (worktree `just test` is broken):**
```bash
/home/olivier/git/aleph/aleph-vm/venv/bin/python -m pytest <paths> -p no:cacheprovider
```
with `PYTHONPATH=$PWD/src:$PWD/.test-roots/stubs` and `ALEPH_VM_CACHE_ROOT` / `ALEPH_VM_EXECUTION_ROOT` pointed at tmp dirs. Confirm against an existing transport test first:
```bash
cd /home/olivier/git/aleph/aleph-vm/.claude/worktrees/grpc-only-supervisor
PYTHONPATH=$PWD/src:$PWD/.test-roots/stubs /home/olivier/git/aleph/aleph-vm/venv/bin/python -m pytest tests/supervisor/ -q
```

---

## File structure

Phase 2 touches a tight set of files. No new modules except tests and systemd units.

| File | Responsibility | Change |
| --- | --- | --- |
| `proto/supervisor.proto` | wire contract | add fields, 4 RPCs + messages, `SevInfo`; remove 3 orphan RPCs |
| `src/aleph/vm/supervisor/_pb/*` | generated | regenerate (never hand-edit) |
| `src/aleph/vm/supervisor/proto_convert.py` | DTO ⇄ pb | carry the dropped fields; add converters for new messages; drop migration converters |
| `src/aleph/vm/supervisor/grpc_server.py` | server handlers | add 4 handlers; carry `include_volumes` |
| `src/aleph/vm/supervisor/grpc_client.py` | client methods | implement the 4 stubs; carry `include_volumes` |
| `src/aleph/vm/supervisor/abc.py` | interface | `reserve_resources(request: ReservationRequest)` (message-free DTO) |
| `src/aleph/vm/supervisor/types.py` | boundary DTOs | new `ReservationRequest` |
| `src/aleph/vm/supervisor/local.py` | embedded engine | `reserve_resources` checks capacity + reserves GPUs by `device_id` |
| `src/aleph/vm/pool.py` | pool | extract `_check_capacity`; add message-free `reserve_gpus` |
| `src/aleph/vm/supervisor/translate.py` | agent message→DTO | new `build_reservation_request` |
| `src/aleph/vm/orchestrator/views/*` | agent endpoint | `operate_reserve_resources` builds the DTO from the message |
| `packaging/aleph-vm/etc/systemd/system/*.service` | units | split into daemon + agent; reorder controller |
| `packaging/aleph-vm/DEBIAN/{preinst,postinst,prerm}` | maintainer scripts | manage both units + migrate old unit |
| `packaging/aleph-vm/etc/aleph-vm/supervisor.env` | runtime defaults | set the socket (production → gRPC) |
| `packaging/Makefile` | build | ship both units |
| `tests/supervisor/test_grpc_roundtrip.py` (new) | gRPC-over-UDS integration | exercise the newly wired methods |

---

## Part A: Wire protocol completion (design P2.1)

The end state: every `Supervisor` method works identically embedded and over gRPC; no field is silently dropped; no `NotImplementedError("wired in Phase 2")` remains; the orphan migration RPCs are gone.

### Task A1: Carry the dropped scalar fields (TeeConfig, GpuConfig, CreateVmRequest, StartBackup)

**Files:**
- Modify: `proto/supervisor.proto` (TeeConfig `:244`, GpuConfig `:256`, CreateVmRequest `:180`, StartBackupRequest `:456`)
- Modify: `src/aleph/vm/supervisor/proto_convert.py` (`create_vm_spec_to_pb` `:197`, `create_vm_spec_from_pb` `:236`)
- Modify: `src/aleph/vm/supervisor/grpc_server.py` (`StartBackup` `:200`)
- Modify: `src/aleph/vm/supervisor/grpc_client.py` (`start_backup` `:262`)
- Test: `tests/supervisor/test_proto_convert.py`

- [ ] **Step 1: Write the failing round-trip test**

Add to `tests/supervisor/test_proto_convert.py`:

```python
from pathlib import Path

from aleph.vm.supervisor import proto_convert as conv
from aleph.vm.supervisor.types import (
    Backend, CreateVmSpec, DiskRole, GpuSpec, NetworkConfig, PciAddress,
    TeeBackend, TeeConfig, DirectoryPath, VmId,
)


def _minimal_spec(**over):
    base = dict(
        vm_id=VmId("vm1"), backend=Backend.QEMU,
        kernel_path=Path(""), initrd_path=Path(""), disks=[],
        vcpus=1, memory_mib=512, tee=None,
        network=NetworkConfig(internet_access=True, requested_ipv6="", ipv6_prefix_len=0),
        gpus=[], numa_node=None, persistent=True,
    )
    base.update(over)
    return CreateVmSpec(**base)


def test_create_vm_spec_carries_owner_address():
    spec = _minimal_spec(owner_address="0xOWNER")
    assert conv.create_vm_spec_from_pb(conv.create_vm_spec_to_pb(spec)).owner_address == "0xOWNER"


def test_create_vm_spec_carries_tee_firmware_path():
    spec = _minimal_spec(
        tee=TeeConfig(backend=TeeBackend.SEV, policy="0x5",
                      session_dir=DirectoryPath(Path("/s")), firmware_path=Path("/ovmf.fd")),
    )
    out = conv.create_vm_spec_from_pb(conv.create_vm_spec_to_pb(spec))
    assert out.tee.firmware_path == Path("/ovmf.fd")


def test_create_vm_spec_carries_gpu_request_fields():
    spec = _minimal_spec(
        gpus=[GpuSpec(pci_host=PciAddress(""), supports_x_vga=True, device_id="10de:2504", model="RTX 3090")],
    )
    out = conv.create_vm_spec_from_pb(conv.create_vm_spec_to_pb(spec))
    assert (out.gpus[0].device_id, out.gpus[0].model) == ("10de:2504", "RTX 3090")
```

- [ ] **Step 2: Run it to verify it fails**

Run: `PYTHONPATH=$PWD/src:$PWD/.test-roots/stubs venv/bin/python -m pytest tests/supervisor/test_proto_convert.py -k "carries" -q`
Expected: FAIL (`firmware_path` is `None`, `device_id`/`model`/`owner_address` are `""` after round-trip).

- [ ] **Step 3: Edit the proto**

In `proto/supervisor.proto`, extend `TeeConfig` (after `session_dir = 3;`):

```proto
message TeeConfig {
  TeeBackend backend = 1;
  string policy = 2;
  string session_dir = 3;
  string firmware_path = 4;          // resolved OVMF blob path (empty = none)
}
```

Extend `GpuConfig`:

```proto
message GpuConfig {
  string pci_host = 1;               // RESOLVED concrete address; empty in a request
  bool supports_x_vga = 2;
  string device_id = 3;              // REQUEST: vendor:device, e.g. "10de:2504"
  string model = 4;                  // REQUEST: human label
}
```

In `CreateVmRequest`, add after `hostname = 15;` (next free number is 16):

```proto
  string owner_address = 16;         // VM owner's Aleph address; engine consumes this owner's GPU reservation
```

In `StartBackupRequest`, add:

```proto
message StartBackupRequest {
  string vm_id = 1;
  bool quiesce_guest = 2;
  bool include_volumes = 3;          // also archive non-read-only persistent volumes
}
```

- [ ] **Step 4: Regenerate the bindings**

Run: `venv/bin/python scripts/generate_proto.py`
Expected: prints the protoc command and "rewrote ... to use relative import", exit 0.

- [ ] **Step 5: Carry the fields in `proto_convert.py`**

In `create_vm_spec_to_pb` (`:197`), add `owner_address` to the `pb.CreateVmRequest(...)` kwargs:

```python
        hostname=spec.hostname,
        owner_address=spec.owner_address,
    )
```

Update the GPU list comprehension in the same constructor to carry the request fields:

```python
        gpus=[
            pb.GpuConfig(
                pci_host=str(gpu.pci_host),
                supports_x_vga=gpu.supports_x_vga,
                device_id=gpu.device_id,
                model=gpu.model,
            )
            for gpu in spec.gpus
        ],
```

In the `if spec.tee is not None:` block, carry the firmware path (empty when `None`):

```python
        request.tee.CopyFrom(
            pb.TeeConfig(
                backend=TEE_BACKEND_TO_PB[spec.tee.backend],
                policy=spec.tee.policy,
                session_dir=path_to_wire(Path(spec.tee.session_dir)),
                firmware_path=path_to_wire(spec.tee.firmware_path) if spec.tee.firmware_path is not None else "",
            )
        )
```

In `create_vm_spec_from_pb` (`:236`), reconstruct `firmware_path` (empty wire string → `None`):

```python
    if msg.HasField("tee"):
        tee = TeeConfig(
            backend=TEE_BACKEND_FROM_PB[msg.tee.backend],
            policy=msg.tee.policy,
            session_dir=DirectoryPath(path_from_wire(msg.tee.session_dir)),
            firmware_path=path_from_wire(msg.tee.firmware_path) if msg.tee.firmware_path else None,
        )
```

Carry the GPU request fields and `owner_address` in the returned `CreateVmSpec`:

```python
        gpus=[
            GpuSpec(
                pci_host=PciAddress(gpu.pci_host),
                supports_x_vga=gpu.supports_x_vga,
                device_id=gpu.device_id,
                model=gpu.model,
            )
            for gpu in msg.gpus
        ],
        ...
        hostname=msg.hostname,
        owner_address=msg.owner_address,
```

- [ ] **Step 6: Carry `include_volumes` through start_backup**

In `grpc_client.py` `start_backup` (`:262`), drop the noqa and send the field:

```python
    async def start_backup(
        self, vm_id: VmId, quiesce_guest: bool = False, include_volumes: bool = False
    ) -> BackupInfo:
        reply = await self._unary(
            "StartBackup",
            pb.StartBackupRequest(vm_id=str(vm_id), quiesce_guest=quiesce_guest, include_volumes=include_volumes),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return conv.backup_info_from_pb(reply)
```

In `grpc_server.py` `StartBackup` (`:200`):

```python
        info = await self._supervisor.start_backup(
            VmId(request.vm_id), quiesce_guest=request.quiesce_guest, include_volumes=request.include_volumes
        )
```

- [ ] **Step 7: Run the tests**

Run: `PYTHONPATH=$PWD/src:$PWD/.test-roots/stubs venv/bin/python -m pytest tests/supervisor/test_proto_convert.py -q`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb \
  src/aleph/vm/supervisor/proto_convert.py src/aleph/vm/supervisor/grpc_server.py \
  src/aleph/vm/supervisor/grpc_client.py tests/supervisor/test_proto_convert.py
git commit -m "feat(supervisor): carry tee firmware, gpu request, owner, include_volumes over the wire"
```

### Task A2: Carry SEV measurement info (SevInfo + launch_measure)

**Files:**
- Modify: `proto/supervisor.proto` (Measurement `:531`; add `SevInfo`)
- Modify: `src/aleph/vm/supervisor/proto_convert.py` (`measurement_to_pb` `:547`, `measurement_from_pb` `:555`)
- Test: `tests/supervisor/test_proto_convert.py`

- [ ] **Step 1: Write the failing test**

```python
from aleph.vm.supervisor.types import Measurement, SevInfo, TeeBackend, VmId


def test_measurement_carries_sev_info_and_launch_measure():
    m = Measurement(
        vm_id=VmId("vm1"), measurement_bytes=b"m", tee_backend=TeeBackend.SEV,
        sev_info=SevInfo(enabled=True, api_major=1, api_minor=55, build_id=21,
                         policy=3, state="launch-update", handle=7),
        launch_measure="bWVhc3VyZQ==",
    )
    out = conv.measurement_from_pb(conv.measurement_to_pb(m))
    assert out.launch_measure == "bWVhc3VyZQ=="
    assert out.sev_info == m.sev_info
```

- [ ] **Step 2: Run to verify it fails**

Run: `... pytest tests/supervisor/test_proto_convert.py -k measurement -q`
Expected: FAIL (`sev_info is None`, `launch_measure == ""`).

- [ ] **Step 3: Edit the proto**

Add a `SevInfo` message and extend `Measurement`:

```proto
message SevInfo {
  bool enabled = 1;
  uint32 api_major = 2;
  uint32 api_minor = 3;
  uint32 build_id = 4;
  uint32 policy = 5;
  string state = 6;
  uint32 handle = 7;
}

message Measurement {
  string vm_id = 1;
  bytes measurement_bytes = 2;
  TeeBackend tee_backend = 3;
  SevInfo sev_info = 4;              // present for SEV launches
  string launch_measure = 5;        // base64 launch measurement
}
```

- [ ] **Step 4: Regenerate**

Run: `venv/bin/python scripts/generate_proto.py` → exit 0.

- [ ] **Step 5: Add the converters**

In `proto_convert.py`, add `SevInfo` to the `types` import, then add converters and wire them into `measurement_*`:

```python
def sev_info_to_pb(info: SevInfo) -> pb.SevInfo:
    return pb.SevInfo(
        enabled=info.enabled, api_major=info.api_major, api_minor=info.api_minor,
        build_id=info.build_id, policy=info.policy, state=info.state, handle=info.handle,
    )


def sev_info_from_pb(msg: pb.SevInfo) -> SevInfo:
    return SevInfo(
        enabled=msg.enabled, api_major=msg.api_major, api_minor=msg.api_minor,
        build_id=msg.build_id, policy=msg.policy, state=msg.state, handle=msg.handle,
    )
```

`measurement_to_pb`:

```python
def measurement_to_pb(measurement: Measurement) -> pb.Measurement:
    msg = pb.Measurement(
        vm_id=str(measurement.vm_id),
        measurement_bytes=measurement.measurement_bytes,
        tee_backend=TEE_BACKEND_TO_PB[measurement.tee_backend],
        launch_measure=measurement.launch_measure,
    )
    if measurement.sev_info is not None:
        msg.sev_info.CopyFrom(sev_info_to_pb(measurement.sev_info))
    return msg
```

`measurement_from_pb`:

```python
def measurement_from_pb(msg: pb.Measurement) -> Measurement:
    return Measurement(
        vm_id=VmId(msg.vm_id),
        measurement_bytes=msg.measurement_bytes,
        tee_backend=TEE_BACKEND_FROM_PB[msg.tee_backend],
        sev_info=sev_info_from_pb(msg.sev_info) if msg.HasField("sev_info") else None,
        launch_measure=msg.launch_measure,
    )
```

- [ ] **Step 6: Run the test**

Run: `... pytest tests/supervisor/test_proto_convert.py -k measurement -q` → PASS.

- [ ] **Step 7: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/proto_convert.py tests/supervisor/test_proto_convert.py
git commit -m "feat(supervisor): carry SEV info and launch measure over the wire"
```

### Task A3: Carry backup archive metadata (checksum, volumes, source_sizes)

**Files:**
- Modify: `proto/supervisor.proto` (BackupInfo `:447`)
- Modify: `src/aleph/vm/supervisor/proto_convert.py` (`backup_info_to_pb` `:489`, `backup_info_from_pb` `:500`)
- Test: `tests/supervisor/test_proto_convert.py`

- [ ] **Step 1: Failing test**

```python
from aleph.vm.supervisor.types import BackupId, BackupInfo, BackupStatus


def test_backup_info_carries_archive_metadata():
    info = BackupInfo(
        vm_id=VmId("vm1"), backup_id=BackupId("b1"), status=BackupStatus.COMPLETE,
        size_bytes=10, created_at_unix_secs=1, error_message="",
        checksum="sha256:abc", volumes=["rootfs", "data"], source_sizes={"rootfs": 100, "data": 50},
    )
    out = conv.backup_info_from_pb(conv.backup_info_to_pb(info))
    assert out.checksum == "sha256:abc"
    assert out.volumes == ["rootfs", "data"]
    assert out.source_sizes == {"rootfs": 100, "data": 50}
```

- [ ] **Step 2: Run, verify it fails** (fields empty after round-trip).

- [ ] **Step 3: Edit proto** — extend `BackupInfo`:

```proto
message BackupInfo {
  string vm_id = 1;
  string backup_id = 2;
  BackupStatus status = 3;
  uint64 size_bytes = 4;
  uint64 created_at_unix_secs = 5;
  string error_message = 6;
  string checksum = 7;                  // archive checksum, populated when COMPLETE
  repeated string volumes = 8;          // archived volume names
  map<string, uint64> source_sizes = 9; // per-volume uncompressed source size
}
```

- [ ] **Step 4: Regenerate** → exit 0.

- [ ] **Step 5: Converters** — `backup_info_to_pb`:

```python
def backup_info_to_pb(info: BackupInfo) -> pb.BackupInfo:
    return pb.BackupInfo(
        vm_id=str(info.vm_id),
        backup_id=str(info.backup_id),
        status=BACKUP_STATUS_TO_PB[info.status],
        size_bytes=info.size_bytes,
        created_at_unix_secs=info.created_at_unix_secs,
        error_message=info.error_message,
        checksum=info.checksum,
        volumes=list(info.volumes),
        source_sizes=dict(info.source_sizes),
    )
```

`backup_info_from_pb`:

```python
def backup_info_from_pb(msg: pb.BackupInfo) -> BackupInfo:
    return BackupInfo(
        vm_id=VmId(msg.vm_id),
        backup_id=BackupId(msg.backup_id),
        status=BACKUP_STATUS_FROM_PB[msg.status],
        size_bytes=msg.size_bytes,
        created_at_unix_secs=msg.created_at_unix_secs,
        error_message=msg.error_message,
        checksum=msg.checksum,
        volumes=list(msg.volumes),
        source_sizes=dict(msg.source_sizes),
    )
```

- [ ] **Step 6: Run** → PASS.

- [ ] **Step 7: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/proto_convert.py tests/supervisor/test_proto_convert.py
git commit -m "feat(supervisor): carry backup archive metadata over the wire"
```

### Task A4: Reconcile HostInfo (add the asymmetric fields)

**Files:**
- Modify: `proto/supervisor.proto` (HostInfo `:103`)
- Modify: `src/aleph/vm/supervisor/types.py` (HostInfo `:410`)
- Modify: `src/aleph/vm/supervisor/proto_convert.py` (`host_info_to_pb` `:363`, `host_info_from_pb` `:385`)
- Test: `tests/supervisor/test_proto_convert.py`

`gpu_inventory` / `available_gpus` are `list[dict]` (rich agent GPU dicts). Carry them as JSON strings to keep `proto_convert` free of a bespoke schema; the scalar figures get real proto fields. The proto already declares `cpu_frequency_mhz`, `memory_type`, `memory_clock_mhz` (unused today): add matching dataclass fields rather than removing the proto fields.

- [ ] **Step 1: Failing test**

```python
import json
from aleph.vm.supervisor.types import HostInfo


def test_host_info_carries_reservation_and_hardware_fields():
    info = HostInfo(
        cpu_count=8, memory_mib=1024, cpu_frequency_mhz=3200,
        memory_type="DDR5", memory_clock_mhz=4800,
        available_disk_bytes=999,
        gpu_inventory=[{"vendor": "nvidia", "device_name": "RTX 3090"}],
        available_gpus=[{"vendor": "nvidia"}],
    )
    out = conv.host_info_from_pb(conv.host_info_to_pb(info))
    assert out.available_disk_bytes == 999
    assert out.gpu_inventory == [{"vendor": "nvidia", "device_name": "RTX 3090"}]
    assert out.cpu_frequency_mhz == 3200
    assert (out.memory_type, out.memory_clock_mhz) == ("DDR5", 4800)
```

- [ ] **Step 2: Run, verify it fails** (`AttributeError`/defaults).

- [ ] **Step 3: Add dataclass fields** — in `types.py` HostInfo, after the existing defaulted fields:

```python
    cpu_frequency_mhz: int = 0
    memory_type: str = ""
    memory_clock_mhz: int = 0
```

(Keep `available_disk_bytes`, `gpu_inventory`, `available_gpus` where they are.)

- [ ] **Step 4: Add the JSON proto fields** — in `proto/supervisor.proto` HostInfo, add (next free numbers are 18-20):

```proto
  uint64 available_disk_bytes = 18;
  string gpu_inventory_json = 19;    // list[dict] as JSON; rich agent GPU inventory
  string available_gpus_json = 20;   // list[dict] as JSON
```

- [ ] **Step 5: Regenerate** → exit 0.

- [ ] **Step 6: Map them** — `host_info_to_pb` gains:

```python
        cpu_frequency_mhz=info.cpu_frequency_mhz,
        memory_type=info.memory_type,
        memory_clock_mhz=info.memory_clock_mhz,
        available_disk_bytes=info.available_disk_bytes,
        gpu_inventory_json=json.dumps(info.gpu_inventory),
        available_gpus_json=json.dumps(info.available_gpus),
```

`host_info_from_pb` gains (empty string → empty list):

```python
        cpu_frequency_mhz=msg.cpu_frequency_mhz,
        memory_type=msg.memory_type,
        memory_clock_mhz=msg.memory_clock_mhz,
        available_disk_bytes=msg.available_disk_bytes,
        gpu_inventory=json.loads(msg.gpu_inventory_json) if msg.gpu_inventory_json else [],
        available_gpus=json.loads(msg.available_gpus_json) if msg.available_gpus_json else [],
```

Add `import json` at the top of `proto_convert.py`.

- [ ] **Step 7: Run** → PASS.

- [ ] **Step 8: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/types.py src/aleph/vm/supervisor/proto_convert.py tests/supervisor/test_proto_convert.py
git commit -m "feat(supervisor): reconcile HostInfo hardware and reservation fields over the wire"
```

### Task A5: Wire `recreate_network` (simplest new RPC first)

**Files:**
- Modify: `proto/supervisor.proto` (service `:24`; new messages near the network/host section)
- Modify: `src/aleph/vm/supervisor/grpc_server.py`
- Modify: `src/aleph/vm/supervisor/grpc_client.py` (`recreate_network` `:343`)
- Test: `tests/supervisor/test_grpc_roundtrip.py` (new, see Task A9 fixture; create it here)

`recreate_network()` returns a JSON-serialisable summary `dict`. Carry it as a JSON string.

- [ ] **Step 1: Create the gRPC-over-UDS fixture + failing test**

Create `tests/supervisor/test_grpc_roundtrip.py`. The fixture serves a fake `Supervisor` over a real UDS and returns a connected `GrpcSupervisor`:

```python
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio

from aleph.vm.supervisor.abc import Supervisor
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.grpc_server import serve_unix


class _Fake(Supervisor):
    """A Supervisor whose every method is an AsyncMock, configured per test."""
    def __init__(self):
        for name in (
            "health", "get_host_info", "create_vm", "get_vm", "get_vm_spec", "list_vms",
            "delete_vm", "stop_vm", "start_vm", "reboot_vm", "reinstall_vm", "run_program_code",
            "add_port_forward", "remove_port_forward", "list_port_forwards", "get_logs",
            "start_backup", "get_backup_status", "list_backups", "delete_backup",
            "restore_backup", "restore_from_image", "initialize_confidential", "get_measurement",
            "inject_secret", "recreate_network", "reserve_resources",
        ):
            setattr(self, name, AsyncMock())

    def watch_events(self): ...
    def stream_logs(self, *a, **k): ...
    def download_backup(self, *a, **k): ...


@pytest_asyncio.fixture
async def grpc_pair(tmp_path):
    fake = _Fake()
    socket = tmp_path / "supervisor.sock"
    server = await serve_unix(fake, socket)
    client = GrpcSupervisor(socket)
    try:
        yield client, fake
    finally:
        await client.close()
        await server.stop(grace=0)


@pytest.mark.asyncio
async def test_recreate_network_roundtrip(grpc_pair):
    client, fake = grpc_pair
    fake.recreate_network.return_value = {"success": True, "recreated_count": 2, "failed_vms": []}
    result = await client.recreate_network()
    assert result == {"success": True, "recreated_count": 2, "failed_vms": []}
    fake.recreate_network.assert_awaited_once()
```

- [ ] **Step 2: Run, verify it fails**

Run: `... pytest tests/supervisor/test_grpc_roundtrip.py -k recreate -q`
Expected: FAIL with `NotImplementedError("wired in Phase 2")` (client stub) — and once that is removed, with `UNIMPLEMENTED` (no server handler) until Step 5.

- [ ] **Step 3: Edit proto** — add the RPC under a `// ── Network ──` group in the service block, and the messages:

```proto
  // ── Network ──
  rpc RecreateNetwork(RecreateNetworkRequest) returns (RecreateNetworkResponse);
```

```proto
message RecreateNetworkRequest {}
message RecreateNetworkResponse {
  string summary_json = 1;           // JSON-encoded summary dict from the engine
}
```

- [ ] **Step 4: Regenerate** → exit 0.

- [ ] **Step 5: Server handler** — in `grpc_server.py`, add a `# ── Network ──` section after Confidential:

```python
    @_translating
    async def RecreateNetwork(self, request: pb.RecreateNetworkRequest, context) -> pb.RecreateNetworkResponse:
        summary = await self._supervisor.recreate_network()
        return pb.RecreateNetworkResponse(summary_json=json.dumps(summary))
```

Add `import json` at the top of `grpc_server.py`.

- [ ] **Step 6: Client method** — replace the `recreate_network` stub in `grpc_client.py`:

```python
    async def recreate_network(self) -> dict:
        reply = await self._unary("RecreateNetwork", pb.RecreateNetworkRequest(), LIFECYCLE_TIMEOUT_SECS)
        return json.loads(reply.summary_json) if reply.summary_json else {}
```

Add `import json` at the top of `grpc_client.py`.

- [ ] **Step 7: Run** → PASS.

- [ ] **Step 8: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/grpc_server.py src/aleph/vm/supervisor/grpc_client.py tests/supervisor/test_grpc_roundtrip.py
git commit -m "feat(supervisor): wire recreate_network over gRPC"
```

### Task A6: Wire `restore_from_image`

**Files:**
- Modify: `proto/supervisor.proto`
- Modify: `src/aleph/vm/supervisor/grpc_server.py`, `grpc_client.py` (`:316`)
- Test: `tests/supervisor/test_grpc_roundtrip.py`

- [ ] **Step 1: Failing test**

```python
@pytest.mark.asyncio
async def test_restore_from_image_roundtrip(grpc_pair, make_vm_info):
    client, fake = grpc_pair
    fake.restore_from_image.return_value = make_vm_info("vm1")
    out = await client.restore_from_image(VmId("vm1"), DirectoryPath(Path("/img.qcow2")), max_virtual_size_bytes=42)
    assert out.vm_id == "vm1"
    fake.restore_from_image.assert_awaited_once()
    args, kwargs = fake.restore_from_image.call_args
    assert str(args[1]) == "/img.qcow2"
    assert kwargs.get("max_virtual_size_bytes", args[2] if len(args) > 2 else None) == 42
```

Add a `make_vm_info` helper to the test module (a minimal `VmInfo` factory) and import `VmId`, `DirectoryPath`, `Path`.

- [ ] **Step 2: Run, verify it fails** (client stub `NotImplementedError`).

- [ ] **Step 3: Edit proto** — add to the lifecycle group:

```proto
  rpc RestoreFromImage(RestoreFromImageRequest) returns (VmInfo);
```

```proto
message RestoreFromImageRequest {
  string vm_id = 1;
  string image_path = 2;             // host path to a staged QCOW2 image
  uint64 max_virtual_size_bytes = 3; // 0 = no cap
}
```

- [ ] **Step 4: Regenerate** → exit 0.

- [ ] **Step 5: Server handler** — in the Backups section of `grpc_server.py`:

```python
    @_translating
    async def RestoreFromImage(self, request: pb.RestoreFromImageRequest, context) -> pb.VmInfo:
        info = await self._supervisor.restore_from_image(
            VmId(request.vm_id),
            DirectoryPath(conv.path_from_wire(request.image_path)),
            max_virtual_size_bytes=request.max_virtual_size_bytes,
        )
        return conv.vm_info_to_pb(info)
```

Add `DirectoryPath` to the `types` import in `grpc_server.py`.

- [ ] **Step 6: Client method** — replace the stub:

```python
    async def restore_from_image(
        self, vm_id: VmId, image_path: DirectoryPath, max_virtual_size_bytes: int = 0
    ) -> VmInfo:
        reply = await self._unary(
            "RestoreFromImage",
            pb.RestoreFromImageRequest(
                vm_id=str(vm_id),
                image_path=conv.path_to_wire(Path(image_path)),
                max_virtual_size_bytes=max_virtual_size_bytes,
            ),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return conv.vm_info_from_pb(reply)
```

- [ ] **Step 7: Run** → PASS.

- [ ] **Step 8: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/grpc_server.py src/aleph/vm/supervisor/grpc_client.py tests/supervisor/test_grpc_roundtrip.py
git commit -m "feat(supervisor): wire restore_from_image over gRPC"
```

### Task A7: Wire `run_program_code` (msgpack-framed scope)

**Files:**
- Modify: `proto/supervisor.proto`
- Modify: `src/aleph/vm/supervisor/grpc_server.py`, `grpc_client.py` (`:206`)
- Test: `tests/supervisor/test_grpc_roundtrip.py`

The agent passes `scope` (an ASGI-style dict) and gets raw `bytes` back. The engine already frames the scope with msgpack downstream (`local.py:213`, `RunCodePayload(scope=...).as_msgpack()`), so the scope is msgpack-serialisable. Carry it as msgpack bytes; the reply is already bytes.

- [ ] **Step 1: Failing test**

```python
@pytest.mark.asyncio
async def test_run_program_code_roundtrip(grpc_pair):
    client, fake = grpc_pair
    fake.run_program_code.return_value = b"RESULT"
    out = await client.run_program_code(VmId("vm1"), {"type": "http", "path": "/"}, timeout=12.5)
    assert out == b"RESULT"
    args, kwargs = fake.run_program_code.call_args
    assert args[1] == {"type": "http", "path": "/"}
    assert kwargs["timeout"] == 12.5
```

- [ ] **Step 2: Run, verify it fails** (client stub).

- [ ] **Step 3: Edit proto** — add to the lifecycle group:

```proto
  rpc RunProgramCode(RunProgramCodeRequest) returns (RunProgramCodeResponse);
```

```proto
message RunProgramCodeRequest {
  string vm_id = 1;
  bytes scope_msgpack = 2;           // ASGI scope dict, msgpack-encoded
  double timeout_secs = 3;
}
message RunProgramCodeResponse {
  bytes reply = 1;                   // raw runtime reply, opaque to the supervisor
}
```

- [ ] **Step 4: Regenerate** → exit 0.

- [ ] **Step 5: Server handler** — in the lifecycle section of `grpc_server.py`:

```python
    @_translating
    async def RunProgramCode(self, request: pb.RunProgramCodeRequest, context) -> pb.RunProgramCodeResponse:
        scope = msgpack.unpackb(request.scope_msgpack, raw=False)
        reply = await self._supervisor.run_program_code(VmId(request.vm_id), scope, timeout=request.timeout_secs)
        return pb.RunProgramCodeResponse(reply=reply)
```

Add `import msgpack` at the top of `grpc_server.py` (confirm the dependency: `grep -rn "import msgpack" src/aleph/vm` — it is already used by the runtime channel).

- [ ] **Step 6: Client method** — replace the stub:

```python
    async def run_program_code(self, vm_id: VmId, scope: dict, *, timeout: float) -> bytes:
        reply = await self._unary(
            "RunProgramCode",
            pb.RunProgramCodeRequest(vm_id=str(vm_id), scope_msgpack=msgpack.packb(scope, use_bin_type=True),
                                     timeout_secs=timeout),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return reply.reply
```

Add `import msgpack` at the top of `grpc_client.py`.

> Note: `run_program_code` carries a per-request `timeout`, but the gRPC deadline here is the fixed `LIFECYCLE_TIMEOUT_SECS`. If a program's `timeout` can exceed 300s, pass `timeout=max(LIFECYCLE_TIMEOUT_SECS, timeout + overhead)` to `_unary` instead so the deadline never fires before the engine's own timeout. Confirm the program runtime's max `timeout` against `content.resources.seconds` at the `run.py:607` call site.

- [ ] **Step 7: Run** → PASS.

- [ ] **Step 8: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/grpc_server.py src/aleph/vm/supervisor/grpc_client.py tests/supervisor/test_grpc_roundtrip.py
git commit -m "feat(supervisor): wire run_program_code over gRPC (msgpack scope)"
```

### Task A8: Wire `reserve_resources` (message-free resources DTO)

**Decision (resolve the design open question here):** no message crosses the boundary, in either direction. The Phase-1 `reserve_resources(content: Any, user)` took an opaque Aleph object; serialising it as JSON would only relocate the `aleph_message` dependency *into the daemon*, which is the exact coupling Phase 1 removed. Instead the **agent translates the message into a resources DTO** (`ReservationRequest`) and the supervisor reserves against that. The supervisor never imports, parses, or holds an Aleph type.

This is cheap because the engine consumes almost nothing message-shaped already: `check_admission` reads `resources.memory` / `resources.vcpus` / rootfs+volume sizes and the instance-vs-program flag (`pool.py:180-217`); the reservation itself (`find_resources_available_for_user`, `pool.py:1149`) matches purely on `gpu.device_id`. The DTO carries exactly those numbers plus the requested GPUs (as the boundary's existing `GpuSpec`, which already carries `device_id`/`model`). A reservation happens before downloads, so it cannot reuse `CreateVmSpec` (no resolved disk paths) — hence a dedicated, smaller DTO.

**Files:**
- Modify: `proto/supervisor.proto`
- Modify: `src/aleph/vm/supervisor/types.py` (new `ReservationRequest`)
- Modify: `src/aleph/vm/supervisor/abc.py` (`reserve_resources` `:168`)
- Modify: `src/aleph/vm/supervisor/local.py` (`reserve_resources` `:1144`)
- Modify: `src/aleph/vm/pool.py` (extract `_check_capacity`; add `reserve_gpus`)
- Modify: `src/aleph/vm/supervisor/translate.py` (new `build_reservation_request`)
- Modify: `src/aleph/vm/supervisor/proto_convert.py` (converters)
- Modify: `src/aleph/vm/supervisor/grpc_server.py`, `grpc_client.py` (`:347`)
- Modify: the `operate_reserve_resources` handler (find it: `grep -rn "def operate_reserve_resources" src/aleph/vm/orchestrator`)
- Test: `tests/supervisor/test_grpc_roundtrip.py`, `tests/supervisor/test_translate.py`, `tests/supervisor/test_supervisor_inprocess_stubs.py`

- [ ] **Step 1: Add the DTO** — in `types.py`, after `CreateVmSpec`:

```python
@dataclass(frozen=True)
class ReservationRequest:
    """Resources an instance needs, translated from an Aleph message by the
    agent. The supervisor reserves against this and never sees a message:
    capacity is checked from the scalar fields, GPUs are held by ``device_id``.
    A reservation precedes downloads, so this is not a CreateVmSpec (no resolved
    disk paths yet)."""

    user_address: str
    vcpus: int
    memory_mib: int
    disk_mib: int
    is_instance: bool  # instance vs program memory bucket
    gpus: list[GpuSpec] = field(default_factory=list)  # request: device_id/model
```

- [ ] **Step 2: Change the ABC signature** — in `abc.py` `ReservationOps` (drop the `Any`/`content` vocabulary and the `datetime`-only import note; `ReservationRequest` is now imported from `types`):

```python
class ReservationOps(ABC):
    @abstractmethod
    async def reserve_resources(self, request: ReservationRequest) -> datetime:
        """Hold the resources (GPUs today) an instance requests for a user,
        returning the reservation expiry. ``request`` is a message-free
        resources DTO the agent built from the Aleph message; the
        implementation runs the same capacity admission as the create path
        before holding anything."""
```

Update `abc.py`'s `types` import to include `ReservationRequest` (and drop `Any` if it is now unused).

- [ ] **Step 3: Give the pool message-free primitives** — in `pool.py`:

  (a) Extract the capacity arithmetic of `check_admission` (`:180-284`) into a private helper so the message path, the spec path, and the reservation path share one implementation:

```python
    def _check_capacity(self, *, memory_mib: int, vcpus: int, disk_mib: int, is_instance: bool) -> None:
        """Raise InsufficientResourcesError if these requirements exceed the
        host caps. The numbers-only core shared by check_admission (message),
        check_spec_admission (spec) and reserve_gpus' pre-check (DTO)."""
        # body: the committed-sum loop + bucket caps + vcpu cap + disk check
        # currently inlined in check_admission, reading the four parameters
        # instead of `message.resources.*` / isinstance(message, InstanceContent).
```

  Then make `check_admission` compute its four numbers from the message and delegate to `_check_capacity`, leaving its public behaviour identical.

  (b) Add a GPU-reservation primitive keyed on `GpuSpec.device_id`, mirroring `find_resources_available_for_user` (`:1149`) without the message:

```python
    async def reserve_gpus(self, requested: list[GpuSpec], user: str) -> datetime:
        expiration_date = datetime.now(tz=timezone.utc) + timedelta(seconds=60)
        if not requested:
            return expiration_date
        async with self.creation_lock:
            available_gpus = self.get_available_gpus()
            for request in requested:
                for available_gpu in available_gpus:
                    if available_gpu.device_id != request.device_id:
                        continue
                    reservation = self.get_valid_reservation(available_gpu)
                    if reservation is not None and reservation.user != user:
                        continue
                    available_gpus.remove(available_gpu)
                    self.reservations[available_gpu] = Reservation(
                        user=user, expiration=expiration_date, resource=available_gpu
                    )
                    break
                else:
                    raise InsufficientResourcesError(
                        f"No available GPU matching device_id {request.device_id!r}",
                        required={"gpu_device_id": request.device_id},
                        available={"gpus": [g.device_id for g in self.get_available_gpus()]},
                    )
        return expiration_date
```

- [ ] **Step 4: Implement the engine method** — replace `local.py:1144`:

```python
    async def reserve_resources(self, request: ReservationRequest) -> datetime:
        with translating_errors():
            self.pool._check_capacity(
                memory_mib=request.memory_mib, vcpus=request.vcpus,
                disk_mib=request.disk_mib, is_instance=request.is_instance,
            )
            return await self.pool.reserve_gpus(request.gpus, request.user_address)
```

Import `ReservationRequest` in `local.py`.

- [ ] **Step 5: Translate the message agent-side** — add to `src/aleph/vm/supervisor/translate.py` a builder that mirrors the resource extraction already in `build_create_vm_spec` (reuse the same GPU mapping so `device_id`/`model` field names stay consistent):

```python
def build_reservation_request(content, user_address: str) -> ReservationRequest:
    """Extract the resources an Aleph message requests into a message-free DTO.

    Keeps message vocabulary on the agent side: the supervisor reserves against
    the returned DTO and never parses a message."""
    from aleph_message.models import InstanceContent

    is_instance = isinstance(content, InstanceContent)
    disk_mib = 0
    if is_instance and content.rootfs:
        disk_mib += content.rootfs.size_mib
    for volume in content.volumes or []:
        disk_mib += getattr(volume, "size_mib", 0) or 0
    requested = content.requirements.gpu if content.requirements and content.requirements.gpu else []
    gpus = [
        GpuSpec(pci_host=PciAddress(""), supports_x_vga=False,
                device_id=g.device_id, model=getattr(g, "model", "") or "")
        for g in requested
    ]
    return ReservationRequest(
        user_address=user_address,
        vcpus=content.resources.vcpus,
        memory_mib=content.resources.memory,
        disk_mib=disk_mib,
        is_instance=is_instance,
        gpus=gpus,
    )
```

Confirm the GPU requirement field names against the existing `build_create_vm_spec` GPU branch and reuse whatever it uses (do not invent a new accessor).

- [ ] **Step 6: Update the agent endpoint** — in `operate_reserve_resources`, build the DTO and call the interface:

```python
    request = build_reservation_request(content, user)
    expiry = await supervisor.reserve_resources(request)
```

- [ ] **Step 7: Failing translate test** — `tests/supervisor/test_translate.py`:

```python
def test_build_reservation_request_extracts_resources():
    content = ...  # a minimal InstanceContent with resources.vcpus=2, memory=2048, one GPU device_id="10de:2504"
    req = build_reservation_request(content, "0xUSER")
    assert (req.vcpus, req.memory_mib, req.is_instance, req.user_address) == (2, 2048, True, "0xUSER")
    assert [g.device_id for g in req.gpus] == ["10de:2504"]
```

Run, verify it fails, then confirm it passes once Step 5 lands.

- [ ] **Step 8: Failing gRPC round-trip test** — `tests/supervisor/test_grpc_roundtrip.py`:

```python
from datetime import datetime, timezone

from aleph.vm.supervisor.types import GpuSpec, PciAddress, ReservationRequest


@pytest.mark.asyncio
async def test_reserve_resources_roundtrip(grpc_pair):
    client, fake = grpc_pair
    expiry = datetime(2030, 1, 1, tzinfo=timezone.utc)
    fake.reserve_resources.return_value = expiry
    req = ReservationRequest(
        user_address="0xUSER", vcpus=2, memory_mib=2048, disk_mib=10, is_instance=True,
        gpus=[GpuSpec(pci_host=PciAddress(""), supports_x_vga=False, device_id="10de:2504", model="X")],
    )
    out = await client.reserve_resources(req)
    assert out == expiry
    (sent,), _ = fake.reserve_resources.call_args
    assert sent == req
```

- [ ] **Step 9: Run, verify it fails** (client stub `NotImplementedError`).

- [ ] **Step 10: Edit proto** — add a `// ── Reservation ──` group and reuse `GpuConfig` (now carries `device_id`/`model` after Task A1):

```proto
  // ── Reservation ──
  rpc ReserveResources(ReserveResourcesRequest) returns (ReserveResourcesResponse);
```

```proto
message ReserveResourcesRequest {
  string user_address = 1;
  uint32 vcpus = 2;
  uint64 memory_mib = 3;
  uint64 disk_mib = 4;
  bool is_instance = 5;
  repeated GpuConfig gpus = 6;        // request: matched by device_id
}
message ReserveResourcesResponse {
  int64 expiry_unix_ns = 1;          // reservation expiry, unix ns UTC
}
```

- [ ] **Step 11: Regenerate** → exit 0.

- [ ] **Step 12: Converters** — in `proto_convert.py` (reuse the GPU mapping; a request `GpuSpec` round-trips through `GpuConfig`):

```python
def reservation_request_to_pb(req: ReservationRequest) -> pb.ReserveResourcesRequest:
    return pb.ReserveResourcesRequest(
        user_address=req.user_address, vcpus=req.vcpus, memory_mib=req.memory_mib,
        disk_mib=req.disk_mib, is_instance=req.is_instance,
        gpus=[
            pb.GpuConfig(pci_host=str(g.pci_host), supports_x_vga=g.supports_x_vga,
                         device_id=g.device_id, model=g.model)
            for g in req.gpus
        ],
    )


def reservation_request_from_pb(msg: pb.ReserveResourcesRequest) -> ReservationRequest:
    return ReservationRequest(
        user_address=msg.user_address, vcpus=msg.vcpus, memory_mib=msg.memory_mib,
        disk_mib=msg.disk_mib, is_instance=msg.is_instance,
        gpus=[
            GpuSpec(pci_host=PciAddress(g.pci_host), supports_x_vga=g.supports_x_vga,
                    device_id=g.device_id, model=g.model)
            for g in msg.gpus
        ],
    )
```

Import `ReservationRequest` in `proto_convert.py`.

- [ ] **Step 13: Server handler** — in `grpc_server.py`:

```python
    @_translating
    async def ReserveResources(self, request: pb.ReserveResourcesRequest, context) -> pb.ReserveResourcesResponse:
        expiry = await self._supervisor.reserve_resources(conv.reservation_request_from_pb(request))
        return pb.ReserveResourcesResponse(expiry_unix_ns=int(expiry.timestamp() * 1_000_000_000))
```

- [ ] **Step 14: Client method** — replace the stub:

```python
    async def reserve_resources(self, request: ReservationRequest) -> datetime:
        reply = await self._unary(
            "ReserveResources",
            conv.reservation_request_to_pb(request),
            LIFECYCLE_TIMEOUT_SECS,
        )
        return datetime.fromtimestamp(reply.expiry_unix_ns / 1_000_000_000, tz=timezone.utc)
```

Add `timezone` to the `datetime` import and `ReservationRequest` to the `types` import in `grpc_client.py`.

- [ ] **Step 15: Update the embedded engine test** — in `test_supervisor_inprocess_stubs.py`, replace any `reserve_resources(content, user)` call with a `ReservationRequest`, and assert the engine calls `pool._check_capacity` + `pool.reserve_gpus` (no message parsing). Add a `pool.reserve_gpus` unit test (reserve by `device_id`; raise when none free; respect another user's hold).

- [ ] **Step 16: Run** all touched tests:

Run: `... pytest tests/supervisor/test_grpc_roundtrip.py::test_reserve_resources_roundtrip tests/supervisor/test_translate.py tests/supervisor/test_supervisor_inprocess_stubs.py tests/test_pool*.py -q` → PASS.

- [ ] **Step 17: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/types.py \
  src/aleph/vm/supervisor/abc.py src/aleph/vm/supervisor/local.py src/aleph/vm/pool.py \
  src/aleph/vm/supervisor/translate.py src/aleph/vm/supervisor/proto_convert.py \
  src/aleph/vm/supervisor/grpc_server.py src/aleph/vm/supervisor/grpc_client.py \
  src/aleph/vm/orchestrator/views tests/supervisor/
git commit -m "feat(supervisor): reserve_resources takes a message-free resources DTO over gRPC"
```

### Task A9: Remove the orphan migration RPCs

**Files:**
- Modify: `proto/supervisor.proto` (RPCs `:76-78`, messages `:497-517`, and `MigrationInfo`/`MigrationPhase` if unused)
- Modify: `src/aleph/vm/supervisor/proto_convert.py` (`migration_info_*` `:519-541`, `MIGRATION_PHASE_*` tables `:135-142`)
- Modify: `src/aleph/vm/supervisor/grpc_server.py` (the migration comment `:235-239`)
- Test: existing suite (no new behaviour)

- [ ] **Step 1: Confirm nothing else uses the migration proto types**

Run:
```bash
grep -rn "MigrationInfo\|MigrationPhase\|migration_info_\|MIGRATION_PHASE\|ExportVm\|ImportVm\|GetMigrationStatus" src/ tests/
```
Expected: hits only in `proto_convert.py`, the generated `_pb`, and `types.py`. (`ErrorCode.MIGRATION_*` and the `MigrationInProgressError`/`MigrationNotFoundError` classes are a separate concern — leave them; migration still exists as a feature, riding lifecycle RPCs.) If a live caller exists, stop and reassess.

- [ ] **Step 2: Remove the proto RPCs and messages**

Delete the three `rpc` lines (`:76-78`), the `// ── Migration ──` provisional note and `ExportVmRequest`/`ImportVmRequest`/`GetMigrationStatusRequest` (`:497-517`), and `MigrationInfo` + `MigrationPhase` (`:479-495`) if Step 1 showed them unused.

- [ ] **Step 3: Regenerate** → exit 0.

- [ ] **Step 4: Remove the dead converters** — delete `migration_info_to_pb`/`migration_info_from_pb` and the `MIGRATION_PHASE_TO_PB`/`FROM_PB` tables from `proto_convert.py`; drop `MigrationInfo`/`MigrationPhase`/`MigrationId` from its `types` import. Remove the stale migration comment block in `grpc_server.py:235-239`.

- [ ] **Step 5: Run the full supervisor suite**

Run: `... pytest tests/supervisor/ -q` → PASS (no import errors; `proto_convert` no longer references the removed messages).

- [ ] **Step 6: Commit**

```bash
git add proto/supervisor.proto src/aleph/vm/supervisor/_pb src/aleph/vm/supervisor/proto_convert.py src/aleph/vm/supervisor/grpc_server.py
git commit -m "refactor(supervisor): drop the orphan directory-based migration RPCs"
```

### Task A10: Prove no method is left unwired

**Files:**
- Test: `tests/supervisor/test_agent_pool_free.py` (extend) or a new `tests/supervisor/test_grpc_complete.py`

- [ ] **Step 1: Guard test — no `NotImplementedError` stub remains in the client**

```python
import inspect
from aleph.vm.supervisor import grpc_client


def test_no_phase2_stubs_remain():
    source = inspect.getsource(grpc_client)
    assert "wired in Phase 2" not in source
    assert "NotImplementedError" not in source
```

- [ ] **Step 2: Guard test — every ABC method has a server handler**

```python
from aleph.vm.supervisor._pb import supervisor_pb2_grpc as g
from aleph.vm.supervisor.grpc_server import SupervisorService


def test_every_rpc_has_a_handler():
    # Names declared on the generated servicer base, implemented on SupervisorService.
    rpc_names = [n for n in dir(g.SupervisorServicer) if n[:1].isupper()]
    for name in rpc_names:
        assert hasattr(SupervisorService, name), f"missing handler: {name}"
```

- [ ] **Step 3: Run** → PASS.

- [ ] **Step 4: Run the whole suite + lint gates**

```bash
PYTHONPATH=$PWD/src:$PWD/.test-roots/stubs venv/bin/python -m pytest tests/supervisor/ -q
venv/bin/ruff format --diff src/aleph/vm/supervisor proto
venv/bin/ruff check src/aleph/vm/supervisor
venv/bin/isort --profile black --check src/aleph/vm/supervisor
venv/bin/mypy src/aleph/vm/
```
Expected: tests PASS; format/isort clean; mypy at or below the branch baseline.

- [ ] **Step 5: Commit**

```bash
git add tests/supervisor/test_grpc_complete.py
git commit -m "test(supervisor): guard that the gRPC surface is complete"
```

---

## Part B: Two-service packaging (design P2.2)

End state: production installs two units, the agent runs in split mode against the daemon's socket, and an upgrade from the single Phase 1 unit migrates cleanly.

### Task B1: Split the systemd units

**Files:**
- Modify: `packaging/aleph-vm/etc/systemd/system/aleph-vm-supervisor.service` (becomes the daemon)
- Create: `packaging/aleph-vm/etc/systemd/system/aleph-vm-agent.service`
- Modify: `packaging/aleph-vm/etc/systemd/system/aleph-vm-controller@.service` (ordering)

Keep the unit name `aleph-vm-supervisor.service` for the daemon (it now genuinely is the supervisor) and add a new `aleph-vm-agent.service` for the HTTP/orchestrator process. This minimises churn in the controller dependency and existing operator muscle memory.

- [ ] **Step 1: Repurpose `aleph-vm-supervisor.service` as the daemon**

```ini
[Unit]
Description=Aleph.im VM supervisor daemon (pool owner, gRPC)
After=network.target
After=docker.service
Wants=docker.service

[Service]
User=0
Group=0
WorkingDirectory=/opt/aleph-vm
Environment=PYTHONPATH=/opt/aleph-vm/:$PYTHONPATH
Environment=PYTHONDONTWRITEBYTECODE="enabled"
EnvironmentFile=/etc/aleph-vm/supervisor.env
ExecStart=python3 -m aleph.vm.supervisor
Restart=on-failure
RestartPreventExitStatus=0 130 143
RestartSec=10s
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
```

- [ ] **Step 2: Create `aleph-vm-agent.service`**

```ini
[Unit]
Description=Aleph.im VM agent (CRN HTTP API)
After=network.target aleph-vm-supervisor.service
Wants=aleph-vm-supervisor.service

[Service]
User=0
Group=0
WorkingDirectory=/opt/aleph-vm
Environment=PYTHONPATH=/opt/aleph-vm/:$PYTHONPATH
Environment=PYTHONDONTWRITEBYTECODE="enabled"
EnvironmentFile=/etc/aleph-vm/supervisor.env
ExecStart=python3 -m aleph.vm.orchestrator --print-settings
Restart=on-failure
RestartPreventExitStatus=0 130 143
RestartSec=10s
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
```

The shared `supervisor.env` sets `ALEPH_VM_SUPERVISOR_GRPC_SOCKET` (Task B4), so the agent boots in split mode and the daemon binds the same socket.

- [ ] **Step 3: Reorder the controller template**

Controllers attach to the daemon's pool, not the agent. In `aleph-vm-controller@.service` the existing `After=`/`Wants=aleph-vm-supervisor.service` is already correct now that `aleph-vm-supervisor.service` is the daemon — confirm no reference to the agent is needed. No change unless it names the agent.

- [ ] **Step 4: Commit**

```bash
git add packaging/aleph-vm/etc/systemd/system/
git commit -m "feat(packaging): split supervisor daemon and agent into two systemd units"
```

### Task B2: Ship both units from the Makefile / install layout

**Files:**
- Modify: `packaging/Makefile` (the `debian-package-resources`/install steps that stage `etc/systemd/system`)

- [ ] **Step 1: Confirm how units are staged**

Run: `grep -n "systemd\|\.service\|etc/" packaging/Makefile`. The unit files live under `packaging/aleph-vm/etc/systemd/system/` and are copied as part of the package tree, so a new `.service` file is included automatically. If the Makefile enumerates units explicitly, add `aleph-vm-agent.service`.

- [ ] **Step 2: Build a package locally to verify both units are present**

Run the package build target used in CI (`grep -n "all-podman\|debian-package" packaging/Makefile` for the exact target) for one distro, then:
```bash
dpkg-deb -c <built>.deb | grep '\.service'
```
Expected: both `aleph-vm-supervisor.service` and `aleph-vm-agent.service` (and `aleph-vm-controller@.service`) appear.

- [ ] **Step 3: Commit** (only if the Makefile changed)

```bash
git add packaging/Makefile
git commit -m "build(packaging): ship the agent unit alongside the supervisor daemon"
```

### Task B3: Maintainer scripts for two units + upgrade migration

**Files:**
- Modify: `packaging/aleph-vm/DEBIAN/preinst`
- Modify: `packaging/aleph-vm/DEBIAN/postinst`
- Modify: `packaging/aleph-vm/DEBIAN/prerm`

The hard part: a host upgrading from Phase 1 has a single `aleph-vm-supervisor.service` running the agent (monolith). After upgrade, `aleph-vm-supervisor.service` is the daemon and `aleph-vm-agent.service` is the HTTP process. Running VMs live in `aleph-vm-controller@` units and survive (the daemon reattaches via `load_persistent_executions`). The migration is therefore: stop the old monolith, start daemon then agent.

- [ ] **Step 1: `preinst` — stop both units before unpacking**

```bash
#!/bin/bash
set -uf -o pipefail
if ! [[ -v container ]]; then
  systemctl stop aleph-vm-agent.service 2>/dev/null || true
  systemctl stop aleph-vm-supervisor.service 2>/dev/null || true
fi
set -e
```

(Stopping the agent first, then the supervisor, mirrors the dependency order; both `|| true` so a fresh install where the units do not yet exist still proceeds.)

- [ ] **Step 2: `postinst` — enable and start daemon then agent**

Replace the final systemd block (`postinst:52-56`) with:

```bash
# Systemd is absent from containers
if ! [[ -v container ]]; then
  systemctl daemon-reload
  systemctl enable aleph-vm-supervisor.service aleph-vm-agent.service
  systemctl restart aleph-vm-supervisor.service
  # Wait for the daemon socket before the agent dials it (split mode).
  for _ in $(seq 1 30); do
    [ -S /var/lib/aleph/vm/supervisor.sock ] && break
    sleep 1
  done
  systemctl restart aleph-vm-agent.service
fi
```

Leave the HAProxy and jailman/IPFS sections of `postinst` unchanged.

- [ ] **Step 3: `prerm` — disable/stop both units**

```bash
#!/bin/bash
set -euf -o pipefail

for unit in aleph-vm-agent.service aleph-vm-supervisor.service; do
  systemctl disable "$unit" || true
  systemctl stop "$unit" || true
  systemctl reset-failed "$unit" 2>/dev/null || true
done
```

- [ ] **Step 4: Commit**

```bash
git add packaging/aleph-vm/DEBIAN/preinst packaging/aleph-vm/DEBIAN/postinst packaging/aleph-vm/DEBIAN/prerm
git commit -m "feat(packaging): manage and migrate the two-service split in maintainer scripts"
```

### Task B4: Set the socket default (production → gRPC)

**Files:**
- Modify: `packaging/aleph-vm/etc/aleph-vm/supervisor.env`

The conf default stays `None` so dev/tests run embedded; production opts into split mode through the shipped env file. `supervisor.env` is a conffile (`DEBIAN/conffiles`), so an operator's edits survive upgrades.

- [ ] **Step 1: Add the socket to `supervisor.env`**

```bash
# System logs make boot ~2x slower
ALEPH_VM_PRINT_SYSTEM_LOGS=False
ALEPH_VM_DOMAIN_NAME=vm.example.org
ALEPH_VM_PAYMENT_RECEIVER_ADDRESS=
# Two-process split: the agent talks to the supervisor daemon over this socket.
# Both units read this file; the daemon binds it, the agent dials it.
ALEPH_VM_SUPERVISOR_GRPC_SOCKET=/var/lib/aleph/vm/supervisor.sock
```

(`/var/lib/aleph/vm` is `EXECUTION_ROOT`, matching `default_socket_path()`.)

- [ ] **Step 2: Commit**

```bash
git add packaging/aleph-vm/etc/aleph-vm/supervisor.env
git commit -m "feat(packaging): default production to the two-process gRPC split"
```

---

## Part C: Default confinement and validation (design P2.3)

### Task C1: Confirm dev/test stay embedded; guard the factory

**Files:**
- Test: `tests/supervisor/test_build_supervisor.py` (new or extend existing)

- [ ] **Step 1: Tests for `build_supervisor`**

```python
from types import SimpleNamespace

from aleph.vm.orchestrator.supervisor import build_supervisor
from aleph.vm.supervisor.grpc_client import GrpcSupervisor
from aleph.vm.supervisor.local import LocalSupervisor


def test_build_supervisor_embedded_when_socket_unset():
    settings = SimpleNamespace(SUPERVISOR_GRPC_SOCKET=None)
    assert isinstance(build_supervisor(settings, pool=object()), LocalSupervisor)


def test_build_supervisor_grpc_when_socket_set():
    settings = SimpleNamespace(SUPERVISOR_GRPC_SOCKET="/tmp/x.sock")
    assert isinstance(build_supervisor(settings, pool=None), GrpcSupervisor)
```

- [ ] **Step 2: Confirm the conf default is `None`**

Run: `grep -n "SUPERVISOR_GRPC_SOCKET" src/aleph/vm/conf.py` — value must remain `Field(None, ...)`. The default lives in packaging (`supervisor.env`), not in code, so the test suite (which does not load the env file) stays embedded.

- [ ] **Step 3: Run** → PASS. Commit.

```bash
git add tests/supervisor/test_build_supervisor.py
git commit -m "test(supervisor): pin embedded-by-default, gRPC-when-socket-set wiring"
```

### Task C2: Full local validation

- [ ] **Step 1: Whole suite + gates**

```bash
cd /home/olivier/git/aleph/aleph-vm/.claude/worktrees/grpc-only-supervisor
PYTHONPATH=$PWD/src:$PWD/.test-roots/stubs ALEPH_VM_CACHE_ROOT=/tmp/avm-cache ALEPH_VM_EXECUTION_ROOT=/tmp/avm-exec \
  venv/bin/python -m pytest tests/ -q
venv/bin/ruff format --diff src proto && venv/bin/ruff check src && venv/bin/isort --profile black --check src
venv/bin/mypy src/aleph/vm/
```
Expected: only the known pre-existing root/env failures (`test_execution`, `test_instance`, `test_interfaces`, `test_port_mappings`); no new failures; gates clean.

- [ ] **Step 2: Smoke-test the daemon ⇄ agent locally (no VMs)**

Start the daemon against a temp socket, then drive `health()` through a `GrpcSupervisor`:

```bash
ALEPH_VM_SUPERVISOR_GRPC_SOCKET=/tmp/sup.sock PYTHONPATH=$PWD/src:$PWD/.test-roots/stubs \
  venv/bin/python -m aleph.vm.supervisor --socket /tmp/sup.sock -v &
# in a second shell, a one-liner that builds GrpcSupervisor('/tmp/sup.sock') and prints await client.health()
```
Expected: the daemon logs "Supervisor daemon ready"; `health()` returns an OK `HealthInfo`. (This exercises the real socket path end to end without hardware.)

### Task C3: Testnet two-process validation

Driven from the `aleph-testnets` repo (PR #27). Out of band of this code repo, tracked here for completeness.

- [ ] **Step 1: Point the testnet manifest at this branch** (`manifesto.yml` aleph-vm `branch:`), deploy, and confirm:
  - both `aleph-vm-supervisor.service` and `aleph-vm-agent.service` are active;
  - the socket exists at `/var/lib/aleph/vm/supervisor.sock`;
  - an instance create/stop/start/delete cycle works (lifecycle over gRPC);
  - the migration and graceful-stop tests that PR #27 already runs still pass.
- [ ] **Step 2:** Capture any split-mode-only failures (e.g. an endpoint that still assumed embedded) and fix forward before flipping `dev`.

---

## Self-review checklist (run before handing off execution)

1. **Spec coverage:** Part A closes all four stubs + all eight dropped fields + the HostInfo asymmetry + the orphan RPCs (design P2.1). Part B is the two-service packaging + postinst migration + socket default (P2.2). Part C confines the embedded path and validates (P2.3). All design P2 items are covered.
2. **Type consistency:** `reserve_resources(request: ReservationRequest)` is changed in the ABC, both implementations, the endpoint, and the tests (Task A8) — no call site keeps the old `(content, user)` object form, and no Aleph type crosses the boundary in either direction (the agent's `build_reservation_request` is the only message reader). `restore_from_image` keeps `max_virtual_size_bytes` as a keyword across client/server/ABC.
3. **No silent caps:** the gRPC `LIFECYCLE_TIMEOUT_SECS` deadline vs the per-request `run_program_code` timeout is called out explicitly (Task A7) rather than left to bite a long program.
4. **Generated code:** every proto edit is followed by `scripts/generate_proto.py`; `_pb/` is committed, never hand-edited.
```
