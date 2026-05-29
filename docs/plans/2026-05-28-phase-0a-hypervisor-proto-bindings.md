# Phase 0.A: `hypervisor.proto` and Python Bindings: Implementation Plan

> **Historical note:** the `hypervisor` boundary was renamed to `supervisor`
> shortly after this phase shipped (QEMU/Firecracker are the actual
> hypervisors; this layer is a supervisor/orchestrator). Paths and
> identifiers below (`proto/hypervisor.proto`, `aleph.vm.hypervisor`,
> service `Hypervisor`, branch `od/hypervisor-boundary`) reflect the
> original 0.A naming and are preserved for historical accuracy. Current
> names: `proto/supervisor.proto`, `aleph.vm.supervisor`, service
> `Supervisor`.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Define the full `hypervisor.proto` contract (Hypervisor service surface + closed wire error enum) and ship the generated Python bindings, with no behavioural change to aleph-vm yet. This is the linchpin deliverable that unblocks the rest of Phase 0.

**Architecture:** A new `proto/hypervisor.proto` is the single source of truth. `scripts/generate_proto.py` invokes `grpcio-tools` to produce `src/aleph/vm/hypervisor/_pb/{hypervisor_pb2.py, hypervisor_pb2_grpc.py, hypervisor_pb2.pyi}`. Generated files are checked in so editors and CI work without a regen step; CI re-runs the script and fails if generated files drift from the source. The Hypervisor ABC and implementations land in later sub-plans (0.B–0.E).

**Tech Stack:** Python ≥3.10, protobuf 4, grpcio, grpcio-tools (dev), mypy-protobuf (for `.pyi` stubs), pytest, hatch.

**Reference spec:** `aleph-cvm/docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md` (§5 RPC list, §9 wire error vocabulary, Annex A.6 exception types).

---

## File Structure

**Create:**

| Path | Responsibility |
| --- | --- |
| `proto/hypervisor.proto` | The contract: single source of truth |
| `proto/README.md` | How to regenerate; what's checked in vs. generated |
| `scripts/generate_proto.py` | Invokes `grpcio-tools` to produce `_pb` modules |
| `src/aleph/vm/hypervisor/__init__.py` | Empty package marker for the new module tree |
| `src/aleph/vm/hypervisor/_pb/__init__.py` | Re-exports the generated symbols; marks the dir as a package |
| `src/aleph/vm/hypervisor/_pb/hypervisor_pb2.py` | Generated (checked in) |
| `src/aleph/vm/hypervisor/_pb/hypervisor_pb2_grpc.py` | Generated (checked in) |
| `src/aleph/vm/hypervisor/_pb/hypervisor_pb2.pyi` | Generated (checked in, mypy-readable) |
| `tests/hypervisor/__init__.py` | Test package marker |
| `tests/hypervisor/test_proto_bindings.py` | Smoke tests: imports, RPC presence, enum coverage |

**Modify:**

| Path | Change |
| --- | --- |
| `pyproject.toml` | Add `grpcio`, `protobuf` runtime deps; add `grpcio-tools`, `mypy-protobuf` dev deps; ensure pytest discovers `tests/hypervisor/` |
| `.gitignore` | Make sure no spurious build artefacts from proto generation leak in |

---

## Conventions used in this plan

- **Working directory:** the worktree root `/home/olivier/git/aleph/aleph-vm/.worktrees/hypervisor-boundary`.
- **Test command:** `pytest tests/hypervisor -v` (covers only the new module's tests; full suite is run in the final task).
- **Regeneration command:** `python scripts/generate_proto.py` (idempotent).
- **Commit style:** Conventional Commits prefix (`feat:`, `chore:`, `test:`, `docs:`). No `Co-Authored-By` footer per the user's preference.
- **Branch:** `od/hypervisor-boundary` (already created).

---

## Tasks

### Task 1: Bootstrap the proto toolchain and an empty hypervisor.proto

**Files:**
- Create: `proto/hypervisor.proto` (minimal: `syntax`, `package`, empty `service Hypervisor {}`)
- Create: `scripts/generate_proto.py`
- Create: `src/aleph/vm/hypervisor/__init__.py` (empty)
- Create: `src/aleph/vm/hypervisor/_pb/__init__.py`
- Create: `tests/hypervisor/__init__.py` (empty)
- Create: `tests/hypervisor/test_proto_bindings.py`
- Modify: `pyproject.toml` (add deps; pytest discovery)

- [ ] **Step 1: Write the failing smoke test**

Create `tests/hypervisor/test_proto_bindings.py`:

```python
"""Smoke tests for the generated hypervisor.proto Python bindings.

These verify that the proto compiles, the generated modules import, and
the service/messages/enums are present with the expected names and
fields. Behavioural tests live with the Hypervisor implementations
(plans 0.C and 0.D).
"""

def test_generated_modules_importable():
    from aleph.vm.hypervisor._pb import hypervisor_pb2, hypervisor_pb2_grpc  # noqa: F401


def test_service_descriptor_present():
    from aleph.vm.hypervisor._pb import hypervisor_pb2_grpc
    assert hasattr(hypervisor_pb2_grpc, "HypervisorStub")
    assert hasattr(hypervisor_pb2_grpc, "HypervisorServicer")
    assert hasattr(hypervisor_pb2_grpc, "add_HypervisorServicer_to_server")
```

- [ ] **Step 2: Run the test, confirm failure**

Run: `pytest tests/hypervisor/test_proto_bindings.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'aleph.vm.hypervisor'`)

- [ ] **Step 3: Add the runtime + dev dependencies in `pyproject.toml`**

Find the `[project]` table's `dependencies = [...]` array and append (alphabetical order if existing list is sorted):

```toml
"grpcio>=1.60",
"protobuf>=4.25,<5",
```

Find the dev/test dependency group (likely `[project.optional-dependencies]` with key `test` or `dev`, or `[tool.hatch.envs.default.dependencies]`). Append:

```toml
"grpcio-tools>=1.60",
"mypy-protobuf>=3.6",
```

If `[tool.pytest.ini_options]` exists with `testpaths`, ensure `tests/hypervisor` is covered (the default `tests/` recursive discovery already covers it; only add if `testpaths` lists specific subdirs).

Install: `pip install -e ".[test]"` (or whichever extra is configured for dev).

- [ ] **Step 4: Create the minimal proto and the generation script**

Create `proto/hypervisor.proto`:

```proto
// SPDX-License-Identifier: MIT
//
// Aleph VM Hypervisor contract.
//
// This service is the infra-only boundary between the network-agent
// (Aleph orchestration: HTTP CRN API, messages, payments, allocations)
// and the hypervisor (controllers, hypervisors, networking, systemd,
// backups). Reference: docs/plans/2026-05-28-aleph-vm-architecture-
// backport-design.md.

syntax = "proto3";

package aleph.hypervisor.v1;

service Hypervisor {
  // RPCs added incrementally in Tasks 2-10.
}
```

Create `scripts/generate_proto.py`:

```python
#!/usr/bin/env python3
"""Generate Python bindings for proto/hypervisor.proto.

Idempotent. Run from the repo root: `python scripts/generate_proto.py`.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
PROTO_DIR = REPO / "proto"
OUT_DIR = REPO / "src" / "aleph" / "vm" / "hypervisor" / "_pb"
PROTO_FILE = PROTO_DIR / "hypervisor.proto"


def main() -> int:
    if not PROTO_FILE.exists():
        print(f"proto file not found: {PROTO_FILE}", file=sys.stderr)
        return 1
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / "__init__.py").touch(exist_ok=True)

    cmd = [
        sys.executable, "-m", "grpc_tools.protoc",
        f"--proto_path={PROTO_DIR}",
        f"--python_out={OUT_DIR}",
        f"--grpc_python_out={OUT_DIR}",
        f"--mypy_out={OUT_DIR}",  # requires mypy-protobuf installed
        str(PROTO_FILE),
    ]
    print(" ".join(cmd))
    result = subprocess.run(cmd, cwd=REPO)
    if result.returncode != 0:
        return result.returncode

    # The grpc plugin emits a `from hypervisor_pb2 import ...` line that
    # breaks when the package is imported via its dotted name. Rewrite
    # to a relative import.
    grpc_file = OUT_DIR / "hypervisor_pb2_grpc.py"
    text = grpc_file.read_text()
    text = text.replace(
        "import hypervisor_pb2 as hypervisor__pb2",
        "from . import hypervisor_pb2 as hypervisor__pb2",
    )
    grpc_file.write_text(text)
    print(f"rewrote {grpc_file} to use relative import")

    return 0


if __name__ == "__main__":
    sys.exit(main())
```

Create the package markers:

```bash
mkdir -p src/aleph/vm/hypervisor/_pb tests/hypervisor
: > src/aleph/vm/hypervisor/__init__.py
: > tests/hypervisor/__init__.py
```

Create `src/aleph/vm/hypervisor/_pb/__init__.py`:

```python
"""Generated Python bindings for proto/hypervisor.proto.

DO NOT EDIT. Run `python scripts/generate_proto.py` to regenerate.
"""
```

- [ ] **Step 5: Generate, run the test, confirm pass**

Run: `python scripts/generate_proto.py`
Expected: prints the protoc command and "rewrote .../hypervisor_pb2_grpc.py".

Run: `pytest tests/hypervisor/test_proto_bindings.py -v`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add proto scripts/generate_proto.py src/aleph/vm/hypervisor pyproject.toml tests/hypervisor
git commit -m "feat(hypervisor): bootstrap proto toolchain with empty Hypervisor service"
```

---

### Task 2: Health + GetHostInfo RPCs (simplest, prove the loop)

**Files:**
- Modify: `proto/hypervisor.proto`
- Regenerate: `src/aleph/vm/hypervisor/_pb/*`
- Modify: `tests/hypervisor/test_proto_bindings.py`

- [ ] **Step 1: Add the failing test**

Append to `tests/hypervisor/test_proto_bindings.py`:

```python
def test_health_rpc_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2, hypervisor_pb2_grpc
    # Request and response types exist
    assert hasattr(hypervisor_pb2, "HealthRequest")
    assert hasattr(hypervisor_pb2, "HealthResponse")
    # Response fields
    fields = {f.name for f in hypervisor_pb2.HealthResponse.DESCRIPTOR.fields}
    assert {"status", "vm_count"} <= fields
    # Service has the RPC
    assert "Health" in hypervisor_pb2_grpc.HypervisorStub.__init__.__doc__ or \
           any("Health" in m.name for m in hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods)


def test_get_host_info_rpc_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    assert hasattr(hypervisor_pb2, "GetHostInfoRequest")
    assert hasattr(hypervisor_pb2, "HostInfo")
    fields = {f.name for f in hypervisor_pb2.HostInfo.DESCRIPTOR.fields}
    assert {"cpu_count", "memory_mib", "numa_nodes", "gpus",
            "sev_snp_supported", "tdx_supported"} <= fields
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 2 new failures with `AttributeError: module ... has no attribute 'HealthRequest'`.

- [ ] **Step 3: Extend the proto**

Edit `proto/hypervisor.proto`. Replace the empty `service Hypervisor {}` block and append message definitions:

```proto
service Hypervisor {
  // ── Host ──
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc GetHostInfo(GetHostInfoRequest) returns (HostInfo);
}

// ── Host ─────────────────────────────────────────────────────────────────

message HealthRequest {}

message HealthResponse {
  string status = 1;       // "ok" | "degraded"
  uint32 vm_count = 2;
}

message GetHostInfoRequest {}

message HostInfo {
  uint32 cpu_count = 1;
  uint64 memory_mib = 2;
  repeated NumaNode numa_nodes = 3;
  repeated GpuDevice gpus = 4;
  bool sev_snp_supported = 5;
  bool tdx_supported = 6;
  string hostname = 7;
  string kernel_version = 8;
}

message NumaNode {
  uint32 index = 1;
  uint32 cpu_count = 2;
  uint64 memory_mib = 3;
}

message GpuDevice {
  string pci_host = 1;     // e.g. "0000:01:00.0"
  string device_id = 2;    // vendor:device
  string model = 3;
  bool supports_x_vga = 4;
}
```

- [ ] **Step 4: Regenerate and run tests**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add Health + GetHostInfo RPCs"
```

---

### Task 3: VM lifecycle RPCs and their messages

**Files:**
- Modify: `proto/hypervisor.proto`
- Regenerate: `src/aleph/vm/hypervisor/_pb/*`
- Modify: `tests/hypervisor/test_proto_bindings.py`

- [ ] **Step 1: Add the failing tests**

Append:

```python
def test_lifecycle_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"CreateVm", "GetVm", "ListVms", "DeleteVm",
            "RebootVm", "ReinstallVm"} <= methods


def test_backend_enum_complete():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    values = {v.name for v in hypervisor_pb2.Backend.DESCRIPTOR.values}
    assert values == {"BACKEND_UNSPECIFIED", "BACKEND_FIRECRACKER",
                      "BACKEND_QEMU", "BACKEND_QEMU_SEV"}


def test_create_vm_request_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.CreateVmRequest.DESCRIPTOR.fields}
    expected = {"vm_id", "backend", "kernel_path", "initrd_path", "disks",
                "vcpus", "memory_mib", "tee", "network", "gpus",
                "numa_node", "persistent"}
    missing = expected - fields
    assert not missing, f"missing fields: {missing}"


def test_disk_config_has_role_and_format_enums():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    disk_fields = {f.name for f in hypervisor_pb2.DiskConfig.DESCRIPTOR.fields}
    assert {"path", "readonly", "format", "role"} <= disk_fields
    formats = {v.name for v in hypervisor_pb2.DiskConfig.Format.DESCRIPTOR.values}
    assert {"FORMAT_UNSPECIFIED", "FORMAT_RAW", "FORMAT_QCOW2",
            "FORMAT_SQUASHFS"} <= formats
    roles = {v.name for v in hypervisor_pb2.DiskConfig.DiskRole.DESCRIPTOR.values}
    assert {"DISK_ROLE_UNSPECIFIED", "DISK_ROLE_ROOTFS", "DISK_ROLE_CODE",
            "DISK_ROLE_RUNTIME", "DISK_ROLE_DATA", "DISK_ROLE_EXTRA"} <= roles


def test_vm_info_has_status_enum_and_core_fields():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.VmInfo.DESCRIPTOR.fields}
    assert {"vm_id", "status", "ipv4", "ipv6", "uptime_secs",
            "backend", "numa_node"} <= fields
    statuses = {v.name for v in hypervisor_pb2.VmStatus.DESCRIPTOR.values}
    assert {"VM_STATUS_UNSPECIFIED", "VM_STATUS_DEFINED", "VM_STATUS_BOOTING",
            "VM_STATUS_RUNNING", "VM_STATUS_STOPPING", "VM_STATUS_STOPPED",
            "VM_STATUS_FAILED"} <= statuses
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 5 new failures (`AttributeError` on `Backend`, `CreateVmRequest`, `VmInfo`, etc.).

- [ ] **Step 3: Extend the proto**

In `proto/hypervisor.proto`, add the lifecycle block to the `service Hypervisor` body (after the Host RPCs):

```proto
  // ── VM lifecycle ──
  rpc CreateVm(CreateVmRequest) returns (VmInfo);
  rpc GetVm(GetVmRequest) returns (VmInfo);
  rpc ListVms(ListVmsRequest) returns (ListVmsResponse);
  rpc DeleteVm(DeleteVmRequest) returns (DeleteVmResponse);
  rpc RebootVm(RebootVmRequest) returns (VmInfo);
  rpc ReinstallVm(ReinstallVmRequest) returns (VmInfo);
```

Append after the Host messages section:

```proto
// ── Lifecycle ────────────────────────────────────────────────────────────

enum Backend {
  BACKEND_UNSPECIFIED = 0;
  BACKEND_FIRECRACKER = 1;
  BACKEND_QEMU = 2;
  BACKEND_QEMU_SEV = 3;
}

enum VmStatus {
  VM_STATUS_UNSPECIFIED = 0;
  VM_STATUS_DEFINED = 1;
  VM_STATUS_BOOTING = 2;
  VM_STATUS_RUNNING = 3;
  VM_STATUS_STOPPING = 4;
  VM_STATUS_STOPPED = 5;
  VM_STATUS_FAILED = 6;
}

message CreateVmRequest {
  string vm_id = 1;                  // agent-issued id, opaque to hypervisor
  Backend backend = 2;
  string kernel_path = 3;            // empty for disk-boot
  string initrd_path = 4;            // empty for disk-boot
  repeated DiskConfig disks = 5;
  uint32 vcpus = 6;
  uint64 memory_mib = 7;
  TeeConfig tee = 8;                 // only meaningful when backend is *_SEV
  NetworkConfig network = 9;
  repeated GpuConfig gpus = 10;
  uint32 numa_node = 11;             // 0 = auto, 1+ = specific (1-indexed)
  bool persistent = 12;              // hypervisor wraps in systemd if true
}

message DiskConfig {
  string path = 1;                   // absolute host path
  bool readonly = 2;
  Format format = 3;
  DiskRole role = 4;

  enum Format {
    FORMAT_UNSPECIFIED = 0;
    FORMAT_RAW = 1;
    FORMAT_QCOW2 = 2;
    FORMAT_SQUASHFS = 3;
  }

  enum DiskRole {
    DISK_ROLE_UNSPECIFIED = 0;
    DISK_ROLE_ROOTFS = 1;
    DISK_ROLE_CODE = 2;
    DISK_ROLE_RUNTIME = 3;
    DISK_ROLE_DATA = 4;
    DISK_ROLE_EXTRA = 5;
  }
}

message TeeConfig {
  string backend = 1;                // "sev-snp", "tdx", "nvidia-cc" or ""
  string policy = 2;                 // empty = default
  string session_dir = 3;            // confidential session files
}

message NetworkConfig {
  bool internet_access = 1;
  string requested_ipv6 = 2;         // empty = pool-assigned
  uint32 ipv6_prefix_len = 3;        // 0 = /128
}

message GpuConfig {
  string pci_host = 1;
  bool supports_x_vga = 2;
}

message VmInfo {
  string vm_id = 1;
  VmStatus status = 2;
  string ipv4 = 3;
  string ipv6 = 4;
  uint64 uptime_secs = 5;
  Backend backend = 6;
  uint32 numa_node = 7;              // 0-indexed effective placement
  string status_message = 8;         // human-readable, optional
}

message GetVmRequest      { string vm_id = 1; }
message ListVmsRequest    {}
message ListVmsResponse   { repeated VmInfo vms = 1; }
message DeleteVmRequest   { string vm_id = 1; }
message DeleteVmResponse  {}
message RebootVmRequest   { string vm_id = 1; bool hard = 2; }
message ReinstallVmRequest{ string vm_id = 1; }
```

- [ ] **Step 4: Regenerate and run tests**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add VM lifecycle RPCs (create/get/list/delete/reboot/reinstall)"
```

---

### Task 4: Port forwarding RPCs

**Files:** same set as Task 3.

- [ ] **Step 1: Add the failing test**

Append:

```python
def test_port_forwarding_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"AddPortForward", "RemovePortForward",
            "ListPortForwards"} <= methods


def test_port_forward_info_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.PortForwardInfo.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields
    fields = {f.name for f in hypervisor_pb2.AddPortForwardRequest.DESCRIPTOR.fields}
    assert {"vm_id", "host_port", "vm_port", "protocol"} <= fields
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 2 new failures.

- [ ] **Step 3: Extend the proto**

Add to the service block:

```proto
  // ── Port forwarding ──
  rpc AddPortForward(AddPortForwardRequest) returns (PortForwardInfo);
  rpc RemovePortForward(RemovePortForwardRequest) returns (RemovePortForwardResponse);
  rpc ListPortForwards(ListPortForwardsRequest) returns (ListPortForwardsResponse);
```

Append messages:

```proto
// ── Port forwarding ──────────────────────────────────────────────────────

message AddPortForwardRequest {
  string vm_id = 1;
  uint32 host_port = 2;              // 0 = auto-allocate
  uint32 vm_port = 3;
  string protocol = 4;               // "tcp" | "udp"
}

message PortForwardInfo {
  string vm_id = 1;
  uint32 host_port = 2;
  uint32 vm_port = 3;
  string protocol = 4;
}

message RemovePortForwardRequest {
  string vm_id = 1;
  uint32 host_port = 2;
  string protocol = 3;
}

message RemovePortForwardResponse {}

message ListPortForwardsRequest {
  string vm_id = 1;                  // empty = all VMs
}

message ListPortForwardsResponse {
  repeated PortForwardInfo forwards = 1;
}
```

- [ ] **Step 4: Regenerate, test**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (11 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add port-forwarding RPCs"
```

---

### Task 5: Log RPCs (unary + streaming)

**Files:** same set.

- [ ] **Step 1: Add the failing test**

Append:

```python
def test_log_rpcs_defined_with_streaming():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name: m for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert "GetLogs" in methods
    assert "StreamLogs" in methods
    assert methods["StreamLogs"].server_streaming is True
    assert methods["GetLogs"].server_streaming is False

    fields = {f.name for f in hypervisor_pb2.LogChunk.DESCRIPTOR.fields}
    assert {"timestamp_ns", "line", "source"} <= fields
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 1 new failure.

- [ ] **Step 3: Extend the proto**

Add to the service block:

```proto
  // ── Logs ──
  rpc GetLogs(GetLogsRequest) returns (GetLogsResponse);
  rpc StreamLogs(StreamLogsRequest) returns (stream LogChunk);
```

Append messages:

```proto
// ── Logs ─────────────────────────────────────────────────────────────────

message GetLogsRequest {
  string vm_id = 1;
  uint32 max_lines = 2;              // 0 = unlimited (subject to server cap)
  bool from_tail = 3;                // true = most recent lines
}

message GetLogsResponse {
  repeated LogChunk lines = 1;
}

message StreamLogsRequest {
  string vm_id = 1;
  bool include_history = 2;          // false = only new lines from now
}

message LogChunk {
  uint64 timestamp_ns = 1;           // unix ns at server-side capture time
  string line = 2;                   // single log line, no trailing newline
  LogSource source = 3;

  enum LogSource {
    LOG_SOURCE_UNSPECIFIED = 0;
    LOG_SOURCE_SERIAL = 1;           // QEMU serial console
    LOG_SOURCE_STDOUT = 2;           // Firecracker vm-stdout
    LOG_SOURCE_SYSTEMD = 3;          // systemd journal for persistent VM unit
  }
}
```

- [ ] **Step 4: Regenerate, test**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (12 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add log RPCs (GetLogs + StreamLogs)"
```

---

### Task 6: Backup / snapshot RPCs

**Files:** same set.

- [ ] **Step 1: Add the failing test**

Append:

```python
def test_backup_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name: m for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"StartBackup", "GetBackupStatus", "ListBackups",
            "DownloadBackup", "DeleteBackup", "RestoreBackup"} <= set(methods)
    assert methods["DownloadBackup"].server_streaming is True


def test_backup_info_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.BackupInfo.DESCRIPTOR.fields}
    assert {"vm_id", "backup_id", "status", "size_bytes",
            "created_at_unix_secs"} <= fields
    statuses = {v.name for v in hypervisor_pb2.BackupStatus.DESCRIPTOR.values}
    assert {"BACKUP_STATUS_UNSPECIFIED", "BACKUP_STATUS_PENDING",
            "BACKUP_STATUS_RUNNING", "BACKUP_STATUS_COMPLETE",
            "BACKUP_STATUS_FAILED"} <= statuses
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 2 new failures.

- [ ] **Step 3: Extend the proto**

Add to the service block:

```proto
  // ── Backups ──
  rpc StartBackup(StartBackupRequest) returns (BackupInfo);
  rpc GetBackupStatus(GetBackupStatusRequest) returns (BackupInfo);
  rpc ListBackups(ListBackupsRequest) returns (ListBackupsResponse);
  rpc DownloadBackup(DownloadBackupRequest) returns (stream BackupChunk);
  rpc DeleteBackup(DeleteBackupRequest) returns (DeleteBackupResponse);
  rpc RestoreBackup(RestoreBackupRequest) returns (VmInfo);
```

Append messages:

```proto
// ── Backups ──────────────────────────────────────────────────────────────

enum BackupStatus {
  BACKUP_STATUS_UNSPECIFIED = 0;
  BACKUP_STATUS_PENDING = 1;
  BACKUP_STATUS_RUNNING = 2;
  BACKUP_STATUS_COMPLETE = 3;
  BACKUP_STATUS_FAILED = 4;
}

message BackupInfo {
  string vm_id = 1;
  string backup_id = 2;              // hypervisor-issued
  BackupStatus status = 3;
  uint64 size_bytes = 4;             // 0 until COMPLETE
  uint64 created_at_unix_secs = 5;
  string error_message = 6;          // populated when status = FAILED
}

message StartBackupRequest {
  string vm_id = 1;
  bool quiesce_guest = 2;            // request guest fs-freeze if supported
}

message GetBackupStatusRequest { string vm_id = 1; string backup_id = 2; }

message ListBackupsRequest { string vm_id = 1; }      // empty = all VMs
message ListBackupsResponse { repeated BackupInfo backups = 1; }

message DownloadBackupRequest { string vm_id = 1; string backup_id = 2; }
message BackupChunk { bytes data = 1; uint64 offset = 2; }

message DeleteBackupRequest { string vm_id = 1; string backup_id = 2; }
message DeleteBackupResponse {}

message RestoreBackupRequest { string vm_id = 1; string backup_id = 2; }
```

- [ ] **Step 4: Regenerate, test**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (14 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add backup/snapshot RPCs"
```

---

### Task 7: Migration RPCs

**Files:** same set.

- [ ] **Step 1: Add the failing test**

Append:

```python
def test_migration_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"ExportVm", "ImportVm", "GetMigrationStatus"} <= methods


def test_migration_info_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.MigrationInfo.DESCRIPTOR.fields}
    assert {"vm_id", "migration_id", "phase", "bytes_transferred",
            "bytes_total"} <= fields
    phases = {v.name for v in hypervisor_pb2.MigrationPhase.DESCRIPTOR.values}
    assert {"MIGRATION_PHASE_UNSPECIFIED", "MIGRATION_PHASE_PREPARING",
            "MIGRATION_PHASE_EXPORTING", "MIGRATION_PHASE_IMPORTING",
            "MIGRATION_PHASE_COMPLETE",
            "MIGRATION_PHASE_FAILED"} <= phases
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 2 new failures.

- [ ] **Step 3: Extend the proto**

Add to the service block:

```proto
  // ── Migration ──
  rpc ExportVm(ExportVmRequest) returns (MigrationInfo);
  rpc ImportVm(ImportVmRequest) returns (VmInfo);
  rpc GetMigrationStatus(GetMigrationStatusRequest) returns (MigrationInfo);
```

Append messages:

```proto
// ── Migration ────────────────────────────────────────────────────────────

enum MigrationPhase {
  MIGRATION_PHASE_UNSPECIFIED = 0;
  MIGRATION_PHASE_PREPARING = 1;
  MIGRATION_PHASE_EXPORTING = 2;
  MIGRATION_PHASE_IMPORTING = 3;
  MIGRATION_PHASE_COMPLETE = 4;
  MIGRATION_PHASE_FAILED = 5;
}

message MigrationInfo {
  string vm_id = 1;
  string migration_id = 2;
  MigrationPhase phase = 3;
  uint64 bytes_transferred = 4;
  uint64 bytes_total = 5;
  string error_message = 6;
}

message ExportVmRequest {
  string vm_id = 1;
  string destination_dir = 2;        // local path on the host
}

message ImportVmRequest {
  string vm_id = 1;                  // agent-issued; same id post-restore
  string source_dir = 2;
}

message GetMigrationStatusRequest {
  string vm_id = 1;
  string migration_id = 2;
}
```

- [ ] **Step 4: Regenerate, test**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (16 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add migration RPCs (export/import/status)"
```

---

### Task 8: Confidential computing RPCs

**Files:** same set.

- [ ] **Step 1: Add the failing test**

Append:

```python
def test_confidential_rpcs_defined():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    methods = {m.name for m in
               hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert {"InitializeConfidential", "GetMeasurement",
            "InjectSecret"} <= methods


def test_confidential_message_shapes():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    init = {f.name for f in
            hypervisor_pb2.InitializeConfidentialRequest.DESCRIPTOR.fields}
    assert {"vm_id", "session_bytes", "godh_bytes"} <= init

    meas = {f.name for f in hypervisor_pb2.Measurement.DESCRIPTOR.fields}
    assert {"vm_id", "measurement_bytes", "tee_backend"} <= meas

    inj = {f.name for f in hypervisor_pb2.InjectSecretRequest.DESCRIPTOR.fields}
    assert {"vm_id", "secret_header_bytes", "secret_bytes"} <= inj
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 2 new failures.

- [ ] **Step 3: Extend the proto**

Add to the service block:

```proto
  // ── Confidential ──
  rpc InitializeConfidential(InitializeConfidentialRequest) returns (InitializeConfidentialResponse);
  rpc GetMeasurement(GetMeasurementRequest) returns (Measurement);
  rpc InjectSecret(InjectSecretRequest) returns (InjectSecretResponse);
```

Append messages:

```proto
// ── Confidential ─────────────────────────────────────────────────────────

message InitializeConfidentialRequest {
  string vm_id = 1;
  bytes session_bytes = 2;           // SEV session blob
  bytes godh_bytes = 3;              // SEV guest-owner DH key
}

message InitializeConfidentialResponse {}

message GetMeasurementRequest { string vm_id = 1; }

message Measurement {
  string vm_id = 1;
  bytes measurement_bytes = 2;       // attestation report / SEV launch measure
  string tee_backend = 3;            // "sev-snp" | "tdx" | ...
}

message InjectSecretRequest {
  string vm_id = 1;
  bytes secret_header_bytes = 2;
  bytes secret_bytes = 3;
}

message InjectSecretResponse {}
```

- [ ] **Step 4: Regenerate, test**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (18 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add confidential computing RPCs"
```

---

### Task 9: Wire error vocabulary (closed enum + ErrorDetail)

This is the Annex A.6 / §9 deliverable: the closed error enum that lets gRPC servers map backend exceptions to status trailers, and lets the agent translate status codes back to HTTP responses.

**Files:** same set.

- [ ] **Step 1: Add the failing test**

Append:

```python
def test_error_code_enum_covers_design_doc_cases():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    values = {v.name for v in hypervisor_pb2.ErrorCode.DESCRIPTOR.values}
    required = {
        "ERROR_CODE_UNSPECIFIED",
        "ERROR_CODE_VM_NOT_FOUND",
        "ERROR_CODE_VM_ALREADY_EXISTS",
        "ERROR_CODE_INSUFFICIENT_RESOURCES",
        "ERROR_CODE_RESOURCE_DOWNLOAD_FAILED",
        "ERROR_CODE_VM_SETUP_FAILED",
        "ERROR_CODE_MICROVM_INIT_FAILED",
        "ERROR_CODE_FILE_TOO_LARGE",
        "ERROR_CODE_INVALID_BACKEND",
        "ERROR_CODE_TEE_UNAVAILABLE",
        "ERROR_CODE_PORT_UNAVAILABLE",
        "ERROR_CODE_BACKUP_NOT_FOUND",
        "ERROR_CODE_MIGRATION_IN_PROGRESS",
        "ERROR_CODE_HOST_NOT_FOUND",
        "ERROR_CODE_INTERNAL",
    }
    missing = required - values
    assert not missing, f"missing error codes: {missing}"


def test_error_detail_message_shape():
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    fields = {f.name for f in hypervisor_pb2.ErrorDetail.DESCRIPTOR.fields}
    assert {"code", "message", "vm_id"} <= fields
```

- [ ] **Step 2: Run, confirm failure**

Run: `pytest tests/hypervisor -v`
Expected: 2 new failures.

- [ ] **Step 3: Extend the proto**

Append (no new RPCs; these are only used in status trailers):

```proto
// ── Wire error vocabulary ────────────────────────────────────────────────
//
// Closed enum of errors the hypervisor can return. Server side: map
// backend exceptions (FileTooLargeError, VmSetupError,
// MicroVMFailedInitError, ResourceDownloadError,
// InsufficientResourcesError, HostNotFoundError, ...) into this enum
// and attach an ErrorDetail in the gRPC status trailers. Agent side:
// catch grpc.AioRpcError, read the trailer, translate to HTTP.

enum ErrorCode {
  ERROR_CODE_UNSPECIFIED = 0;

  // Lifecycle
  ERROR_CODE_VM_NOT_FOUND = 1;
  ERROR_CODE_VM_ALREADY_EXISTS = 2;
  ERROR_CODE_INSUFFICIENT_RESOURCES = 3;

  // Resource preparation
  ERROR_CODE_RESOURCE_DOWNLOAD_FAILED = 4;
  ERROR_CODE_FILE_TOO_LARGE = 5;

  // Backend
  ERROR_CODE_VM_SETUP_FAILED = 6;
  ERROR_CODE_MICROVM_INIT_FAILED = 7;
  ERROR_CODE_INVALID_BACKEND = 8;
  ERROR_CODE_TEE_UNAVAILABLE = 9;

  // Networking
  ERROR_CODE_PORT_UNAVAILABLE = 10;
  ERROR_CODE_HOST_NOT_FOUND = 11;

  // Backup / migration
  ERROR_CODE_BACKUP_NOT_FOUND = 12;
  ERROR_CODE_MIGRATION_IN_PROGRESS = 13;

  // Catch-all
  ERROR_CODE_INTERNAL = 99;
}

message ErrorDetail {
  ErrorCode code = 1;
  string message = 2;                // human-readable, agent surfaces verbatim
  string vm_id = 3;                  // optional context
}
```

- [ ] **Step 4: Regenerate, test**

Run: `python scripts/generate_proto.py`
Run: `pytest tests/hypervisor -v`
Expected: all PASS (20 tests).

- [ ] **Step 5: Commit**

```bash
git add proto/hypervisor.proto src/aleph/vm/hypervisor/_pb tests/hypervisor
git commit -m "feat(hypervisor): add closed wire error enum (ErrorCode + ErrorDetail)"
```

---

### Task 10: Sanity sweep: service has the full RPC list

A single test that pins the full RPC count and names so future drift is loud. This is the contract's "table of contents."

**Files:**
- Modify: `tests/hypervisor/test_proto_bindings.py`

- [ ] **Step 1: Add the pinning test**

Append:

```python
def test_full_service_surface_pinned():
    """Whole-surface assertion. Update this list intentionally when the
    contract changes (and bump the proto package version when breaking)."""
    from aleph.vm.hypervisor._pb import hypervisor_pb2
    expected = {
        # Host
        "Health", "GetHostInfo",
        # Lifecycle
        "CreateVm", "GetVm", "ListVms", "DeleteVm", "RebootVm", "ReinstallVm",
        # Port forwarding
        "AddPortForward", "RemovePortForward", "ListPortForwards",
        # Logs
        "GetLogs", "StreamLogs",
        # Backups
        "StartBackup", "GetBackupStatus", "ListBackups",
        "DownloadBackup", "DeleteBackup", "RestoreBackup",
        # Migration
        "ExportVm", "ImportVm", "GetMigrationStatus",
        # Confidential
        "InitializeConfidential", "GetMeasurement", "InjectSecret",
    }
    actual = {m.name for m in
              hypervisor_pb2.DESCRIPTOR.services_by_name["Hypervisor"].methods}
    assert actual == expected, (
        f"unexpected drift: missing {expected - actual}, "
        f"extra {actual - expected}"
    )
```

- [ ] **Step 2: Run, confirm pass**

Run: `pytest tests/hypervisor -v`
Expected: all PASS (21 tests).

- [ ] **Step 3: Commit**

```bash
git add tests/hypervisor/test_proto_bindings.py
git commit -m "test(hypervisor): pin full service surface (25 RPCs)"
```

---

### Task 11: Documentation in `proto/README.md`

**Files:**
- Create: `proto/README.md`

- [ ] **Step 1: Write the README**

```markdown
# aleph-vm hypervisor protocol

This directory holds `hypervisor.proto` — the single source of truth for
the contract between **network-agent** (Aleph orchestration) and
**hypervisor** (infra-only VM management) inside aleph-vm.

Design reference:
`docs/plans/2026-05-28-aleph-vm-architecture-backport-design.md` (mirror
of the same file in the aleph-cvm repo).

## Regenerating Python bindings

```bash
python scripts/generate_proto.py
```

This (re)writes `src/aleph/vm/hypervisor/_pb/`:

- `hypervisor_pb2.py` — message classes
- `hypervisor_pb2_grpc.py` — `HypervisorStub`, `HypervisorServicer`,
  `add_HypervisorServicer_to_server`
- `hypervisor_pb2.pyi` — type stubs for mypy

**Generated files are checked in.** Reviewers can read them directly;
new contributors don't need to run protoc to navigate the code. CI runs
the script on every PR and fails if the generated files drift from
`hypervisor.proto`.

## Why a closed error enum?

gRPC's status codes (`grpc.StatusCode`) are too coarse to map back to
the aleph-vm HTTP API faithfully — today's views catch
backend-internal exception types directly (`FileTooLargeError`,
`MicroVMFailedInitError`, ...; see Annex A.6 of the design doc). The
`ErrorCode` enum + `ErrorDetail` message let the hypervisor surface
those distinctions across the wire without exporting Python types.

Server side: backend exception → `ErrorDetail` packed into status
trailers, status code chosen from a small mapping table.

Client (agent) side: `grpc.AioRpcError` → read `ErrorDetail` from
trailers → translate to the HTTP shape the view used to derive from
the exception class.

## Versioning

Package: `aleph.hypervisor.v1`. Breaking changes bump to `v2`. Field
additions are non-breaking as long as field numbers are stable.
```

- [ ] **Step 2: Commit**

```bash
git add proto/README.md
git commit -m "docs(hypervisor): proto README — regeneration, error enum, versioning"
```

---

### Task 12: CI verification that generated files match the proto

This catches the "engineer edited `_pb2.py` by hand" footgun and the "forgot to regenerate after editing the proto" mistake.

**Files:**
- Create: `scripts/check_proto_clean.sh`
- Modify: `.github/workflows/<existing-CI>.yml` (or the equivalent CI config; verify path first)

- [ ] **Step 1: Find the existing CI workflow**

Run: `ls .github/workflows/ 2>/dev/null`
Expected: at least one `.yml` file (likely `tests.yml`, `ci.yml`, or `python.yml`).

Pick the workflow that runs pytest on PRs. If multiple, the canonical one is whichever has `pytest` in its steps.

- [ ] **Step 2: Write the check script**

Create `scripts/check_proto_clean.sh`:

```bash
#!/usr/bin/env bash
# Re-run the proto generator and fail if the working tree changes.
# Used in CI to enforce: proto changes must be accompanied by
# regenerated _pb modules.

set -euo pipefail

cd "$(dirname "$0")/.."

python scripts/generate_proto.py

if ! git diff --quiet --exit-code -- src/aleph/vm/hypervisor/_pb proto/; then
    echo
    echo "ERROR: generated proto bindings are out of date." >&2
    echo "Run: python scripts/generate_proto.py" >&2
    echo "Then commit the changes." >&2
    git diff -- src/aleph/vm/hypervisor/_pb proto/
    exit 1
fi

echo "proto bindings are up to date."
```

Make it executable:

```bash
chmod +x scripts/check_proto_clean.sh
```

- [ ] **Step 3: Add the CI step**

Edit the chosen workflow file. Find the job that installs deps and runs tests, add a new step BEFORE the test step:

```yaml
      - name: Verify proto bindings are up to date
        run: ./scripts/check_proto_clean.sh
```

The exact step name and dependencies-install step preceding it depend on the existing workflow; mirror its style and ensure `grpcio-tools` and `mypy-protobuf` are installed before this step runs (they come from the dev extras you added in Task 1).

- [ ] **Step 4: Run the script locally to verify**

Run: `./scripts/check_proto_clean.sh`
Expected: prints `proto bindings are up to date.` and exits 0.

- [ ] **Step 5: Commit**

```bash
git add scripts/check_proto_clean.sh .github/workflows
git commit -m "ci(hypervisor): verify generated proto bindings match source on every PR"
```

---

### Task 13: Final whole-suite run + plan-complete commit

**Files:** none.

- [ ] **Step 1: Install deps if not already done**

Run: `pip install -e ".[test]"`

- [ ] **Step 2: Run the hypervisor tests in isolation**

Run: `pytest tests/hypervisor -v`
Expected: all PASS (21 tests).

- [ ] **Step 3: Run the full aleph-vm test suite to confirm no regressions**

Run: `pytest -x`
Expected: same number of passing tests as `origin/main` (this plan adds tests, does not change behaviour). If any pre-existing tests fail, capture the output and investigate; they should not be related to this plan's changes.

- [ ] **Step 4: Final review**

Eyeball `proto/hypervisor.proto` against §5 of the design doc. The RPC list should match exactly. Eyeball `tests/hypervisor/test_proto_bindings.py::test_full_service_surface_pinned`: the same list, alphabetised by category.

- [ ] **Step 5: Push and open PR**

```bash
git push -u origin od/hypervisor-boundary
```

PR title: `feat(hypervisor): Phase 0.A — hypervisor.proto contract + Python bindings`

PR body: link to the design doc, summarise §5 coverage, list Phase 0 sub-plan decomposition (this is 1 of 5), call out the new CI check.

---

## What this plan deliberately does NOT do

- **No `Hypervisor` ABC.** Lands in Plan 0.B.
- **No backend exception mapping logic.** The enum exists; the server-side mapping table comes with the in-process impl in Plan 0.C.
- **No imports from existing aleph-vm code.** Generated bindings are leaf modules; nothing in `controllers/`, `models.py`, `pool.py`, or `orchestrator/` is touched. The blast radius of merging this PR is zero behavioural change.
- **No `vm_id` semantics decision** (whether `vm_id` is the Aleph `ItemHash` or hypervisor-issued). The proto treats `vm_id` as an opaque agent-issued string; the semantics question (open issue §9 in the design doc) gets resolved at the ABC layer in Plan 0.B.
