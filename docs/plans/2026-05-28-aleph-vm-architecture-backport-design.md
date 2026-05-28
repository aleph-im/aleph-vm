# Backporting the aleph-cvm Architecture to aleph-vm

**Status:** Design / roadmap
**Date:** 2026-05-28
**Owner:** Olivier Desenfans
**Subject repo:** `aleph-im/aleph-vm` (this design lives in `aleph-cvm` for drafting; will move to aleph-vm when implementation begins)
**Reference architecture:** this repo (`aleph-cvm`), which already realises the target shape in Rust

## 1. Context

aleph-cvm was built from scratch as a clean architecture for confidential VMs: a hypervisor-agnostic compute node exposing gRPC, a separate Aleph-network adapter (the network agent) acting as gRPC client, and a thin contract (`compute.proto`) between them. The split has proven out, but it is too sharp a break to drop onto production CRNs.

aleph-vm is the production Aleph Cloud compute node: a Python monolith (aiohttp) running Firecracker microVMs (on-demand programs), QEMU instances (persistent VPS), and a partially-wired QEMU+SEV path. Its orchestration, networking, payment, message handling, and VM lifecycle are braided through `VmExecution` (`models.py`) and `VmPool` (`pool.py`), and its HTTP control views call hypervisor code directly.

The goal of this work is to **evolve aleph-vm in place toward aleph-cvm's architecture**: same shape (hypervisor service ⇄ gRPC ⇄ Aleph agent), without merging repos, without breaking CRNs, and without changing the public CRN HTTP API. aleph-cvm serves as the proven reference; the Rust crates here will eventually replace aleph-vm's Python services, starting with the hypervisor (Phase 2) and then the agent (Phase 3).

## 2. Target architecture

Per CRN, two daemons communicating over a Unix-domain-socket gRPC link:

```
┌──────────────────────────────────────────┐       ┌──────────────────────────────────────┐
│  network-agent  (Aleph-only)              │       │  hypervisor  (infra-only)             │
│                                           │       │                                       │
│  • orchestrator/views: public CRN HTTP    │       │  • controllers/ (fc, qemu, qemu-sev)  │
│    API (unchanged for clients)             │  gRPC │  • hypervisors/ drivers               │
│  • messages / tasks / reactor             │ ───►  │  • TAP create + IP assign             │
│  • payment / PAYG / allocations           │  UDS  │  • systemd supervision (persistent)   │
│  • storage.py: download → local paths     │       │  • GPU passthrough, NUMA, hugepages   │
│  • node identity, aggregate settings      │       │  • backups, snapshots, reboot, logs   │
│  • port-redirect *policy*                 │       │  • confidential session (phase 3)     │
│  • on-demand program HTTP proxy + idle    │       │                                       │
│                                           │       │                                       │
│  gRPC CLIENT                              │       │  gRPC SERVER                          │
└──────────────────────────────────────────┘       └──────────────────────────────────────┘
```

**Vocabulary on the wire is infra-only.** A `CreateVm` carries `vm_id`, `backend` (firecracker / qemu / qemu-sev), `kernel/initrd/rootfs` *paths*, `disks`, `vcpus`, `memory`, `tee`, `gpu`, `ipv6`, requested port-forwards. An Aleph `ExecutableMessage` never crosses the wire. The agent downloads code/runtime/data volumes (via `storage.py`) and hands the hypervisor local paths, exactly the pattern aleph-cvm's `VolumeCache` + `adapter.rs` already implement.

**Sources of truth.** Hypervisor owns *what IS running* (process, TAP, mapped ports, backup files). Agent owns *what SHOULD be running* (allocation, message, payment status, expiry). Reconciliation = compare `ListVms` against the allocation, the same loop `aleph-network-agent` already does.

**The public CRN HTTP API does not change.** The split is internal; the scheduler, front-end, and operator tooling see no difference.

## 3. Mapping the seam onto aleph-vm

From the audit of `aleph-im/aleph-vm` `src/aleph/vm/`:

| Today (aleph-vm)                                  | Lands on side  | Notes                                                                 |
| ------------------------------------------------- | -------------- | --------------------------------------------------------------------- |
| `controllers/` (fc, qemu, qemu_confidential)      | **hypervisor** | Wrapped behind the gRPC server. Existing code, minimal rewrite.       |
| `hypervisors/` drivers                            | **hypervisor** | Unchanged, internal to the hypervisor daemon.                         |
| `network/interfaces.py` (TAP, IP)                 | **hypervisor** | Pure infra: create TAP, assign IP.                                    |
| `network/firewall.py` (nft NAT, port forwards)    | **hypervisor** | Mechanism only: *which* ports to forward comes from the agent.        |
| `network/ndp_proxy.py`, `network/hostnetwork.py`  | **hypervisor** | Bridge / NDP / IPv6; host-network setup is infra.                     |
| `sevclient.py`                                    | **hypervisor** | Platform certificate export; merges into hypervisor's TEE module.     |
| `orchestrator/views/`                             | **agent**      | Public HTTP API surface stays here; calls hypervisor over gRPC.       |
| `orchestrator/messages.py`, `tasks.py`, `reactor` | **agent**      | Aleph message subscription, status reactor.                           |
| `orchestrator/payment.py`                         | **agent**      | Superfluid + credits + PAYG.                                          |
| `orchestrator/run.py`, `node_identity.py`         | **agent**      | Execution dispatcher, node identity.                                  |
| `orchestrator/resources.py` (`about_capability`)  | **agent**      | But sources data via a new `GetHostInfo` RPC from the hypervisor.     |
| `storage.py`                                      | **agent**      | Volume / code / runtime download → local paths.                       |
| `migration/`                                      | **hypervisor** | Disk export/import is a VM-management operation.                      |
| `haproxy.py`                                      | **agent**      | Domain routing is an Aleph-network policy concern.                    |
| `guest_api/`                                      | **agent**      | In-VM agent API endpoint; not hypervisor business.                    |
| `models.py::VmExecution`                          | **split**      | The hardest piece. See §4.                                            |
| `pool.py::VmPool`                                 | **split**      | Same. See §4.                                                         |

## 4. The detangling work (language-independent)

Most of the cost of Phase 1 is here. It must happen regardless of whether the hypervisor stays Python or becomes Rust.

**Split `VmExecution`.** Today it holds both the controller instance *and* Aleph state (message, mapped_ports policy, persistent flag, systemd manager, payment record). Cleave into:
- *Hypervisor-side `Vm` record*: process handle, TAP, IPs, status, actually-mapped ports, backup files.
- *Agent-side `Execution` record*: Aleph message, allocation, payment, expiry, the desired port-forward set.
Tie them by `vm_id` only.

**Split `VmPool`.** The pool currently does resource admission, TAP allocation, systemd supervision, and Aleph message caching. After the split:
- Hypervisor owns the inventory of running VMs (queryable by `ListVms`), local resource admission (memory/CPU/GPU buckets, NUMA placement), systemd supervision.
- Agent owns the *desired state* set indexed by `ItemHash`, and the reconcile loop that maps it to `CreateVm`/`DeleteVm` calls.

**Move volume download out of `controllers.setup()`.** Today the Firecracker controller's `setup()` fetches code/runtime/data from Aleph storage. That belongs in the agent: agent downloads, caches under `/var/cache/aleph-vm/...`, then passes local paths in `CreateVmRequest.disks[]`. (Matches aleph-cvm exactly.)

**Move port-redirect policy to the agent.** Today `VmExecution.fetch_port_redirect_config_and_setup()` fetches the user's aggregate settings *and* writes nft rules. After the split: agent reads aggregate settings and computes the desired forwards; hypervisor applies them via `AddPortForward`/`RemovePortForward`. Mechanism vs policy.

**Lift the on-demand program path.** When a request arrives at `/vm/{ref}` or `/{suffix}`, the agent: looks up or creates a VM (`CreateVm` if not present), waits for ready, proxies HTTP, applies idle teardown. The hypervisor sees nothing program-specific; it just gets `CreateVm`/`DeleteVm` like any other lifecycle event. Idle policy is an agent concern.

## 5. The contract (Phase 0 deliverable, sketched here)

`hypervisor.proto` extends aleph-cvm's `compute.proto` to cover aleph-vm's full surface. RPC list (final shape TBD in the Phase 0 spec):

- **Lifecycle**: `CreateVm`, `GetVm`, `ListVms`, `DeleteVm`, `RebootVm`, `ReinstallVm` (note: expiry/TTL is an *agent* concern; timer fires → eventual `DeleteVm`; the hypervisor stays unaware)
- **Port forwarding** (already in `compute.proto`): `AddPortForward`, `RemovePortForward`, `ListPortForwards`
- **Logs**: `GetLogs` (paginated), `StreamLogs` (server-streaming)
- **Backup / snapshot**: `StartBackup`, `GetBackupStatus`, `ListBackups`, `DownloadBackup` (server-streaming bytes), `DeleteBackup`, `RestoreBackup`
- **Migration**: `ExportVm`, `ImportVm`, `GetMigrationStatus`
- **Confidential** (Phase 3): `InitializeConfidential`, `GetMeasurement`, `InjectSecret`
- **Host info**: `Health`, `GetHostInfo` (CPU, NUMA, memory, GPUs, SEV/TDX support, which feeds `/about/capability`)

`CreateVm` grows fields aleph-cvm doesn't have today: `backend` enum (firecracker | qemu | qemu-sev), program-mode flags, GPU requests, runtime/code/data disk semantics.

The contract must avoid backend leakage. Two examples to watch:
- **Snapshots/backups** differ semantically between Firecracker and QEMU. The proto should expose a single backup operation per VM with backend-neutral semantics; hypervisor picks the mechanism.
- **`StreamLogs`** must work for both Firecracker (file-tail of vm-stdout) and QEMU (serial console / systemd journal). One RPC, hypervisor abstracts.

## 6. Phases

### Phase 0: Contract and in-process boundary
**Deliverable:** the finalised `hypervisor.proto`; a Python `Hypervisor` abstraction (ABC) inside aleph-vm with two implementations: in-process (wraps current `VmPool` / controllers) and gRPC client (stub for now). `orchestrator/views` and `orchestrator/run.py` are migrated to call the abstraction. No process split yet.
**Exit criteria:** every call into hypervisor functionality from agent code goes through the abstraction; the in-process implementation passes the existing test suite; the gRPC client compiles.
**Validates:** the contract is expressible without leaking Aleph types into the hypervisor side.

### Phase 1: Carve out the hypervisor process, still Python
Strangler-fig, one capability at a time. For each capability: stand up the corresponding gRPC server-side handler in the hypervisor daemon, switch the `Hypervisor` abstraction to use the gRPC implementation for that capability, ship a release, monitor, move on.

**Order (decided 2026-05-28):**
1. **Persistent QEMU instances**: closest match to aleph-cvm's proven flow.
2. **Firecracker microVMs / programs**: the on-demand HTTP path, hardest entanglement.
3. **Confidential (stub-level)**: wire the existing `sevctl` cert export and the stub endpoints; full attestation deferred to Phase 3.

In parallel with (1)–(3), detangle `VmExecution`/`VmPool` (§4). Backups, migration, logs, reboot/reinstall/expire migrate as they become needed by the carved-out paths.

**Exit criteria:** each CRN runs two Python daemons (`aleph-vm-agent`, `aleph-vm-hypervisor`) talking over UDS gRPC; no agent code reaches into hypervisor internals; the in-process implementation of `Hypervisor` is deleted.

### Phase 2: Swap hypervisor to Rust
Drop in aleph-cvm's `aleph-compute-node` as a replacement for the Python hypervisor daemon. Same socket, same proto, no agent changes. A/B per CRN: an operator can run the Python or Rust hypervisor under the same agent.

Work mostly inside this repo: extend `aleph-compute-node` to cover the firecracker backend, program semantics, backups, logs, migration, i.e. catch up to whatever the Python hypervisor exposed at end of Phase 1.

**Exit criteria:** the Rust hypervisor is the default on at least one production tier; the Python hypervisor codepath is removed from aleph-vm.

### Phase 3: Agent to Rust and real SEV-SNP
Port `aleph-vm-agent` to Rust, borrowing from `aleph-network-agent`. Wire genuine SEV-SNP attestation using `aleph-tee` + `aleph-attest-agent` + measured OVMF/kernel/initrd from this repo's Nix build. The contract gains `InitializeConfidential`/`GetMeasurement`/`InjectSecret` (or these become real implementations of the stubs).

**Exit criteria:** confidential VMs on aleph-vm provide remote attestation comparable to aleph-cvm; the Python agent is removed.

## 7. Non-goals

- **Merging the aleph-cvm and aleph-vm repos.** They stay independent. Code travels by being moved/published, not by repo merger.
- **Changing the public CRN HTTP API.** Clients (scheduler, front-end, CLIs) see no change at any phase.
- **Replacing Firecracker with QEMU (or vice versa).** Backend selection stays where it is today.
- **Adding new VM-shaped product features** (e.g. new TEE backends, new disk types) during the carve-out. The migration is structural; features land before or after.
- **Distributed/multi-host hypervisor.** Each CRN runs its own agent + hypervisor pair locally over UDS.

## 8. Risks and mitigations

| Risk                                                                                    | Mitigation                                                                                                                |
| --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| Contract leaks backend specifics (FC vs QEMU vs SEV), bleeds Aleph concepts back in     | Review the proto against aleph-cvm's `compute.proto` discipline; reject any field that names an Aleph message type        |
| The strangler intermediate state (some capabilities via gRPC, some in-process) leaks    | The `Hypervisor` abstraction is the *only* call path from agent → hypervisor; transport is implementation-detail          |
| Python gRPC server adds latency on the program cold-start path                          | Persistent first; profile microVM cold-start before carving; gRPC over UDS adds sub-ms vs the multi-100ms cold start      |
| Detangling `VmExecution`/`VmPool` becomes an open-ended yak shave                       | Bound each carve-out to a single capability; defer non-blocking cleanup; accept temporary ugliness behind the abstraction |
| Backups/migration semantics diverge per backend, contract becomes two parallel surfaces | Design the backup/migration RPCs from the agent's point of view, not the backend's; hypervisor adapts                     |
| The Python hypervisor daemon is throwaway; effort wasted                                | It is, but its purpose is to battle-test the contract under real RPC conditions, *before* the Rust swap. Worth it.        |
| Aleph aggregate-settings semantics drift mid-migration                                  | Agent owns aggregate-settings reads; freeze the shape the hypervisor sees (just `port_forwards`) on day one               |

## 9. Open questions

These are deliberately deferred to the Phase 0 contract spec:

- Exact shape of `CreateVm` for firecracker-program mode (code/runtime/data as `DiskConfig` with roles, or distinct fields?).
- Backup/snapshot RPC granularity (one operation vs. per-backend variants behind a discriminator).
- Log streaming protocol (server-streaming bytes vs. line-oriented messages with timestamps).
- Reconciliation cadence and idempotency: does the agent push allocations imperatively (today's model) or move to a desired-state diff loop driven by `ListVms`?
- GPU reservation semantics: does the agent reserve, or does the hypervisor own the GPU bucket?
- How `vm_id` is assigned: stays the Aleph `ItemHash` (today's identity) or becomes hypervisor-issued? (Recommendation: keep `ItemHash` as the agent's key, allow the hypervisor to be agnostic.)
- **Wire error vocabulary.** Today the HTTP views catch hypervisor-internal exception types directly (see Annex A.6). The proto needs a closed error enum covering at least `FileTooLargeError`, `VmSetupError`, `MicroVMFailedInitError`, `ResourceDownloadError`, `InsufficientResourcesError`, plus QEMU/SEV cases. Mapping happens at the gRPC server; views translate `status.code()` → HTTP response.

## 10. Next steps

1. User review of this design.
2. Write **Phase 0 spec**: detailed `hypervisor.proto` (every RPC, every field), the Python `Hypervisor` ABC, the test strategy for the in-process implementation.
3. Implementation plan for Phase 0 (followed by per-capability plans for Phase 1).

---

## Annex A: Concrete entanglements

References are to `aleph-im/aleph-vm@main`. The point of this annex is to make §4 ("detangling work") inspectable: each exhibit is a concrete piece of code today, what's tangled in it, and what it becomes after the split.

### A.1 `VmExecution`'s import list

`src/aleph/vm/models.py:11-46`: one file pulls from every layer:

```python
from aleph_message.models import ExecutableContent, InstanceContent, ItemHash, ProgramContent
from aleph_message.models.execution.environment import GpuProperties, HypervisorType
from aleph.vm.controllers.firecracker.executable import AlephFirecrackerExecutable
from aleph.vm.controllers.firecracker.instance import AlephInstanceResources
from aleph.vm.controllers.firecracker.program import AlephFirecrackerProgram, AlephProgramResources
from aleph.vm.controllers.firecracker.snapshot_manager import SnapshotManager
from aleph.vm.controllers.qemu.instance import AlephQemuInstance, AlephQemuResources
from aleph.vm.controllers.qemu_confidential.instance import AlephQemuConfidentialInstance, AlephQemuConfidentialResources
from aleph.vm.network.firewall import add_port_redirect_rule, build_port_redirect_entities, ...
from aleph.vm.network.interfaces import TapInterface
```

A single "execution" class imports Aleph message types, four concrete VM backends, and raw nftables operations. There is no abstraction in between. The first thing the gRPC seam does is delete most of these imports from the agent side.

### A.2 One method touches five conceptual layers

`models.py:133-160`, function `fetch_port_redirect_config_and_setup`:

```python
async def fetch_port_redirect_config_and_setup(self):
    if not self.is_instance:                                              # ① Aleph type predicate
        return
    if not self.mapped_ports:
        self.mapped_ports = await get_port_mappings(self.vm_hash)         # ② Aleph DB
        if self.mapped_ports:
            await self.recreate_port_redirect_rules()                     # ⑤ nft writes

    port_forwarding_settings = await get_user_settings(                   # ③ Aleph aggregate API
        message.address, "port-forwarding")
    vm_port_forwarding = port_forwarding_settings.get(self.vm_hash, {}) or {}
    ports_requests = {int(k): v for k, v in vm_port_forwarding.get("ports", {}).items()}
    if not ports_requests.get(22, None):                                  # ④ Aleph product policy
        ports_requests[22] = {"tcp": True, "udp": False}
    await self.update_port_redirects(ports_requests)                      # ⑤ nft writes
```

In one method: Aleph type system + Aleph DB schema + Aleph aggregate-settings HTTP API + Aleph product policy ("port 22 is sacred") + nftables. No transport boundary can be drawn through this without rewriting it.

**After:** agent reads aggregate settings, computes desired forwards, calls `AddPortForward(vm_id, host_port=0 /* auto */, vm_port, protocol)` per entry. Hypervisor allocates `host_port`, writes nft rules, returns the assignment. The "always forward port 22" rule lives in the agent.

### A.3 The "model" hand-constructs concrete backends

`models.py:480-540`, function `VmExecution.create`:

```python
def create(self, vm_id, tap_interface=None, prepare=True):
    if self.is_program:
        self.vm = AlephFirecrackerProgram(vm_id=vm_id, ..., persistent=self.persistent)
    elif self.is_instance:
        if self.hypervisor == HypervisorType.firecracker:
            self.vm = AlephFirecrackerInstance(vm_id=vm_id, ...)
        elif self.hypervisor == HypervisorType.qemu:
            if self.is_confidential:
                self.vm = AlephQemuConfidentialInstance(vm_id=vm_id, ...)
            else:
                self.vm = AlephQemuInstance(vm_id=vm_id, ...)
```

The "model" is the backend selector: it reads Aleph predicates (`is_program`, `is_confidential`, `hypervisor`) and constructs the matching controller class by direct import.

**After:** this whole ladder moves to the hypervisor side, behind `CreateVm`. The agent sends `{backend: "qemu" | "qemu-sev" | "firecracker", program_mode: bool, ...}`; the hypervisor picks the class. `VmExecution.create` ceases to exist; the agent's `Execution` record just holds the `vm_id` returned by `CreateVm`.

### A.4 `VmExecution.start` interleaves four subsystems

`models.py:542-587` (excerpt):

```python
async def start(self):
    await self.vm.setup()                                                  # controller
    if not self.persistent:
        await self.vm.start()                                              # ephemeral
    await self.vm.configure()                                              # controller
    await self.vm.start_guest_api()                                        # Aleph guest API
    if self.persistent and not self.is_confidential and self.systemd_manager:
        await self.systemd_manager.enable_and_start(self.controller_service)   # systemd
        if self.is_program:
            await self.wait_for_init()                                     # program wait
            await self.vm.load_configuration()
        else:
            if not await self.non_blocking_wait_for_boot():                # instance wait
                raise RuntimeError(...)
        if self.vm.support_snapshot and self.snapshot_manager:
            await self.snapshot_manager.start_for(vm=self.vm)              # snapshots
```

Hypervisor lifecycle + Aleph guest-API plumbing + systemd + program/instance branch + snapshot subsystem, all driven from one method, communicating via mutable state on `self`.

**After:** this whole method lives inside the hypervisor service, called from the `CreateVm` handler. The agent issues `CreateVm` and then waits for status via `GetVm` or a streaming `WatchVm`.

### A.5 `VmPool` is a god-object

`pool.py:77-104`, the constructor:

```python
def __init__(self):
    self.executions: dict[ItemHash, VmExecution] = {}      # Aleph-keyed registry
    self.message_cache: dict[str, ExecutableMessage] = {}  # Aleph message cache
    self.reservations = {}                                 # GPU reservation policy
    self.gpus = []
    self.creation_lock = asyncio.Lock()
    self.network = Network(                                # nftables + IP allocators
        vm_ipv4_address_pool_range=settings.IPV4_ADDRESS_POOL,
        ipv6_allocator=make_ipv6_allocator(...), use_ndp_proxy=settings.USE_NDP_PROXY,
        ipv6_forwarding_enabled=settings.IPV6_FORWARDING_ENABLED,
    ) if settings.ALLOW_VM_NETWORKING else None
    self.systemd_manager = SystemDManager()                # host systemd via dbus
    if settings.SNAPSHOT_FREQUENCY > 0:
        self.snapshot_manager = SnapshotManager()          # background thread
```

A "pool" owns the Aleph message cache, the Aleph execution registry, the Aleph GPU reservation policy, the IPv4/IPv6 allocators, the nftables host setup, host-systemd, and the snapshot thread.

`pool.py:309-398`: `create_a_vm` orchestrates the entire stack in 90 lines: admission against an Aleph message → GPU reservation (`find_resources_available_for_user(message, message.address)`) → volume download (`execution.prepare()`) → TAP allocation → controller construction (`execution.create`) → controller start (`execution.start`) → port forwards (`execution.fetch_port_redirect_config_and_setup`).

**After:**
- Hypervisor keeps `Network`, `SystemDManager`, `SnapshotManager`, `executions: dict[vm_id, Vm]`, local admission, NUMA placement.
- Agent keeps `message_cache`, `executions: dict[ItemHash, Execution]`, reservations, the reconcile loop.
- `create_a_vm` becomes: agent prepares local paths → `CreateVm` → `AddPortForward`. Three RPCs replace 90 lines of orchestration.

### A.6 HTTP views catch hypervisor-internal exception types (the hardest tangle)

`orchestrator/views/__init__.py:22-70` (imports) and `:541-557, 936-950` (uses):

```python
from aleph.vm.controllers.firecracker.executable import ResourceDownloadError, VmSetupError
from aleph.vm.controllers.firecracker.program import FileTooLargeError
from aleph.vm.hypervisors.firecracker.microvm import MicroVMFailedInitError
from aleph.vm.models import VmExecution
from aleph.vm.network.firewall import initialize_nftables, recreate_network_for_vms
from aleph.vm.pool import VmPool
...
# inside notify_allocation:
vm_creation_exceptions = (FileTooLargeError, VmSetupError, MicroVMFailedInitError,
                          HostNotFoundError, InsufficientResourcesError)
try:
    await start_persistent_vm(item_hash, pubsub, pool)
except vm_creation_exceptions as error:
    ...
```

`views/operator.py` is similar: it imports `controllers.qemu.backup.*`, `controllers.qemu.client.QemuVmClient`, `controllers.qemu.instance.AlephQemuInstance`, `controllers.qemu_confidential.instance.AlephQemuConfidentialInstance` and uses them by concrete type.

**Why this is the most important entanglement for the seam:** exceptions cannot cross gRPC. They become status codes. Before any of this can be lifted, those backend-internal exception types must map to a small wire-error vocabulary; views must catch only `grpc.AioRpcError` and translate `status.code()` to HTTP. Today they don't even pretend; backend exception messages are surfaced straight to API responses.

This is the open question added to §9.

### Pattern

| Tangle                                                | Where                                | Cleanup                                                                                                                                                |
| ----------------------------------------------------- | ------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `VmExecution` mixes Aleph state + controller state    | `models.py`                          | Split into agent `Execution` (vm_hash, message, payment, expiry, desired_forwards) and hypervisor `Vm` (vm_id, process, tap, status). Link by `vm_id`. |
| `VmPool` owns infra collaborators + Aleph caches      | `pool.py`                            | Hypervisor keeps `Network`, `SystemDManager`, `SnapshotManager`, `executions: dict[vm_id, Vm]`. Agent keeps `message_cache`, `Execution` map, reservations, reconcile loop. |
| Views catch hypervisor exception types                | `views/__init__.py`, `views/operator.py` | Closed error enum on the wire. Map backend exceptions → enum at the gRPC server. Views catch only `grpc.AioRpcError`.                              |

The first two are mostly **moving code**. The third is **designing the wire error vocabulary**, the single most underestimated piece of Phase 0.
