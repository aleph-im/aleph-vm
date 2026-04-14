# aleph-gateway Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone Rust L4 proxy that assigns each VM a fixed IPv6 from a shared prefix and proxies TCP+UDP traffic to the CRN node hosting the VM.

**Architecture:** Four ractor actors build an in-memory routing table (`gateway_ipv6 -> node_local_ipv6`) from three data sources (corechannel aggregate, scheduler plan, CRN status). A TPROXY-based data plane uses that table to forward TCP connections and UDP datagrams. An actix-web dashboard exposes operational status.

**Tech Stack:** Rust, tokio, ractor, aleph-sdk (crates.io 0.8.4+), socket2, actix-web, reqwest, clap, tracing, arc-swap

**Spec:** `docs/plans/2026-04-14-aleph-gateway-design.md` (in aleph-vm repo)

**Reference codebase:** The scheduler at `/home/olivier/git/aleph/aleph-vm-scheduler/scheduler-rs/` uses the same actor framework and aleph-sdk patterns. Refer to it for ractor conventions, corechannel types, and CLI structure.

---

## File Map

```
aleph-gateway/
  Cargo.toml
  src/
    main.rs                -- CLI (clap), actor wiring, startup/shutdown
    config.rs              -- GatewayConfig struct, clap Args
    ipv6.rs                -- derive_vm_ipv6() — port of StaticIPv6Allocator
    routing_table.rs       -- RoutingSnapshot: HashMap<Ipv6Addr, Ipv6Addr> + rebuild()
    actors/
      mod.rs               -- re-exports
      corechannel.rs       -- CorechannelWatcher ractor actor
      scheduler.rs         -- SchedulerPoller ractor actor
      node_config.rs       -- NodeConfigMonitor ractor actor
      routing.rs           -- RoutingTable ractor actor, owns Arc<ArcSwap<RoutingSnapshot>>
    proxy/
      mod.rs               -- re-exports, shared types (ProxyStats)
      tcp.rs               -- tcp_proxy_loop(): IP_TRANSPARENT accept + copy_bidirectional
      udp.rs               -- udp_proxy_loop(): IP_TRANSPARENT recv + session table
    network_setup.rs       -- setup_tproxy(): ip route + nftables rules via Command
    dashboard.rs           -- actix-web: GET /status
  tests/
    ipv6_test.rs           -- cross-validated with Python test vectors
    routing_table_test.rs  -- rebuild logic with synthetic data
    scheduler_parse_test.rs -- /api/v0/plan JSON deserialization
```

---

### Task 1: Project Scaffolding

**Files:**
- Create: `aleph-gateway/Cargo.toml`
- Create: `aleph-gateway/src/main.rs`
- Create: `aleph-gateway/src/config.rs`

- [ ] **Step 1: Create repository and Cargo.toml**

```bash
cd /home/olivier/git/aleph
mkdir aleph-gateway && cd aleph-gateway
git init
```

Create `Cargo.toml`:

```toml
[package]
name = "aleph-gateway"
version = "0.1.0"
edition = "2024"

[dependencies]
aleph-sdk = "0.8.4"
aleph-types = "0.8.4"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "net", "io-util", "signal"] }
ractor = "0.15"
actix-web = { version = "4", features = ["rustls-0_23"] }
reqwest = { version = "0.13", features = ["json"] }
socket2 = "0.5"
clap = { version = "4", features = ["derive", "env"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
arc-swap = "1"
ipnet = { version = "2", features = ["serde"] }
futures = "0.3"
thiserror = "2"
libc = "0.2"
```

- [ ] **Step 2: Create config.rs with CLI args**

```rust
use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use clap::Parser;
use ipnet::Ipv6Net;

#[derive(Parser, Debug)]
#[command(name = "aleph-gateway", about = "Aleph Cloud IPv6 gateway")]
pub struct CliArgs {
    /// Shared VM IPv6 prefix (/56 or /64)
    #[arg(long, env = "ALEPH_GATEWAY_PREFIX")]
    pub gateway_prefix: Ipv6Net,

    /// Scheduler API base URL
    #[arg(long, env = "ALEPH_GATEWAY_SCHEDULER_URL",
          default_value = "https://scheduler.api.aleph.cloud")]
    pub scheduler_url: String,

    /// Aleph API server URL
    #[arg(long, env = "ALEPH_GATEWAY_ALEPH_API_SERVER",
          default_value = "https://api3.aleph.im")]
    pub aleph_api_server: String,

    /// Corechannel aggregate owner address
    #[arg(long, env = "ALEPH_GATEWAY_CORECHANNEL_ADDRESS",
          default_value = "0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10")]
    pub corechannel_address: String,

    /// Scheduler plan polling interval in seconds
    #[arg(long, env = "ALEPH_GATEWAY_PLAN_POLL_INTERVAL", default_value = "30")]
    pub plan_poll_interval_secs: u64,

    /// CRN /status/config refresh interval in seconds
    #[arg(long, env = "ALEPH_GATEWAY_NODE_CONFIG_REFRESH", default_value = "14400")]
    pub node_config_refresh_secs: u64,

    /// Dashboard listen address
    #[arg(long, env = "ALEPH_GATEWAY_DASHBOARD_LISTEN",
          default_value = "[::1]:8080")]
    pub dashboard_listen: SocketAddr,

    /// UDP session idle timeout in seconds
    #[arg(long, env = "ALEPH_GATEWAY_UDP_SESSION_TIMEOUT", default_value = "60")]
    pub udp_session_timeout_secs: u64,
}

impl CliArgs {
    pub fn plan_poll_interval(&self) -> Duration {
        Duration::from_secs(self.plan_poll_interval_secs)
    }

    pub fn node_config_refresh(&self) -> Duration {
        Duration::from_secs(self.node_config_refresh_secs)
    }

    pub fn udp_session_timeout(&self) -> Duration {
        Duration::from_secs(self.udp_session_timeout_secs)
    }
}
```

- [ ] **Step 3: Create main.rs skeleton**

```rust
mod config;

use clap::Parser;
use config::CliArgs;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aleph_gateway=info".into()),
        )
        .init();

    let args = CliArgs::parse();
    tracing::info!(?args.gateway_prefix, "aleph-gateway starting");

    Ok(())
}
```

- [ ] **Step 4: Verify it compiles**

```bash
cd /home/olivier/git/aleph/aleph-gateway
cargo build
```

Expected: compiles with no errors.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml src/
git commit -m "feat: project scaffolding with CLI and config"
```

---

### Task 2: IPv6 Derivation

**Files:**
- Create: `aleph-gateway/src/ipv6.rs`
- Create: `aleph-gateway/tests/ipv6_test.rs`

This is a pure function with no I/O — port of Python's `StaticIPv6Allocator.allocate_vm_ipv6_subnet()` from `aleph-vm/src/aleph/vm/network/hostnetwork.py:50-75`.

- [ ] **Step 1: Write the failing test**

Create `tests/ipv6_test.rs`. These test vectors come from the Python test at
`aleph-vm/tests/supervisor/test_ipv6_allocator.py:14-21`:

```rust
use std::net::Ipv6Addr;

use aleph_gateway::ipv6::{VmType, derive_vm_ipv6};
use ipnet::Ipv6Net;

/// Cross-validated against Python's StaticIPv6Allocator.
/// Source: aleph-vm/tests/supervisor/test_ipv6_allocator.py
#[test]
fn test_derive_vm_ipv6_microvm() {
    let prefix: Ipv6Net = "1111:2222:3333:4444::/64".parse().unwrap();
    let vm_hash = "8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446";

    let subnet = derive_vm_ipv6(&prefix, vm_hash, VmType::MicroVm);

    // Python produces: 1111:2222:3333:4444:0001:8920:215b:2e90/124
    let expected_network: Ipv6Net = "1111:2222:3333:4444:0001:8920:215b:2e90/124".parse().unwrap();
    assert_eq!(subnet, expected_network);
}

#[test]
fn test_derive_vm_ipv6_instance() {
    let prefix: Ipv6Net = "1111:2222:3333:4444::/64".parse().unwrap();
    let vm_hash = "8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446";

    let subnet = derive_vm_ipv6(&prefix, vm_hash, VmType::Instance);

    // type prefix "3" instead of "1"
    let expected_network: Ipv6Net = "1111:2222:3333:4444:0003:8920:215b:2e90/124".parse().unwrap();
    assert_eq!(subnet, expected_network);
}

#[test]
fn test_routable_address_is_index_1() {
    let prefix: Ipv6Net = "1111:2222:3333:4444::/64".parse().unwrap();
    let vm_hash = "8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446";

    let subnet = derive_vm_ipv6(&prefix, vm_hash, VmType::MicroVm);
    let hosts: Vec<Ipv6Addr> = subnet.hosts().collect();
    // [1] in the /124 = the second usable address
    let routable = hosts[1];
    let expected: Ipv6Addr = "1111:2222:3333:4444:0001:8920:215b:2e91".parse().unwrap();
    assert_eq!(routable, expected);
}

#[test]
#[should_panic(expected = "prefix must be /56 or /64")]
fn test_rejects_invalid_prefix_length() {
    let prefix: Ipv6Net = "1111:2222:3333:4444:5555::/80".parse().unwrap();
    derive_vm_ipv6(&prefix, "abcdef0123456789", VmType::Instance);
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --test ipv6_test
```

Expected: compile error — `ipv6` module doesn't exist.

- [ ] **Step 3: Implement derive_vm_ipv6**

Create `src/ipv6.rs`:

```rust
use ipnet::Ipv6Net;
use std::net::Ipv6Addr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmType {
    MicroVm,
    PersistentProgram,
    Instance,
}

impl VmType {
    /// Returns the 4-character hex type prefix used in IPv6 derivation.
    /// Matches Python's VM_TYPE_PREFIX: microvm="1", persistent_program="2", instance="3"
    fn type_prefix(self) -> &'static str {
        match self {
            VmType::MicroVm => "0001",
            VmType::PersistentProgram => "0002",
            VmType::Instance => "0003",
        }
    }
}

/// Derive a deterministic /124 IPv6 subnet for a VM.
///
/// Port of Python's `StaticIPv6Allocator.allocate_vm_ipv6_subnet()`.
/// Algorithm: base_prefix(64 bits) + vm_type(16) + hash[0:4](16) + hash[4:8](16) + hash[8:11]+"0"(16) = /124
///
/// The VM's routable address is `subnet.hosts().nth(1)` (index [1] in the /124).
pub fn derive_vm_ipv6(prefix: &Ipv6Net, vm_hash: &str, vm_type: VmType) -> Ipv6Net {
    let prefix_len = prefix.prefix_len();
    assert!(
        prefix_len == 56 || prefix_len == 64,
        "prefix must be /56 or /64, got /{prefix_len}"
    );

    // Take the first 4 hextets (64 bits) from the prefix
    let segments = prefix.network().segments();
    let base = format!(
        "{:04x}:{:04x}:{:04x}:{:04x}",
        segments[0], segments[1], segments[2], segments[3]
    );

    // Build the full address: base + type + hash[0:4] + hash[4:8] + hash[8:11]+"0"
    let addr_str = format!(
        "{}:{}:{}:{}:{}0",
        base,
        vm_type.type_prefix(),
        &vm_hash[0..4],
        &vm_hash[4..8],
        &vm_hash[8..11],
    );

    let addr: Ipv6Addr = addr_str.parse().expect("constructed invalid IPv6 address");
    Ipv6Net::new(addr, 124).expect("invalid /124 subnet")
}
```

Add `pub mod ipv6;` to `main.rs` and add a `[lib]` section or convert to lib+bin. The simplest approach:

Add to `Cargo.toml`:
```toml
[lib]
name = "aleph_gateway"
path = "src/lib.rs"

[[bin]]
name = "aleph-gateway"
path = "src/main.rs"
```

Create `src/lib.rs`:
```rust
pub mod config;
pub mod ipv6;
```

Update `src/main.rs` to use `aleph_gateway::config::CliArgs;` instead of `mod config;`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --test ipv6_test
```

Expected: all 4 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/ipv6.rs src/lib.rs tests/ipv6_test.rs Cargo.toml
git commit -m "feat: deterministic IPv6 derivation, cross-validated with Python"
```

---

### Task 3: Scheduler Plan Types

**Files:**
- Create: `aleph-gateway/src/scheduler_types.rs`
- Create: `aleph-gateway/tests/scheduler_parse_test.rs`

Define types matching the scheduler API's `/api/v0/plan` response and the flat
routing structures the gateway needs.

- [ ] **Step 1: Write the failing test**

Create `tests/scheduler_parse_test.rs`:

```rust
use aleph_gateway::scheduler_types::{PlanResponse, VmAllocation, VmType};

/// JSON shape taken from scheduler-api/src/routes/v0.rs:220-275
#[test]
fn test_parse_plan_response() {
    let json = r#"{
        "period": {
            "start_timestamp": "2026-04-14T12:00:00Z",
            "duration_seconds": 60.0
        },
        "plan": {
            "abc123def456": {
                "persistent_vms": ["vm_hash_1"],
                "instances": ["vm_hash_2", "vm_hash_3"],
                "on_demand_vms": ["vm_hash_4"],
                "jobs": []
            },
            "node_hash_2": {
                "persistent_vms": [],
                "instances": ["vm_hash_5"],
                "on_demand_vms": [],
                "jobs": []
            }
        }
    }"#;

    let response: PlanResponse = serde_json::from_str(json).unwrap();

    let allocations = response.into_vm_allocations();
    assert_eq!(allocations.len(), 5);

    // Check that VM types are correctly inferred from which list they appear in
    let vm1 = allocations.iter().find(|a| a.vm_hash == "vm_hash_1").unwrap();
    assert_eq!(vm1.vm_type, VmType::PersistentProgram);
    assert_eq!(vm1.node_hash, "abc123def456");

    let vm2 = allocations.iter().find(|a| a.vm_hash == "vm_hash_2").unwrap();
    assert_eq!(vm2.vm_type, VmType::Instance);

    let vm4 = allocations.iter().find(|a| a.vm_hash == "vm_hash_4").unwrap();
    assert_eq!(vm4.vm_type, VmType::MicroVm);
}

#[test]
fn test_parse_empty_plan() {
    let json = r#"{"period": {"start_timestamp": "2026-04-14T12:00:00Z", "duration_seconds": 60.0}, "plan": {}}"#;
    let response: PlanResponse = serde_json::from_str(json).unwrap();
    assert!(response.into_vm_allocations().is_empty());
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --test scheduler_parse_test
```

Expected: compile error — `scheduler_types` module doesn't exist.

- [ ] **Step 3: Implement scheduler_types**

Create `src/scheduler_types.rs`:

```rust
use std::collections::HashMap;

use serde::Deserialize;

pub use crate::ipv6::VmType;

#[derive(Debug, Deserialize)]
pub struct PlanResponse {
    pub period: Period,
    pub plan: HashMap<String, NodePlan>,
}

#[derive(Debug, Deserialize)]
pub struct Period {
    pub start_timestamp: String,
    pub duration_seconds: f64,
}

#[derive(Debug, Deserialize)]
pub struct NodePlan {
    #[serde(default)]
    pub persistent_vms: Vec<String>,
    #[serde(default)]
    pub instances: Vec<String>,
    #[serde(default)]
    pub on_demand_vms: Vec<String>,
    #[serde(default)]
    pub jobs: Vec<String>,
}

/// A single VM-to-node allocation with its inferred type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmAllocation {
    pub vm_hash: String,
    pub node_hash: String,
    pub vm_type: VmType,
}

impl PlanResponse {
    /// Flatten the per-node plan into a list of (vm_hash, node_hash, vm_type) tuples.
    pub fn into_vm_allocations(self) -> Vec<VmAllocation> {
        let mut allocations = Vec::new();

        for (node_hash, node_plan) in self.plan {
            for vm_hash in node_plan.on_demand_vms {
                allocations.push(VmAllocation {
                    vm_hash,
                    node_hash: node_hash.clone(),
                    vm_type: VmType::MicroVm,
                });
            }
            for vm_hash in node_plan.persistent_vms {
                allocations.push(VmAllocation {
                    vm_hash,
                    node_hash: node_hash.clone(),
                    vm_type: VmType::PersistentProgram,
                });
            }
            for vm_hash in node_plan.instances {
                allocations.push(VmAllocation {
                    vm_hash,
                    node_hash: node_hash.clone(),
                    vm_type: VmType::Instance,
                });
            }
        }

        allocations
    }
}
```

Add `pub mod scheduler_types;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --test scheduler_parse_test
```

Expected: all 2 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/scheduler_types.rs tests/scheduler_parse_test.rs src/lib.rs
git commit -m "feat: scheduler plan response types with VM type inference"
```

---

### Task 4: Routing Table

**Files:**
- Create: `aleph-gateway/src/routing_table.rs`
- Create: `aleph-gateway/tests/routing_table_test.rs`

The core data structure: builds `HashMap<Ipv6Addr, Ipv6Addr>` from the three
data sources. Pure logic, no actors yet.

- [ ] **Step 1: Write the failing test**

Create `tests/routing_table_test.rs`:

```rust
use std::collections::HashMap;
use std::net::Ipv6Addr;

use aleph_gateway::ipv6::VmType;
use aleph_gateway::routing_table::{NodeInfo, RoutingSnapshot};
use aleph_gateway::scheduler_types::VmAllocation;
use ipnet::Ipv6Net;

#[test]
fn test_rebuild_routing_table() {
    let gateway_prefix: Ipv6Net = "2001:db8:aaaa:0::/64".parse().unwrap();

    // Two nodes with different IPv6 prefixes
    let mut nodes = HashMap::new();
    nodes.insert(
        "node_aaa".to_string(),
        NodeInfo { ipv6_prefix: "fd00:1:2:3::/64".parse().unwrap() },
    );
    nodes.insert(
        "node_bbb".to_string(),
        NodeInfo { ipv6_prefix: "fd00:4:5:6::/64".parse().unwrap() },
    );

    let vm_hash = "8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446";

    let allocations = vec![
        VmAllocation {
            vm_hash: vm_hash.to_string(),
            node_hash: "node_aaa".to_string(),
            vm_type: VmType::Instance,
        },
    ];

    let snapshot = RoutingSnapshot::rebuild(&gateway_prefix, &allocations, &nodes);

    // The gateway IPv6 for this VM (using gateway prefix):
    // 2001:db8:aaaa:0000:0003:8920:215b:2e91
    let gw_addr: Ipv6Addr = "2001:db8:aaaa:0:3:8920:215b:2e91".parse().unwrap();
    // The node-local IPv6 (using node_aaa's prefix):
    // fd00:1:2:3:0003:8920:215b:2e91
    let node_addr: Ipv6Addr = "fd00:1:2:3:3:8920:215b:2e91".parse().unwrap();

    assert_eq!(snapshot.lookup(&gw_addr), Some(&node_addr));
    assert_eq!(snapshot.len(), 1);
}

#[test]
fn test_rebuild_skips_vms_on_unknown_nodes() {
    let gateway_prefix: Ipv6Net = "2001:db8:aaaa:0::/64".parse().unwrap();
    let nodes = HashMap::new(); // no nodes known

    let allocations = vec![VmAllocation {
        vm_hash: "aaaa0000111122223333".to_string(),
        node_hash: "unknown_node".to_string(),
        vm_type: VmType::MicroVm,
    }];

    let snapshot = RoutingSnapshot::rebuild(&gateway_prefix, &allocations, &nodes);
    assert_eq!(snapshot.len(), 0);
}

#[test]
fn test_vm_migration_updates_routing() {
    let gateway_prefix: Ipv6Net = "2001:db8:aaaa:0::/64".parse().unwrap();
    let vm_hash = "8920215b2e961a4d4c59a8ceb2803af53f91530ff53d6704273ab4d380bc6446";

    let mut nodes = HashMap::new();
    nodes.insert("node_a".to_string(), NodeInfo { ipv6_prefix: "fd00:a::/64".parse().unwrap() });
    nodes.insert("node_b".to_string(), NodeInfo { ipv6_prefix: "fd00:b::/64".parse().unwrap() });

    // VM starts on node_a
    let alloc_a = vec![VmAllocation {
        vm_hash: vm_hash.to_string(),
        node_hash: "node_a".to_string(),
        vm_type: VmType::Instance,
    }];
    let snap_a = RoutingSnapshot::rebuild(&gateway_prefix, &alloc_a, &nodes);

    // VM migrates to node_b
    let alloc_b = vec![VmAllocation {
        vm_hash: vm_hash.to_string(),
        node_hash: "node_b".to_string(),
        vm_type: VmType::Instance,
    }];
    let snap_b = RoutingSnapshot::rebuild(&gateway_prefix, &alloc_b, &nodes);

    let gw_addr: Ipv6Addr = "2001:db8:aaaa:0:3:8920:215b:2e91".parse().unwrap();

    // Same gateway IPv6, different backend
    let target_a = snap_a.lookup(&gw_addr).unwrap();
    let target_b = snap_b.lookup(&gw_addr).unwrap();
    assert_ne!(target_a, target_b);

    // Gateway address is the same in both snapshots
    assert!(snap_a.lookup(&gw_addr).is_some());
    assert!(snap_b.lookup(&gw_addr).is_some());
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cargo test --test routing_table_test
```

Expected: compile error.

- [ ] **Step 3: Implement routing_table.rs**

Create `src/routing_table.rs`:

```rust
use std::collections::HashMap;
use std::net::Ipv6Addr;

use ipnet::Ipv6Net;

use crate::ipv6::derive_vm_ipv6;
use crate::scheduler_types::VmAllocation;

/// Cached info about a CRN node.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub ipv6_prefix: Ipv6Net,
}

/// Immutable snapshot of the routing table.
/// Maps gateway VM IPv6 -> node-local VM IPv6.
#[derive(Debug, Clone)]
pub struct RoutingSnapshot {
    table: HashMap<Ipv6Addr, Ipv6Addr>,
}

impl RoutingSnapshot {
    /// Build a new routing snapshot from the current state of all data sources.
    pub fn rebuild(
        gateway_prefix: &Ipv6Net,
        allocations: &[VmAllocation],
        nodes: &HashMap<String, NodeInfo>,
    ) -> Self {
        let mut table = HashMap::with_capacity(allocations.len());

        for alloc in allocations {
            let Some(node_info) = nodes.get(&alloc.node_hash) else {
                tracing::warn!(
                    vm_hash = %alloc.vm_hash,
                    node_hash = %alloc.node_hash,
                    "skipping VM on unknown node"
                );
                continue;
            };

            let gw_subnet = derive_vm_ipv6(gateway_prefix, &alloc.vm_hash, alloc.vm_type);
            let node_subnet = derive_vm_ipv6(&node_info.ipv6_prefix, &alloc.vm_hash, alloc.vm_type);

            // The routable address is [1] in the /124 subnet
            let gw_addr = gw_subnet.hosts().nth(1).expect("/124 always has hosts");
            let node_addr = node_subnet.hosts().nth(1).expect("/124 always has hosts");

            table.insert(gw_addr, node_addr);
        }

        Self { table }
    }

    /// Look up the node-local IPv6 for a given gateway IPv6.
    pub fn lookup(&self, gateway_addr: &Ipv6Addr) -> Option<&Ipv6Addr> {
        self.table.get(gateway_addr)
    }

    /// Number of VMs in the routing table.
    pub fn len(&self) -> usize {
        self.table.len()
    }

    pub fn is_empty(&self) -> bool {
        self.table.is_empty()
    }
}
```

Add `pub mod routing_table;` to `src/lib.rs`.

- [ ] **Step 4: Run tests to verify they pass**

```bash
cargo test --test routing_table_test
```

Expected: all 3 tests pass.

- [ ] **Step 5: Commit**

```bash
git add src/routing_table.rs tests/routing_table_test.rs src/lib.rs
git commit -m "feat: routing table rebuild from gateway prefix + allocations + node configs"
```

---

### Task 5: CorechannelWatcher Actor

**Files:**
- Create: `aleph-gateway/src/actors/mod.rs`
- Create: `aleph-gateway/src/actors/corechannel.rs`

Mirrors the scheduler's `NodeRegistryWatcher` pattern. Subscribes to corechannel
aggregate via WebSocket, falls back to periodic polling. Emits node add/remove
messages to downstream actors.

Reference: `aleph-vm-scheduler/scheduler-rs/src/actors/node_registry_watcher.rs`

- [ ] **Step 1: Create actors/mod.rs**

```rust
pub mod corechannel;
pub mod node_config;
pub mod routing;
pub mod scheduler;
```

Add `pub mod actors;` to `src/lib.rs`.

- [ ] **Step 2: Define the actor message types and state**

Create `src/actors/corechannel.rs`:

```rust
use std::collections::HashMap;
use std::time::Duration;

use aleph_sdk::aggregate_models::corechannel::{CrnInfo, NodeHash};
use aleph_sdk::client::{AlephAggregateClient, AlephMessageClient};
use aleph_types::chain::Address;
use aleph_types::message::MessageType;
use futures::StreamExt;
use ractor::{Actor, ActorProcessingErr, ActorRef};

use super::routing::RoutingTableMsg;

/// Messages the CorechannelWatcher handles.
pub enum CorechannelWatcherMsg {
    /// Trigger a refresh of the corechannel aggregate.
    Update,
}

impl ractor::Message for CorechannelWatcherMsg {}

/// Arguments passed to the actor on startup.
pub struct CorechannelWatcherArgs<C> {
    pub client: C,
    pub corechannel_address: Address,
    pub poll_interval: Duration,
    pub routing_table: ActorRef<RoutingTableMsg>,
}

/// Internal state of the actor.
struct CorechannelWatcherState<C> {
    client: C,
    corechannel_address: Address,
    poll_interval: Duration,
    routing_table: ActorRef<RoutingTableMsg>,
    known_crns: HashMap<NodeHash, CrnInfo>,
    ws_abort_handle: Option<tokio::task::AbortHandle>,
}

pub struct CorechannelWatcher<C> {
    _phantom: std::marker::PhantomData<C>,
}

impl<C> CorechannelWatcher<C> {
    pub fn new() -> Self {
        Self { _phantom: std::marker::PhantomData }
    }
}

/// Spawn a background task that listens for corechannel aggregate updates
/// via WebSocket and sends Update messages to the actor.
async fn websocket_listener<C: AlephMessageClient>(
    client: C,
    corechannel_address: Address,
    myself: ActorRef<CorechannelWatcherMsg>,
) -> Result<(), ActorProcessingErr> {
    let filter = aleph_sdk::client::MessageFilter {
        message_type: Some(MessageType::Aggregate),
        owners: Some(vec![corechannel_address]),
        ..Default::default()
    };

    let mut stream = client.subscribe_to_messages(&filter, Some(0)).await?;

    while let Some(result) = stream.next().await {
        match result {
            Ok(_) => {
                tracing::info!("corechannel aggregate update via WebSocket");
                if myself.cast(CorechannelWatcherMsg::Update).is_err() {
                    break; // actor stopped
                }
            }
            Err(e) => {
                tracing::error!("WebSocket error: {e:?}");
            }
        }
    }

    Ok(())
}

impl<C> Actor for CorechannelWatcher<C>
where
    C: AlephMessageClient + AlephAggregateClient + Clone + Send + Sync + 'static,
{
    type Msg = CorechannelWatcherMsg;
    type State = CorechannelWatcherState<C>;
    type Arguments = CorechannelWatcherArgs<C>;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        // Spawn WebSocket listener
        let ws_handle = tokio::spawn(websocket_listener(
            args.client.clone(),
            args.corechannel_address.clone(),
            myself.clone(),
        ));

        // Schedule immediate first update
        myself.send_after(Duration::ZERO, || CorechannelWatcherMsg::Update);

        Ok(CorechannelWatcherState {
            client: args.client,
            corechannel_address: args.corechannel_address,
            poll_interval: args.poll_interval,
            routing_table: args.routing_table,
            known_crns: HashMap::new(),
            ws_abort_handle: Some(ws_handle.abort_handle()),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            CorechannelWatcherMsg::Update => {
                match state
                    .client
                    .get_corechannel_aggregate(&state.corechannel_address)
                    .await
                {
                    Ok(aggregate) => {
                        let current_crns: HashMap<NodeHash, CrnInfo> = aggregate
                            .corechannel
                            .resource_nodes
                            .into_iter()
                            .map(|crn| (crn.hash, crn))
                            .collect();

                        // Compute delta and notify routing table
                        for (hash, crn) in &current_crns {
                            if !state.known_crns.contains_key(hash) {
                                tracing::info!(
                                    node_hash = ?hash,
                                    url = %crn.address,
                                    "node discovered"
                                );
                                let _ = state.routing_table.cast(
                                    RoutingTableMsg::NodeDiscovered {
                                        node_hash: format!("{hash:?}"),
                                        url: crn.address.clone(),
                                    },
                                );
                            }
                        }

                        for hash in state.known_crns.keys() {
                            if !current_crns.contains_key(hash) {
                                tracing::info!(node_hash = ?hash, "node removed");
                                let _ = state.routing_table.cast(
                                    RoutingTableMsg::NodeRemoved {
                                        node_hash: format!("{hash:?}"),
                                    },
                                );
                            }
                        }

                        state.known_crns = current_crns;
                    }
                    Err(e) => {
                        tracing::error!("failed to fetch corechannel aggregate: {e:?}");
                    }
                }

                // Schedule next poll as fallback
                myself.send_after(state.poll_interval, || CorechannelWatcherMsg::Update);
            }
        }

        Ok(())
    }

    async fn post_stop(
        &self,
        _myself: ActorRef<Self::Msg>,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        if let Some(handle) = state.ws_abort_handle.take() {
            handle.abort();
        }
        Ok(())
    }
}
```

Note: `RoutingTableMsg` is forward-declared here; it will be defined in Task 8.
For this to compile, create a stub in `src/actors/routing.rs`:

```rust
pub enum RoutingTableMsg {
    NodeDiscovered { node_hash: String, url: String },
    NodeRemoved { node_hash: String },
    NodeConfigUpdated { node_hash: String, ipv6_prefix: ipnet::Ipv6Net },
    PlanUpdated { allocations: Vec<crate::scheduler_types::VmAllocation> },
}

impl ractor::Message for RoutingTableMsg {}
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build
```

Expected: compiles. Full testing of actors against a real Aleph API is an
integration test — unit testing ractor actors requires mocking the AlephClient
traits, which is out of scope for v1. The scheduler doesn't unit-test its
`NodeRegistryWatcher` either.

- [ ] **Step 4: Commit**

```bash
git add src/actors/
git commit -m "feat: CorechannelWatcher actor with WebSocket + polling fallback"
```

---

### Task 6: SchedulerPoller Actor

**Files:**
- Create: `aleph-gateway/src/actors/scheduler.rs`

Polls the scheduler's `/api/v0/plan` endpoint on a configurable interval and
sends `PlanUpdated` to the routing table actor.

- [ ] **Step 1: Implement the actor**

Create `src/actors/scheduler.rs`:

```rust
use std::time::Duration;

use ractor::{Actor, ActorProcessingErr, ActorRef};
use reqwest::Client;

use super::routing::RoutingTableMsg;
use crate::scheduler_types::PlanResponse;

pub enum SchedulerPollerMsg {
    Poll,
}

impl ractor::Message for SchedulerPollerMsg {}

pub struct SchedulerPollerArgs {
    pub scheduler_url: String,
    pub poll_interval: Duration,
    pub routing_table: ActorRef<RoutingTableMsg>,
}

struct SchedulerPollerState {
    http_client: Client,
    scheduler_url: String,
    poll_interval: Duration,
    routing_table: ActorRef<RoutingTableMsg>,
}

pub struct SchedulerPoller;

impl Actor for SchedulerPoller {
    type Msg = SchedulerPollerMsg;
    type State = SchedulerPollerState;
    type Arguments = SchedulerPollerArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        // Schedule immediate first poll
        myself.send_after(Duration::ZERO, || SchedulerPollerMsg::Poll);

        Ok(SchedulerPollerState {
            http_client: Client::new(),
            scheduler_url: args.scheduler_url,
            poll_interval: args.poll_interval,
            routing_table: args.routing_table,
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            SchedulerPollerMsg::Poll => {
                let url = format!("{}/api/v0/plan", state.scheduler_url);

                match state.http_client.get(&url).send().await {
                    Ok(resp) => match resp.json::<PlanResponse>().await {
                        Ok(plan) => {
                            let allocations = plan.into_vm_allocations();
                            tracing::info!(vm_count = allocations.len(), "plan updated");
                            let _ = state.routing_table.cast(
                                RoutingTableMsg::PlanUpdated { allocations },
                            );
                        }
                        Err(e) => {
                            tracing::error!("failed to parse plan response: {e}");
                        }
                    },
                    Err(e) => {
                        tracing::error!("failed to fetch scheduler plan: {e}");
                    }
                }

                // Schedule next poll
                myself.send_after(state.poll_interval, || SchedulerPollerMsg::Poll);
            }
        }

        Ok(())
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 3: Commit**

```bash
git add src/actors/scheduler.rs
git commit -m "feat: SchedulerPoller actor, polls /api/v0/plan"
```

---

### Task 7: NodeConfigMonitor Actor

**Files:**
- Create: `aleph-gateway/src/actors/node_config.rs`

When the routing table actor receives a `NodeDiscovered` message, it tells
the `NodeConfigMonitor` to fetch that node's `/status/config`. The monitor
fetches, parses the IPv6 prefix, and sends it back to the routing table.
It also periodically refreshes all known nodes.

- [ ] **Step 1: Implement the actor**

Create `src/actors/node_config.rs`:

```rust
use std::collections::HashMap;
use std::time::Duration;

use ractor::{Actor, ActorProcessingErr, ActorRef};
use reqwest::Client;
use serde::Deserialize;

use super::routing::RoutingTableMsg;

pub enum NodeConfigMonitorMsg {
    /// Fetch config for a newly discovered node.
    FetchNode { node_hash: String, url: String },
    /// Periodic refresh of all known nodes.
    RefreshAll,
}

impl ractor::Message for NodeConfigMonitorMsg {}

pub struct NodeConfigMonitorArgs {
    pub refresh_interval: Duration,
    pub routing_table: ActorRef<RoutingTableMsg>,
}

struct NodeConfigMonitorState {
    http_client: Client,
    refresh_interval: Duration,
    routing_table: ActorRef<RoutingTableMsg>,
    /// node_hash -> base URL, for periodic refresh
    known_nodes: HashMap<String, String>,
}

pub struct NodeConfigMonitor;

/// Partial parse of the /status/config response — we only need networking.
#[derive(Debug, Deserialize)]
struct StatusConfigResponse {
    networking: NetworkingConfig,
}

#[derive(Debug, Deserialize)]
struct NetworkingConfig {
    #[serde(rename = "IPV6_ADDRESS_POOL")]
    ipv6_address_pool: String,
}

async fn fetch_node_ipv6_prefix(
    client: &Client,
    base_url: &str,
) -> Result<ipnet::Ipv6Net, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("{}/status/config", base_url.trim_end_matches('/'));
    let resp: StatusConfigResponse = client.get(&url).send().await?.json().await?;
    let prefix: ipnet::Ipv6Net = resp.networking.ipv6_address_pool.parse()?;
    Ok(prefix)
}

impl Actor for NodeConfigMonitor {
    type Msg = NodeConfigMonitorMsg;
    type State = NodeConfigMonitorState;
    type Arguments = NodeConfigMonitorArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        // Schedule periodic refresh
        myself.send_after(args.refresh_interval, || NodeConfigMonitorMsg::RefreshAll);

        Ok(NodeConfigMonitorState {
            http_client: Client::builder()
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to build HTTP client"),
            refresh_interval: args.refresh_interval,
            routing_table: args.routing_table,
            known_nodes: HashMap::new(),
        })
    }

    async fn handle(
        &self,
        myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            NodeConfigMonitorMsg::FetchNode { node_hash, url } => {
                match fetch_node_ipv6_prefix(&state.http_client, &url).await {
                    Ok(prefix) => {
                        tracing::info!(
                            node_hash = %node_hash,
                            prefix = %prefix,
                            "fetched node IPv6 prefix"
                        );
                        state.known_nodes.insert(node_hash.clone(), url);
                        let _ = state.routing_table.cast(
                            RoutingTableMsg::NodeConfigUpdated {
                                node_hash,
                                ipv6_prefix: prefix,
                            },
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            node_hash = %node_hash,
                            url = %url,
                            "failed to fetch node config: {e}"
                        );
                    }
                }
            }

            NodeConfigMonitorMsg::RefreshAll => {
                let nodes: Vec<(String, String)> = state
                    .known_nodes
                    .iter()
                    .map(|(h, u)| (h.clone(), u.clone()))
                    .collect();

                for (node_hash, url) in nodes {
                    if let Ok(prefix) = fetch_node_ipv6_prefix(&state.http_client, &url).await {
                        let _ = state.routing_table.cast(
                            RoutingTableMsg::NodeConfigUpdated {
                                node_hash,
                                ipv6_prefix: prefix,
                            },
                        );
                    }
                }

                myself.send_after(state.refresh_interval, || NodeConfigMonitorMsg::RefreshAll);
            }
        }

        Ok(())
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 3: Commit**

```bash
git add src/actors/node_config.rs
git commit -m "feat: NodeConfigMonitor actor, fetches CRN IPv6 prefixes"
```

---

### Task 8: RoutingTable Actor

**Files:**
- Modify: `aleph-gateway/src/actors/routing.rs` (replace the stub from Task 5)

The central actor that receives updates from all three sources, rebuilds the
`RoutingSnapshot`, and publishes it via `Arc<ArcSwap<RoutingSnapshot>>` for
lock-free reads by the proxy data plane.

- [ ] **Step 1: Implement the full actor**

Replace `src/actors/routing.rs`:

```rust
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ipnet::Ipv6Net;
use ractor::{Actor, ActorProcessingErr, ActorRef};

use super::node_config::{NodeConfigMonitor, NodeConfigMonitorArgs, NodeConfigMonitorMsg};
use crate::routing_table::{NodeInfo, RoutingSnapshot};
use crate::scheduler_types::VmAllocation;

pub enum RoutingTableMsg {
    /// A new CRN was discovered in the corechannel aggregate.
    NodeDiscovered { node_hash: String, url: String },
    /// A CRN was removed from the corechannel aggregate.
    NodeRemoved { node_hash: String },
    /// A CRN's IPv6 prefix was fetched or refreshed.
    NodeConfigUpdated { node_hash: String, ipv6_prefix: Ipv6Net },
    /// A new scheduler plan was received.
    PlanUpdated { allocations: Vec<VmAllocation> },
}

impl ractor::Message for RoutingTableMsg {}

pub struct RoutingTableArgs {
    pub gateway_prefix: Ipv6Net,
    pub snapshot: Arc<ArcSwap<RoutingSnapshot>>,
    /// How often NodeConfigMonitor should refresh CRN /status/config.
    pub node_config_refresh: Duration,
}

struct RoutingTableState {
    gateway_prefix: Ipv6Net,
    snapshot: Arc<ArcSwap<RoutingSnapshot>>,
    node_config_monitor: ActorRef<NodeConfigMonitorMsg>,
    /// node_hash -> NodeInfo (with IPv6 prefix)
    nodes: HashMap<String, NodeInfo>,
    /// Latest VM allocations from the scheduler
    allocations: Vec<VmAllocation>,
}

impl RoutingTableState {
    fn rebuild_and_publish(&self) {
        let new_snapshot = RoutingSnapshot::rebuild(
            &self.gateway_prefix,
            &self.allocations,
            &self.nodes,
        );
        tracing::info!(
            vm_count = new_snapshot.len(),
            node_count = self.nodes.len(),
            "routing table rebuilt"
        );
        self.snapshot.store(Arc::new(new_snapshot));
    }
}

pub struct RoutingTableActor;

impl Actor for RoutingTableActor {
    type Msg = RoutingTableMsg;
    type State = RoutingTableState;
    type Arguments = RoutingTableArgs;

    async fn pre_start(
        &self,
        myself: ActorRef<Self::Msg>,
        args: Self::Arguments,
    ) -> Result<Self::State, ActorProcessingErr> {
        // Spawn NodeConfigMonitor as a child — resolves the circular dependency
        // (RoutingTable needs NodeConfigMonitor ref, NodeConfigMonitor needs RoutingTable ref)
        let (node_config_ref, _) = Actor::spawn(
            Some("node-config-monitor".to_string()),
            NodeConfigMonitor,
            NodeConfigMonitorArgs {
                refresh_interval: args.node_config_refresh,
                routing_table: myself.clone(),
            },
        )
        .await?;

        Ok(RoutingTableState {
            gateway_prefix: args.gateway_prefix,
            snapshot: args.snapshot,
            node_config_monitor: node_config_ref,
            nodes: HashMap::new(),
            allocations: Vec::new(),
        })
    }

    async fn handle(
        &self,
        _myself: ActorRef<Self::Msg>,
        msg: Self::Msg,
        state: &mut Self::State,
    ) -> Result<(), ActorProcessingErr> {
        match msg {
            RoutingTableMsg::NodeDiscovered { node_hash, url } => {
                // Tell NodeConfigMonitor to fetch this node's IPv6 prefix
                let _ = state.node_config_monitor.cast(
                    NodeConfigMonitorMsg::FetchNode {
                        node_hash,
                        url,
                    },
                );
                // Don't rebuild yet — wait for NodeConfigUpdated
            }

            RoutingTableMsg::NodeRemoved { node_hash } => {
                if state.nodes.remove(&node_hash).is_some() {
                    state.rebuild_and_publish();
                }
            }

            RoutingTableMsg::NodeConfigUpdated { node_hash, ipv6_prefix } => {
                state.nodes.insert(node_hash, NodeInfo { ipv6_prefix });
                state.rebuild_and_publish();
            }

            RoutingTableMsg::PlanUpdated { allocations } => {
                state.allocations = allocations;
                state.rebuild_and_publish();
            }
        }

        Ok(())
    }
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 3: Commit**

```bash
git add src/actors/routing.rs
git commit -m "feat: RoutingTable actor, rebuilds snapshot on any source update"
```

---

### Task 9: Network Setup (TPROXY + Local Route)

**Files:**
- Create: `aleph-gateway/src/network_setup.rs`

Runs shell commands at startup to configure the kernel for transparent proxying.
Requires root / `CAP_NET_ADMIN`.

- [ ] **Step 1: Implement network_setup.rs**

```rust
use std::process::Command;

use ipnet::Ipv6Net;

/// Set up the kernel to accept and redirect traffic for the VM prefix.
///
/// 1. `ip -6 route add local <prefix> dev lo` — accept packets for the whole prefix
/// 2. nftables TPROXY rules — redirect matching traffic to the gateway process
///
/// Requires root or CAP_NET_ADMIN + CAP_NET_RAW.
pub fn setup_tproxy(prefix: &Ipv6Net, tproxy_port: u16) -> Result<(), SetupError> {
    // Step 1: Mark the entire prefix as local
    let status = Command::new("ip")
        .args(["-6", "route", "add", "local", &prefix.to_string(), "dev", "lo"])
        .status()
        .map_err(|e| SetupError::Command("ip route".into(), e))?;

    if !status.success() {
        // May already exist from a previous run — try replace
        let status = Command::new("ip")
            .args(["-6", "route", "replace", "local", &prefix.to_string(), "dev", "lo"])
            .status()
            .map_err(|e| SetupError::Command("ip route replace".into(), e))?;
        if !status.success() {
            return Err(SetupError::CommandFailed("ip -6 route add/replace local".into()));
        }
    }

    // Step 2: Create nftables table and chain for TPROXY
    let nft_commands = format!(
        r#"
        add table ip6 aleph-gateway
        add chain ip6 aleph-gateway prerouting {{ type filter hook prerouting priority -150 ; policy accept ; }}
        flush chain ip6 aleph-gateway prerouting
        add rule ip6 aleph-gateway prerouting ip6 daddr {prefix} meta l4proto tcp tproxy to [::1]:{tproxy_port} mark set 0x1
        add rule ip6 aleph-gateway prerouting ip6 daddr {prefix} meta l4proto udp tproxy to [::1]:{tproxy_port} mark set 0x1
        "#,
    );

    let status = Command::new("nft")
        .args(["-f", "-"])
        .stdin(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            child.stdin.take().unwrap().write_all(nft_commands.as_bytes())?;
            child.wait()
        })
        .map_err(|e| SetupError::Command("nft".into(), e))?;

    if !status.success() {
        return Err(SetupError::CommandFailed("nft tproxy rules".into()));
    }

    // Step 3: Routing policy to handle marked packets
    let _ = Command::new("ip")
        .args(["-6", "rule", "add", "fwmark", "1", "lookup", "100"])
        .status();
    let _ = Command::new("ip")
        .args(["-6", "route", "add", "local", "::/0", "dev", "lo", "table", "100"])
        .status();

    tracing::info!(%prefix, tproxy_port, "TPROXY network setup complete");
    Ok(())
}

/// Clean up nftables rules and routes on shutdown.
pub fn teardown_tproxy(prefix: &Ipv6Net) {
    let _ = Command::new("nft")
        .args(["delete", "table", "ip6", "aleph-gateway"])
        .status();
    let _ = Command::new("ip")
        .args(["-6", "route", "del", "local", &prefix.to_string(), "dev", "lo"])
        .status();
    let _ = Command::new("ip")
        .args(["-6", "rule", "del", "fwmark", "1", "lookup", "100"])
        .status();
    let _ = Command::new("ip")
        .args(["-6", "route", "del", "local", "::/0", "dev", "lo", "table", "100"])
        .status();

    tracing::info!(%prefix, "TPROXY network teardown complete");
}

#[derive(Debug, thiserror::Error)]
pub enum SetupError {
    #[error("failed to run {0}: {1}")]
    Command(String, std::io::Error),
    #[error("{0} exited with non-zero status")]
    CommandFailed(String),
}
```

Add `pub mod network_setup;` to `src/lib.rs`.

- [ ] **Step 2: Verify it compiles**

```bash
cargo build
```

Note: this cannot be unit-tested without root. It will be tested manually on the
target machine during integration testing.

- [ ] **Step 3: Commit**

```bash
git add src/network_setup.rs src/lib.rs
git commit -m "feat: TPROXY network setup and teardown via ip/nft commands"
```

---

### Task 10: TCP Proxy

**Files:**
- Create: `aleph-gateway/src/proxy/mod.rs`
- Create: `aleph-gateway/src/proxy/tcp.rs`

Listens on a TPROXY-redirected socket, looks up the original destination in
the routing table, and proxies bytes bidirectionally.

- [ ] **Step 1: Create proxy/mod.rs**

```rust
pub mod tcp;
pub mod udp;

use std::sync::atomic::AtomicU64;

/// Shared proxy statistics exposed via the dashboard.
#[derive(Debug, Default)]
pub struct ProxyStats {
    pub active_tcp_connections: AtomicU64,
    pub active_udp_sessions: AtomicU64,
}
```

Add `pub mod proxy;` to `src/lib.rs`.

- [ ] **Step 2: Implement tcp.rs**

Create `src/proxy/tcp.rs`:

```rust
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::sync::Arc;

use arc_swap::ArcSwap;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;

use super::ProxyStats;
use crate::routing_table::RoutingSnapshot;

/// Run the TCP transparent proxy loop.
///
/// Binds an IP_TRANSPARENT socket on `[::]:listen_port`, accepts connections
/// whose original destination was in the gateway prefix (redirected by TPROXY),
/// looks up the backend in the routing table, and proxies bytes bidirectionally.
pub async fn tcp_proxy_loop(
    listen_port: u16,
    routing: Arc<ArcSwap<RoutingSnapshot>>,
    stats: Arc<ProxyStats>,
) -> std::io::Result<()> {
    let socket = create_transparent_tcp_socket(listen_port)?;
    let listener = tokio::net::TcpListener::from_std(socket.into())?;

    tracing::info!(port = listen_port, "TCP proxy listening");

    loop {
        let (mut client_stream, client_addr) = listener.accept().await?;

        // The original destination is the local address of the accepted socket
        // (TPROXY preserves this).
        let orig_dest = client_stream.local_addr()?;

        let dest_ipv6 = match orig_dest {
            SocketAddr::V6(v6) => *v6.ip(),
            _ => continue,
        };
        let dest_port = orig_dest.port();

        let snapshot = routing.load();
        let Some(&backend_addr) = snapshot.lookup(&dest_ipv6) else {
            tracing::debug!(dest = %dest_ipv6, "no route, dropping connection");
            continue;
        };

        let stats = stats.clone();
        tokio::spawn(async move {
            stats.active_tcp_connections.fetch_add(1, Ordering::Relaxed);

            let upstream_addr = SocketAddrV6::new(backend_addr, dest_port, 0, 0);
            match TcpStream::connect(SocketAddr::V6(upstream_addr)).await {
                Ok(mut upstream_stream) => {
                    let result = copy_bidirectional(&mut client_stream, &mut upstream_stream).await;
                    if let Err(e) = result {
                        tracing::debug!(
                            client = %client_addr,
                            dest = %dest_ipv6,
                            backend = %backend_addr,
                            "proxy error: {e}"
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        backend = %backend_addr,
                        port = dest_port,
                        "upstream connect failed: {e}"
                    );
                }
            }

            stats.active_tcp_connections.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn create_transparent_tcp_socket(port: u16) -> std::io::Result<std::net::TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent(true)?;
    socket.set_nonblocking(true)?;

    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    Ok(socket.into())
}
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 4: Commit**

```bash
git add src/proxy/ src/lib.rs
git commit -m "feat: TCP transparent proxy with IP_TRANSPARENT + copy_bidirectional"
```

---

### Task 11: UDP Proxy

**Files:**
- Create: `aleph-gateway/src/proxy/udp.rs`

UDP transparent proxy with a session table for return traffic routing.

- [ ] **Step 1: Implement udp.rs**

Create `src/proxy/udp.rs`:

```rust
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

use super::ProxyStats;
use crate::routing_table::RoutingSnapshot;

/// A UDP session tracks the mapping between a client and an upstream socket.
struct UdpSession {
    /// Socket used to communicate with the upstream (node-local VM).
    upstream_socket: Arc<UdpSocket>,
    last_activity: Instant,
}

/// Key for the session table: (client_addr, original_dest_addr).
type SessionKey = (SocketAddr, SocketAddr);

/// Run the UDP transparent proxy loop.
///
/// Receives datagrams on an IP_TRANSPARENT socket, reads the original destination
/// from ancillary data, looks up the backend, and forwards. Return traffic is
/// routed back through the session table.
pub async fn udp_proxy_loop(
    listen_port: u16,
    routing: Arc<ArcSwap<RoutingSnapshot>>,
    stats: Arc<ProxyStats>,
    session_timeout: Duration,
) -> std::io::Result<()> {
    let socket = create_transparent_udp_socket(listen_port)?;
    let recv_socket = Arc::new(UdpSocket::from_std(socket)?);
    let sessions: Arc<Mutex<HashMap<SessionKey, UdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn session cleanup task
    let sessions_cleanup = sessions.clone();
    let stats_cleanup = stats.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(session_timeout).await;
            let mut table = sessions_cleanup.lock().await;
            let before = table.len();
            table.retain(|_, session| session.last_activity.elapsed() < session_timeout);
            let removed = before - table.len();
            if removed > 0 {
                stats_cleanup
                    .active_udp_sessions
                    .fetch_sub(removed as u64, Ordering::Relaxed);
                tracing::debug!(removed, remaining = table.len(), "cleaned expired UDP sessions");
            }
        }
    });

    tracing::info!(port = listen_port, "UDP proxy listening");

    let mut buf = vec![0u8; 65535];
    loop {
        let (len, client_addr) = recv_socket.recv_from(&mut buf).await?;

        // For TPROXY UDP, the local address of the socket is the original destination.
        // We need to get it from the socket's local addr after recvmsg.
        // With TPROXY, each received packet has the original dest as the local addr.
        let orig_dest = recv_socket.local_addr()?;

        let dest_ipv6 = match orig_dest {
            SocketAddr::V6(v6) => *v6.ip(),
            _ => continue,
        };
        let dest_port = orig_dest.port();

        let snapshot = routing.load();
        let Some(&backend_addr) = snapshot.lookup(&dest_ipv6) else {
            tracing::debug!(dest = %dest_ipv6, "no UDP route, dropping datagram");
            continue;
        };

        let upstream_target = SocketAddr::V6(SocketAddrV6::new(backend_addr, dest_port, 0, 0));
        let session_key = (client_addr, orig_dest);

        let mut table = sessions.lock().await;
        let session = if let Some(session) = table.get_mut(&session_key) {
            session.last_activity = Instant::now();
            session
        } else {
            // Create new upstream socket for this session
            let upstream_sock = UdpSocket::bind("[::]:0").await?;
            let upstream_sock = Arc::new(upstream_sock);

            // Spawn return-traffic forwarder
            let ret_sock = upstream_sock.clone();
            let recv_sock = recv_socket.clone();
            let client = client_addr;
            tokio::spawn(async move {
                let mut ret_buf = vec![0u8; 65535];
                loop {
                    match ret_sock.recv_from(&mut ret_buf).await {
                        Ok((len, _from)) => {
                            if let Err(e) = recv_sock.send_to(&ret_buf[..len], client).await {
                                tracing::debug!(client = %client, "failed to send return UDP: {e}");
                                break;
                            }
                        }
                        Err(e) => {
                            tracing::debug!("upstream UDP recv error: {e}");
                            break;
                        }
                    }
                }
            });

            stats.active_udp_sessions.fetch_add(1, Ordering::Relaxed);
            table.entry(session_key).or_insert(UdpSession {
                upstream_socket: upstream_sock,
                last_activity: Instant::now(),
            })
        };

        if let Err(e) = session.upstream_socket.send_to(&buf[..len], upstream_target).await {
            tracing::debug!(target = %upstream_target, "failed to forward UDP: {e}");
        }
    }
}

fn create_transparent_udp_socket(port: u16) -> std::io::Result<std::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_ip_transparent(true)?;
    socket.set_nonblocking(true)?;

    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0);
    socket.bind(&addr.into())?;

    Ok(socket.into())
}
```

- [ ] **Step 2: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 3: Commit**

```bash
git add src/proxy/udp.rs
git commit -m "feat: UDP transparent proxy with session table and idle cleanup"
```

---

### Task 12: Dashboard

**Files:**
- Create: `aleph-gateway/src/dashboard.rs`

Minimal actix-web endpoint exposing gateway status.

- [ ] **Step 1: Implement dashboard.rs**

Create `src/dashboard.rs`:

```rust
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use actix_web::{web, App, HttpResponse, HttpServer};
use arc_swap::ArcSwap;
use serde::Serialize;

use crate::proxy::ProxyStats;
use crate::routing_table::RoutingSnapshot;

#[derive(Serialize)]
struct StatusResponse {
    vm_count: usize,
    active_tcp_connections: u64,
    active_udp_sessions: u64,
}

struct DashboardState {
    routing: Arc<ArcSwap<RoutingSnapshot>>,
    stats: Arc<ProxyStats>,
}

async fn status(data: web::Data<DashboardState>) -> HttpResponse {
    let snapshot = data.routing.load();
    HttpResponse::Ok().json(StatusResponse {
        vm_count: snapshot.len(),
        active_tcp_connections: data.stats.active_tcp_connections.load(Ordering::Relaxed),
        active_udp_sessions: data.stats.active_udp_sessions.load(Ordering::Relaxed),
    })
}

/// Start the actix-web dashboard server.
pub async fn run_dashboard(
    listen: SocketAddr,
    routing: Arc<ArcSwap<RoutingSnapshot>>,
    stats: Arc<ProxyStats>,
) -> std::io::Result<()> {
    tracing::info!(%listen, "dashboard listening");

    let state = web::Data::new(DashboardState { routing, stats });

    HttpServer::new(move || {
        App::new()
            .app_data(state.clone())
            .route("/status", web::get().to(status))
    })
    .bind(listen)?
    .run()
    .await
}
```

Add `pub mod dashboard;` to `src/lib.rs`.

- [ ] **Step 2: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 3: Commit**

```bash
git add src/dashboard.rs src/lib.rs
git commit -m "feat: actix-web dashboard with /status endpoint"
```

---

### Task 13: Main Entrypoint — Wire Everything Together

**Files:**
- Modify: `aleph-gateway/src/main.rs`

Wire actors, start proxy loops, start dashboard, handle shutdown.

- [ ] **Step 1: Implement main.rs**

Replace `src/main.rs`:

```rust
use std::sync::Arc;

use aleph_sdk::client::AlephClient;
use aleph_types::chain::Address;
use arc_swap::ArcSwap;
use clap::Parser;
use ractor::Actor;

use aleph_gateway::actors::corechannel::{CorechannelWatcher, CorechannelWatcherArgs};
use aleph_gateway::actors::node_config::{NodeConfigMonitor, NodeConfigMonitorArgs};
use aleph_gateway::actors::routing::{RoutingTableActor, RoutingTableArgs, RoutingTableMsg};
use aleph_gateway::actors::scheduler::{SchedulerPoller, SchedulerPollerArgs};
use aleph_gateway::config::CliArgs;
use aleph_gateway::dashboard::run_dashboard;
use aleph_gateway::network_setup::{setup_tproxy, teardown_tproxy};
use aleph_gateway::proxy::tcp::tcp_proxy_loop;
use aleph_gateway::proxy::udp::udp_proxy_loop;
use aleph_gateway::proxy::ProxyStats;
use aleph_gateway::routing_table::RoutingSnapshot;

const TPROXY_PORT: u16 = 50000;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "aleph_gateway=info".into()),
        )
        .init();

    let args = CliArgs::parse();
    tracing::info!(prefix = %args.gateway_prefix, "aleph-gateway starting");

    // Set up TPROXY network rules
    setup_tproxy(&args.gateway_prefix, TPROXY_PORT)?;

    // Shared state
    let empty_snapshot = RoutingSnapshot::rebuild(&args.gateway_prefix, &[], &Default::default());
    let routing_snapshot = Arc::new(ArcSwap::from_pointee(empty_snapshot));
    let proxy_stats = Arc::new(ProxyStats::default());

    // Create Aleph SDK client
    let aleph_client = AlephClient::new(&args.aleph_api_server);
    let corechannel_address: Address = args.corechannel_address.parse()
        .expect("invalid corechannel address");

    // Spawn actors (order matters due to dependencies)
    // 1. NodeConfigMonitor (no deps on other actors except RoutingTable)
    // 2. RoutingTable (depends on NodeConfigMonitor)
    // 3. CorechannelWatcher (depends on RoutingTable)
    // 4. SchedulerPoller (depends on RoutingTable)

    // We need RoutingTable's ActorRef for the other actors, but RoutingTable needs
    // NodeConfigMonitor's ActorRef. Solve with a two-phase approach:
    // spawn NodeConfigMonitor with a placeholder, then wire it.

    // Actually, ractor actors receive their deps via Args at pre_start.
    // We need to spawn RoutingTable and NodeConfigMonitor with circular refs.
    // Solution: spawn RoutingTable first, then NodeConfigMonitor with the routing ref,
    // then update RoutingTable's state with the node_config ref.
    // Simpler: have RoutingTable create and own NodeConfigMonitor internally.
    // But the spec has them as separate actors. Use ractor's ActorRef cloning.

    // Spawn a "dummy" NodeConfigMonitor first, then RoutingTable, then replace.
    // OR: just spawn them in order using ractor's spawn pattern.

    // Simplest approach: RoutingTable takes NodeConfigMonitor ref in Args.
    // NodeConfigMonitor takes RoutingTable ref in Args.
    // This is a circular dependency. Break it by having RoutingTable spawn
    // NodeConfigMonitor itself.

    // For now: spawn RoutingTable with a channel-based approach.
    // Actually the simplest: spawn NodeConfigMonitor first with a routing table ref
    // that we'll create from ractor::Actor::spawn. But we can't get the routing ref
    // before spawning it.

    // Use ractor's pattern: spawn with a late-binding message.
    // The scheduler does this: cast(Msg::SetXxx) after all actors are spawned.

    // Let's use a simpler flat approach:
    // 1. Spawn RoutingTable (without node_config_monitor ref — use Option)
    // 2. Spawn NodeConfigMonitor (with routing_table ref)
    // 3. Send RoutingTable a SetNodeConfigMonitor message

    // This requires adding a SetNodeConfigMonitor variant to RoutingTableMsg.
    // But to keep the plan simpler, let's have RoutingTable spawn NodeConfigMonitor
    // in its own pre_start. This is what the scheduler does with some actors.

    // For this plan, we'll keep it simple: RoutingTable creates NodeConfigMonitor.
    // This is an implementation detail; the logical actor boundary is preserved.

    // TODO for implementer: adjust RoutingTableArgs to include node_config params
    // and have RoutingTable spawn NodeConfigMonitor in pre_start. Or use the
    // SetXxx message pattern from the scheduler.

    // Spawn RoutingTable
    let (routing_ref, routing_handle) = Actor::spawn(
        Some("routing-table".to_string()),
        RoutingTableActor,
        RoutingTableArgs {
            gateway_prefix: args.gateway_prefix,
            snapshot: routing_snapshot.clone(),
            node_config_refresh: args.node_config_refresh(),
        },
    )
    .await?;

    // Spawn CorechannelWatcher
    let (_cc_ref, cc_handle) = Actor::spawn(
        Some("corechannel-watcher".to_string()),
        CorechannelWatcher::new(),
        CorechannelWatcherArgs {
            client: aleph_client.clone(),
            corechannel_address,
            poll_interval: std::time::Duration::from_secs(3600),
            routing_table: routing_ref.clone(),
        },
    )
    .await?;

    // Spawn SchedulerPoller
    let (_sched_ref, sched_handle) = Actor::spawn(
        Some("scheduler-poller".to_string()),
        SchedulerPoller,
        SchedulerPollerArgs {
            scheduler_url: args.scheduler_url.clone(),
            poll_interval: args.plan_poll_interval(),
            routing_table: routing_ref.clone(),
        },
    )
    .await?;

    // Start proxy loops
    let routing_tcp = routing_snapshot.clone();
    let stats_tcp = proxy_stats.clone();
    let tcp_handle = tokio::spawn(async move {
        if let Err(e) = tcp_proxy_loop(TPROXY_PORT, routing_tcp, stats_tcp).await {
            tracing::error!("TCP proxy error: {e}");
        }
    });

    let routing_udp = routing_snapshot.clone();
    let stats_udp = proxy_stats.clone();
    let udp_timeout = args.udp_session_timeout();
    let udp_handle = tokio::spawn(async move {
        if let Err(e) = udp_proxy_loop(TPROXY_PORT, routing_udp, stats_udp, udp_timeout).await {
            tracing::error!("UDP proxy error: {e}");
        }
    });

    // Start dashboard
    let dashboard_handle = tokio::spawn(run_dashboard(
        args.dashboard_listen,
        routing_snapshot.clone(),
        proxy_stats.clone(),
    ));

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    tracing::info!("shutting down");

    // Teardown
    teardown_tproxy(&args.gateway_prefix);

    Ok(())
}
```

Note: the circular dependency between `RoutingTable` and `NodeConfigMonitor` actors
needs resolution during implementation. Two clean approaches:

**Option A:** `RoutingTable` spawns `NodeConfigMonitor` in its `pre_start()` and
holds the ref internally. Adjust `RoutingTableArgs` to include node_config params
(`refresh_interval`) instead of an `ActorRef<NodeConfigMonitorMsg>`.

**Option B:** Use the scheduler's `SetXxx` message pattern: spawn both actors,
then send a `RoutingTableMsg::SetNodeConfigMonitor(ActorRef<NodeConfigMonitorMsg>)`
to wire them together. Add that variant to `RoutingTableMsg` and handle it by
storing the ref in state.

Option A is simpler; prefer it.

- [ ] **Step 2: Adjust RoutingTable actor for Option A**

Update `src/actors/routing.rs` — change `RoutingTableArgs`:

```rust
pub struct RoutingTableArgs {
    pub gateway_prefix: Ipv6Net,
    pub snapshot: Arc<ArcSwap<RoutingSnapshot>>,
    pub node_config_refresh: Duration,
}
```

In `pre_start`, spawn NodeConfigMonitor:

```rust
async fn pre_start(
    &self,
    myself: ActorRef<Self::Msg>,
    args: Self::Arguments,
) -> Result<Self::State, ActorProcessingErr> {
    let (node_config_ref, _) = Actor::spawn(
        Some("node-config-monitor".to_string()),
        NodeConfigMonitor,
        NodeConfigMonitorArgs {
            refresh_interval: args.node_config_refresh,
            routing_table: myself.clone(),
        },
    )
    .await?;

    Ok(RoutingTableState {
        gateway_prefix: args.gateway_prefix,
        snapshot: args.snapshot,
        node_config_monitor: node_config_ref,
        nodes: HashMap::new(),
        allocations: Vec::new(),
    })
}
```

- [ ] **Step 3: Verify it compiles**

```bash
cargo build
```

- [ ] **Step 4: Commit**

```bash
git add src/main.rs src/actors/routing.rs
git commit -m "feat: main entrypoint, wire actors + proxy + dashboard + shutdown"
```

---

### Task 14: Integration Smoke Test

**Files:** none (manual testing)

Run the gateway on a test machine with appropriate permissions.

- [ ] **Step 1: Build release binary**

```bash
cargo build --release
```

- [ ] **Step 2: Run with a test prefix**

```bash
sudo RUST_LOG=aleph_gateway=debug ./target/release/aleph-gateway \
  --gateway-prefix "2001:db8:test::/64" \
  --scheduler-url "https://scheduler.api.aleph.cloud" \
  --dashboard-listen "[::1]:8080"
```

- [ ] **Step 3: Verify dashboard responds**

```bash
curl -s http://[::1]:8080/status | jq .
```

Expected: `{"vm_count": <N>, "active_tcp_connections": 0, "active_udp_sessions": 0}`

- [ ] **Step 4: Verify routing table is populated**

Check logs for:
- `corechannel aggregate update via WebSocket` or `Fetching core channel aggregate`
- `plan updated` with `vm_count > 0`
- `fetched node IPv6 prefix` for discovered nodes
- `routing table rebuilt` with `vm_count > 0`

- [ ] **Step 5: Verify TPROXY rules**

```bash
sudo nft list table ip6 aleph-gateway
sudo ip -6 route show table local | grep "2001:db8:test"
```

- [ ] **Step 6: Commit any fixes**

```bash
git add -A
git commit -m "fix: integration test fixes"
```
