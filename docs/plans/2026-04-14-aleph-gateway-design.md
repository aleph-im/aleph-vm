# aleph-gateway Design — V1

## Overview

A standalone Rust service that owns a shared IPv6 prefix and proxies TCP+UDP
traffic to the CRN node hosting each VM. The gateway is a stateless L4 proxy —
it does not inspect payload contents. VMs handle their own TLS.

```
Client --> [IPv6 prefix routed to gateway] --> aleph-gateway (L4 proxy) --> CRN node --> VM
```

Multiple gateways can share the same IPv6 prefix (BGP anycast in the future).
Each VM gets a single, stable, globally-unique IPv6 address regardless of which
node hosts it or which gateway routes the traffic.

## IPv6 Addressing

### Deterministic derivation

The gateway reuses the same algorithm as aleph-vm's `StaticIPv6Allocator`, rooted
in the gateway's shared prefix instead of each node's local prefix. The prefix
must be a /64 or /56 (same constraint as the existing allocator):

```
Gateway prefix (64 bits) + VM type (16 bits) + Hash[0:11] (44 bits) + subnet (4 bits) = /124
```

VM type prefixes: `1` = microvm, `2` = persistent_program, `3` = instance.

Example with gateway prefix `2001:db8:aleph:0::/64`, instance VM hash `8920215b2e96...`:

```
2001:db8:aleph:0000:0003:8920:215b:2e90/124
|-- gateway prefix ---|type|--- hash ---|/124
```

The VM's routable address is `[1]` in the /124 subnet (i.e. `...2e91`).

### No node-side changes

The gateway is an L4 proxy: it terminates the client connection and opens a new
one to the node. The destination on the node leg is the VM's existing node-local
IPv6 (derived from the node's own prefix + the same VM hash). Nodes are unaware
of the gateway. No DNAT, no configuration changes, no asymmetric routing.

The gateway can derive the node-local VM IPv6 because:
1. It knows the node's IPv6 prefix (from `/status/config`).
2. The derivation algorithm is deterministic given prefix + VM hash.

## Routing Table

### Data structure

The hot path is a `HashMap<Ipv6Addr, Ipv6Addr>` mapping each VM's gateway IPv6
to its node-local IPv6. One hash lookup per incoming packet.

### Data sources

| Source | Provides | Method | Refresh |
|--------|----------|--------|---------|
| Corechannel aggregate | `node_hash -> CRN URL` | WebSocket subscription (same pattern as scheduler's `NodeRegistryWatcher` via `aleph-sdk`) + 1h polling fallback | Real-time via WS |
| CRN `/status/config` | `node_hash -> IPv6 prefix` | HTTP GET per node, cached | On first discovery, then every few hours |
| Scheduler `/api/v0/plan` | `vm_hash -> node_hash` | HTTP polling (websocket upgrade later) | ~30s |

### Corechannel aggregate

Fetched via the Aleph API as a `CoreChannelAggregate`:

```
GET /api/v0/aggregates/{corechannel_address}.json?keys=corechannel
```

The `corechannel.resource_nodes` list provides `CrnInfo` entries with:
- `hash`: the node's unique identifier (`NodeHash`)
- `address`: the CRN's base URL (e.g. `https://crn1.example.com`)
- `status`: `Linked { parent }` (staked) or `Waiting` (unstaked)

Real-time updates arrive via WebSocket subscription to AGGREGATE-type messages
filtered by the corechannel owner address, using `aleph-sdk`'s
`subscribe_to_messages()`.

### CRN `/status/config`

Returns a JSON object including:
```json
{
  "networking": {
    "IPV6_ADDRESS_POOL": "<CIDR prefix>",
    "IPV6_ALLOCATION_POLICY": "static",
    "IPV6_SUBNET_PREFIX": 124
  }
}
```

The `IPV6_ADDRESS_POOL` field gives the node's IPv6 prefix, which the gateway
uses to derive node-local VM addresses.

### Routing table rebuild

On any source update:
1. For each VM in the scheduler plan, look up its `node_hash`.
2. Look up the node's IPv6 prefix from cache.
3. Derive the VM's gateway IPv6: `gateway_prefix + vm_hash`.
4. Derive the VM's node-local IPv6: `node_prefix + vm_hash`.
5. Insert `gateway_ipv6 -> node_local_ipv6` into the map.

## Actor Architecture (ractor)

Four actors, matching the scheduler's actor-based patterns:

| Actor | Responsibility | Messages emitted |
|-------|---------------|-----------------|
| `CorechannelWatcher` | WebSocket subscription to corechannel aggregate + 1h polling fallback | `NodeAdded { hash, url }`, `NodeRemoved { hash }` |
| `SchedulerPoller` | Polls `/api/v0/plan` on a configurable interval | `PlanUpdated { vm_hash -> node_hash }` |
| `NodeConfigMonitor` | Fetches `/status/config` per node, caches IPv6 prefix, periodic refresh | `NodeConfigUpdated { hash, ipv6_prefix }` |
| `RoutingTable` | Receives messages from the above three, rebuilds the `HashMap<Ipv6Addr, Ipv6Addr>` | Exposes read handle to proxy data plane |

The `RoutingTable` actor owns the authoritative map. The proxy data plane reads
from a shared snapshot (e.g. `Arc<ArcSwap<HashMap>>`) so lookups are lock-free.

## L4 Proxy Data Plane

### Network setup (one-time, at startup)

1. `ip -6 route add local <prefix> dev lo` — marks the entire VM prefix as local
   so the kernel accepts packets for any address in the range.
2. nftables TPROXY rule redirects all TCP+UDP traffic for the prefix to the
   gateway process.
3. These rules exclude the gateway's own management addresses (different prefix).

### TCP proxy

1. Accept connection on `IP_TRANSPARENT` socket (via `socket2` crate).
2. Read original destination from socket address.
3. Look up `gateway_ipv6 -> node_local_ipv6` in the routing table snapshot.
4. Open upstream connection to `node_local_ipv6:same_port`.
5. Bidirectional byte copy (`tokio::io::copy_bidirectional`).
6. If the VM is not in the routing table, drop the connection immediately.

### UDP proxy

1. Receive datagram on `IP_TRANSPARENT` socket.
2. Read original destination via `IPV6_RECVORIGDSTADDR` ancillary data.
3. Look up destination, forward datagram to `node_local_ipv6:same_port`.
4. Maintain a session table for return UDP traffic (keyed by client
   addr:port + destination addr:port), with a configurable idle timeout.

### What the gateway does NOT do (v1)

- No TLS inspection or termination.
- No payload inspection.
- No rate limiting or filtering.
- No health checking of upstream VMs. If a node is down, TCP connect fails
  and the client sees a connection error.

## Management and Operations

### Gateway's own addresses

The gateway machine has its own IPv6 (and IPv4) for management, from a different
prefix than the VM range. SSH, the dashboard, and all management traffic use
these addresses. The TPROXY rules only capture traffic for the VM prefix.

### Dashboard

A minimal HTTP endpoint served by actix-web on a management address/port
(e.g. `[::1]:8080`), exposing:

- Current routing table: VM count, node count.
- Data source health: WebSocket connected? Last successful plan poll timestamp?
- Basic traffic stats: active TCP connections, UDP sessions.

### Logging

Structured logging via the `tracing` crate:
- Startup, routing table changes, data source errors at info level.
- No per-connection logging by default (too noisy).
- Per-connection logging available at debug level.

### Configuration

| Setting | Example | Description |
|---------|---------|-------------|
| `gateway_prefix` | `2001:db8:aleph:0::/64` | Shared VM IPv6 prefix (/56 or /64) |
| `scheduler_url` | `https://scheduler.api.aleph.cloud` | Scheduler API base URL |
| `aleph_api_server` | `https://api3.aleph.im` | Aleph API for corechannel aggregate |
| `corechannel_address` | `0xa1B3bb7d2332383D96b7796B908fB7f7F3c2Be10` | Corechannel aggregate owner |
| `plan_poll_interval` | `30s` | Scheduler plan polling interval |
| `node_config_refresh` | `4h` | CRN `/status/config` refresh interval |
| `dashboard_listen` | `[::1]:8080` | Management dashboard bind address |
| `udp_session_timeout` | `60s` | Idle timeout for UDP session entries |

## Project Structure

Single-crate Rust binary in its own repository.

```
aleph-gateway/
  Cargo.toml
  src/
    main.rs                -- CLI parsing, startup, TPROXY/nftables setup
    config.rs              -- Configuration struct + loading
    routing_table.rs       -- HashMap<Ipv6Addr, Ipv6Addr> + rebuild logic
    ipv6.rs                -- Deterministic IPv6 derivation (port of StaticIPv6Allocator)
    actors/
      mod.rs
      corechannel.rs       -- CorechannelWatcher actor
      scheduler.rs         -- SchedulerPoller actor
      node_config.rs       -- NodeConfigMonitor actor
      routing.rs           -- RoutingTable actor
    proxy/
      mod.rs
      tcp.rs               -- TCP transparent proxy (tokio + IP_TRANSPARENT)
      udp.rs               -- UDP proxy + session table
    dashboard.rs           -- actix-web status/metrics endpoint
```

### Dependencies

| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime |
| `ractor` | Actor framework (same as scheduler) |
| `aleph-sdk` | Corechannel WS subscription, aggregate models |
| `socket2` | `IP_TRANSPARENT`, `IPV6_RECVORIGDSTADDR` |
| `actix-web` | Dashboard HTTP endpoint |
| `reqwest` | Polling scheduler + node `/status/config` |
| `clap` | CLI argument parsing |
| `tracing` | Structured logging |
| `serde` | Config + API response deserialization |
| `arc-swap` | Lock-free read access to routing table snapshot |

### Shared code

- `aleph-sdk`: reuse `CoreChannelAggregate`, `CrnInfo`, WebSocket client.
- IPv6 derivation is ported from Python's `StaticIPv6Allocator` (~30 lines).
  Both implementations are tested against the same known test vectors.
- The `CorechannelWatcher` actor follows the scheduler's `NodeRegistryWatcher`
  pattern. If the two diverge, consider extracting into a shared component
  in `aleph-sdk`.
