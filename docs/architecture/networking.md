# Networking

> Verified against: b2b31381 (2026-08-14)

## What this covers

How a CRN node wires a VM's tap device to the network: IPv4/IPv6 address
derivation (static pool math and, for IPv6, an optional dynamic scheme),
the nftables ruleset the supervisor builds and maintains, the port-forward
store and its healing behavior, the NDP proxy for routed IPv6, the per-VM
DHCP server that exists only for SEV-SNP measured guests, and the host
forwarding sysctls that make any of this reachable. Everything here is the
Rust supervisor daemon (`rust/crates/supervisor-daemon`), the mechanism
side of the agent/supervisor split described in
[`process-model.md`](process-model.md); adoption and boot reconcile
mechanics (which recreate this same state on restart) are also covered
there and only summarized here where the networking specifics differ.
Policy for *which* ports get forwarded belongs to the agent
(`src/aleph/vm/agent/run.py`) and is described below only at the boundary
where it hands off to the hypervisor mechanism.

## The model

### Tap assignment and address derivation

Every VM gets one `vmtap{vm_index}` device, where `vm_index` is a small
integer the daemon allocates and never reuses while the VM is tracked
(`WorldView::unique_vm_index` in `rust/crates/supervisor-daemon/src/world.rs`,
scanning from `START_ID_INDEX`, default 4, up to 255*255, skipping indices
already held by a live entry or reserved by a hidden/failed-reattach VM). A
negative `vm_index` on an adopted config is treated as a hard IP-derivation
failure that hides the VM rather than serving it the pool's last subnet
(the divergence from Python's negative list indexing: silently serving the
last subnet on a corrupt index is a list-indexing accident, and two VMs
could then share a subnet).

`derive_tap_assignment` (`rust/crates/supervisor-daemon/src/world.rs`) turns
`(vm_index, vm_hash, vm_type)` into an IPv4 pair and an IPv6 pair; `TapAssignment`
(`rust/crates/supervisor-daemon/src/tap.rs`) wraps them with the device name and
the CIDR-formatted host/guest address strings the tap creation and
cloud-init paths consume.

**IPv4** is always static pool math (`ipv4_assignment` in `world.rs`): the
pool (`IPV4_ADDRESS_POOL`, default `172.16.0.0/12`) is split into
`/{IPV4_NETWORK_PREFIX_LENGTH}` subnets (default `/24`, so 4096 subnets),
and `vm_index` selects the subnet at that position. Inside the subnet, the
gateway (host side) is network+1 and the guest address is network+2; both
must fit inside the subnet, or derivation fails.

**IPv6** has two policies, selected by `IPV6_ALLOCATION_POLICY`
(`Ipv6AllocationPolicy::Static` is the default):

- **Static** (`ipv6_static_assignment`): the pool (`IPV6_ADDRESS_POOL`,
  default `fc00:1:2:3::/64`) must be a `/56` or `/64`. The VM's `/124`
  subnet is built from the pool's first four hextets, a fifth hextet that
  encodes the VM type (`VmType::prefix()`: `0x1` for microvms, `0x3` for
  instances), and three more hextets sliced out of the VM hash (bytes
  `0..4`, `4..8`, and `8..11` with a trailing zero nibble appended) parsed
  as hex. Guest = network+1, gateway = the network address itself. Because
  the address is a pure function of `vm_index`-independent inputs (VM type
  plus hash), it is reproducible without any allocator state, which is why
  it is the default: the CRN and the publisher can agree on the exact
  address before boot, which SEV-SNP's measured-image requirement (no
  per-VM data in the image or kernel cmdline) depends on.
- **Dynamic** (`ipv6_dynamic_assignment`): the ordinal-th
  `/{IPV6_SUBNET_PREFIX}` subnet of the pool (default prefix 124), ordinal 0
  reserved for the host. `WorldView::ipv6_dynamic_ordinal` is seeded at boot
  from every adopted running VM (sorted config order) and advances by one on
  every subsequent derivation, so it behaves like the Python generator: it
  never rewinds within a daemon's lifetime, and a restart replays the same
  count from the same adopted set before handing out anything new.

Both parsers (`parse_ipv4_cidr`/`parse_ipv6_cidr`) reject a pool with host
bits set and a prefix that does not actually subnet the pool, matching
Python's strict `IPv{4,6}Network` construction.

### The kernel edge: tap creation

`TapBackend` (`rust/crates/supervisor-daemon/src/tap.rs`) is the seam over
`ip(8)`: create the tap, add both host addresses, bring the link up, and
tear it down again. It tolerates the same failure classes Python's pyroute2
binding tolerated as warnings rather than errors: `EEXIST` on an
already-existing device or address, and `EBUSY` on tap creation ("is
another process using it?"); everything else propagates. A missing device
on delete is a warning, not a failure: deletion is idempotent by design.

### nftables ruleset structure

`rust/crates/supervisor-daemon/src/nft.rs` operates on `serde_json::Value`,
the same dialect `nft -j` speaks, deliberately untyped (typing the nftables
JSON schema would only invite drift from the Python builders it ports
rule-for-rule from `src/aleph/vm/network/firewall.py`). Every mutation is
computed as a pure function from a fetched ruleset snapshot to a batch of
`{"add": ...}`/`{"delete": ...}` commands, deduplicated against what is
already present (`add_entities_if_not_present`, an `is_superset` match on
each entity's own keys against the fetched entry, extra attributes like
handles ignored); a thin `NftExecutor` trait applies the batch at the edge.

**Base wiring** (`initialize_ipv4_commands`/`initialize_ipv6_commands`,
run once at daemon startup and again inside `RecreateNetwork`): the daemon
finds (or creates, on a bare host) the base `nat`-type postrouting chain,
the `filter` forward chain, and the `nat` prerouting chain, then hangs
three chains off them, all named with the configurable
`NFTABLES_CHAIN_PREFIX` (default `aleph`):

- `{prefix}-supervisor-nat`, jumped to from the base postrouting chain.
- `{prefix}-supervisor-filter`, jumped to from the base forward chain, with
  one rule accepting established/related connection-tracking state. The
  IPv6 phase (only run when `IPV6_FORWARDING_ENABLED`) builds the same
  chain and rule off the `ip6 filter FORWARD` base chain, but has no NAT
  counterpart: IPv6 addresses are routed, never masqueraded.
- `{prefix}-supervisor-prerouting`, jumped to from the base prerouting
  chain; this is where per-VM port-redirect DNAT rules live.

**Per-VM chains** (`setup_vm_commands`, called on every create/start/boot
reconcile/RecreateNetwork pass for a VM with networking enabled): two
chains named by `vm_index`, `{prefix}-vm-nat-{vm_index}` (jumped from
`{prefix}-supervisor-nat`) holding one IPv4 masquerade rule matched on
`iifname == vmtap{N}` and `oifname == <uplink>`, and
`{prefix}-vm-filter-{vm_index}` (jumped from `{prefix}-supervisor-filter`,
and separately from the IPv6 supervisor-filter chain when IPv6 forwarding
is on) holding the matching forward-accept rule for both families, matched
on tap iifname and unconditional otherwise (`forward_rule_entities`). Port
redirects (`port_redirect_entities`) add two more rules per (host_port,
vm_port, protocol), both matched on **uplink** iifname rather than the
tap's: a DNAT rule in `{prefix}-supervisor-prerouting` matched on uplink
iifname and destination port, and a second forward-accept rule (distinct
from the general per-VM one above) in the VM's own filter chain matched on
uplink iifname and the *guest*-side port. DNAT is IPv4-only; there is no
IPv6 port-redirect path since IPv6 addresses are directly reachable.

Chain and rule removal (`remove_chain_commands`, used by `DeleteVm`/`StopVm`
teardown and by `RecreateNetwork`'s flush) deletes every jump rule pointing
at a chain before deleting the chain itself, refetching the ruleset between
steps like the Python loop it replaces.

**Two different reconciliation modes exist and must not be confused:**
boot reconcile (`reconcile_boot`, see `process-model.md`) and every
create/start path are strictly **create-if-absent**: a flush here would
drop live guest connections on a host being adopted with VMs already
running. `RecreateNetwork` (the operator-facing RPC, `recreate_network` in
`rust/crates/supervisor-daemon/src/lifecycle.rs`) is the opposite: it
explicitly flushes every aleph-prefixed chain, reinitializes the base
ruleset, and rebuilds the per-VM chains and persisted port redirects of
every running VM from scratch. Before filtering to running VMs it also
rederives any missing `ipv4`/`ipv6` assignment from `vm_index`/`vm_hash`
for entries whose IP was never populated (e.g. adopted during a D-Bus
outage), so a node that booted degraded can heal its chains through this
one RPC rather than staying permanently unnetworked. A failed per-chain
removal is excluded from the reported `removed_chains` (logged, not fatal);
a failed per-VM chain rebuild lands in `failed_vms` and that VM's DNAT
rules are not reapplied that pass.

Tap and chain teardown is gated on the controller config's
`interface_name` being non-empty (`networking_enabled` in `lifecycle.rs`),
not on the spec's `internet_access` flag directly: gating on the latter
would leak an `internet_access=false` VM's tap device and nftables chains
for the life of the daemon, since such a VM never gets an `interface_name`
to begin with.

### Port forwards: agent policy, hypervisor mechanism, sqlite persistence

The split is total. The **agent** (`resolve_port_forwards` /
`reconcile_port_forwards` in `src/aleph/vm/agent/run.py`) reads the user's
`port-forwarding` aggregate, always adds port 22/tcp regardless of what the
aggregate says (`ports_requests.setdefault(22, {"tcp": True, "udp": False})`),
diffs the desired set against what `list_port_forwards` reports, and issues
`add_port_forward`/`remove_port_forward`. It never calls anything that
mutates nftables state directly, and never recreates persisted redirects
itself; the **hypervisor** applies, persists, reports and reapplies port
forwards entirely on its own.

Persisted mappings live in `port_mappings` inside
`{SUPERVISOR_DATABASE}` (default `{EXECUTION_ROOT}/supervisor.sqlite3`),
the same SQLAlchemy-defined schema and byte-identical DDL the Python daemon
used (`rust/crates/supervisor-daemon/src/ports.rs`): soft delete via
`deleted_at IS NULL`, datetimes rendered in SQLAlchemy's own sqlite string
format. This lets either daemon implementation read what the other wrote,
which is what makes the zero-downtime cutover in `process-model.md`
possible for this piece of state specifically: port forwards are the one
thing the daemon cannot simply rederive from disk/systemd, so they get
their own durable store rather than living only in memory.

Host ports come from `get_available_host_port`/`fast_get_available_host_port`
(`ports.rs`): candidates in `MIN_DYNAMIC_PORT..MAX_PORT` (24000-65535) are
checked against active DB rows, the current nftables prerouting rules
(`check_nftables_redirections`), and a real TCP+UDP bind probe, with a
rotating cursor for the fast path so repeated allocations do not all start
scanning from the bottom of the range.

**Healing** happens in `recreate_port_redirect_rules`
(`rust/crates/supervisor-daemon/src/lifecycle.rs`), called from `StartVm`,
boot reconcile, and `RecreateNetwork`: for each persisted forward whose
nftables rule is missing, if the recorded `host_port` is no longer
available on this host it allocates a fresh one, persists the reassignment
to sqlite, and only then creates the DNAT/forward-accept rule pair; the
in-memory `VmEntry.port_forwards` list is updated last, after both the nft
diff and the sqlite write succeed, so a reader never observes a
partially-applied reassignment. This whole sequence runs under the
daemon's single host-network mutation lock (`net_lock`), which also
serializes tap/nftables setup-teardown and `RecreateNetwork`'s
flush-and-rebuild; it is the innermost lock in the daemon's lock order
(after `creation_lock`, then the per-VM lock), and it is never held across
a systemd wait.

### NDP proxy

For the static/routed IPv6 model, SLAAC cannot serve guest addresses (Linux
only autoconfigures from a prefix advertised as a full `/64`, and a `/124`
can never be handed out that way), so the host proxies neighbor discovery
for each VM's `/124` instead. `NdpProxy`
(`rust/crates/supervisor-daemon/src/ndppd.rs`) keeps an in-memory,
insertion-ordered map of `tap interface -> proxied range`; every mutation
rewrites `/etc/ndppd.conf` from the whole map and schedules a debounced
(500ms) `systemctl restart ndppd`, so a burst of adds/deletes at startup or
teardown collapses into one restart. Adoption primes the map for already-running
VMs with `update_service=false`: the on-disk config already covers them,
and a boot-time restart would drop live NDP answers for no reason; the same
priming path is what boot reconcile uses (see `process-model.md`). The
proxy only runs when `USE_NDP_PROXY` is set (default on) and networking is
allowed.

### Per-VM DHCP for SEV-SNP measured guests

Every non-SNP VM (plain and SEV/SEV-ES) gets its IPv4 statically, seeded
into cloud-init by the QEMU controller. SEV-SNP measured guests cannot use
that path: the measured image's kernel cmdline deliberately carries no
`ip=` parameter, because the launch measurement must be identical across
every deployment regardless of the address the guest will actually get, so
the guest's init falls back to `udhcpc`. Without a DHCP server on the tap
an SNP guest never receives its allocated address and is unreachable, which
breaks attestation.

`rust/crates/supervisor-daemon/src/dhcp.rs` stands up a minimal, per-tap
DHCP server for exactly this case: a `dnsmasq` process with `--dhcp-range`
set to a **single address**, the VM's own allocated IPv4, so the guest can
only ever lease precisely that address (there is no MAC to key a
`--dhcp-hostsdir` reservation on, since the SNP NIC has no fixed MAC).
`DhcpConfig::for_snp` derives the config from the VM's `TapAssignment`
(guest IP, gateway as DHCP option 3, tap-prefix netmask, the daemon's
resolved nameservers as option 6 when any were found); `--port=0` disables
dnsmasq's own DNS server so per-tap instances never collide on port 53.
Each server runs as a transient systemd unit named
`aleph-vm-dhcp-{vm_hash}.service`, launched via `systemd-run --collect -p
Type=exec` (`Type=exec` is load-bearing: with the default
`Type=simple` a failed dnsmasq exec would still report success, and the
daemon would boot the VM with no working DHCP while believing it worked).
Lease files live one-per-VM under `{EXECUTION_ROOT}/dhcp/{vm_hash}.leases`
so concurrent per-tap servers never share a lease database. This server is
started and stopped alongside the tap on every path that manages SNP
networking (create, stop, start, boot reconcile); a `debug_assert_eq!`
in `create_vm_inner` checks the request-level and written-config `snp()`
predicates agree, specifically to prevent a DHCP server leaking on a VM
that teardown treats as "plain."

### Forwarding sysctls

At startup, when `ALLOW_VM_NETWORKING` is on, the daemon enables IPv4
forwarding (`enable_forwarding_sysctl` on
`/proc/sys/net/ipv4/ip_forward`) unconditionally, and IPv6 forwarding
(`/proc/sys/net/ipv6/conf/all/forwarding`) when `IPV6_FORWARDING_ENABLED`
is set; otherwise it logs a warning that VMs will have no IPv6 internet
access. Each write only happens when the current value parses as the
integer `0`: a host whose IPv6 forwarding sysctl already reads `2`
(forwarding with router-advertisement acceptance) is left untouched rather
than overwritten to `1`, matching the Python daemon's falsy-only gate
exactly.

## Key invariants

- IPv4 addressing is always static pool math derived from `vm_index`; IPv6
  is static (derived from VM type + hash, the default) or dynamic
  (allocator-ordinal-based), selected once per node by
  `IPV6_ALLOCATION_POLICY`
  (`rust/crates/supervisor-daemon/src/world.rs`).
- A negative or otherwise invalid `vm_index`/derivation input hides the VM
  instead of silently serving a fallback subnet; two VMs never share a tap
  network (`rust/crates/supervisor-daemon/src/world.rs`).
- Boot reconcile, create, start and stop only ever create-if-absent
  tap/nftables/ndppd/DHCP state; only the operator-invoked
  `RecreateNetwork` RPC flushes and rebuilds
  (`rust/crates/supervisor-daemon/src/lifecycle.rs`).
- The supervisor is the sole writer of nftables and port-forward state; the
  agent only computes desired forwards and diffs against
  `list_port_forwards`, never recreating persisted rules itself
  (`src/aleph/vm/agent/run.py`, `rust/crates/supervisor-daemon/src/lifecycle.rs`).
- Port 22/tcp is always in the agent's desired forward set regardless of
  the user's aggregate settings (`src/aleph/vm/agent/run.py`,
  `resolve_port_forwards`).
- A port-forward reassignment during healing is persisted to sqlite before
  the in-memory entry is updated, and the nftables rule is created before
  either; a reader never sees a partially-applied reassignment
  (`rust/crates/supervisor-daemon/src/lifecycle.rs`,
  `recreate_port_redirect_rules`).
- All host-network mutations (port allocation through persistence,
  tap/nftables setup and teardown, `RecreateNetwork`) serialize on one lock,
  innermost in the daemon's lock order and never held across a systemd wait
  (`rust/crates/supervisor-daemon/src/lifecycle.rs`, `net_lock`).
- DNAT port redirects exist only for IPv4; IPv6 guest addresses are
  directly routable and never masqueraded or redirected
  (`rust/crates/supervisor-daemon/src/nft.rs`).
- Per-tap DHCP exists only for SEV-SNP VMs; every other VM (plain,
  SEV/SEV-ES) gets a static cloud-init network config and never runs a
  dnsmasq instance (`rust/crates/supervisor-daemon/src/dhcp.rs`,
  `rust/crates/supervisor-daemon/src/lifecycle.rs`).
- Tap/chain teardown is gated on the controller config's `interface_name`,
  not the spec's `internet_access` flag, so an internet-disabled VM never
  leaks a tap or nftables chain for the daemon's lifetime
  (`rust/crates/supervisor-daemon/src/lifecycle.rs`, `networking_enabled`).
- A forwarding sysctl is only written when its current value parses as `0`;
  a host already configured for forwarding-with-RA-acceptance (`2`) is left
  alone (`rust/crates/supervisor-daemon/src/main.rs`,
  `enable_forwarding_sysctl`).

## Pointers into code

- `rust/crates/supervisor-daemon/src/world.rs`: `derive_tap_assignment`,
  `ipv4_assignment`, `ipv6_static_assignment`, `ipv6_dynamic_assignment`,
  `unique_vm_index`, `VmType`.
- `rust/crates/supervisor-daemon/src/tap.rs`: `TapAssignment`, the
  `TapBackend` trait and its `ip(8)` production implementation.
- `rust/crates/supervisor-daemon/src/nft.rs`: the pure ruleset-diff layer
  (`initialize_ipv4_commands`, `initialize_ipv6_commands`,
  `setup_vm_commands`, `port_redirect_entities`, `remove_chain_commands`)
  and the `NftExecutor` apply-layer seam.
- `rust/crates/supervisor-daemon/src/ports.rs`: the `port_mappings` sqlite
  store, the legacy-DB migration, and the host-port allocator.
- `rust/crates/supervisor-daemon/src/ndppd.rs`: `NdpProxy`, the
  `/etc/ndppd.conf` renderer and the `NdppdEdge` seam.
- `rust/crates/supervisor-daemon/src/dhcp.rs`: `DhcpConfig::for_snp`, the
  `dnsmasq`/`systemd-run` argument construction, the `DhcpBackend` seam.
- `rust/crates/supervisor-daemon/src/net.rs`: default-interface and
  host-IPv4 discovery, DNS nameserver resolution feeding DHCP option 6.
- `rust/crates/supervisor-daemon/src/lifecycle.rs`: `net_lock`,
  `networking_enabled`, `nft_setup_vm`, `recreate_port_redirect_rules`,
  `recreate_network`, and every lifecycle RPC's networking side effects.
- `rust/crates/supervisor-daemon/src/main.rs`: startup ordering (schema,
  legacy migration, sysctls, NDP proxy construction, base ruleset, boot
  reconcile), `enable_forwarding_sysctls`/`enable_forwarding_sysctl`.
- `src/aleph/vm/agent/run.py`: `resolve_port_forwards`,
  `reconcile_port_forwards`, the agent-side port-forwarding policy.
- `src/aleph/vm/agent/tasks.py`: `_handle_port_forwarding_aggregate`, the
  real-time trigger on `port-forwarding` aggregate updates.
- `src/aleph/vm/network/`: the Python reference implementation
  (`firewall.py`, `interfaces.py`, `hostnetwork.py`, `ndp_proxy.py`,
  `port_availability_checker.py`) the Rust daemon ported.
