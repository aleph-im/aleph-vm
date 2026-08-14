# V-PROGRAM guest IPv6: static allocation via per-tap DHCPv6 + RA

Status: approved design, 2026-08-13.
Supersedes the SLAAC approach of PR #1080 (branch `od/vprogram-ipv6`, to be
closed). Base branch: `origin/dev`. The old branch is a parts donor only.

## 1. Problem

Confidential V-PROGRAM guests (SEV-SNP measured boot) need inbound IPv6
reachability to the attestation/serving port `:8443`, without any per-VM data
in the measured image or kernel cmdline (the publisher precomputes one
measurement for all deployments).

PR #1080 solved the guest half with SLAAC (dynamic allocation) and left "a
host RA sender (radvd)" as a follow-up. That follow-up cannot work:

1. Linux only autoconfigures from a prefix advertised as a /64. The CRN
   model allocates a static /124 per VM out of a single host /64
   (`StaticIPv6Allocator` vm-type hextet scheme, shared with the scheduler;
   single-/64-per-host confirmed by the Scaleway experiments,
   `2026-07-03-scaleway-ipv6-experiments.md`). A /124 can never be handed
   out via SLAAC.
2. Advertising the whole /64 on the tap instead would let the guest pick its
   own interface ID, which never matches the daemon's derived address: the
   published address would be fiction, the ndppd proxy range for the /124
   would not cover the guest's real address (unreachable), and the vm-type
   hextet scheme would be dead for v-programs.

Decision (with Olivier, 2026-08-13): the CRN allocates and knows the exact
address up front, and the guest must end up with precisely that address.
Static end-to-end, mirroring the IPv4 design already shipped for SNP guests
(per-tap dnsmasq handing the guest exactly its allocated IPv4, "Increment
D2").

## 2. Design

DHCPv6 + Router Advertisements from the existing per-tap dnsmasq. No new
daemon, no radvd. dnsmasq assigns the exact allocated IPv6 (DHCPv6 assigns
/128s, so the /124 scheme is irrelevant to the lease, unlike SLAAC); its RA
provides the default route (DHCPv6 cannot convey routes) with M=1/A=0 so the
guest never autoconfigures.

### 2.1 Host side (`rust/crates/supervisor-daemon`)

- `world.rs`: add `VmType::VProgram` (hextet 0x4, matching Python
  `StaticIPv6Allocator.VM_TYPE_PREFIX` and the scheduler's
  `VmType::ipv6_value()`), plus `VmEntry::vm_type()` keyed on
  `config.snp().is_some()`. Reused from the donor branch, including the
  create/adopt call-site threading in `lifecycle.rs` (create-time `snp`
  predicate identical to the persisted one, no address drift across
  restart) and its two tests.
- `dhcp.rs`: `DhcpConfig::for_snp` gains IPv6 fields populated from
  `TapAssignment.ipv6`. Not optional: `derive_tap_assignment` always
  produces an IPv6 pair (static or dynamic policy; there is no "no pool"
  case in the Rust daemon), and non-SNP instances likewise always receive
  static v6 config via cloud-init. `dnsmasq_args()` additionally emits:
  - `--dhcp-range=<guest_v6>,<guest_v6>,<prefix_len>,1h`: single-address
    stateful DHCPv6 range, same "the guest can only ever lease its
    allocated address" property as the v4 range;
  - `--enable-ra`: RAs on the tap. With a plain (non-`slaac`, non-`ra-only`)
    DHCPv6 range dnsmasq advertises M=1/A=0: default route yes, SLAAC no.
  - v6 DNS is not emitted (no `option6:dns-server`, deferred per section 6);
    the guest keeps the v4 DNS servers from udhcpc (acceptable).
- `lifecycle.rs`: no structural change. Same dnsmasq start/stop points,
  same `Type=exec` transient unit, same teardown. The tap already carries
  the host-side gateway (`create_tap` adds `host_ipv6_cidr`), so dnsmasq
  can bind; ndppd `add_range`/`delete_range` for the /124 and the nft
  per-VM rules are already in place and untouched.

### 2.2 Guest side (`nix/init.sh`, new `nix/udhcpc6.script`)

- Enable IPv6 on the interface and `accept_ra=2` (kernel installs the
  default route from the RA; reused from the donor branch).
- `busybox udhcpc6 -i $iface -q -n -t 5 -A 2 -s /bin/udhcpc6.script`, bounded
  and non-fatal exactly like the v4 `udhcpc` call (which also gains `-n`):
  `-n` makes the client exit 1 once its solicit retries are exhausted
  instead of looping forever, so `||` in init.sh always runs and no DHCPv6
  server on the tap means the guest simply stays IPv4-only.
- `udhcpc6.script` mirrors `udhcpc.script`: applies the leased address to
  the interface. No route handling (the RA covers it), no resolv.conf
  handling unless option6:dns-server was sent.
- Guest firewall (reused ICMPv6 rule from the donor branch). The stateless
  `policy drop` input chain gains:
  - `icmpv6 type { nd-router-advert, nd-neighbor-solicit,
    nd-neighbor-advert, destination-unreachable, packet-too-big,
    time-exceeded, parameter-problem } accept`: RA lifetime refresh
    (periodic RAs keep the default route alive), neighbor discovery/NUD,
    and PMTU. Without these, v6 blackholes minutes into the VM's life, not
    at boot.
  - `tcp dport 8443 accept` already covers v6 (the table is family `inet`).
  - No DHCP client rules (udp 68/546) are needed: both clients run with
    `-q` (exit after obtaining the lease), the scripts apply the address
    permanently, and the exchanges complete before `setup_firewall`
    installs the ruleset. See section 4.

### 2.3 Attestation agent (`rust/crates/aleph-attest-agent`)

Bind `[::]:{port}` instead of `0.0.0.0:{port}` (reused from the donor
branch). Dual-stack: Linux default `IPV6_V6ONLY=0`, verified for actix-web,
so the IPv4 path and the Task-1 host-port map are unaffected.

### 2.4 Image (`nix/`)

Busybox comes from stock `pkgs.busybox`. Verify the `udhcpc6` applet is
enabled in the nixpkgs build; if not, enable `CONFIG_UDHCPC6` via the
busybox `extraConfig` override. Ship `udhcpc6.script` in the initrd next to
`udhcpc.script`.

Measurement impact: init.sh, the new script, and the attest-agent bind all
shift the measured image, so a downstream measurement re-pin is required
before shipping (same cost the SLAAC PR already carried).

## 3. What is deliberately unchanged

- The static /124 allocation scheme, vm-type hextets, ndppd ranges, nft
  rules, `/v2/about/executions/list` discovery: all keep working as-is; the
  guest simply now ends up holding the address the daemon reports.
- Plain and SEV/SEV-ES QEMU instances: cloud-init static config, no per-tap
  dnsmasq, `VmType::Instance`. Firecracker programs: `VmType::Microvm`.
- Python supervisor: not touched (Rust daemon only, like the donor PR).

## 4. Non-issue: DHCP renewals vs the guest firewall

An earlier draft flagged the ruleset's lack of `udp dport 68 accept` as a
v4 renewal gap. Reading `init.sh` closed it: `udhcpc` runs with `-q`, so
the client exits after obtaining the lease and no renewal traffic ever
occurs; `udhcpc.script` applies the address permanently (`ip addr add`,
no valid_lft), and the DHCP exchange completes before `setup_firewall`
installs the ruleset. The same holds for `udhcpc6`. The dnsmasq lease
expiring server-side is harmless: the single-address range is reserved
for this guest by construction. What genuinely must survive the firewall
is the periodic RA flow that refreshes the default route's lifetime,
which the ICMPv6 rule covers (section 2.2).

## 5. Testing

- `dhcp.rs` unit tests: v6 args (single-address range, `enable-ra`,
  prefix-len 124) when the tap has IPv6; v4-only args unchanged when it
  does not (no-pool regression case).
- `lifecycle.rs`: extend `create_snp_starts_a_per_tap_dhcp_server_...` to
  assert the v6 half; keep the donor branch's
  `create_snp_allocates_the_v_program_ipv6_hextet` and persisted-predicate
  tests.
- Guest: shellcheck on init.sh + udhcpc6.script.
- End-to-end (manual, SNP host): boot a v-program, `curl` the published
  `[guest_v6]:8443` from an external v6 vantage point; confirm the leased
  address equals the daemon-derived one; confirm both addresses and the
  v6 default route survive past the 1h lease and RA lifetime (the
  firewall must not starve the RA refresh).

## 6. Risks and open items

- dnsmasq DHCPv6/RA support requires dnsmasq >= 2.60ish; every supported
  CRN distro ships far newer. No version gate needed.
- If `pkgs.busybox` lacks `udhcpc6`, the `extraConfig` override changes the
  busybox derivation (image shift already accounted for).
- IPv6 nameservers: deferred unless the daemon already resolves v6-capable
  ones; guests function with v4 DNS.
- The Task-1 port-map (#1079) is not on `origin/dev` yet; this work does
  not depend on it (independent reachability paths).
