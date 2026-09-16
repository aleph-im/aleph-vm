//! The daemon's world view: every VM the host defines, rebuilt from disk,
//! systemd and sqlite at boot. The nftables and ndppd reconcile that follows
//! it lives in lifecycle::reconcile_boot.
//!
//! Python parity notes. The oracle is the restarted Python daemon
//! (`VmPool.load_persistent_executions`): it scans
//! `{EXECUTION_ROOT}/*-controller.json` in sorted order, batch-queries
//! systemd, and rebuilds an execution per ACTIVE controller (keyed on the
//! EMBEDDED `Configuration.vm_hash`, never the file name), setting
//! `defined_at`/`preparing_at`/`prepared_at`/`started_at` to the adoption
//! instant and leaving `starting_at` unset. Like Python's `claimed_vm_ids`
//! guard, when two active configs claim the same vm_index only the first
//! (sorted file order) is adopted. This module ports that faithfully for
//! running VMs, with the deliberate differences below:
//!
//! - A config whose controller unit is NOT active is kept and reported
//!   STOPPED (with `stopped_at` = the adoption instant), where Python stops
//!   and disables the unit and deletes the config. That sweep also destroyed
//!   confidential VMs still waiting for their owner to upload a session.
//!   Duplicate vm_index claims get the same treatment: not adopted, never
//!   deleted.
//! - An unparseable, oversized or non-regular-file config is logged and
//!   skipped, where Python's startup aborts (the crash-loop lesson) or, for
//!   a FIFO, would hang. One bad file on disk must not cost the node every
//!   VM it runs.
//! - A `hypervisor: firecracker` config is logged and skipped: Python's
//!   reattach also fails for it (spec_from_controller_configuration is
//!   QEMU-only), leaving the VM untracked, so both daemons hide it from
//!   ListVms and queue it for (doomed) background retries.
//! - When the boot-time ListUnits call FAILS (bus unreachable), no VM is
//!   stamped stopped: unit states are unknown, and each VM's status defers
//!   to the live per-RPC unit queries until the bus answers.
//! - A per-VM IP-derivation failure hides the VM (skipped with a WARN),
//!   like a failed Python reattach that excludes the VM from ListVms via
//!   the retry queue. A negative vm_index is one such failure: Python's list
//!   indexing serves the pool's LAST subnet for it, aliasing two VMs.
//! - The daemon never derives a guest IPv6: the agent owns allocation and
//!   every create carries the address, persisted as `guest_ipv6_cidr`. A
//!   legacy config without it adopts the address live on its tap, and is
//!   hidden (like a failed reattach) when there is none.
//!
//! A controller unit without a config file gets a WARN and is left alone.
//!
//! The view is rebuilt at boot and mutated by the lifecycle RPCs (the
//! RwLock in `DaemonState`).

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::config::Settings;
use crate::controller_config::{
    self, ControllerConfig, QemuVmConfig, VmConfiguration, parse_controller_config,
};
use crate::ports::{self, PortForward};
use crate::tap::TapBackend;
use crate::units::{UnitLiveness, UnitStateSource, controller_unit_name};

const CONFIG_SUFFIX: &str = "-controller.json";

/// Failures deriving a VM's tap/IP assignment or its vm_index (the "IP
/// assignment math" section below). Display strings are identical to the
/// pre-typed messages they replace; every underlying parse error
/// (ParseIntError/AddrParseError/TryFromIntError) is discarded exactly as
/// it was before typing, so the enum carries no source.
#[derive(Debug, thiserror::Error)]
pub enum WorldError {
    #[error("No available value for vm_index.")]
    NoFreeVmIndex,

    #[error("prefix /{prefix} does not subnet the pool {pool}")]
    PrefixNotSubnet { prefix: u8, pool: String },

    #[error("negative vm_index {vm_index}")]
    NegativeVmIndex { vm_index: i64 },

    #[error("vm_index {vm_index} out of range for {pool} split into /{prefix} subnets")]
    IndexOutOfRange {
        vm_index: i64,
        pool: String,
        prefix: u8,
    },

    #[error("no guest address in a /{prefix} subnet")]
    NoGuestAddress { prefix: u8 },

    #[error(
        "VM {vm_id} has no known guest IPv6: its config predates the persisted address and its tap carries none; delete it and create it again with a requested address"
    )]
    NoKnownIpv6 { vm_id: String },

    #[error("the requested IPv6 network {requested} overlaps {held}, held by VM {holder}")]
    Ipv6Overlap {
        requested: String,
        held: String,
        holder: String,
    },

    #[error("invalid IPv{family} pool {pool:?}")]
    InvalidCidr { family: &'static str, pool: String },

    #[error("invalid IPv{family} pool address {pool:?}")]
    InvalidCidrAddress { family: &'static str, pool: String },

    #[error("invalid IPv{family} pool prefix {pool:?}")]
    InvalidCidrPrefix { family: &'static str, pool: String },

    #[error("the IPv{family} pool {pool:?} has host bits set")]
    HostBitsSet { family: &'static str, pool: String },
}

/// Lifecycle instants in unix nanoseconds UTC, 0 = stage not reached.
/// Same shape as the Python `VmExecutionTimes` after `_ns()` conversion
/// (microsecond precision).
#[derive(Debug, Clone, Copy, Default)]
pub struct VmTimes {
    pub defined_at_ns: u64,
    pub preparing_at_ns: u64,
    pub prepared_at_ns: u64,
    pub starting_at_ns: u64,
    pub started_at_ns: u64,
    pub stopping_at_ns: u64,
    pub stopped_at_ns: u64,
}

/// One address family's computed assignment (VmInfo.IpAssignment fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpPair {
    /// The guest's address, bare IP.
    pub address: String,
    /// The tap network, e.g. "172.16.3.0/24".
    pub network_cidr: String,
    /// Host-side tap address (bare IP), the guest's default route.
    pub gateway: String,
}

/// One GPU attachment as `_to_vm_info` reports it: the Python `HostGPU`
/// rebuilt from the host inventory (post-#1023) or, for a card absent from
/// the inventory, recorded bare from the config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedGpu {
    pub pci_host: String,
    /// vendor:device ids when the card is in the lspci inventory, empty
    /// otherwise (the bare `HostGPU(pci_host=...)` case).
    pub device_id: String,
    pub supports_x_vga: bool,
}

/// Python `VmPool._rebuild_reattached_gpus`: never rejects (the cards are
/// facts, not requests); inventory cards keep their metadata and hardware
/// x-vga flag, unknown cards are recorded from the config alone.
pub fn rebuild_attached_gpus(
    config_gpus: &[controller_config::QemuGpu],
    inventory: &[crate::lspci::GpuDevice],
) -> Vec<AttachedGpu> {
    config_gpus
        .iter()
        .map(|gpu| {
            match inventory
                .iter()
                .find(|device| device.pci_host == gpu.pci_host)
            {
                Some(device) => AttachedGpu {
                    pci_host: device.pci_host.clone(),
                    device_id: device.device_id.clone(),
                    supports_x_vga: device.supports_x_vga(),
                },
                None => {
                    tracing::warn!(
                        pci_host = gpu.pci_host,
                        "reattached VM holds a GPU absent from the host inventory; \
                         recording the attachment from the config alone"
                    );
                    AttachedGpu {
                        pci_host: gpu.pci_host.clone(),
                        device_id: String::new(),
                        supports_x_vga: gpu.supports_x_vga,
                    }
                }
            }
        })
        .collect()
}

/// The ephemeral-program half of a VmEntry (spec.backend FIRECRACKER,
/// increment 4): the MicroVM-derived facts the Python execution carries.
#[derive(Debug, Clone)]
pub struct ProgramEntry {
    /// Host UDS endpoint of the guest channel (`MicroVM.vsock_path`).
    pub vsock_path: String,
    /// Raw bytes from the guest's ready signal (`MicroVM.init_payload`).
    pub ready_payload: Vec<u8>,
    /// Handle on the firecracker child; teardown is kill-based, idempotent.
    pub handle: std::sync::Arc<dyn crate::firecracker::ProgramHandle>,
}

/// One adopted VM.
#[derive(Debug, Clone)]
pub struct VmEntry {
    pub vm_hash: String,
    /// `Configuration.vm_id`, the tap/IPv4-range index.
    pub vm_index: i64,
    /// The controller configuration for QEMU VMs. For ephemeral programs
    /// (`is_program`) this holds a SYNTHESIZED record
    /// (`QemuVmConfig::for_program`: memory + interface name only, never
    /// written to disk) so the shared accounting paths (memory backstop,
    /// networking_enabled, GPU exclusion) read one shape; anything beyond
    /// those fields must branch on `is_program` instead.
    pub config: QemuVmConfig,
    pub settings_slice: controller_config::ControllerSettingsSlice,
    pub times: VmTimes,
    /// Whether the controller unit was active when the view was built.
    /// Status queries use the LIVE unit state; this drives what was
    /// populated at adoption (times, IPs, port forwards).
    pub adopted_running: bool,
    /// Whether the controller unit had FAILED when the view was built: the
    /// VM ran and died, so it reports FAILED, but no guest of it is left to
    /// hold a card's CC mode or to wait for its confidential session.
    /// Cleared by the start that brings the VM back.
    pub adopted_failed: bool,
    /// Set while StartVm or RebootVm is deliberately bringing the controller
    /// unit back up, and cleared on the way out whether or not it worked.
    /// Status reads take no per-VM lock, so without this a poll landing in
    /// the gap would read the VM as a guest that died on its own.
    pub restarting: bool,
    /// Computed like the Python `TapInterface` the reattach rebuilds; only
    /// for VMs adopted running (a stopped VM's tap was torn down, and the
    /// proto documents empty assignments until the tap exists).
    pub ipv4: Option<IpPair>,
    pub ipv6: Option<IpPair>,
    /// Active persisted port mappings, loaded at adoption for running VMs
    /// (Python parity: a stopped persistent VM's `mapped_ports` is empty
    /// until StartVm reloads it from the database).
    pub port_forwards: Vec<PortForward>,
    /// The `execution.gpus` attachments `_to_vm_info` reports: rebuilt from
    /// the inventory for VMs adopted running, set from the validated request
    /// at create.
    pub gpus: Vec<AttachedGpu>,
    /// The original VmSpec for VMs created through CreateVm on this daemon
    /// instance: the exact idempotency comparand and GetVmSpec payload,
    /// like the live Python daemon's `execution.vm_spec`. None for adopted
    /// VMs, where the reconstruction stands in (the restarted-Python
    /// behavior).
    pub spec: Option<supervisor_proto::pb::VmSpec>,
    /// Insertion position, the Python dict order: adoption in sorted config
    /// order, then creation order. ListVms/ListPortForwards/RecreateNetwork
    /// enumerate by it (a BTreeMap walk would sort by hash instead, an
    /// observable difference after a post-boot create). Assigned by
    /// [`WorldView::insert_entry`]; a replacement keeps the old position,
    /// like a Python dict assignment to an existing key.
    pub ordinal: u64,
    /// True for an ephemeral Firecracker program created on this daemon
    /// instance (spec.backend FIRECRACKER, never persistent, never
    /// adopted: an ephemeral program cannot outlive the daemon that
    /// spawned it). Liveness is times-based (the Python non-persistent
    /// `_is_running`), never a systemd unit query.
    pub is_program: bool,
    /// Set once the program booted (the ready handshake completed).
    pub program: Option<ProgramEntry>,
    /// Effective NUMA placement (Phase 3 increment C1): the node the
    /// supervisor pinned this VM's vCPUs to via `AllowedCPUs`, or None when
    /// placement is inert (no NUMA topology) or the VM is unpinned (adopted
    /// from a pre-NUMA daemon with no `AllowedCPUs` drop-in). Reported in
    /// `VmInfo.numa_node`; drives the ledger release on delete.
    pub numa_node: Option<u32>,
}

impl VmEntry {
    pub fn unit_name(&self) -> String {
        controller_unit_name(&self.vm_hash)
    }

    /// A minimal QEMU entry for tests that only read a few config fields
    /// (quiescence reads qga_socket_path, confidential reads image_path).
    #[cfg(test)]
    pub fn test_qemu(vm_hash: &str, image_path: &str) -> Self {
        let mut config = QemuVmConfig::for_program(256, None);
        config.image_path = image_path.to_string();
        Self {
            vm_hash: vm_hash.to_string(),
            vm_index: 4,
            config,
            settings_slice: controller_config::ControllerSettingsSlice::default(),
            times: VmTimes::default(),
            adopted_running: false,
            adopted_failed: false,
            restarting: false,
            ipv4: None,
            ipv6: None,
            port_forwards: Vec::new(),
            gpus: Vec::new(),
            spec: None,
            ordinal: 0,
            is_program: false,
            program: None,
            numa_node: None,
        }
    }

    /// A minimal ephemeral-program entry for tests.
    #[cfg(test)]
    pub fn test_program(vm_hash: &str) -> Self {
        let mut entry = Self::test_qemu(vm_hash, "");
        entry.is_program = true;
        entry
    }

    /// Python `is_stopping`: stopping_at set, stopped_at not yet.
    pub fn is_stopping(&self) -> bool {
        self.times.stopping_at_ns != 0 && self.times.stopped_at_ns == 0
    }
}

/// Python `_FailedReattach` (pool.py): a VM left running-but-untracked
/// after a failed adoption, awaiting background retry
/// (`lifecycle::retry_failed_reattachments_once`). `attempts` counts TOTAL
/// attempts including the startup one; once it reaches
/// `REATTACH_RETRY_MAX_ATTEMPTS` the VM is `exhausted`: the daemon stops
/// retrying and leaves the live controller alone (operator intervention).
#[derive(Debug, Clone)]
pub struct FailedReattach {
    pub vm_index: i64,
    pub attempts: u32,
    pub exhausted: bool,
}

impl FailedReattach {
    pub fn new(vm_index: i64) -> Self {
        Self {
            vm_index,
            attempts: 1,
            exhausted: false,
        }
    }
}

/// The in-memory map, keyed and iterated by vm_hash. The BTreeMap order
/// equals the Python pool's insertion order (sorted config paths), so
/// ListVms enumerates identically.
#[derive(Debug, Default)]
pub struct WorldView {
    pub entries: BTreeMap<String, VmEntry>,
    /// vm_indices claimed by ACTIVE on-disk configs that were NOT adopted
    /// as entries (hidden VMs: failed IP derivation, duplicate indices,
    /// Firecracker configs). Their live controllers still own the index
    /// (tap device, nft chains), so vm_index allocation must skip them,
    /// like the Python `_failed_reattach` protection in
    /// `get_unique_vm_index`.
    pub reserved_vm_indices: std::collections::HashSet<i64>,
    /// Hidden VMs with a LIVE controller queued for background reattach
    /// retry, the Python `VmPool._failed_reattach` dict. Keyed by vm_hash;
    /// entries are removed once re-adopted (retry pass, readopt or an
    /// explicit delete), kept exhausted once given up.
    pub failed_reattach: std::collections::HashMap<String, FailedReattach>,
    /// The next [`VmEntry::ordinal`] to hand out.
    pub next_ordinal: u64,
}

impl WorldView {
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Insert (or replace) an entry, maintaining the Python dict insertion
    /// order: a new key goes last, an existing key keeps its position
    /// (`self.executions[vm_id] = execution` in the pool).
    pub fn insert_entry(&mut self, mut entry: VmEntry) {
        entry.ordinal = match self.entries.get(&entry.vm_hash) {
            Some(existing) => existing.ordinal,
            None => {
                let ordinal = self.next_ordinal;
                self.next_ordinal += 1;
                ordinal
            }
        };
        self.entries.insert(entry.vm_hash.clone(), entry);
    }

    /// Entries in insertion order, the Python `pool.executions.values()`
    /// enumeration.
    pub fn ordered_entries(&self) -> Vec<&VmEntry> {
        let mut entries: Vec<&VmEntry> = self.entries.values().collect();
        entries.sort_by_key(|entry| entry.ordinal);
        entries
    }

    /// The entry (other than `except_vm`) whose guest IPv6 network overlaps
    /// `requested`, with the network it holds: its live assignment or, for
    /// an entry without one (stopped), its persisted /124, which it gets
    /// back on start. The agent allocates addresses; this is the backstop
    /// that keeps two VMs from ever sharing a subnet.
    pub fn ipv6_holder(&self, requested: &IpPair, except_vm: &str) -> Option<(String, String)> {
        let wanted = ipv6_network_of(requested)?;
        self.entries
            .values()
            .filter(|entry| entry.vm_hash != except_vm)
            .find_map(|entry| {
                entry_ipv6_networks(entry)
                    .into_iter()
                    .find(|held| ipv6_networks_overlap(ipv6_network_of(held), Some(wanted)))
                    .map(|held| (entry.vm_hash.clone(), held.network_cidr))
            })
    }

    /// Python `get_unique_vm_index`: the first free index from
    /// START_ID_INDEX, skipping live entries and hidden VMs' claims.
    pub fn unique_vm_index(&self, start_id_index: i64) -> Result<i64, WorldError> {
        let used: std::collections::HashSet<i64> = self
            .entries
            .values()
            .map(|entry| entry.vm_index)
            .chain(self.reserved_vm_indices.iter().copied())
            .collect();
        // Python: range(START_ID_INDEX, 255**2).
        (start_id_index..255 * 255)
            .find(|candidate| !used.contains(candidate))
            .ok_or(WorldError::NoFreeVmIndex)
    }
}

/// The guest IPv6 networks an entry holds: its live assignment and its
/// persisted /124 (a stopped entry has only the latter).
fn entry_ipv6_networks(entry: &VmEntry) -> Vec<IpPair> {
    let persisted = entry
        .config
        .guest_ipv6_cidr
        .as_deref()
        .and_then(|cidr| ipv6_from_cidr(cidr).ok());
    entry.ipv6.clone().into_iter().chain(persisted).collect()
}

/// A pair's network as (address bits, prefix length).
fn ipv6_network_of(pair: &IpPair) -> Option<(u128, u8)> {
    parse_ipv6_cidr(&pair.network_cidr)
        .ok()
        .map(|(network, prefix)| (u128::from(network), prefix))
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix.min(128)))
    }
}

/// Two networks overlap when they agree on the shorter prefix.
fn ipv6_networks_overlap(a: Option<(u128, u8)>, b: Option<(u128, u8)>) -> bool {
    let (Some((a, a_len)), Some((b, b_len))) = (a, b) else {
        return false;
    };
    let mask = ipv6_mask(a_len.min(b_len));
    a & mask == b & mask
}

/// The vm_index-th IPv4 tap subnet from the settings (guest = network+2,
/// gateway = network+1). IPv4 stays daemon-derived: it is host-local.
pub fn ipv4_for_index(settings: &Settings, vm_index: i64) -> Result<IpPair, WorldError> {
    ipv4_assignment(
        &settings.ipv4_address_pool,
        settings.ipv4_network_prefix_length,
        vm_index,
    )
}

/// The IPv4/IPv6 pair of a tap. The IPv4 half is the vm_index-th subnet;
/// the IPv6 half is the `network/prefix` the agent allocated (the daemon
/// never derives a guest IPv6 itself), guest = network+1.
pub fn derive_tap_assignment(
    settings: &Settings,
    vm_index: i64,
    ipv6_cidr: &str,
) -> Result<(IpPair, IpPair), WorldError> {
    let ipv4 = ipv4_for_index(settings, vm_index)?;
    let ipv6 = ipv6_from_cidr(ipv6_cidr)?;
    Ok((ipv4, ipv6))
}

/// The IPv6 configured on a VM's live tap (`vmtap{vm_index}`) as a guest
/// pair: the host side of the tap holds the guest network address (see
/// [`ipv6_pair`]). The fallback for a legacy config that predates the
/// persisted `guest_ipv6_cidr`: the tap is what the running guest uses.
/// `None` when the tap is gone or carries no global IPv6.
pub fn ipv6_from_tap(taps: &dyn TapBackend, vm_index: i64) -> Option<IpPair> {
    let cidr = taps.global_ipv6_address(&format!("vmtap{vm_index}"))?;
    let (address, prefix) = cidr.split_once('/')?;
    let address: Ipv6Addr = address.parse().ok()?;
    let prefix: u8 = prefix.parse().ok().filter(|prefix| *prefix <= 128)?;
    let network = Ipv6Addr::from(u128::from(address) & ipv6_mask(prefix));
    ipv6_from_cidr(&format!("{network}/{prefix}")).ok()
}

/// Unix nanoseconds now, truncated to microsecond precision like the
/// Python `_ns()` (whole seconds * 1e9 + microseconds * 1000).
pub fn now_ns() -> u64 {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    elapsed.as_micros() as u64 * 1_000
}

/// Build the world view: scan configs, query systemd once, load port
/// mappings. Never fails: every per-VM problem is logged and isolated,
/// exactly like the Python per-VM reattach isolation.
pub fn build_world_view(
    settings: &Settings,
    units: &dyn UnitStateSource,
    gpu_inventory: &[crate::lspci::GpuDevice],
    taps: &dyn TapBackend,
) -> WorldView {
    let configs = scan_controller_configs(settings);

    let unit_names: Vec<String> = configs
        .iter()
        .map(|config| controller_unit_name(&config.vm_hash))
        .collect();
    // None: the bus did not answer, so unit states are UNKNOWN. Adopted
    // entries must not be stamped stopped on a transient bus outage; their
    // status defers to the live per-RPC unit queries instead.
    let unit_states: Option<std::collections::HashMap<String, UnitLiveness>> =
        match units.unit_states(&unit_names) {
            Ok(states) => Some(states),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "system bus unreachable at adoption; unit states unknown, \
                     deferring every VM's status to live queries"
                );
                None
            }
        };

    // Adoption step 3's counterpart check: units without a config file are
    // reported and left alone. Best-effort, and only when the bus already
    // answered above: a second call on a dead bus would just burn another
    // method timeout at boot.
    if unit_states.is_some() {
        let known: std::collections::HashSet<&String> = unit_names.iter().collect();
        match units.controller_units() {
            Ok(controller_units) => {
                for (unit, active) in controller_units {
                    if !known.contains(&unit) {
                        tracing::warn!(
                            unit,
                            active,
                            "controller unit has no configuration file; leaving it alone"
                        );
                    }
                }
            }
            Err(error) => {
                tracing::warn!(
                    %error,
                    "could not list controller units for the orphan check"
                );
            }
        }
    }

    let mut world = WorldView::default();
    // Python's claimed_vm_ids guard (pool.load_persistent_executions): a
    // stale config can reuse a vm_index; only the first active one (sorted
    // file order) is adopted, so two VMs never share a tap interface.
    let mut claimed_vm_indices: std::collections::HashSet<i64> = std::collections::HashSet::new();

    for config in configs {
        let vm_hash = config.vm_hash.clone();
        let unit = controller_unit_name(&vm_hash);
        // Some(state): the bus answered; None: unknown (bus unreachable).
        let liveness: Option<UnitLiveness> = unit_states
            .as_ref()
            .map(|states| states.get(&unit).copied().unwrap_or(UnitLiveness::Unknown));
        let active = liveness.is_some_and(UnitLiveness::is_active);

        // Like Python, the vm_index claim precedes the per-VM rebuild: an
        // active duplicate is never adopted (Python destroys it at startup
        // and answers NOT_FOUND; this daemon just does not adopt, because a
        // daemon that adopts must not destroy state).
        if active && !claimed_vm_indices.insert(config.vm_index) {
            tracing::warn!(
                vm_hash,
                vm_index = config.vm_index,
                "vm_index already claimed by an earlier active config; skipping the VM"
            );
            continue;
        }

        let mut qemu = match config.vm {
            VmConfiguration::Qemu(qemu) => *qemu,
            VmConfiguration::Firecracker => {
                tracing::warn!(
                    vm_hash,
                    "skipping non-QEMU controller config (adoption is QEMU-only, \
                     as in the Python reattach); leaving the VM alone"
                );
                // Python queues every failed reattach of an ACTIVE
                // controller for background retry, including these doomed
                // ones (spec_from_controller_configuration is QEMU-only on
                // every retry too); they exhaust after the attempt cap.
                if active {
                    world
                        .failed_reattach
                        .insert(vm_hash, FailedReattach::new(config.vm_index));
                }
                continue;
            }
        };

        // Mirrors the instants the Python restore path stamps: __init__
        // sets defined_at, prepare() sets preparing_at/prepared_at,
        // _restore_running_execution_from_config sets started_at;
        // starting_at is never set on this path.
        let mut times = VmTimes {
            defined_at_ns: now_ns(),
            ..VmTimes::default()
        };
        let mut ipv4 = None;
        let mut ipv6 = None;
        let mut port_forwards = Vec::new();
        let mut adopted_failed = false;
        match liveness {
            Some(UnitLiveness::Active) => {
                times.preparing_at_ns = now_ns();
                times.prepared_at_ns = now_ns();

                if settings.allow_vm_networking {
                    // Python rebuilds the tap unconditionally for adopted VMs
                    // (even when the config carries no interface_name). A
                    // derivation failure fails the whole per-VM reattach
                    // there, hiding the VM from ListVms (retry queue); hide
                    // it here too instead of serving empty assignments.
                    match ipv4_for_index(settings, config.vm_index) {
                        Ok(pair) => ipv4 = Some(pair),
                        Err(error) => {
                            tracing::warn!(
                                vm_hash,
                                %error,
                                "cannot compute the IPv4 assignment; hiding the VM \
                                 like a failed Python reattach"
                            );
                            world
                                .failed_reattach
                                .insert(vm_hash, FailedReattach::new(config.vm_index));
                            continue;
                        }
                    }
                    // A current config carries the guest /124 the agent
                    // allocated; adopt it verbatim. A legacy config (written
                    // before the address was persisted) adopts the address
                    // live on the VM's tap, recorded in memory so the
                    // reconstructed spec and a later start agree with it.
                    // With neither, the daemon has no address to serve (it
                    // never derives one): hide the VM like a failed reattach.
                    let persisted_ipv6 =
                        qemu.guest_ipv6_cidr.clone().filter(|cidr| !cidr.is_empty());
                    let ipv6_result = match persisted_ipv6 {
                        Some(cidr) => ipv6_from_cidr(&cidr),
                        None => match ipv6_from_tap(taps, config.vm_index) {
                            Some(pair) => {
                                tracing::info!(
                                    vm_hash,
                                    network = pair.network_cidr,
                                    "legacy config without a persisted guest IPv6; \
                                     adopting the address live on its tap"
                                );
                                qemu.guest_ipv6_cidr = Some(pair.network_cidr.clone());
                                Ok(pair)
                            }
                            None => Err(WorldError::NoKnownIpv6 {
                                vm_id: vm_hash.clone(),
                            }),
                        },
                    };
                    match ipv6_result {
                        Ok(pair) => ipv6 = Some(pair),
                        Err(error) => {
                            tracing::warn!(
                                vm_hash,
                                %error,
                                "cannot determine the IPv6 assignment; hiding the VM \
                                 like a failed Python reattach"
                            );
                            world
                                .failed_reattach
                                .insert(vm_hash, FailedReattach::new(config.vm_index));
                            continue;
                        }
                    }
                }

                // Python: execution.mapped_ports = await get_port_mappings(vm_id)
                // during _restore_running_execution_from_config.
                match ports::load_port_forwards(&settings.supervisor_database, &vm_hash) {
                    Ok(forwards) => port_forwards = forwards,
                    Err(error) => {
                        tracing::warn!(vm_hash, %error, "cannot load persisted port mappings");
                    }
                }

                times.started_at_ns = now_ns();
            }
            Some(UnitLiveness::Failed) => {
                // The VM ran and its unit died on its own, so it is a death
                // to report and rebuild, not the stop the arm below stamps.
                // started_at with no stopped_at is the dead-unit arm's shape.
                times.started_at_ns = times.defined_at_ns;
                adopted_failed = true;
                tracing::info!(
                    vm_hash,
                    "controller config present but its unit failed; reporting the VM failed"
                );
            }
            Some(UnitLiveness::Dead) => {
                // No Python counterpart (the Python startup destroys these);
                // the daemon observed the VM stopped at adoption.
                times.stopped_at_ns = times.defined_at_ns;
                tracing::info!(
                    vm_hash,
                    "controller config present but its unit is not active; reporting the VM stopped"
                );
            }
            Some(state) => {
                // A job in flight, or a state systemd grew since: neither is
                // proof the VM stopped, so leave every stamp but defined_at
                // unset and let vm_status follow the live unit state.
                tracing::info!(
                    vm_hash,
                    ?state,
                    "unit state undecided at adoption; \
                     the VM's status defers to live unit queries"
                );
            }
            None => {
                // Bus unreachable at boot: not proof the VM stopped either.
                tracing::info!(
                    vm_hash,
                    "unit state unknown at adoption (bus unreachable); \
                     the VM's status defers to live unit queries"
                );
            }
        }

        // execution.gpus is rebuilt for VMs adopted running: reporting an
        // attached card as available invites a double attachment after every
        // restart. Stopped entries keep an empty list until StartVm.
        let gpus = if active {
            rebuild_attached_gpus(&qemu.gpus, gpu_inventory)
        } else {
            Vec::new()
        };

        world.insert_entry(VmEntry {
            vm_hash,
            vm_index: config.vm_index,
            config: qemu,
            settings_slice: config.settings,
            times,
            adopted_running: active,
            adopted_failed,
            restarting: false,
            ipv4,
            ipv6,
            port_forwards,
            gpus,
            spec: None,
            ordinal: 0, // assigned by insert_entry
            is_program: false,
            program: None,
            // Unknown at adoption: reconstructed by reconcile_numa_ledger
            // from the VM's AllowedCPUs drop-in, or left unpinned (a VM
            // adopted from a pre-NUMA daemon has no drop-in).
            numa_node: None,
        });
    }

    // Claims without an entry are hidden VMs whose LIVE controllers still
    // own their index (failed IP derivation, duplicates, Firecracker
    // configs); vm_index allocation must never hand these out (the Python
    // `_failed_reattach` protection).
    let adopted: std::collections::HashSet<i64> =
        world.entries.values().map(|entry| entry.vm_index).collect();
    world.reserved_vm_indices = claimed_vm_indices
        .into_iter()
        .filter(|index| !adopted.contains(index))
        .collect();
    tracing::info!(count = world.len(), "world view built");
    world
}

/// Sanity cap on one controller config file: real configs are KB-sized, so
/// anything above this is not a config and must not be buffered.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;

/// Scan `{EXECUTION_ROOT}/*-controller.json` in sorted order, parsing each;
/// unparseable, oversized or non-regular files are logged and skipped,
/// never fatal. Each config is keyed on its EMBEDDED `vm_hash`, like the
/// Python loader (pool.py keys the unit name, port mappings, static IPv6
/// and vm_id on `config.vm_hash`; the file name only locates the file).
fn scan_controller_configs(settings: &Settings) -> Vec<ControllerConfig> {
    let mut paths: Vec<std::path::PathBuf> = match std::fs::read_dir(&settings.execution_root) {
        Ok(dir) => dir
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with(CONFIG_SUFFIX))
            })
            .collect(),
        Err(error) => {
            tracing::warn!(%error, "Failed to enumerate controller configs");
            return Vec::new();
        }
    };
    paths.sort();

    let mut configs = Vec::new();
    for path in paths {
        let file_hash = path
            .file_name()
            .and_then(|name| name.to_str())
            .map(|name| name[..name.len() - CONFIG_SUFFIX.len()].to_string())
            .unwrap_or_default();
        // symlink_metadata: never follow links, never open the path before
        // knowing what it is. A FIFO dropped into EXECUTION_ROOT must not
        // hang boot inside read_to_string.
        let metadata = match std::fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cannot stat controller config; skipping the VM");
                continue;
            }
        };
        if !metadata.is_file() {
            tracing::warn!(
                path = %path.display(),
                "controller config is not a regular file (symlink, FIFO or directory); skipping the VM"
            );
            continue;
        }
        if metadata.len() > MAX_CONFIG_BYTES {
            tracing::warn!(
                path = %path.display(),
                size = metadata.len(),
                "controller config exceeds the 1 MiB sanity cap; skipping the VM"
            );
            continue;
        }
        let contents = match std::fs::read_to_string(&path) {
            Ok(contents) => contents,
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "cannot read controller config; skipping the VM");
                continue;
            }
        };
        match parse_controller_config(&contents) {
            Ok(config) => {
                if config.vm_hash != file_hash {
                    // Python keys everything on the embedded hash (unit
                    // name, port mappings, static IPv6, vm_id); trust it
                    // and note the mismatch.
                    tracing::warn!(
                        path = %path.display(),
                        embedded = config.vm_hash,
                        "controller config vm_hash differs from its file name; using the embedded hash"
                    );
                }
                configs.push(config);
            }
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "unparseable controller config; skipping the VM");
            }
        }
    }
    configs
}

// ── IP assignment math ──────────────────────────────────────────────────
//
// Ports of the Python derivations the reattach path performs:
// Network.get_network_for_tap (IPv4) and the TapInterface properties
// (guest_ip/host_ip/guest_ipv6/host_ipv6) in
// src/aleph/vm/network/{hostnetwork,interfaces}.py. The guest IPv6 network
// itself is never derived here: the agent allocates it (static or dynamic
// policy) and the daemon only turns the CIDR into the tap pair.

/// The vm_index-th /{prefix} subnet of the pool: guest = network+2,
/// gateway = network+1, like `TapInterface.guest_ip`/`host_ip`.
fn ipv4_assignment(pool: &str, prefix: u8, vm_index: i64) -> Result<IpPair, WorldError> {
    let (base, pool_len) = parse_ipv4_cidr(pool)?;
    if prefix > 32 || prefix < pool_len {
        return Err(WorldError::PrefixNotSubnet {
            prefix,
            pool: pool.to_string(),
        });
    }
    let index = u64::try_from(vm_index).map_err(|_| WorldError::NegativeVmIndex { vm_index })?;
    let subnet_count = 1u64 << (prefix - pool_len);
    if index >= subnet_count {
        // Python raises IndexError from `subnets[vm_index]`.
        return Err(WorldError::IndexOutOfRange {
            vm_index,
            pool: pool.to_string(),
            prefix,
        });
    }
    let subnet_size = 1u64 << (32 - prefix);
    let network = u64::from(u32::from(base)) + index * subnet_size;
    let broadcast = network + subnet_size - 1;
    if network + 2 > broadcast {
        return Err(WorldError::NoGuestAddress { prefix });
    }
    let network_addr = Ipv4Addr::from(network as u32);
    let gateway = Ipv4Addr::from((network + 1) as u32);
    let guest = Ipv4Addr::from((network + 2) as u32);
    Ok(IpPair {
        address: guest.to_string(),
        network_cidr: format!("{network_addr}/{prefix}"),
        gateway: gateway.to_string(),
    })
}

fn ipv6_pair(network: Ipv6Addr, prefix: u8) -> IpPair {
    let guest = Ipv6Addr::from(u128::from(network) + 1);
    IpPair {
        address: guest.to_string(),
        network_cidr: format!("{network}/{prefix}"),
        gateway: network.to_string(),
    }
}

/// Build the guest IPv6 pair from a `network/prefix` CIDR the agent
/// allocated or that the daemon persisted at create time. The CIDR's network
/// address becomes the gateway, guest = network + 1. The agent sends the
/// Python `str(IPv6Network(...))` form; Rust re-emits `network_cidr` in its
/// own notation, so the served string never depends on the sender's
/// formatting.
pub fn ipv6_from_cidr(cidr: &str) -> Result<IpPair, WorldError> {
    let (network, prefix) = parse_ipv6_cidr(cidr)?;
    if prefix >= 127 {
        // No room for a guest next to the gateway.
        return Err(WorldError::NoGuestAddress { prefix });
    }
    Ok(ipv6_pair(network, prefix))
}

fn parse_ipv4_cidr(pool: &str) -> Result<(Ipv4Addr, u8), WorldError> {
    let (address, len) = pool
        .split_once('/')
        .ok_or_else(|| WorldError::InvalidCidr {
            family: "4",
            pool: pool.to_string(),
        })?;
    let address: Ipv4Addr = address
        .parse()
        .map_err(|_| WorldError::InvalidCidrAddress {
            family: "4",
            pool: pool.to_string(),
        })?;
    let len: u8 = len.parse().map_err(|_| WorldError::InvalidCidrPrefix {
        family: "4",
        pool: pool.to_string(),
    })?;
    if len > 32 {
        return Err(WorldError::InvalidCidrPrefix {
            family: "4",
            pool: pool.to_string(),
        });
    }
    // Python's IPv4Network is strict: host bits must be zero.
    let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
    if u32::from(address) & !mask != 0 {
        return Err(WorldError::HostBitsSet {
            family: "4",
            pool: pool.to_string(),
        });
    }
    Ok((address, len))
}

fn parse_ipv6_cidr(pool: &str) -> Result<(Ipv6Addr, u8), WorldError> {
    let (address, len) = pool
        .split_once('/')
        .ok_or_else(|| WorldError::InvalidCidr {
            family: "6",
            pool: pool.to_string(),
        })?;
    let address: Ipv6Addr = address
        .parse()
        .map_err(|_| WorldError::InvalidCidrAddress {
            family: "6",
            pool: pool.to_string(),
        })?;
    let len: u8 = len.parse().map_err(|_| WorldError::InvalidCidrPrefix {
        family: "6",
        pool: pool.to_string(),
    })?;
    if len > 128 {
        return Err(WorldError::InvalidCidrPrefix {
            family: "6",
            pool: pool.to_string(),
        });
    }
    let mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - len)
    };
    if u128::from(address) & !mask != 0 {
        return Err(WorldError::HostBitsSet {
            family: "6",
            pool: pool.to_string(),
        });
    }
    Ok((address, len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tap::FakeTapBackend;
    use crate::test_fixtures;
    use crate::units::StaticUnitStates;

    fn test_settings(root: &std::path::Path) -> Settings {
        Settings::from_vars(
            [(
                "ALEPH_VM_EXECUTION_ROOT".to_string(),
                root.to_string_lossy().into_owned(),
            )]
            .into_iter(),
        )
        .unwrap()
    }

    /// Copy the committed fixtures into a temp EXECUTION_ROOT.
    fn populate_execution_root(root: &std::path::Path) {
        for hash in [
            test_fixtures::QEMU_HASH,
            test_fixtures::GPU_HASH,
            test_fixtures::CONFIDENTIAL_HASH,
        ] {
            let name = format!("{hash}-controller.json");
            std::fs::copy(test_fixtures::fixtures_dir().join(&name), root.join(&name)).unwrap();
        }
        std::fs::copy(
            test_fixtures::fixtures_dir().join("supervisor.sqlite3"),
            root.join("supervisor.sqlite3"),
        )
        .unwrap();
    }

    #[test]
    fn assembles_the_world_from_configs_units_and_sqlite() {
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        // An unparseable config must be skipped, never fatal (the Python
        // crash-loop lesson).
        std::fs::write(tmp.path().join("ffff-controller.json"), "{broken").unwrap();

        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[test_fixtures::QEMU_HASH]);
        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        assert_eq!(world.len(), 3, "the broken config is skipped");
        let qemu = &world.entries[test_fixtures::QEMU_HASH];
        assert!(qemu.adopted_running);
        assert_eq!(qemu.vm_index, 3);
        assert_ne!(qemu.times.defined_at_ns, 0);
        assert_ne!(qemu.times.started_at_ns, 0);
        assert_eq!(
            qemu.times.starting_at_ns, 0,
            "the restore path never sets starting_at"
        );
        assert_eq!(qemu.times.stopped_at_ns, 0);
        // vm_index 3 in the default 172.16.0.0/12 pool split into /24s.
        assert_eq!(
            qemu.ipv4,
            Some(IpPair {
                address: "172.16.3.2".to_string(),
                network_cidr: "172.16.3.0/24".to_string(),
                gateway: "172.16.3.1".to_string(),
            })
        );
        let hash = test_fixtures::QEMU_HASH;
        assert_eq!(
            qemu.ipv6,
            Some(IpPair {
                address: format!(
                    "fc00:1:2:3:3:{}:{}:{}1",
                    &hash[0..4],
                    &hash[4..8],
                    &hash[8..11]
                ),
                network_cidr: format!(
                    "fc00:1:2:3:3:{}:{}:{}0/124",
                    &hash[0..4],
                    &hash[4..8],
                    &hash[8..11]
                ),
                gateway: format!(
                    "fc00:1:2:3:3:{}:{}:{}0",
                    &hash[0..4],
                    &hash[4..8],
                    &hash[8..11]
                ),
            })
        );
        assert_eq!(qemu.port_forwards.len(), 2);

        // The GPU VM's unit is not active: stopped, no tap, no ports.
        let gpu = &world.entries[test_fixtures::GPU_HASH];
        assert!(!gpu.adopted_running);
        assert_ne!(gpu.times.stopped_at_ns, 0);
        assert_eq!(gpu.times.started_at_ns, 0);
        assert_eq!(gpu.ipv4, None);
        assert_eq!(gpu.ipv6, None);
        assert!(gpu.port_forwards.is_empty());
        assert_eq!(gpu.config.gpus.len(), 1);

        let confidential = &world.entries[test_fixtures::CONFIDENTIAL_HASH];
        assert_eq!(confidential.config.confidential().unwrap().sev_policy, 0x5);
    }

    #[test]
    fn adoption_serves_the_persisted_guest_ipv6() {
        // A config written after the agent took over IPv6 allocation carries
        // the assigned /124. Adoption must read it back verbatim instead of
        // re-deriving the scheme, so a deliberately off-scheme persisted value
        // is what the adopted entry serves.
        let tmp = tempfile::tempdir().unwrap();
        let hash = "e".repeat(64);
        let fixture = std::fs::read_to_string(
            test_fixtures::fixtures_dir()
                .join(format!("{}-controller.json", test_fixtures::QEMU_HASH)),
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&fixture).unwrap();
        value["vm_id"] = 12.into();
        value["vm_hash"] = hash.clone().into();
        let persisted = "fc00:1:2:3:3:dead:beef:0aa0/124";
        value["vm_configuration"]
            .as_object_mut()
            .unwrap()
            .insert("guest_ipv6_cidr".to_string(), persisted.into());
        std::fs::write(
            tmp.path().join(format!("{hash}-controller.json")),
            value.to_string(),
        )
        .unwrap();

        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[hash.as_str()]);
        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        let entry = &world.entries[hash.as_str()];
        assert!(entry.adopted_running);
        assert_eq!(
            entry.ipv6,
            Some(ipv6_from_cidr(persisted).unwrap()),
            "adoption must serve the persisted guest IPv6 verbatim"
        );
    }

    #[test]
    fn a_legacy_config_with_no_address_anywhere_is_hidden() {
        // No persisted address and no live tap: the daemon never derives
        // one, so the VM is hidden and queued like a failed reattach.
        let tmp = tempfile::tempdir().unwrap();
        let hash = "f".repeat(64);
        write_config(tmp.path(), &hash, 13, None);
        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[hash.as_str()]);

        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        assert!(!world.entries.contains_key(hash.as_str()));
        assert!(world.failed_reattach.contains_key(hash.as_str()));
        assert!(world.reserved_vm_indices.contains(&13));
    }

    #[test]
    fn a_legacy_stopped_config_adopts_without_an_address() {
        // A stopped VM needs no address until it starts, so a legacy config
        // is still listed (STOPPED); the start is what fails.
        let tmp = tempfile::tempdir().unwrap();
        let hash = "f".repeat(64);
        write_config(tmp.path(), &hash, 13, None);
        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::default();

        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        let entry = &world.entries[hash.as_str()];
        assert!(!entry.adopted_running);
        assert_eq!(entry.ipv6, None);
        assert_eq!(entry.config.guest_ipv6_cidr, None);
    }

    /// Write a copy of the QEMU fixture config under `hash` / `vm_id`,
    /// with an optional persisted guest IPv6.
    fn write_config(root: &std::path::Path, hash: &str, vm_id: i64, persisted: Option<&str>) {
        let fixture = std::fs::read_to_string(
            test_fixtures::fixtures_dir()
                .join(format!("{}-controller.json", test_fixtures::QEMU_HASH)),
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&fixture).unwrap();
        value["vm_id"] = vm_id.into();
        value["vm_hash"] = hash.into();
        let vm = value["vm_configuration"].as_object_mut().unwrap();
        vm.remove("guest_ipv6_cidr");
        if let Some(cidr) = persisted {
            vm.insert("guest_ipv6_cidr".to_string(), cidr.into());
        }
        std::fs::write(
            root.join(format!("{hash}-controller.json")),
            value.to_string(),
        )
        .unwrap();
    }

    #[test]
    fn a_legacy_config_adopts_the_address_live_on_its_tap() {
        // The production shape: allocated ::b0/124 by an older daemon, the
        // config predates persistence. The tap is the truth, whatever the
        // node's allocation policy, and the address is kept in memory.
        let tmp = tempfile::tempdir().unwrap();
        let hash = "1".repeat(64);
        write_config(tmp.path(), &hash, 8, None);
        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[hash.as_str()]);
        let taps = FakeTapBackend::new().with_ipv6_device("vmtap8", "fc00:1:2:3::b0/124");

        let world = build_world_view(&settings, &units, &[], &taps);

        let entry = &world.entries[hash.as_str()];
        assert_eq!(
            entry.ipv6,
            Some(ipv6_from_cidr("fc00:1:2:3::b0/124").unwrap()),
            "the live tap address must be adopted"
        );
        assert_eq!(
            entry.config.guest_ipv6_cidr.as_deref(),
            Some("fc00:1:2:3::b0/124"),
            "kept for the reconstructed spec and the next start"
        );
    }

    #[test]
    fn a_persisted_address_wins_over_the_tap() {
        let tmp = tempfile::tempdir().unwrap();
        let hash = "2".repeat(64);
        write_config(tmp.path(), &hash, 8, Some("fc00:1:2:3::20/124"));
        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[hash.as_str()]);
        let taps = FakeTapBackend::new().with_ipv6_device("vmtap8", "fc00:1:2:3::b0/124");

        let world = build_world_view(&settings, &units, &[], &taps);

        assert_eq!(
            world.entries[hash.as_str()].ipv6,
            Some(ipv6_from_cidr("fc00:1:2:3::20/124").unwrap())
        );
    }

    #[test]
    fn ipv6_holder_finds_live_and_persisted_overlaps() {
        let tmp = tempfile::tempdir().unwrap();
        let running = "3".repeat(64);
        let stopped = "4".repeat(64);
        write_config(tmp.path(), &running, 8, Some("fc00:1:2:3::10/124"));
        write_config(tmp.path(), &stopped, 9, Some("fc00:1:2:3::50/124"));
        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[running.as_str()]);
        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());
        let pair = |cidr: &str| ipv6_from_cidr(cidr).unwrap();

        assert_eq!(
            world.ipv6_holder(&pair("fc00:1:2:3::10/124"), "new"),
            Some((running.clone(), "fc00:1:2:3::10/124".to_string()))
        );
        assert_eq!(
            world.ipv6_holder(&pair("fc00:1:2:3::50/124"), "new"),
            Some((stopped.clone(), "fc00:1:2:3::50/124".to_string())),
            "a stopped VM keeps its persisted subnet"
        );
        // A wider request covering a held /124 overlaps too.
        assert!(
            world
                .ipv6_holder(&pair("fc00:1:2:3::/120"), "new")
                .is_some()
        );
        assert_eq!(world.ipv6_holder(&pair("fc00:1:2:3::20/124"), "new"), None);
        // A VM never collides with itself (an idempotent re-create).
        assert_eq!(
            world.ipv6_holder(&pair("fc00:1:2:3::10/124"), &running),
            None
        );
    }

    #[test]
    fn ipv6_from_tap_masks_the_host_address_to_its_network() {
        let taps = FakeTapBackend::new()
            .with_ipv6_device("vmtap3", "fc00:1:2:3::b0/124")
            .with_ipv6_device("vmtap4", "fc00:1:2:3::b5/124")
            .with_ipv6_device("vmtap5", "fc00:1:2:3::1/128");
        assert_eq!(
            ipv6_from_tap(&taps, 3),
            Some(ipv6_from_cidr("fc00:1:2:3::b0/124").unwrap())
        );
        assert_eq!(
            ipv6_from_tap(&taps, 4),
            Some(ipv6_from_cidr("fc00:1:2:3::b0/124").unwrap())
        );
        assert_eq!(ipv6_from_tap(&taps, 5), None, "no room for a guest");
        assert_eq!(ipv6_from_tap(&taps, 6), None, "no such tap");
    }

    #[test]
    fn an_empty_or_missing_execution_root_is_an_empty_world() {
        let tmp = tempfile::tempdir().unwrap();
        let settings = test_settings(&tmp.path().join("does-not-exist"));
        let units = StaticUnitStates::default();
        assert!(build_world_view(&settings, &units, &[], &FakeTapBackend::new()).is_empty());
    }

    #[test]
    fn networking_disabled_means_no_ip_assignments() {
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        let mut settings = test_settings(tmp.path());
        settings.allow_vm_networking = false;
        let units = StaticUnitStates::with_active_vms(&[test_fixtures::QEMU_HASH]);
        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());
        let qemu = &world.entries[test_fixtures::QEMU_HASH];
        assert_eq!(qemu.ipv4, None);
        assert_eq!(qemu.ipv6, None);
    }

    #[test]
    fn a_vm_whose_unit_failed_adopts_as_a_death() {
        // A planned VM whose guest died across a daemon restart must report
        // FAILED, so the agent rebuilds it instead of reading the deliberate
        // stop a STOPPED stamp would claim.
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        let settings = test_settings(tmp.path());
        let units = crate::units::FakeSystemd::new();
        units.set_state(&controller_unit_name(test_fixtures::QEMU_HASH), "failed");

        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        let entry = &world.entries[test_fixtures::QEMU_HASH];
        assert!(entry.adopted_failed);
        assert!(!entry.adopted_running);
        assert_ne!(entry.times.started_at_ns, 0, "the VM did run");
        assert_eq!(entry.times.stopped_at_ns, 0, "a death is not a stop");
        assert_eq!(
            crate::service::vm_status(&entry.times, false, UnitLiveness::Failed),
            supervisor_proto::pb::VmStatus::Failed
        );
        // The runtime attachment list is rebuilt only for a live VM; the
        // config's claim on the card is what survives, untouched here.
        assert!(entry.gpus.is_empty());
    }

    #[test]
    fn a_vm_stopped_through_stop_vm_still_adopts_stopped() {
        // StopVm leaves the unit inactive, which is the owner's decision and
        // must keep reporting STOPPED across a restart.
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        let settings = test_settings(tmp.path());
        let units = crate::units::FakeSystemd::with_active_vms(&[test_fixtures::QEMU_HASH]);
        let unit = controller_unit_name(test_fixtures::QEMU_HASH);
        crate::units::stop_and_disable(&units, &unit).unwrap();
        assert_eq!(units.get_active_state(&unit), "inactive");

        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        let entry = &world.entries[test_fixtures::QEMU_HASH];
        assert!(!entry.adopted_failed);
        assert_eq!(entry.times.stopped_at_ns, entry.times.defined_at_ns);
        assert_eq!(entry.times.started_at_ns, 0);
        assert_eq!(
            crate::service::vm_status(&entry.times, false, UnitLiveness::Dead),
            supervisor_proto::pb::VmStatus::Stopped
        );
    }

    #[test]
    fn a_unit_mid_job_at_adoption_is_not_stamped_stopped() {
        // A unit systemd is still working on has neither died nor stopped;
        // stamping it stopped would freeze the VM there for the rest of its
        // life, the same trap the failed unit was in.
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        let settings = test_settings(tmp.path());
        let units = crate::units::FakeSystemd::new();
        units.set_state(
            &controller_unit_name(test_fixtures::QEMU_HASH),
            "activating",
        );

        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        let entry = &world.entries[test_fixtures::QEMU_HASH];
        assert!(!entry.adopted_failed);
        assert_eq!(entry.times.stopped_at_ns, 0);
        assert_eq!(entry.times.started_at_ns, 0);
    }

    #[test]
    fn a_bus_failure_at_boot_leaves_statuses_undecided() {
        // R2: a transient bus outage must NOT stamp every VM stopped
        // forever; the entries carry no stopped_at (and no started_at), so
        // vm_status follows the live unit state once the bus answers.
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        let settings = test_settings(tmp.path());
        let world = build_world_view(
            &settings,
            &crate::units::UnreachableBus,
            &[],
            &FakeTapBackend::new(),
        );

        assert_eq!(world.len(), 3);
        for entry in world.entries.values() {
            assert!(!entry.adopted_running);
            assert!(!entry.adopted_failed, "an unanswered bus is not a death");
            assert_ne!(entry.times.defined_at_ns, 0);
            assert_eq!(entry.times.stopped_at_ns, 0, "unknown is not stopped");
            assert_eq!(entry.times.started_at_ns, 0);
            assert_eq!(entry.ipv4, None);
            assert_eq!(entry.ipv6, None);
            assert!(entry.port_forwards.is_empty());
        }
    }

    #[test]
    fn non_regular_and_oversized_configs_are_skipped() {
        // R5b: a directory (or FIFO/symlink) named like a config must not be
        // opened, and a huge file must not be buffered.
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        std::fs::create_dir(tmp.path().join("dddd-controller.json")).unwrap();
        std::fs::write(
            tmp.path().join("eeee-controller.json"),
            vec![b'x'; (MAX_CONFIG_BYTES + 1) as usize],
        )
        .unwrap();

        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[test_fixtures::QEMU_HASH]);
        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());
        assert_eq!(world.len(), 3, "only the three real fixture configs");
    }

    #[test]
    fn the_world_is_keyed_on_the_embedded_vm_hash() {
        // P2: Python keys everything on Configuration.vm_hash; a config
        // file whose name disagrees is served under the embedded hash.
        let tmp = tempfile::tempdir().unwrap();
        let fixture = test_fixtures::fixtures_dir()
            .join(format!("{}-controller.json", test_fixtures::QEMU_HASH));
        let misnamed = format!("{}-controller.json", "0".repeat(64));
        std::fs::copy(&fixture, tmp.path().join(&misnamed)).unwrap();

        let settings = test_settings(tmp.path());
        // The unit lookup must also use the embedded hash.
        let units = StaticUnitStates::with_active_vms(&[test_fixtures::QEMU_HASH]);
        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        assert_eq!(world.len(), 1);
        let entry = &world.entries[test_fixtures::QEMU_HASH];
        assert!(
            entry.adopted_running,
            "unit name derives from the embedded hash"
        );
        assert!(!world.entries.contains_key(&"0".repeat(64)));
    }

    #[test]
    fn duplicate_vm_indices_adopt_only_the_first_active_config() {
        // P1: Python's claimed_vm_ids guard. Two ACTIVE configs share
        // vm_index 3; the first in sorted file order wins, the second is
        // not served at all.
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        let clone_hash = "a".repeat(64);
        let fixture = std::fs::read_to_string(
            test_fixtures::fixtures_dir()
                .join(format!("{}-controller.json", test_fixtures::QEMU_HASH)),
        )
        .unwrap();
        let mut value: serde_json::Value = serde_json::from_str(&fixture).unwrap();
        value["vm_hash"] = clone_hash.clone().into();
        // "aaaa..." sorts before the real fixture file name, so the clone
        // is scanned (and claims vm_index 3) first.
        std::fs::write(
            tmp.path().join(format!("{clone_hash}-controller.json")),
            value.to_string(),
        )
        .unwrap();

        let settings = test_settings(tmp.path());
        let units =
            StaticUnitStates::with_active_vms(&[clone_hash.as_str(), test_fixtures::QEMU_HASH]);
        let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        assert!(world.entries.contains_key(clone_hash.as_str()));
        assert!(
            !world.entries.contains_key(test_fixtures::QEMU_HASH),
            "the duplicate is skipped, not served"
        );
        assert_eq!(world.len(), 3, "the clone plus the two inactive fixtures");
    }

    #[test]
    fn an_ip_derivation_failure_hides_the_vm() {
        // P5: restarted Python answers NOT_FOUND for a VM whose reattach
        // failed (retry queue); a running VM whose IP cannot be derived is
        // hidden, not served with empty assignments.
        for bad_index in [-1, 4096] {
            let tmp = tempfile::tempdir().unwrap();
            populate_execution_root(tmp.path());
            let fixture = tmp
                .path()
                .join(format!("{}-controller.json", test_fixtures::QEMU_HASH));
            let mut value: serde_json::Value =
                serde_json::from_str(&std::fs::read_to_string(&fixture).unwrap()).unwrap();
            value["vm_id"] = bad_index.into();
            std::fs::write(&fixture, value.to_string()).unwrap();

            let settings = test_settings(tmp.path());
            let units = StaticUnitStates::with_active_vms(&[test_fixtures::QEMU_HASH]);
            let world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());
            assert!(
                !world.entries.contains_key(test_fixtures::QEMU_HASH),
                "vm_index {bad_index} must hide the VM"
            );
            assert_eq!(world.len(), 2, "the other fixtures are unaffected");
        }
    }

    #[test]
    fn entries_enumerate_in_insertion_order_like_the_python_dict() {
        // Adoption is sorted config order; the fixture hashes sort as
        // 1806... (confidential), c110... (qemu), f2fb... (gpu). The
        // ordinals must pin that order for enumeration even though the
        // BTreeMap would give it anyway; a replacement keeps its position
        // (Python dict assignment to an existing key).
        let tmp = tempfile::tempdir().unwrap();
        populate_execution_root(tmp.path());
        let settings = test_settings(tmp.path());
        let units = StaticUnitStates::with_active_vms(&[test_fixtures::QEMU_HASH]);
        let mut world = build_world_view(&settings, &units, &[], &FakeTapBackend::new());

        let order: Vec<&str> = world
            .ordered_entries()
            .iter()
            .map(|entry| entry.vm_hash.as_str())
            .collect();
        assert_eq!(
            order,
            vec![
                test_fixtures::CONFIDENTIAL_HASH,
                test_fixtures::QEMU_HASH,
                test_fixtures::GPU_HASH,
            ]
        );

        // A new key goes last, whatever its hash sorts like.
        let mut newcomer = world.entries[test_fixtures::QEMU_HASH].clone();
        newcomer.vm_hash = "0".repeat(64);
        newcomer.vm_index = 9;
        world.insert_entry(newcomer);
        let order: Vec<&str> = world
            .ordered_entries()
            .iter()
            .map(|entry| entry.vm_hash.as_str())
            .collect();
        assert_eq!(order.last().copied(), Some("0".repeat(64)).as_deref());
        assert_eq!(order.len(), 4);

        // Replacing an existing key keeps its position.
        let replacement = world.entries[test_fixtures::QEMU_HASH].clone();
        world.insert_entry(replacement);
        let order: Vec<&str> = world
            .ordered_entries()
            .iter()
            .map(|entry| entry.vm_hash.as_str())
            .collect();
        assert_eq!(order[1], test_fixtures::QEMU_HASH);
    }

    #[test]
    fn ipv4_math_matches_the_python_pool() {
        // Python: list(IPv4Network("172.16.0.0/12").subnets(new_prefix=24))[5]
        // is 172.16.5.0/24; guest [2], host [1].
        let pair = ipv4_assignment("172.16.0.0/12", 24, 5).unwrap();
        assert_eq!(pair.address, "172.16.5.2");
        assert_eq!(pair.network_cidr, "172.16.5.0/24");
        assert_eq!(pair.gateway, "172.16.5.1");
        // Subnet 300 crosses the second octet: 172.17.44.0/24.
        let pair = ipv4_assignment("172.16.0.0/12", 24, 300).unwrap();
        assert_eq!(pair.network_cidr, "172.17.44.0/24");

        assert!(ipv4_assignment("172.16.0.0/12", 24, 4096).is_err());
        let host_bits_error = ipv4_assignment("172.16.0.1/12", 24, 0).unwrap_err();
        assert!(
            matches!(
                &host_bits_error,
                WorldError::HostBitsSet { family: "4", .. }
            ),
            "host bits set: {host_bits_error:?}"
        );
        assert!(
            ipv4_assignment("172.16.0.0/24", 12, 0).is_err(),
            "prefix above pool"
        );
    }

    #[test]
    fn a_requested_ipv6_becomes_the_tap_pair() {
        // The agent sends the Python `str(IPv6Network(...))` CIDR; the pair
        // is gateway = network, guest = network + 1, in Rust notation.
        let pair = ipv6_from_cidr("2a01:240:2:c8:3:abcd:ef01:2340/124").unwrap();
        assert_eq!(pair.network_cidr, "2a01:240:2:c8:3:abcd:ef01:2340/124");
        assert_eq!(pair.address, "2a01:240:2:c8:3:abcd:ef01:2341");
        assert_eq!(pair.gateway, "2a01:240:2:c8:3:abcd:ef01:2340");
        // Re-parsing the daemon's own notation is idempotent.
        assert_eq!(ipv6_from_cidr(&pair.network_cidr).unwrap(), pair);
        // Leading zeros are re-emitted canonically.
        assert_eq!(
            ipv6_from_cidr("fc00:1:2:3:3:dead:beef:0aa0/124")
                .unwrap()
                .network_cidr,
            "fc00:1:2:3:3:dead:beef:aa0/124"
        );
        assert!(ipv6_from_cidr("fc00::1/124").is_err(), "host bits set");
        assert!(ipv6_from_cidr("fc00::/127").is_err(), "no guest address");
        assert!(ipv6_from_cidr("").is_err());
        assert!(ipv6_from_cidr("not-an-address/124").is_err());
    }

    #[test]
    fn derive_tap_assignment_pairs_the_index_ipv4_with_the_given_ipv6() {
        let tmp = tempfile::tempdir().unwrap();
        let settings = test_settings(tmp.path());
        let requested = "2a01:240:2:c8:3:dead:beef:caf0/124";
        let (ipv4, ipv6) = derive_tap_assignment(&settings, 3, requested).unwrap();
        assert_eq!(ipv4.network_cidr, "172.16.3.0/24");
        assert_eq!(ipv6, ipv6_from_cidr(requested).unwrap());
        assert!(derive_tap_assignment(&settings, 3, "").is_err());
    }
}
