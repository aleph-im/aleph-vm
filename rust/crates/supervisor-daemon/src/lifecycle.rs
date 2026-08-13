//! The persistent-VM lifecycle (increment 3): CreateVm/StopVm/StartVm/
//! RebootVm/ReinstallVm/DeleteVm, the port-forward mutations,
//! RecreateNetwork and the boot-time reconcile (adoption step 5).
//!
//! Ported 1:1 from the Python LocalSupervisor + VmPool + VmExecution
//! composition (src/aleph/vm/supervisor/local.py, src/aleph/vm/pool.py,
//! src/aleph/vm/models.py), QEMU persistent instances only: ephemeral
//! Firecracker programs are increment 4, confidential creation increment 6.
//!
//! Every function here is BLOCKING (subprocesses, D-Bus round trips, sqlite,
//! poll-with-sleep waits); the gRPC handlers hop to the blocking pool, the
//! same way the Python daemon awaits these flows on its event loop. World
//! access uses the blocking lock forms; guards are never held across the
//! slow edges except where the Python creation_lock semantics require
//! serialization (one create at a time, held across the whole boot wait).

use std::sync::Arc;
use std::time::Duration;

use supervisor_proto::pb;

use crate::controller_config::{
    self, QemuVmConfig, VmConfiguration, WrittenControllerConfig, WrittenControllerSettings,
    WrittenGpu, WrittenHostVolume, WrittenQemuVmConfiguration, parse_controller_config,
};
use crate::firecracker::{ProgramBootError, ProgramBootRequest};
use crate::service::DaemonState;
use crate::tap::TapAssignment;
use crate::units::{self, controller_unit_name};
use crate::world::{self, AttachedGpu, ProgramEntry, VmEntry, VmTimes, VmType, now_ns};
use crate::{checks, cloudinit, dhcp, nft, ports};

/// The closed error vocabulary slice these RPCs can produce, mapped in
/// service.rs onto the same gRPC status codes and ErrorDetail trailers as
/// src/aleph/vm/supervisor/grpc_server.py.
#[derive(Debug)]
pub enum RpcError {
    /// VmNotFoundError: message is the vm_id itself.
    NotFound(String),
    /// VmAlreadyExistsError.
    AlreadyExists(String),
    /// InsufficientResourcesError.
    InsufficientResources(String),
    /// InvalidBackendError.
    InvalidBackend(String),
    /// BackupNotFoundError: message is the backup_id itself (NOT_FOUND,
    /// trailer code BACKUP_NOT_FOUND).
    BackupNotFound(String),
    /// MicroVMInitError: the guest never signalled ready (INTERNAL,
    /// trailer code MICROVM_INIT_FAILED; the Python exception text is
    /// empty).
    MicroVmInit(String),
    /// NotImplementedSupervisorError (UNIMPLEMENTED, trailer code INTERNAL).
    Unimplemented(String),
    /// InternalSupervisorError, the translating_errors catch-all.
    Internal(String),
}

impl From<String> for RpcError {
    fn from(message: String) -> Self {
        RpcError::Internal(message)
    }
}

/// Poll/sleep pacing; production values mirror the Python constants, tests
/// shrink them to keep hermetic runs fast.
#[derive(Debug, Clone)]
pub struct Pacing {
    /// wait_for_controller_ready: sleep between ActiveState polls (2s) and
    /// before the crash-loop double check (2s).
    pub ready_poll: Duration,
    /// wait_for_controller_stopped: 1s between polls.
    pub stop_poll: Duration,
    /// TapInterface.delete's 100ms "Device/Resource busy" grace.
    pub tap_delete_delay: Duration,
}

impl Default for Pacing {
    fn default() -> Self {
        Self {
            ready_poll: Duration::from_secs(2),
            stop_poll: Duration::from_secs(1),
            tap_delete_delay: Duration::from_millis(100),
        }
    }
}

impl Pacing {
    /// Zero waits for hermetic tests.
    pub fn instant() -> Self {
        Self {
            ready_poll: Duration::ZERO,
            stop_poll: Duration::ZERO,
            tap_delete_delay: Duration::ZERO,
        }
    }
}

// ── Shared helpers ──────────────────────────────────────────────────────

/// The host-network mutation lock (`DaemonState::net_lock`): serializes
/// host-port allocation-through-persistence, tap/nftables setup and
/// teardown, and RecreateNetwork's flush-and-rebuild. Innermost lock
/// (creation_lock, then vm_lock, then this); never held across the systemd
/// waits, and never held while calling a function that acquires it.
fn net_lock(state: &DaemonState) -> std::sync::MutexGuard<'_, ()> {
    state
        .net_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The per-VM mutation lock. Python relies on per-execution locks and
/// event-loop interleaving; blocking threads need the real thing.
fn vm_lock(state: &DaemonState, vm_id: &str) -> Arc<std::sync::Mutex<()>> {
    let mut locks = state
        .vm_locks
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    locks
        .entry(vm_id.to_string())
        .or_insert_with(|| Arc::new(std::sync::Mutex::new(())))
        .clone()
}

fn entry_snapshot(state: &DaemonState, vm_id: &str) -> Option<VmEntry> {
    state.world.blocking_read().entries.get(vm_id).cloned()
}

fn with_entry_mut<R>(
    state: &DaemonState,
    vm_id: &str,
    mutate: impl FnOnce(&mut VmEntry) -> R,
) -> Option<R> {
    state
        .world
        .blocking_write()
        .entries
        .get_mut(vm_id)
        .map(mutate)
}

// ── NUMA placement (Phase 3 increment C1) ───────────────────────────────
//
// The supervisor auto-places persistent QEMU VMs on NUMA nodes (pack-first)
// and pins their vCPUs through the systemd `AllowedCPUs=` property, written
// as a per-instance drop-in. There is NO Python oracle; the reference is the
// aleph-cvm donor. Every function is inert (returns None / does nothing)
// UNLESS the host has more than one NUMA node (`is_placement_active`). A
// single-node host - every CONFIG_NUMA kernel exposes node0 even on one
// socket - is treated exactly like a non-NUMA host: pinning to the only node
// is all host CPUs, a no-op, so no drop-in, no daemon-reload, no reservation,
// and `VmInfo.numa_node` stays None. The topology is still REPORTED in
// `HostInfo.numa_nodes` for a single node (that is pure reporting).

/// Choose a NUMA node for a new VM and reserve its vCPUs in the ledger.
///
/// Honors a requested `numa_node` when the spec carries one (decision 4),
/// otherwise packs onto the first node (node 0, then 1, ...) with room.
/// Returns `Ok(None)` when placement is inert (fewer than two nodes). The
/// ledger mutation is serialized by the caller's creation lock.
fn place_vm_numa(
    state: &DaemonState,
    vcpus: u32,
    memory_mib: u64,
    requested: Option<u32>,
) -> Result<Option<crate::numa::NumaPlacement>, RpcError> {
    if !state.numa.is_placement_active() {
        return Ok(None);
    }
    // Hugepage backing is opt-in (ALEPH_VM_NUMA_HUGEPAGES); when off, the
    // allocator tracks only vCPUs and never selects a page size, so C2 delivers
    // just the regular-page NUMA memory binding. The hugepage pools are u32
    // pages; a memory value beyond u32 MB saturates (no host has that RAM).
    let uses_hugepages = state.host.settings.numa_hugepages;
    let memory_mb = memory_mib.min(u32::MAX as u64) as u32;
    let mut ledger = state
        .numa_ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match ledger.allocate(vcpus, memory_mb, requested, uses_hugepages) {
        Ok(placement) => Ok(Some(placement)),
        Err(crate::numa::PlacementError::UnknownNode(message)) => {
            // A bad client argument (InvalidArgument on the wire).
            Err(RpcError::InvalidBackend(message))
        }
        Err(crate::numa::PlacementError::Insufficient(message)) => {
            Err(RpcError::InsufficientResources(message))
        }
    }
}

/// Write the `AllowedCPUs=` drop-in for a placed VM. The controller is an
/// instance of the shared `aleph-vm-controller@.service` template, so a
/// per-VM pin can only live in a per-instance drop-in, not in the unit file.
/// Called inside the create boot closure, before the controller starts, so
/// the pin applies from the first instruction. The daemon-reload only
/// matters when the instance unit is still loaded from a previous life of
/// the same vm_hash (stop then recreate); on a first boot it is a no-op.
fn apply_numa_dropin(
    state: &DaemonState,
    vm_id: &str,
    placement: &crate::numa::NumaPlacement,
) -> Result<(), String> {
    crate::numa::write_cpuset_dropin(
        &state.host.settings.systemd_unit_dir,
        vm_id,
        &placement.cpuset,
    )
    .map_err(|error| format!("{error:#}"))?;
    // A freshly written drop-in only applies after a reload if the unit was
    // already loaded; harmless on first load.
    state.units.reload()?;
    tracing::info!(
        vm_id,
        node = placement.node,
        cpuset = placement.cpuset,
        "pinned controller vCPUs via AllowedCPUs"
    );
    Ok(())
}

/// The hugepage backing a written config recorded: its memory in MB (saturated
/// into the u32 page-pool domain, like `place_vm_numa`) and the page size the
/// allocator selected (`None` for regular pages). Used to return the exact
/// pages a VM reserved on release and to re-register them at adoption.
fn config_hugepage_backing(config: &QemuVmConfig) -> (u32, Option<crate::numa::HugePageSize>) {
    let memory_mb = config.mem_size_mb.count().min(u32::MAX as u64) as u32;
    let hugepage_size = config
        .hugepage_size
        .as_deref()
        .and_then(crate::numa::HugePageSize::from_qemu);
    (memory_mb, hugepage_size)
}

/// Release a VM's reserved vCPUs AND hugepages from the ledger (idempotent-safe:
/// saturating subtracts). Passing the VM's `memory_mb` + `hugepage_size` returns
/// its reserved pages to the node's pool, so an enabled hugepage pool does not
/// leak on delete/failed-create. No-op when placement is inert.
fn release_numa_placement(
    state: &DaemonState,
    node: u32,
    vcpus: u32,
    memory_mb: u32,
    hugepage_size: Option<crate::numa::HugePageSize>,
) {
    if !state.numa.is_placement_active() {
        return;
    }
    state
        .numa_ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .release(node, vcpus, memory_mb, hugepage_size);
}

/// Remove a VM's NUMA drop-in on teardown and reload systemd. Best effort:
/// a failure is logged, never fatal to a delete. Deliberately NOT gated on
/// `is_placement_active` or `entry.numa_node`: a drop-in written under an
/// earlier topology must not outlive its VM (systemd would apply it to a
/// future same-hash controller), and a VM reconciled as unpinned (its cpuset
/// no longer matches any node) still has a file to clean up. The unpinned
/// common case stays cheap because the daemon-reload only runs when a file
/// was actually removed.
fn remove_numa_dropin(state: &DaemonState, vm_id: &str) {
    let removed =
        match crate::numa::remove_cpuset_dropin(&state.host.settings.systemd_unit_dir, vm_id) {
            Ok(removed) => removed,
            Err(error) => {
                tracing::warn!(
                    vm_id,
                    error = format!("{error:#}"),
                    "failed to remove the NUMA drop-in"
                );
                return;
            }
        };
    if !removed {
        return;
    }
    if let Err(error) = state.units.reload() {
        tracing::warn!(
            vm_id,
            error,
            "daemon-reload after NUMA drop-in removal failed"
        );
    }
}

/// Rebuild a VM's ledger reservation from its on-disk `AllowedCPUs` drop-in
/// and return the effective node. Used at boot reconcile and when
/// re-adopting a live controller: a VM whose drop-in maps to a known node is
/// re-registered so pack-first stays correct across a daemon restart; one
/// with no drop-in (or an unrecognized cpuset) is treated as UNPINNED and
/// counts against no node (design section 8 risk: pre-NUMA adopted VMs must
/// not be silently attributed to node 0).
fn reconstruct_numa_placement(
    state: &DaemonState,
    vm_id: &str,
    vcpus: u32,
    memory_mb: u32,
    hugepage_size: Option<crate::numa::HugePageSize>,
) -> Option<u32> {
    if !state.numa.is_placement_active() {
        return None;
    }
    // Read the on-disk drop-in BEFORE taking the ledger mutex: the fs read
    // must not run while the std::Mutex is held (FIX 8).
    let cpuset = crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, vm_id)?;
    let mut ledger = state
        .numa_ledger
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let node = ledger.node_for_cpuset(&cpuset)?;
    // Re-register vCPUs AND the VM's hugepage usage (from its written config)
    // so the page pool is correct across a daemon restart, not reset to 0.
    ledger.register(node, vcpus, memory_mb, hugepage_size);
    tracing::info!(
        vm_id,
        node,
        cpuset,
        "re-registered NUMA placement from the AllowedCPUs drop-in"
    );
    Some(node)
}

/// Rebuild the NUMA placement ledger at boot from the effective placement of
/// every adopted-running VM (design section 8). Runs unconditionally at
/// startup, independent of `reconcile_boot` (which is gated on networking):
/// the ledger must be consistent even on a host with `ALLOW_VM_NETWORKING`
/// off. Adopted VMs with no `AllowedCPUs` drop-in are left unpinned.
///
/// INVARIANT (no double-count with `readopt_live_controller`): this runs
/// EXACTLY ONCE at boot, before the socket exists, over the boot-time world;
/// `reconstruct_numa_placement` `register`s each adopted entry once.
/// `readopt_live_controller` also reconstructs+registers, but ONLY for a
/// controller that is live yet NOT tracked - a set disjoint from what this
/// pass sees. An entry counted here stays tracked until DeleteVm (which
/// releases), and nothing turns a counted, tracked entry back into an
/// untracked-but-live one, so readopt can never re-register a VM this pass
/// already counted. The two paths are therefore mutually exclusive per VM
/// and neither needs to be idempotent.
pub fn reconcile_numa_ledger(state: &DaemonState) {
    if !state.numa.is_placement_active() {
        return;
    }
    let adopted: Vec<(String, u32, u32, Option<crate::numa::HugePageSize>)> = state
        .world
        .blocking_read()
        .ordered_entries()
        .into_iter()
        .filter(|entry| entry.adopted_running && !entry.is_program)
        .map(|entry| {
            let (memory_mb, hugepage_size) = config_hugepage_backing(&entry.config);
            (
                entry.vm_hash.clone(),
                entry.config.vcpu_count,
                memory_mb,
                hugepage_size,
            )
        })
        .collect();
    for (vm_id, vcpus, memory_mb, hugepage_size) in adopted {
        let node = reconstruct_numa_placement(state, &vm_id, vcpus, memory_mb, hugepage_size);
        with_entry_mut(state, &vm_id, |entry| entry.numa_node = node);
    }
}

/// Python `_is_running` for one persistent execution: a batched-state
/// lookup that degrades to "inactive" on a bus failure (ledger entry 13).
fn unit_active(state: &DaemonState, unit: &str) -> bool {
    match state
        .units
        .active_states(std::slice::from_ref(&unit.to_string()))
    {
        Ok(states) => states.get(unit).copied().unwrap_or(false),
        Err(error) => {
            tracing::error!(error, "Failed to get services active states");
            false
        }
    }
}

/// AlephQemuInstance.enable_networking: the spec asked for internet access
/// (bool(interface_name) for adopted VMs) AND host networking is allowed.
fn networking_enabled(state: &DaemonState, entry: &VmEntry) -> bool {
    state.host.settings.allow_vm_networking
        && entry
            .config
            .interface_name
            .as_deref()
            .is_some_and(|name| !name.is_empty())
}

fn network_interface(state: &DaemonState) -> String {
    state.host.network_interface.clone().unwrap_or_default()
}

/// Where per-tap DHCP lease files live: `{EXECUTION_ROOT}/dhcp` (increment
/// D2). One lease file per SNP VM so concurrent per-tap servers never clobber
/// a shared database.
fn dhcp_lease_dir(state: &DaemonState) -> std::path::PathBuf {
    state.host.settings.execution_root.join("dhcp")
}

/// Python `_is_running`: systemd for persistent VMs, times for ephemeral
/// programs (`starting_at and not stopping_at`).
pub(crate) fn entry_running(state: &DaemonState, entry: &VmEntry) -> bool {
    if entry.is_program {
        entry.times.starting_at_ns != 0 && entry.times.stopping_at_ns == 0
    } else {
        unit_active(state, &entry.unit_name())
    }
}

/// Python `_status_snapshot`: the wire status of an entry right now, with a
/// live unit query for the running flag. Every mutation snapshots it before
/// acting so the emitted event carries the pre-mutation status.
fn status_snapshot(state: &DaemonState, entry: &VmEntry) -> pb::VmStatus {
    crate::service::vm_status(&entry.times, entry_running(state, entry))
}

fn chain_prefix(state: &DaemonState) -> &str {
    &state.host.settings.nftables_chain_prefix
}

/// The tap assignment of an entry; derives (and stores) it when absent
/// (adopted-stopped entries have none until StartVm).
fn tap_assignment(state: &DaemonState, vm_id: &str) -> Result<TapAssignment, String> {
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| format!("no entry for {vm_id}"))?;
    if let (Some(ipv4), Some(ipv6)) = (&entry.ipv4, &entry.ipv6) {
        return Ok(TapAssignment::new(
            entry.vm_index,
            ipv4.clone(),
            ipv6.clone(),
        ));
    }
    let vm_type = if entry.is_program {
        VmType::Microvm
    } else {
        VmType::Instance
    };
    let mut world = state.world.blocking_write();
    let mut ordinal = world.ipv6_dynamic_ordinal;
    let (ipv4, ipv6) = world::derive_tap_assignment(
        &state.host.settings,
        entry.vm_index,
        vm_id,
        vm_type,
        &mut ordinal,
    )
    .map_err(|error| error.to_string())?;
    world.ipv6_dynamic_ordinal = ordinal;
    if let Some(entry) = world.entries.get_mut(vm_id) {
        entry.ipv4 = Some(ipv4.clone());
        entry.ipv6 = Some(ipv6.clone());
    }
    Ok(TapAssignment::new(entry.vm_index, ipv4, ipv6))
}

// ── nftables application (fetch + pure commands + run) ──────────────────

fn nft_setup_vm(state: &DaemonState, vm_index: i64, device_name: &str) -> Result<(), String> {
    let ruleset = nft::fetch_ruleset(&*state.nft);
    let commands = nft::setup_vm_commands(
        &ruleset,
        vm_index,
        device_name,
        &network_interface(state),
        chain_prefix(state),
        state.host.settings.ipv6_forwarding_enabled,
    )
    .map_err(|error| error.to_string())?;
    nft::run_commands_logged(&*state.nft, &commands);
    Ok(())
}

/// Python `teardown_nftables_for_vm`: remove_chain fetches the ruleset per
/// chain (the first removal changes what the second sees).
fn nft_teardown_vm(state: &DaemonState, vm_index: i64) {
    let prefix = chain_prefix(state);
    for chain in [
        format!("{prefix}-vm-nat-{vm_index}"),
        format!("{prefix}-vm-filter-{vm_index}"),
    ] {
        let ruleset = nft::fetch_ruleset(&*state.nft);
        let commands = nft::remove_chain_commands(&ruleset, &chain);
        nft::run_commands_logged(&*state.nft, &commands);
    }
}

fn nft_add_redirect(
    state: &DaemonState,
    vm_index: i64,
    guest_ipv4: &str,
    host_port: u32,
    vm_port: u32,
    protocol: &str,
) -> Result<(), String> {
    let ruleset = nft::fetch_ruleset(&*state.nft);
    let commands = nft::add_port_redirect_commands(
        &ruleset,
        vm_index,
        guest_ipv4,
        host_port,
        vm_port,
        protocol,
        &network_interface(state),
        chain_prefix(state),
    )
    .map_err(|error| error.to_string())?;
    nft::run_commands_logged(&*state.nft, &commands);
    Ok(())
}

fn nft_remove_redirect(
    state: &DaemonState,
    device_name: &str,
    guest_ipv4: &str,
    host_port: u32,
    vm_port: u32,
    protocol: &str,
) -> Result<(), String> {
    let ruleset = nft::fetch_ruleset(&*state.nft);
    let commands = nft::remove_port_redirect_commands(
        &ruleset,
        device_name,
        guest_ipv4,
        host_port,
        vm_port,
        protocol,
        &network_interface(state),
        chain_prefix(state),
    )
    .map_err(|error| error.to_string())?;
    nft::run_commands_logged(&*state.nft, &commands);
    Ok(())
}

/// Python `initialize_nftables`: the ip phase, then (when IPv6 forwarding
/// is on) a re-fetch and the ip6 phase.
pub fn initialize_nftables(state: &DaemonState) -> Result<(), String> {
    let prefix = chain_prefix(state);
    let ruleset = nft::fetch_ruleset(&*state.nft);
    let commands = nft::initialize_ipv4_commands(&ruleset, prefix)?;
    nft::run_commands_logged(&*state.nft, &commands);
    if !state.host.settings.ipv6_forwarding_enabled {
        return Ok(());
    }
    let ruleset = nft::fetch_ruleset(&*state.nft);
    let commands = nft::initialize_ipv6_commands(&ruleset, prefix);
    nft::run_commands_logged(&*state.nft, &commands);
    Ok(())
}

// ── systemd waits (models.py) ───────────────────────────────────────────

/// Python `wait_for_controller_ready`: poll ActiveState up to 30 times,
/// with the anti-crash-loop double check on "active".
fn wait_for_controller_ready(state: &DaemonState, unit: &str) -> Result<(), String> {
    const MAX_ATTEMPT: u32 = 30;
    for attempt in 1..=MAX_ATTEMPT {
        let active_state = state.units.get_active_state(unit);
        match active_state.as_str() {
            "active" => {
                // A unit whose process dies right after start samples as
                // "active" between crashes; confirm it stayed active.
                std::thread::sleep(state.pacing.ready_poll);
                let recheck = state.units.get_active_state(unit);
                if recheck == "active" {
                    return Ok(());
                }
                return Err(format!(
                    "{unit} controller service went '{recheck}' right after starting (crash loop?)"
                ));
            }
            "failed" => {
                return Err(format!("{unit} controller service entered 'failed' state"));
            }
            // "inactive"/"deactivating"/"unknown"/... are retried; the
            // attempt cap below bounds them.
            _ => {}
        }
        tracing::debug!(
            unit,
            state = active_state,
            attempt,
            "controller not ready yet"
        );
        if attempt < MAX_ATTEMPT {
            std::thread::sleep(state.pacing.ready_poll);
        }
    }
    Err(format!(
        "{unit} controller service did not become active after {MAX_ATTEMPT} attempts"
    ))
}

/// Python `wait_for_controller_stopped`: up to 75 seconds for the guest's
/// graceful ACPI shutdown; tearing the tap down under a live qemu corrupts
/// the rootfs.
fn wait_for_controller_stopped(state: &DaemonState, unit: &str) {
    const MAX_ATTEMPT: u32 = 75;
    for attempt in 1..=MAX_ATTEMPT {
        let active_state = state.units.get_active_state(unit);
        if matches!(active_state.as_str(), "inactive" | "failed" | "not-loaded") {
            return;
        }
        tracing::debug!(
            unit,
            state = active_state,
            attempt,
            "controller still stopping"
        );
        std::thread::sleep(state.pacing.stop_poll);
    }
    tracing::warn!(unit, "controller did not stop in time, tearing down anyway");
}

// ── VmExecution.stop / restart_persistent_vm ────────────────────────────

/// The entry's guest IPv4 for nftables rules: the stored assignment, or
/// the deterministic derivation from its vm_index.
fn guest_ipv4(state: &DaemonState, entry: &VmEntry) -> String {
    if let Some(ipv4) = &entry.ipv4 {
        return ipv4.address.clone();
    }
    let mut ordinal = 0;
    world::derive_tap_assignment(
        &state.host.settings,
        entry.vm_index,
        &entry.vm_hash,
        if entry.is_program {
            VmType::Microvm
        } else {
            VmType::Instance
        },
        &mut ordinal,
    )
    .map(|(ipv4, _)| ipv4.address)
    .unwrap_or_default()
}

/// Python `VmExecution.stop()`: idempotent; stop the unit, wait for the
/// graceful shutdown, drop the port redirects, tear down nftables and the
/// tap.
fn stop_vm_execution(state: &DaemonState, vm_id: &str) -> Result<(), RpcError> {
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if entry.times.stopped_at_ns != 0 {
        tracing::debug!(vm_id, "already stopped");
        return Ok(());
    }
    let unit = entry.unit_name();
    units::stop_and_disable(&*state.units, &unit).map_err(RpcError::Internal)?;
    wait_for_controller_stopped(state, &unit);
    with_entry_mut(state, vm_id, |entry| entry.times.stopping_at_ns = now_ns());

    // removed_all_ports_redirection. Protocol order is Python's
    // SUPPORTED_PROTOCOL_FOR_REDIRECT = ["udp", "tcp"].
    let device = format!("vmtap{}", entry.vm_index);
    let guest_ip = guest_ipv4(state, &entry);
    {
        let _net = net_lock(state);
        for forward in &entry.port_forwards {
            for (active, protocol) in [(forward.udp, "udp"), (forward.tcp, "tcp")] {
                if active {
                    nft_remove_redirect(
                        state,
                        &device,
                        &guest_ip,
                        forward.host_port,
                        forward.vm_port,
                        protocol,
                    )
                    .map_err(RpcError::Internal)?;
                }
            }
        }
        with_entry_mut(state, vm_id, |entry| entry.port_forwards.clear());

        // vm.teardown(): nftables chains, then the tap (with the ndp range).
        if networking_enabled(state, &entry) {
            // SNP measured VMs ran a per-tap DHCP server; tear it down with
            // the tap (idempotent, SNP only). Covers StopVm and
            // delete_tracked_vm, which both route through here. Plain and SEV
            // VMs never started one, so this is a no-op for them (ledger entry
            // 77).
            if entry.config.snp().is_some()
                && let Err(dhcp_error) = state
                    .dhcp
                    .stop(vm_id, &dhcp::lease_file_path(&dhcp_lease_dir(state), vm_id))
            {
                tracing::warn!(vm_id, dhcp_error, "cannot stop the DHCP server, continuing");
            }
            nft_teardown_vm(state, entry.vm_index);
            std::thread::sleep(state.pacing.tap_delete_delay);
            if let Some(ndp) = &state.ndp {
                ndp.delete_range(&device, true)
                    .map_err(RpcError::Internal)?;
            }
            // Only the device name matters for the deletion; the addresses go
            // with the link (a missing device is a warning inside the backend).
            let tap = TapAssignment::new(
                entry.vm_index,
                entry.ipv4.clone().unwrap_or(world::IpPair {
                    address: String::new(),
                    network_cidr: "0.0.0.0/0".into(),
                    gateway: String::new(),
                }),
                entry.ipv6.clone().unwrap_or(world::IpPair {
                    address: String::new(),
                    network_cidr: "::/0".into(),
                    gateway: String::new(),
                }),
            );
            if let Err(error) = state.taps.delete_tap(&tap) {
                // Python's TapInterface.delete swallows every deletion
                // failure with a warning (interfaces.py); a stop must not
                // fail on a stuck tap device.
                tracing::warn!(vm_id, %error, "cannot delete the tap interface, continuing");
            }
        }
    }

    // The tap ASSIGNMENT stays on the entry: the Python execution keeps its
    // TapInterface object after stop, and _to_vm_info keeps reporting the
    // addresses of a stopped VM (bug-for-bug; the proto says they should
    // empty once the tap is gone).
    with_entry_mut(state, vm_id, |entry| entry.times.stopped_at_ns = now_ns());
    tracing::info!(vm_id, "VM stopped");
    Ok(())
}

/// Python `VmExecution.stop()` for an ephemeral program: idempotent;
/// stopping_at, record_usage (non-persistent VMs drop their persisted port
/// mappings on stop), the port-redirect removal, the MicroVM teardown
/// (halt attempt, kill, artifact removal) plus the nftables chains and the
/// tap, then stopped_at. No systemd involvement.
fn stop_program_execution(state: &DaemonState, vm_id: &str) -> Result<(), RpcError> {
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if entry.times.stopped_at_ns != 0 {
        tracing::debug!(vm_id, "already stopped");
        return Ok(());
    }
    with_entry_mut(state, vm_id, |entry| entry.times.stopping_at_ns = now_ns());

    // record_usage: non-persistent VMs will not restart, so their persisted
    // port mappings go on stop, whatever keep_port_mappings said (Python
    // deletes them here AND in delete_vm; both daemons agree).
    ports::delete_port_mappings(
        &state.host.settings.supervisor_database,
        vm_id,
        &ports::sqlalchemy_utc_now(),
    )
    .map_err(RpcError::Internal)?;

    // removed_all_ports_redirection (udp then tcp, the Python
    // SUPPORTED_PROTOCOL_FOR_REDIRECT order).
    if !entry.port_forwards.is_empty() {
        let device = format!("vmtap{}", entry.vm_index);
        let guest_ip = guest_ipv4(state, &entry);
        let _net = net_lock(state);
        for forward in &entry.port_forwards {
            for (active, protocol) in [(forward.udp, "udp"), (forward.tcp, "tcp")] {
                if active {
                    nft_remove_redirect(
                        state,
                        &device,
                        &guest_ip,
                        forward.host_port,
                        forward.vm_port,
                        protocol,
                    )
                    .map_err(RpcError::Internal)?;
                }
            }
        }
        with_entry_mut(state, vm_id, |entry| entry.port_forwards.clear());
    }

    // vm.teardown(): the MicroVM half first, then the network half
    // (AlephFirecrackerExecutable.teardown order). The chain removal is
    // unconditional there (teardown_nftables_for_vm on a VM without chains
    // emits nothing); the tap only exists when the spec asked for internet.
    if let Some(program) = &entry.program {
        program.handle.teardown();
    }
    {
        let _net = net_lock(state);
        nft_teardown_vm(state, entry.vm_index);
        if let (Some(ipv4), Some(ipv6)) = (&entry.ipv4, &entry.ipv6) {
            let tap = TapAssignment::new(entry.vm_index, ipv4.clone(), ipv6.clone());
            std::thread::sleep(state.pacing.tap_delete_delay);
            if let Some(ndp) = &state.ndp {
                ndp.delete_range(&tap.device_name, true)
                    .map_err(RpcError::Internal)?;
            }
            if let Err(error) = state.taps.delete_tap(&tap) {
                tracing::warn!(vm_id, %error, "cannot delete the tap interface, continuing");
            }
        }
    }

    with_entry_mut(state, vm_id, |entry| entry.times.stopped_at_ns = now_ns());
    tracing::info!(vm_id, "ephemeral program stopped");
    Ok(())
}

/// Python `VmExecution.recreate_port_redirect_rules`: create-if-absent
/// against one fetched ruleset, reassigning unavailable host ports.
fn recreate_port_redirect_rules(state: &DaemonState, vm_id: &str) -> Result<(), String> {
    let Some(entry) = entry_snapshot(state, vm_id) else {
        return Ok(());
    };
    if entry.port_forwards.is_empty() {
        return Ok(());
    }
    // Allocation-through-persistence and the rule batch run under the
    // host-network lock: a reassigned host port must be persisted before
    // any other thread allocates.
    let _net = net_lock(state);
    let guest_ip = guest_ipv4(state, &entry);
    let ruleset = nft::fetch_ruleset(&*state.nft);
    let prefix = chain_prefix(state);
    let prerouting_table =
        nft::get_table_for_hook(&ruleset, "prerouting", "ip").map_err(|error| error.to_string())?;
    let forward_table =
        nft::get_table_for_hook(&ruleset, "forward", "ip").map_err(|error| error.to_string())?;

    let mut forwards = entry.port_forwards.clone();
    let mut port_changed = false;
    let mut entities = Vec::new();
    for forward in &mut forwards {
        // SUPPORTED_PROTOCOL_FOR_REDIRECT order: udp, then tcp.
        let protocols_to_create: Vec<&str> = [(forward.udp, "udp"), (forward.tcp, "tcp")]
            .into_iter()
            .filter(|(active, _)| *active)
            .map(|(_, protocol)| protocol)
            .filter(|protocol| {
                let exists = nft::check_port_redirect_exists(
                    &ruleset,
                    forward.host_port,
                    &guest_ip,
                    forward.vm_port,
                    protocol,
                    prefix,
                );
                if exists {
                    tracing::debug!(
                        protocol,
                        host_port = forward.host_port,
                        vm_port = forward.vm_port,
                        "port redirect rule already exists, skipping"
                    );
                }
                !exists
            })
            .collect();
        if protocols_to_create.is_empty() {
            continue;
        }
        if !ports::is_host_port_available(forward.host_port) {
            let new_port = state.port_cursor.fast_get_available_host_port(
                &state.host.settings.supervisor_database,
                &*state.nft,
            )?;
            tracing::warn!(
                old = forward.host_port,
                new = new_port,
                vm_port = forward.vm_port,
                vm_id,
                "host port unavailable, reassigned"
            );
            forward.host_port = new_port;
            port_changed = true;
        }
        for protocol in protocols_to_create {
            entities.extend(nft::port_redirect_entities(
                entry.vm_index,
                &guest_ip,
                forward.host_port,
                forward.vm_port,
                protocol,
                &prerouting_table,
                &forward_table,
                &network_interface(state),
                prefix,
            ));
        }
    }
    if !entities.is_empty() {
        let commands = nft::add_entities_if_not_present(&ruleset, &entities);
        nft::run_commands_logged(&*state.nft, &commands);
    }
    if port_changed {
        ports::save_port_mappings(
            &state.host.settings.supervisor_database,
            vm_id,
            &forwards,
            &ports::sqlalchemy_utc_now(),
        )?;
    }
    with_entry_mut(state, vm_id, |entry| entry.port_forwards = forwards);
    Ok(())
}

/// Python `VmPool.restart_persistent_vm`: clear the stop stamps, ensure the
/// tap and nftables state, restart the unit and wait, reload the persisted
/// port mappings.
fn start_vm_execution(state: &DaemonState, vm_id: &str) -> Result<(), RpcError> {
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    with_entry_mut(state, vm_id, |entry| {
        entry.times.stopping_at_ns = 0;
        entry.times.stopped_at_ns = 0;
    });

    if networking_enabled(state, &entry) {
        let tap = tap_assignment(state, vm_id).map_err(RpcError::Internal)?;
        let _net = net_lock(state);
        if !state.taps.interface_exists(&tap.device_name) {
            state
                .taps
                .create_tap(&tap)
                .map_err(|error| RpcError::Internal(error.to_string()))?;
            if let Some(ndp) = &state.ndp {
                ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, true)
                    .map_err(RpcError::Internal)?;
            }
        }
        // Even when the interface survived, the nftables rules may have
        // been flushed; always re-apply (create-if-absent).
        nft_setup_vm(state, entry.vm_index, &tap.device_name).map_err(RpcError::Internal)?;
        // Stop tore the SNP per-tap DHCP server down with the tap and nft
        // rules; recreate it with them, or the rebooting measured guest
        // (whose cmdline has no `ip=`, ledger entry 78) can never lease its
        // IP and attestation is unreachable. `DhcpBackend::start` replaces a
        // leftover unit, so a partial stop cannot fail this start.
        if entry.config.snp().is_some() {
            let config = dhcp::DhcpConfig::for_snp(
                vm_id,
                &tap,
                state.host.dns_nameservers.as_deref().unwrap_or(&[]),
                &dhcp_lease_dir(state),
            )
            .map_err(RpcError::Internal)?;
            state.dhcp.start(&config).map_err(RpcError::Internal)?;
        }
    }

    let unit = entry.unit_name();
    state.units.restart(&unit).map_err(RpcError::Internal)?;
    wait_for_controller_ready(state, &unit).map_err(RpcError::Internal)?;
    with_entry_mut(state, vm_id, |entry| entry.times.started_at_ns = now_ns());

    // stop() cleared the in-memory mappings; the store keeps them for
    // persistent VMs.
    let forwards = ports::load_port_forwards(&state.host.settings.supervisor_database, vm_id)
        .map_err(RpcError::Internal)?;
    let has_forwards = !forwards.is_empty();
    with_entry_mut(state, vm_id, |entry| entry.port_forwards = forwards);
    if has_forwards {
        recreate_port_redirect_rules(state, vm_id).map_err(RpcError::Internal)?;
    }
    Ok(())
}

// ── RPC surfaces ────────────────────────────────────────────────────────

pub fn stop_vm(state: &DaemonState, vm_id: &str) -> Result<VmEntry, RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if entry.is_program {
        return Err(RpcError::Unimplemented(
            "Stopping an ephemeral VM is not supported; the cycle is DeleteVm + CreateVm"
                .to_string(),
        ));
    }
    let old_status = status_snapshot(state, &entry);
    stop_vm_execution(state, vm_id)?;
    // Python stop_vm: the event fires on every successful stop, including
    // the idempotent already-stopped one (old = STOPPED there).
    state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);
    entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))
}

pub fn start_vm(state: &DaemonState, vm_id: &str) -> Result<(VmEntry, bool), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if entry.is_program {
        return Err(RpcError::Unimplemented(
            "Starting an ephemeral VM is not supported; the cycle is DeleteVm + CreateVm"
                .to_string(),
        ));
    }
    if unit_active(state, &entry.unit_name()) {
        // Python start_vm: the already-running short circuit emits nothing.
        return Ok((entry, true));
    }
    let old_status = status_snapshot(state, &entry);
    start_vm_execution(state, vm_id)?;
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let running = unit_active(state, &entry.unit_name());
    state.events.emit(
        vm_id,
        old_status,
        crate::service::vm_status(&entry.times, running),
    );
    Ok((entry, running))
}

pub fn reboot_vm(state: &DaemonState, vm_id: &str) -> Result<(VmEntry, bool), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if entry.is_program {
        // Python reboot_vm, non-persistent branch: a real reboot; the
        // supervisor holds the spec, so it stops the VM and recreates it
        // from that spec (fresh vm_index, fresh tap) instead of returning
        // a stopped husk.
        let spec = entry
            .spec
            .clone()
            .ok_or_else(|| RpcError::Internal("ephemeral VM without a spec".to_string()))?;
        let old_status = status_snapshot(state, &entry);
        stop_program_execution(state, vm_id)?;
        state.world.blocking_write().entries.remove(vm_id);
        state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);
        // Release the per-VM lock before the create re-acquires it
        // (creation_lock first, then vm_lock).
        drop(_guard);
        let (entry, running) = create_vm_inner(state, spec)?;
        state.events.emit(
            vm_id,
            pb::VmStatus::Stopped,
            crate::service::vm_status(&entry.times, running),
        );
        return Ok((entry, running));
    }
    let old_status = status_snapshot(state, &entry);
    let unit = entry.unit_name();
    // RestartUnit only queues a job: wait until the unit is confirmed
    // active so the reported status is truthful.
    state.units.restart(&unit).map_err(RpcError::Internal)?;
    wait_for_controller_ready(state, &unit).map_err(RpcError::Internal)?;
    with_entry_mut(state, vm_id, |entry| entry.times.started_at_ns = now_ns());
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let running = unit_active(state, &unit);
    // A reboot is a down-then-up pair; watchers that drop per-VM state on
    // "down" must see the down (the Python reboot_vm comment).
    state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);
    state.events.emit(
        vm_id,
        pb::VmStatus::Stopped,
        crate::service::vm_status(&entry.times, running),
    );
    Ok((entry, running))
}

pub fn reinstall_vm(
    state: &DaemonState,
    vm_id: &str,
    wipe_volumes: bool,
) -> Result<(VmEntry, bool), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if entry.is_program {
        // Python reinstall_vm, non-persistent branch: stop, forget, erase;
        // the agent re-creates through the create path (it owns the
        // message), so the stopped state is returned.
        let old_status = status_snapshot(state, &entry);
        stop_program_execution(state, vm_id)?;
        state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);
        let stopped =
            entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
        state.world.blocking_write().entries.remove(vm_id);
        erase_volumes(&stopped, true, wipe_volumes).map_err(RpcError::Internal)?;
        // Status is STOPPED, so no second event (the Python
        // `if info.status is not VmStatus.STOPPED` guard).
        return Ok((stopped, false));
    }
    let old_status = status_snapshot(state, &entry);
    stop_vm_execution(state, vm_id)?;
    state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);
    // erase_volumes(include_rootfs=True, include_data_volumes=wipe_volumes).
    erase_volumes(&entry, true, wipe_volumes).map_err(RpcError::Internal)?;
    // prepare(): resources rebuilt from the spec, re-stamping the
    // preparation instants.
    with_entry_mut(state, vm_id, |entry| {
        entry.times.preparing_at_ns = now_ns();
        entry.times.prepared_at_ns = now_ns();
    });
    start_vm_execution(state, vm_id)?;
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let running = unit_active(state, &entry.unit_name());
    let new_status = crate::service::vm_status(&entry.times, running);
    if new_status != pb::VmStatus::Stopped {
        state.events.emit(vm_id, pb::VmStatus::Stopped, new_status);
    }
    Ok((entry, running))
}

/// Python `VmExecution.erase_volumes`: unlink errors propagate (an
/// undeletable rootfs fails the reinstall/delete INTERNAL, exactly like
/// the Python unlink), except where Python passes missing_ok=True (a
/// vanished data volume is tolerated).
fn erase_volumes(
    entry: &VmEntry,
    include_rootfs: bool,
    include_data_volumes: bool,
) -> Result<(), String> {
    // The on-disk sources: the controller config for QEMU VMs, the spec's
    // disks for ephemeral programs (SpecProgramResources: the ROOTFS disk
    // plus the EXTRA disks, none of which reach a controller config).
    let (rootfs_path, volumes): (String, Vec<(String, bool)>) = if entry.is_program {
        // The Python erase_volumes crashes on programs before reaching the
        // extra disks: `self.resources.volumes` does not exist on
        // SpecProgramResources (models.py:653), so the AttributeError
        // answers INTERNAL after the rootfs step already ran. The Rust
        // daemon keeps Python's disk outcome (rootfs erased when asked,
        // extra disks never touched) but answers success instead of
        // reproducing the crash (ledger entry 43, fix-in-python-later).
        let spec_disks = entry
            .spec
            .as_ref()
            .map(|spec| spec.disks.as_slice())
            .unwrap_or_default();
        let rootfs = spec_disks
            .iter()
            .find(|disk| disk.role == pb::disk_config::DiskRole::Rootfs as i32)
            .map(|disk| disk.path.clone())
            .unwrap_or_default();
        (rootfs, Vec::new())
    } else {
        (
            entry.config.image_path.clone(),
            entry
                .config
                .host_volumes
                .iter()
                .map(|volume| (volume.path_on_host.clone(), volume.read_only))
                .collect(),
        )
    };
    if include_rootfs {
        let rootfs = std::path::Path::new(&rootfs_path);
        if rootfs.exists() {
            tracing::info!(path = %rootfs.display(), "deleting rootfs");
            std::fs::remove_file(rootfs).map_err(|error| {
                format!("cannot delete the rootfs {}: {error}", rootfs.display())
            })?;
        }
    }
    if include_data_volumes {
        for (path_on_host, read_only) in &volumes {
            if *read_only {
                continue;
            }
            tracing::info!(path = path_on_host, "deleting volume");
            if let Err(error) = std::fs::remove_file(path_on_host)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(format!("cannot delete the volume {path_on_host}: {error}"));
            }
        }
    }
    Ok(())
}

/// `LocalSupervisor.restore_backup`: swap the rootfs for a verified backup
/// archive's rootfs member, stopping and restarting the VM around the swap.
/// Persistent QEMU VMs only (a program fails the rootfs-path resolution with
/// InvalidBackend).
pub fn restore_backup(
    state: &DaemonState,
    vm_id: &str,
    backup_id: &str,
) -> Result<(VmEntry, bool), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let rootfs_path = crate::backup::qemu_rootfs_path(&entry)?;
    crate::backup::validate_backup_id(vm_id, backup_id)?;
    let backup_dir = crate::backup::backup_directory(state)?;
    let tar_path = backup_dir.join(format!("{backup_id}.tar"));
    if !tar_path.exists() {
        return Err(RpcError::BackupNotFound(backup_id.into()));
    }

    // The per-VM disk lock, shared with a running StartBackup: neither may
    // touch the disks while the other converts or swaps them.
    let disk_lock = state.backups.vm_lock(vm_id);
    let _disk_guard = disk_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let staging = backup_dir.join(format!("{backup_id}.restore.qcow2"));
    let outcome = restore_rootfs_swap(state, vm_id, &entry, &tar_path, &staging, &rootfs_path);
    let _ = std::fs::remove_file(&staging);
    outcome?;

    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let running = unit_active(state, &entry.unit_name());
    let status = status_snapshot(state, &entry);
    if status != pb::VmStatus::Stopped {
        state.events.emit(vm_id, pb::VmStatus::Stopped, status);
    }
    Ok((entry, running))
}

/// The stop/restore/restart core shared by restore_backup: extract and
/// verify the archived rootfs, stop the running VM, swap the disk, restart.
fn restore_rootfs_swap(
    state: &DaemonState,
    vm_id: &str,
    entry: &VmEntry,
    tar_path: &std::path::Path,
    staging: &std::path::Path,
    rootfs_path: &std::path::Path,
) -> Result<(), RpcError> {
    crate::backup::extract_rootfs_member(tar_path, staging)?;
    // verify_qemu_disk: a check failure here propagates as INTERNAL (Python's
    // uncaught CalledProcessError -> translate).
    if let Err(error) = state.disk_tools.check(staging) {
        return Err(RpcError::Internal(match error {
            crate::backup::QemuImgError::CheckFailed(message)
            | crate::backup::QemuImgError::Unavailable(message) => message,
        }));
    }
    let old_status = status_snapshot(state, entry);
    if entry_running(state, entry) {
        stop_vm_execution(state, vm_id)?;
        state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);
    }
    crate::backup::restore_rootfs(staging, rootfs_path)?;
    start_vm_execution(state, vm_id)
}

/// `LocalSupervisor.restore_from_image`: swap the rootfs for a QCOW2 image
/// already staged on a host path. Rejects a non-QCOW2 upload (InvalidBackend)
/// and one larger than the declared rootfs (a restore must not grow the disk).
pub fn restore_from_image(
    state: &DaemonState,
    vm_id: &str,
    image_path: &str,
    max_virtual_size_bytes: u64,
) -> Result<(VmEntry, bool), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let rootfs_path = crate::backup::qemu_rootfs_path(&entry)?;

    let image = std::path::Path::new(image_path);
    if !image.exists() {
        return Err(RpcError::Internal(format!(
            "staged restore image {} does not exist",
            image.display()
        )));
    }
    // qemu-img rejects anything that is not a valid QCOW2 with a non-zero
    // exit: a client error (a bad upload) -> InvalidBackendError (a 400). A
    // spawn failure (qemu-img missing) stays INTERNAL, like Python.
    match state.disk_tools.check(image) {
        Ok(()) => {}
        Err(crate::backup::QemuImgError::CheckFailed(_)) => {
            let name = image
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or_default();
            return Err(RpcError::InvalidBackend(format!(
                "Restore image {name} is not a valid QCOW2 disk"
            )));
        }
        Err(crate::backup::QemuImgError::Unavailable(message)) => {
            return Err(RpcError::Internal(message));
        }
    }
    if max_virtual_size_bytes != 0 {
        let new_size = state
            .disk_tools
            .virtual_size(image)
            .map_err(RpcError::Internal)?;
        if new_size > max_virtual_size_bytes {
            return Err(RpcError::InvalidBackend(format!(
                "New rootfs virtual size ({new_size} bytes) exceeds the declared rootfs size \
                 ({max_virtual_size_bytes} bytes). Restore cannot increase disk size."
            )));
        }
    }

    let disk_lock = state.backups.vm_lock(vm_id);
    let _disk_guard = disk_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let old_status = status_snapshot(state, &entry);
    if entry_running(state, &entry) {
        stop_vm_execution(state, vm_id)?;
        state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);
    }
    crate::backup::restore_rootfs(image, &rootfs_path)?;
    start_vm_execution(state, vm_id)?;

    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let running = unit_active(state, &entry.unit_name());
    let status = status_snapshot(state, &entry);
    if status != pb::VmStatus::Stopped {
        state.events.emit(vm_id, pb::VmStatus::Stopped, status);
    }
    Ok((entry, running))
}

pub fn delete_vm(
    state: &DaemonState,
    vm_id: &str,
    wipe: bool,
    keep_port_mappings: bool,
) -> Result<(), RpcError> {
    {
        let lock = vm_lock(state, vm_id);
        let _guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if entry_snapshot(state, vm_id).is_some() {
            return delete_tracked_vm(state, vm_id, wipe, keep_port_mappings);
        }
    }

    // Python `discard_failed_reattach`: a VM the daemon never adopted
    // (hidden at boot) may still have a live controller and an on-disk
    // definition; honor the delete by stopping and removing both, instead
    // of letting NOT_FOUND leave an unmanageable instance that the retry
    // loop resurrects. Serialize with the retry pass under creation_lock
    // (the Python method takes it for the same reason); lock order
    // creation_lock then vm_lock, so the vm_lock above was released first.
    let _create_guard = state
        .creation_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if entry_snapshot(state, vm_id).is_some() {
        // A concurrent retry pass adopted the VM while we waited for the
        // creation lock; the delete goes through the tracked path.
        return delete_tracked_vm(state, vm_id, wipe, keep_port_mappings);
    }

    let root = &state.host.settings.execution_root;
    let config_path = controller_config::controller_config_path(root, vm_id);
    if !config_path.exists() {
        return Err(RpcError::NotFound(vm_id.into()));
    }
    tracing::info!(
        vm_id,
        "deleting an untracked VM (failed adoption): stopping its controller"
    );
    let unit = controller_unit_name(vm_id);
    if let Err(error) = units::stop_and_disable(&*state.units, &unit) {
        tracing::warn!(unit, error, "failed to stop/disable the stale controller");
    }
    // Release the hidden VM's vm_index claim (and its retry-queue entry,
    // the Python `_failed_reattach.pop`) before the config goes. NOTE the
    // NUMA ledger is deliberately NOT touched here: a hidden VM (adoption
    // failed, never entered `world.entries`) was NEVER registered by
    // `reconcile_numa_ledger` (which only registers adopted-running tracked
    // entries), so releasing its vCPUs would subtract a reservation that was
    // never added and steal capacity from co-located VMs (increment C1). Its
    // drop-in is still removed below for cleanliness.
    let mut discarded_is_snp = false;
    {
        let mut world = state.world.blocking_write();
        world.failed_reattach.remove(vm_id);
        if let Ok(contents) = std::fs::read_to_string(&config_path)
            && let Ok(config) = parse_controller_config(&contents)
        {
            world.reserved_vm_indices.remove(&config.vm_index);
            if let VmConfiguration::Qemu(qemu) = &config.vm {
                discarded_is_snp = qemu.snp().is_some();
            }
        }
    }
    // A still-live SNP VM whose adoption failed ran a per-tap DHCP server
    // (increment D2, ledger 77). The tracked teardown paths stop it, but this
    // discard path did not, orphaning aleph-vm-dhcp-<hash>.service (and leaking
    // its lease file) on every failed-adoption delete of a live SNP VM. Stop it
    // here too, gated on the parsed config being SNP so plain/SEV VMs (which
    // never started one) are untouched. Best-effort, like the controller stop.
    if discarded_is_snp
        && let Err(dhcp_error) = state
            .dhcp
            .stop(vm_id, &dhcp::lease_file_path(&dhcp_lease_dir(state), vm_id))
    {
        tracing::warn!(
            vm_id,
            dhcp_error,
            "cannot stop the DHCP server for a discarded SNP VM, continuing"
        );
    }
    remove_numa_dropin(state, vm_id);
    controller_config::remove_controller_configuration(root, vm_id).map_err(RpcError::Internal)?;
    Ok(())
}

/// The tracked half of DeleteVm; the caller holds the VM's lock.
fn delete_tracked_vm(
    state: &DaemonState,
    vm_id: &str,
    wipe: bool,
    keep_port_mappings: bool,
) -> Result<(), RpcError> {
    let root = &state.host.settings.execution_root;
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;

    let old_status = status_snapshot(state, &entry);
    if entry.is_program {
        stop_program_execution(state, vm_id)?;
    } else {
        stop_vm_execution(state, vm_id)?;
    }
    state.events.emit(vm_id, old_status, pb::VmStatus::Stopped);

    // The per-VM backup disk lock, shared with a running StartBackup: a delete
    // that erases writable volumes must not race a backup's qemu-img read of
    // the same disks (a corrupt member or a spurious FAILED job), and the
    // world-entry removal must not leave a backup run tracked for a VM that no
    // longer exists. Lock order matches the restore paths: the lifecycle
    // vm_lock (held by the caller) then this disk lock (ledger entry 51).
    let disk_lock = state.backups.vm_lock(vm_id);
    let _disk_guard = disk_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    state.world.blocking_write().entries.remove(vm_id);
    // Release the NUMA reservation alongside the other teardown (increment
    // C1). No-op for an unpinned or program VM (numa_node is None).
    if let Some(node) = entry.numa_node {
        let (memory_mb, hugepage_size) = config_hugepage_backing(&entry.config);
        release_numa_placement(
            state,
            node,
            entry.config.vcpu_count,
            memory_mb,
            hugepage_size,
        );
    }
    // The drop-in removal is NOT gated on numa_node: a VM reconciled as
    // unpinned after a topology change still has a stale drop-in on disk,
    // and leaving it behind would pin a future same-hash controller.
    remove_numa_dropin(state, vm_id);
    // Delete releases the definition: the controller config and the
    // cloud-init seed go too (stop keeps them for reattach).
    controller_config::remove_controller_configuration(root, vm_id).map_err(RpcError::Internal)?;
    // A delete is final unless the caller says otherwise; delete+recreate
    // cycles pass keep_port_mappings, wipe overrides it.
    if wipe || !keep_port_mappings {
        ports::delete_port_mappings(
            &state.host.settings.supervisor_database,
            vm_id,
            &ports::sqlalchemy_utc_now(),
        )
        .map_err(RpcError::Internal)?;
    }
    if wipe {
        // Mirrors operate_erase: writable data volumes go, the rootfs stays.
        erase_volumes(&entry, false, true).map_err(RpcError::Internal)?;
    }
    // Reap the backup registry entry (jobs, the in-flight task slot, the disk
    // lock) for the now-deleted VM so a completed/failed run does not linger
    // in ListBackups and a fresh create reuses no stale state (R1/R3).
    state.backups.reap(vm_id);
    Ok(())
}

// ── Port forwards ───────────────────────────────────────────────────────

/// Python `VmExecution.update_port_redirects`: diff the requested map
/// against the live one, add/remove nftables rules, persist on change.
fn update_port_redirects(
    state: &DaemonState,
    vm_id: &str,
    requested: Vec<(u32, bool, bool)>,
) -> Result<(), RpcError> {
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if entry.is_program && entry.ipv4.is_none() {
        // Python: update_port_redirects dereferences vm.tap_interface,
        // which is None for a program created without internet_access; the
        // AttributeError aborts INTERNAL (text differs, ledger entry 33).
        return Err(RpcError::Internal(format!(
            "VM {vm_id} has no tap interface; cannot change port redirects"
        )));
    }
    // One global lock from allocation through persistence: without it, two
    // concurrent AddPortForwards for different VMs can both allocate the
    // same host_port (the bind probe is transient), and the loser has a
    // live DNAT rule pointing at the wrong guest by the time its DB save
    // fails on the partial unique index. Python's event loop makes the
    // interleaving impossible; this lock is the blocking-thread equivalent.
    let _net = net_lock(state);
    let device = format!("vmtap{}", entry.vm_index);
    let guest_ip = guest_ipv4(state, &entry);
    let mut forwards = entry.port_forwards.clone();
    let mut changed = false;

    // Removed vm_ports.
    let requested_ports: std::collections::HashSet<u32> =
        requested.iter().map(|(port, _, _)| *port).collect();
    let mut kept = Vec::new();
    for forward in forwards.drain(..) {
        if requested_ports.contains(&forward.vm_port) {
            kept.push(forward);
            continue;
        }
        // SUPPORTED_PROTOCOL_FOR_REDIRECT order: udp, then tcp.
        for (active, protocol) in [(forward.udp, "udp"), (forward.tcp, "tcp")] {
            if active {
                nft_remove_redirect(
                    state,
                    &device,
                    &guest_ip,
                    forward.host_port,
                    forward.vm_port,
                    protocol,
                )
                .map_err(RpcError::Internal)?;
            }
        }
        changed = true;
    }
    forwards = kept;

    for (vm_port, tcp, udp) in requested {
        match forwards
            .iter_mut()
            .find(|forward| forward.vm_port == vm_port)
        {
            None => {
                // A new vm_port: allocate a host port, then add the rules
                // for the active protocols.
                let host_port = state
                    .port_cursor
                    .fast_get_available_host_port(
                        &state.host.settings.supervisor_database,
                        &*state.nft,
                    )
                    .map_err(RpcError::Internal)?;
                // SUPPORTED_PROTOCOL_FOR_REDIRECT order: udp, then tcp.
                for (active, protocol) in [(udp, "udp"), (tcp, "tcp")] {
                    if active {
                        nft_add_redirect(
                            state,
                            entry.vm_index,
                            &guest_ip,
                            host_port,
                            vm_port,
                            protocol,
                        )
                        .map_err(RpcError::Internal)?;
                    }
                }
                forwards.push(ports::PortForward {
                    vm_port,
                    host_port,
                    tcp,
                    udp,
                });
                changed = true;
            }
            Some(forward) => {
                let host_port = forward.host_port;
                // SUPPORTED_PROTOCOL_FOR_REDIRECT order: udp, then tcp.
                for (current, target, protocol) in
                    [(forward.udp, udp, "udp"), (forward.tcp, tcp, "tcp")]
                {
                    if current == target {
                        continue;
                    }
                    if target {
                        nft_add_redirect(
                            state,
                            entry.vm_index,
                            &guest_ip,
                            host_port,
                            vm_port,
                            protocol,
                        )
                        .map_err(RpcError::Internal)?;
                    } else {
                        nft_remove_redirect(
                            state, &device, &guest_ip, host_port, vm_port, protocol,
                        )
                        .map_err(RpcError::Internal)?;
                    }
                    changed = true;
                }
                forward.tcp = tcp;
                forward.udp = udp;
            }
        }
    }

    if changed {
        ports::save_port_mappings(
            &state.host.settings.supervisor_database,
            vm_id,
            &forwards,
            &ports::sqlalchemy_utc_now(),
        )
        .map_err(RpcError::Internal)?;
    }
    with_entry_mut(state, vm_id, |entry| entry.port_forwards = forwards);
    Ok(())
}

fn protocol_name(protocol: pb::Protocol) -> Result<&'static str, RpcError> {
    match protocol {
        pb::Protocol::Tcp => Ok("tcp"),
        pb::Protocol::Udp => Ok("udp"),
        // Python: PROTOCOL_FROM_PB[...] raises KeyError -> INTERNAL.
        pb::Protocol::Unspecified => Err(RpcError::Internal(
            "unspecified port-forward protocol".to_string(),
        )),
    }
}

/// Python `LocalSupervisor.add_port_forward`. The request's host_port is
/// ignored (bug-for-bug: the Python engine always auto-allocates).
pub fn add_port_forward(
    state: &DaemonState,
    request: &pb::AddPortForwardRequest,
) -> Result<pb::PortForwardInfo, RpcError> {
    let protocol = protocol_name(request.protocol())?;
    let vm_id = &request.vm_id;
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;

    let mut requested: Vec<(u32, bool, bool)> = entry
        .port_forwards
        .iter()
        .map(|forward| (forward.vm_port, forward.tcp, forward.udp))
        .collect();
    match requested
        .iter_mut()
        .find(|(port, _, _)| *port == request.vm_port)
    {
        Some(existing) => match protocol {
            "tcp" => existing.1 = true,
            _ => existing.2 = true,
        },
        None => requested.push((request.vm_port, protocol == "tcp", protocol == "udp")),
    }
    update_port_redirects(state, vm_id, requested)?;

    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let mapping = entry
        .port_forwards
        .iter()
        .find(|forward| forward.vm_port == request.vm_port)
        .ok_or_else(|| RpcError::Internal("the added mapping vanished".to_string()))?;
    Ok(pb::PortForwardInfo {
        vm_id: vm_id.clone(),
        host_port: mapping.host_port,
        vm_port: request.vm_port,
        protocol: request.protocol,
    })
}

/// Python `LocalSupervisor.remove_port_forward`: clear the protocol on the
/// mapping holding host_port; a port whose last protocol goes is dropped.
pub fn remove_port_forward(
    state: &DaemonState,
    vm_id: &str,
    host_port: u32,
    protocol: pb::Protocol,
) -> Result<(), RpcError> {
    let protocol = protocol_name(protocol)?;
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;

    let requested: Vec<(u32, bool, bool)> = entry
        .port_forwards
        .iter()
        .map(|forward| {
            let mut flags = (forward.vm_port, forward.tcp, forward.udp);
            if forward.host_port == host_port {
                match protocol {
                    "tcp" => flags.1 = false,
                    _ => flags.2 = false,
                }
            }
            flags
        })
        // All-false entries are dropped from the request entirely, so
        // update_port_redirects removes the mapping (ghost-entry guard).
        .filter(|(_, tcp, udp)| *tcp || *udp)
        .collect();
    update_port_redirects(state, vm_id, requested)
}

// ── CreateVm ────────────────────────────────────────────────────────────

/// Python `_require_same_spec`: an identical spec returns the live VM
/// (safe retry), a different one conflicts.
fn same_spec_or_conflict(entry: &VmEntry, request: &pb::VmSpec) -> Result<VmEntry, RpcError> {
    let current = crate::service::vm_spec_message(entry);
    if current == *request {
        Ok(entry.clone())
    } else {
        Err(RpcError::AlreadyExists(format!(
            "VM {} already exists with a different spec",
            request.vm_id
        )))
    }
}

/// Python `_validate_spec_gpus`: every requested pci_host exists in the
/// inventory and is attached nowhere (nor claimed twice).
fn validate_spec_gpus(
    state: &DaemonState,
    requested: &[pb::GpuConfig],
) -> Result<Vec<AttachedGpu>, RpcError> {
    let world = state.world.blocking_read();
    let mut validated = Vec::new();
    let mut claimed: std::collections::HashSet<&str> = Default::default();
    for request in requested {
        let pci_host = request.pci_host.as_str();
        let Some(device) = state
            .host
            .gpus
            .iter()
            .find(|device| device.pci_host == pci_host)
        else {
            return Err(RpcError::InsufficientResources(format!(
                "No GPU at pci_host '{pci_host}' in the host inventory"
            )));
        };
        let attached = world
            .entries
            .values()
            .any(|entry| entry.config.gpus.iter().any(|gpu| gpu.pci_host == pci_host));
        if attached {
            return Err(RpcError::InsufficientResources(format!(
                "GPU at pci_host '{pci_host}' is already attached to a VM"
            )));
        }
        if !claimed.insert(pci_host) {
            return Err(RpcError::InsufficientResources(format!(
                "GPU at pci_host '{pci_host}' is claimed twice in this spec"
            )));
        }
        validated.push(AttachedGpu {
            pci_host: device.pci_host.clone(),
            device_id: device.device_id.clone(),
            supports_x_vga: device.supports_x_vga(),
        });
    }
    Ok(validated)
}

/// Python `_check_memory_backstop`: committed plus requested must fit in
/// physical memory minus the host reserve. Runs under creation_lock.
fn check_memory_backstop(state: &DaemonState, required_memory_mib: u64) -> Result<(), RpcError> {
    let committed: u64 = state
        .world
        .blocking_read()
        .entries
        .values()
        .map(|entry| entry.config.mem_size_mb.count())
        .sum();
    let physical =
        crate::host::memory_total_mib().map_err(|error| RpcError::Internal(error.to_string()))?;
    let cap = physical.saturating_sub(state.host.settings.host_memory_reserved_mib);
    // saturating_add: a hostile memory_mib request must fail the backstop,
    // not overflow the sum (Python ints are unbounded).
    if committed.saturating_add(required_memory_mib) > cap {
        return Err(RpcError::InsufficientResources(format!(
            "Insufficient memory to create VM: required {required_memory_mib} MiB, \
             committed {committed} MiB, cap {cap} MiB (physical {physical} MiB, \
             host_reserved {} MiB)",
            state.host.settings.host_memory_reserved_mib
        )));
    }
    Ok(())
}

/// The rootfs disk of the spec, Python `CreateVmSpec.require_rootfs`:
/// exactly one ROOTFS disk. A missing or duplicated rootfs raises
/// InvalidBackendError there (types.py), which the wire maps to
/// INVALID_ARGUMENT with the INVALID_BACKEND ErrorDetail trailer; message
/// texts are byte-identical.
fn require_rootfs(spec: &pb::VmSpec) -> Result<&pb::DiskConfig, RpcError> {
    let rootfs_disks: Vec<&pb::DiskConfig> = spec
        .disks
        .iter()
        .filter(|disk| disk.role == pb::disk_config::DiskRole::Rootfs as i32)
        .collect();
    if rootfs_disks.len() > 1 {
        return Err(RpcError::InvalidBackend(format!(
            "CreateVmSpec has {} ROOTFS disks, expected at most one",
            rootfs_disks.len()
        )));
    }
    rootfs_disks
        .first()
        .copied()
        .ok_or_else(|| RpcError::InvalidBackend("CreateVmSpec has no ROOTFS disk".to_string()))
}

/// Build the controller Configuration for a spec create, the Python
/// `build_qemu_configuration` inputs (cloud-init path is deterministic, so
/// the JSON is complete before the drive image exists).
fn build_written_config(
    state: &DaemonState,
    spec: &pb::VmSpec,
    vm_index: i64,
    interface_name: Option<String>,
) -> Result<WrittenControllerConfig, RpcError> {
    let settings = &state.host.settings;
    let root = &settings.execution_root;
    let vm_hash = &spec.vm_id;
    let qemu_bin_path = checks::which("qemu-system-x86_64")
        .ok_or_else(|| RpcError::Internal("qemu-system-x86_64 not found on PATH".to_string()))?;
    let image_path = require_rootfs(spec)?.path.clone();
    // SEV-SNP (increment B1) is resolved first: it is a distinct measured-boot
    // path (no session/godh), so the SEV confidential slice is suppressed when
    // an SNP slice is present and the two never overlap.
    let snp_slice = snp_config_slice(state, spec)?;
    let confidential_slice = if snp_slice.is_some() {
        None
    } else {
        confidential_config_slice(state, spec)?
    };
    // dm-verity hash tree device (/dev/vdb) is inserted as the FIRST host
    // volume for an SNP VM, before any agent-supplied extra disks, mirroring
    // the aleph-cvm donor (vm/manager.rs inserts the hash tree at index 1).
    let mut host_volumes: Vec<WrittenHostVolume> = Vec::new();
    if let Some(snp) = &snp_slice {
        host_volumes.push(WrittenHostVolume {
            mount: String::new(),
            path_on_host: snp.hashtree_path.clone(),
            read_only: true,
        });
    }
    host_volumes.extend(
        spec.disks
            .iter()
            .filter(|disk| disk.role == pb::disk_config::DiskRole::Extra as i32)
            .map(|disk| WrittenHostVolume {
                // The guest mount point never crosses the boundary; QemuVM
                // never consumed the field, written empty since the spec path.
                mount: String::new(),
                path_on_host: disk.path.clone(),
                read_only: disk.readonly,
            }),
    );
    // The confidential build (build_qemu_confidential_configuration) creates
    // QemuGPU(pci_host=...) with the default supports_x_vga=True, unlike the
    // plain path which passes the spec's flag. SNP is confidential-like here.
    let confidential_like = confidential_slice.is_some() || snp_slice.is_some();
    let gpus = spec
        .gpus
        .iter()
        .map(|gpu| WrittenGpu {
            pci_host: gpu.pci_host.clone(),
            supports_x_vga: confidential_like || gpu.supports_x_vga,
        })
        .collect();
    // SNP shares ovmf_path/sev_policy with the SEV slot but adds the measured
    // kernel/initrd/cmdline and the sev_snp marker; SEV/SEV-ES fills the
    // session/godh slots instead. A plain VM leaves them all None.
    let (
        ovmf_path,
        sev_session_file,
        sev_dh_cert_file,
        sev_policy,
        sev_snp,
        kernel_path,
        initrd_path,
        kernel_cmdline,
    ) = match (&snp_slice, confidential_slice) {
        (Some(snp), _) => (
            Some(snp.ovmf_path.clone()),
            None,
            None,
            Some(snp.sev_policy),
            Some(true),
            Some(snp.kernel_path.clone()),
            Some(snp.initrd_path.clone()),
            Some(snp.kernel_cmdline.clone()),
        ),
        (None, Some(slice)) => (
            Some(slice.ovmf_path),
            Some(slice.sev_session_file),
            Some(slice.sev_dh_cert_file),
            Some(slice.sev_policy),
            None,
            None,
            None,
            None,
        ),
        (None, None) => (None, None, None, None, None, None, None, None),
    };
    // A measured SNP VM boots from the Nix image via kernel+initrd (its in-guest
    // init handles networking / provisioning), so it carries NO cloud-init drive
    // (which the SEV/plain paths always attach).
    let cloud_init_drive_path = if snp_slice.is_some() {
        None
    } else {
        Some(
            root.join(format!("cloud-init-{vm_hash}.img"))
                .to_string_lossy()
                .into_owned(),
        )
    };
    Ok(WrittenControllerConfig {
        vm_id: vm_index,
        vm_hash: vm_hash.clone(),
        settings: WrittenControllerSettings {
            jailer_base_dir: Some(settings.jailer_base_dir.to_string_lossy().into_owned()),
            network_interface: state.host.network_interface.clone(),
            ipv4_address_pool: settings.ipv4_address_pool.clone(),
            ipv4_network_prefix_length: settings.ipv4_network_prefix_length,
            ipv6_address_pool: settings.ipv6_address_pool.clone(),
            ipv6_allocation_policy: match settings.ipv6_allocation_policy {
                crate::config::Ipv6AllocationPolicy::Static => {
                    controller_config::AllocationPolicyValue::Static
                }
                crate::config::Ipv6AllocationPolicy::Dynamic => {
                    controller_config::AllocationPolicyValue::Dynamic
                }
            },
            ipv6_subnet_prefix: settings.ipv6_subnet_prefix,
            ipv6_forwarding_enabled: settings.ipv6_forwarding_enabled,
            use_ndp_proxy: settings.use_ndp_proxy,
        },
        vm_configuration: WrittenQemuVmConfiguration {
            qemu_bin_path: qemu_bin_path.to_string_lossy().into_owned(),
            cloud_init_drive_path,
            image_path,
            monitor_socket_path: root
                .join(format!("{vm_hash}-monitor.socket"))
                .to_string_lossy()
                .into_owned(),
            qmp_socket_path: root
                .join(format!("{vm_hash}-qmp.socket"))
                .to_string_lossy()
                .into_owned(),
            qga_socket_path: Some(
                root.join(format!("{vm_hash}-qga.socket"))
                    .to_string_lossy()
                    .into_owned(),
            ),
            vcpu_count: spec.vcpus,
            mem_size_mb: spec.memory_mib,
            interface_name,
            host_volumes,
            gpus,
            ovmf_path,
            sev_session_file,
            sev_dh_cert_file,
            sev_policy,
            sev_snp,
            kernel_path,
            initrd_path,
            kernel_cmdline,
            // NUMA memory binding + hugepages (increment C2) are filled in by
            // the create path AFTER placement is chosen (place_vm_numa runs
            // after this builder), so they start None here and are injected
            // before the config is written to disk. A plain/SEV/no-NUMA config
            // leaves them None (byte-identical to pre-C2).
            numa_node: None,
            hugepage_size: None,
        },
        hypervisor: "qemu",
    })
}

/// The confidential SEV slice `build_qemu_confidential_configuration` fills,
/// or `None` for a plain VM. Requires a resolved firmware_path (InvalidBackend
/// otherwise: a confidential VM must never boot under a weaker config). The
/// session/godh paths must match InitializeConfidential's writes under
/// CONFIDENTIAL_SESSION_DIRECTORY/<vm_hash>.
struct ConfidentialSlice {
    ovmf_path: String,
    sev_session_file: String,
    sev_dh_cert_file: String,
    sev_policy: u32,
}

fn confidential_config_slice(
    state: &DaemonState,
    spec: &pb::VmSpec,
) -> Result<Option<ConfidentialSlice>, RpcError> {
    let Some(tee) = &spec.tee else {
        return Ok(None);
    };
    // SEV-SNP is handled by snp_config_slice, not here (it has no session/godh).
    if tee.backend == pb::TeeBackend::SevSnp as i32 {
        return Ok(None);
    }
    if tee.firmware_path.is_empty() {
        return Err(RpcError::InvalidBackend(
            "Confidential spec has no resolved firmware_path; refusing to build configuration"
                .to_string(),
        ));
    }
    let session_dir = state
        .host
        .settings
        .confidential_session_directory
        .join(&spec.vm_id);
    Ok(Some(ConfidentialSlice {
        ovmf_path: tee.firmware_path.clone(),
        sev_session_file: session_dir
            .join("vm_session.b64")
            .to_string_lossy()
            .into_owned(),
        sev_dh_cert_file: session_dir
            .join("vm_godh.b64")
            .to_string_lossy()
            .into_owned(),
        // SEV policy crosses the boundary as a string; int(policy, 0) accepts
        // hex ("0x1"), octal, binary and decimal forms.
        sev_policy: parse_sev_policy(&tee.policy)?,
    }))
}

/// The default SEV-SNP guest policy (0x30000: SNP enabled, SMT allowed, debug
/// disabled), matching the aleph-tee generator's DEFAULT_POLICY. Used when the
/// spec's `tee.policy` is empty.
const DEFAULT_SNP_POLICY: u32 = 0x30000;

/// Upper bound on the dm-verity roothash sidecar read. A real roothash is a
/// ~64-hex-char digest; 4 KiB is generous headroom while capping a pathological
/// sidecar so it cannot load unbounded into RAM.
const MAX_ROOTHASH_SIDECAR_BYTES: u64 = 4096;

/// The SEV-SNP measured-boot slice `build_written_config` fills, or `None` when
/// the spec is not SNP. A measured SNP launch must present the EXACT OVMF +
/// kernel + initrd + cmdline the B2a Nix image's `sev-snp-measure` covered, or
/// attestation will not match, so all inputs are required and a missing one is
/// InvalidBackend (fail closed, never boot a mismeasured SNP VM).
#[derive(Debug)]
struct SnpSlice {
    ovmf_path: String,
    kernel_path: String,
    initrd_path: String,
    kernel_cmdline: String,
    sev_policy: u32,
    hashtree_path: String,
}

fn snp_config_slice(_state: &DaemonState, spec: &pb::VmSpec) -> Result<Option<SnpSlice>, RpcError> {
    let Some(tee) = &spec.tee else {
        return Ok(None);
    };
    if tee.backend != pb::TeeBackend::SevSnp as i32 {
        return Ok(None);
    }
    if tee.firmware_path.is_empty() {
        return Err(RpcError::InvalidBackend(
            "SEV-SNP spec has no resolved firmware_path (measured OVMF); refusing to build \
             configuration"
                .to_string(),
        ));
    }
    if spec.kernel_path.is_empty() || spec.initrd_path.is_empty() {
        return Err(RpcError::InvalidBackend(
            "SEV-SNP measured boot requires kernel_path and initrd_path".to_string(),
        ));
    }
    // GPU passthrough into a confidential SEV-SNP guest (confidential GPU /
    // NVIDIA CC) is not supported yet, and `build_snp_argv` emits no passthrough
    // devices. Accepting GPUs here would write them into the controller config
    // and then silently drop them at launch, giving the owner a VM without the
    // hardware they asked for. Fail closed instead. See divergence 68.
    if !spec.gpus.is_empty() {
        return Err(RpcError::InvalidBackend(
            "GPU passthrough is not supported on SEV-SNP VMs yet".to_string(),
        ));
    }
    // The dm-verity roothash and hash tree are sidecars of the rootfs image, the
    // convention the B2a Nix image emits (`rootfs.ext4.roothash` /
    // `rootfs.ext4.verity`) and the aleph-cvm donor's `ensure_verity` uses. The
    // proto has no cmdline field (frozen), so the measured cmdline is DERIVED
    // here from the roothash, exactly as the donor's `build_kernel_cmdline`
    // does. See divergence 68.
    let rootfs_path = require_rootfs(spec)?.path.clone();
    let roothash_path = format!("{rootfs_path}.roothash");
    // Bound the sidecar read: a real dm-verity roothash is ~64 hex chars, so a
    // 4 KiB cap is generous. A pathological sidecar (the node builds its own
    // image, but defense in depth) cannot then load unbounded into RAM; an
    // over-cap file fails closed (InvalidBackend), never a mismeasured boot.
    let roothash = {
        use std::io::Read as _;
        let mut reader = std::fs::File::open(&roothash_path)
            .map_err(|error| {
                RpcError::InvalidBackend(format!(
                    "cannot read the dm-verity roothash sidecar {roothash_path}: {error}"
                ))
            })?
            .take(MAX_ROOTHASH_SIDECAR_BYTES + 1);
        let mut contents = String::new();
        reader.read_to_string(&mut contents).map_err(|error| {
            RpcError::InvalidBackend(format!(
                "cannot read the dm-verity roothash sidecar {roothash_path}: {error}"
            ))
        })?;
        if contents.len() as u64 > MAX_ROOTHASH_SIDECAR_BYTES {
            return Err(RpcError::InvalidBackend(format!(
                "the dm-verity roothash sidecar {roothash_path} exceeds \
                 {MAX_ROOTHASH_SIDECAR_BYTES} bytes"
            )));
        }
        contents.trim().to_string()
    };
    // The roothash goes verbatim into the kernel cmdline; reject anything that
    // is not a bare hex string so it cannot inject extra kernel parameters.
    if roothash.is_empty() || !roothash.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(RpcError::InvalidBackend(format!(
            "the dm-verity roothash in {roothash_path} is not a hex string"
        )));
    }
    let kernel_cmdline =
        format!("console=ttyS0 root=/dev/mapper/verity-root ro roothash={roothash}");
    // Optional measured workload: if the launcher staged a
    // {rootfs}.workload_roothash sidecar (from content.workload.roothash), bind
    // the workload volume into the launch digest via the cmdline too. The
    // proto has no workload field (frozen), so this mirrors the dm-verity
    // roothash sidecar convention above. An absent sidecar leaves the cmdline
    // byte-identical to a workload-less SNP VM (parity with every existing
    // measured image).
    let workload_roothash_path = format!("{rootfs_path}.workload_roothash");
    let kernel_cmdline = match std::fs::File::open(&workload_roothash_path) {
        Ok(file) => {
            use std::io::Read as _;
            let mut contents = String::new();
            file.take(MAX_ROOTHASH_SIDECAR_BYTES + 1)
                .read_to_string(&mut contents)
                .map_err(|error| {
                    RpcError::InvalidBackend(format!(
                        "cannot read the workload roothash sidecar {workload_roothash_path}: \
                         {error}"
                    ))
                })?;
            if contents.len() as u64 > MAX_ROOTHASH_SIDECAR_BYTES {
                return Err(RpcError::InvalidBackend(format!(
                    "the workload roothash sidecar {workload_roothash_path} exceeds \
                     {MAX_ROOTHASH_SIDECAR_BYTES} bytes"
                )));
            }
            let workload_roothash = contents.trim().to_string();
            // Like the platform roothash, this is spliced verbatim into
            // -append, so only a bare hex string is accepted.
            if workload_roothash.is_empty()
                || !workload_roothash.bytes().all(|b| b.is_ascii_hexdigit())
            {
                return Err(RpcError::InvalidBackend(format!(
                    "the workload roothash in {workload_roothash_path} is not a hex string"
                )));
            }
            format!("{kernel_cmdline} workload_roothash={workload_roothash}")
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => kernel_cmdline,
        Err(error) => {
            return Err(RpcError::InvalidBackend(format!(
                "cannot read the workload roothash sidecar {workload_roothash_path}: {error}"
            )));
        }
    };
    let sev_policy = if tee.policy.is_empty() {
        DEFAULT_SNP_POLICY
    } else {
        parse_sev_policy(&tee.policy)?
    };
    Ok(Some(SnpSlice {
        ovmf_path: tee.firmware_path.clone(),
        kernel_path: spec.kernel_path.clone(),
        initrd_path: spec.initrd_path.clone(),
        kernel_cmdline,
        sev_policy,
        hashtree_path: format!("{rootfs_path}.verity"),
    }))
}

/// Python `int(tee.policy, 0)`: base-0 integer parsing. Matches CPython's
/// grammar exactly (see [`parse_int_base0`]), so a policy string Python
/// rejects (`"010"`, `"07"`, `"1__0"`, `"_10"`, ...) is rejected here too and
/// one it accepts (`"0x1_0"`, `"0X1F"`, `"0b101"`, `"00"`) parses the same.
/// A malformed policy raises ValueError there (mapped to INTERNAL here).
///
/// Python's int is signed and arbitrary precision; a SEV policy is a small
/// unsigned bitfield (`sev_policy: u32`). A syntactically valid but negative
/// (`"-5"`) or `> u32::MAX` value, which Python would accept, cannot be
/// represented and is rejected INTERNAL rather than silently truncated
/// (ledger entry 49); such a policy is not reachable from a real agent.
fn parse_sev_policy(policy: &str) -> Result<u32, RpcError> {
    parse_int_base0(policy)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or_else(|| RpcError::Internal(format!("invalid SEV policy {policy:?}")))
}

/// CPython `int(text, 0)` on `text`, as an `i128` (enough to distinguish a
/// representable SEV policy from an out-of-range one; a value overflowing
/// `i128`, like a bignum Python accepts, returns `None` and is rejected the
/// same as a syntactically invalid string). Grammar: surrounding whitespace,
/// an optional `+`/`-` sign, then either a `0x`/`0o`/`0b` (case-insensitive)
/// prefix with base-appropriate digits, or a plain decimal with no leading
/// zero except the value zero. Single underscores are permitted only between
/// digits (and immediately after a base prefix), never leading, trailing, or
/// doubled (PEP 515).
fn parse_int_base0(text: &str) -> Option<i128> {
    let trimmed = text.trim();
    let (negative, unsigned) = if let Some(rest) = trimmed.strip_prefix('-') {
        (true, rest)
    } else if let Some(rest) = trimmed.strip_prefix('+') {
        (false, rest)
    } else {
        (false, trimmed)
    };
    fn strip_ci<'a>(body: &'a str, lower: &str, upper: &str) -> Option<&'a str> {
        body.strip_prefix(lower)
            .or_else(|| body.strip_prefix(upper))
    }
    let (radix, digits, prefixed) = if let Some(rest) = strip_ci(unsigned, "0x", "0X") {
        (16u32, rest, true)
    } else if let Some(rest) = strip_ci(unsigned, "0o", "0O") {
        (8, rest, true)
    } else if let Some(rest) = strip_ci(unsigned, "0b", "0B") {
        (2, rest, true)
    } else {
        (10, unsigned, false)
    };
    let value = parse_int_digits(digits, radix, prefixed)?;
    // Base-0 decimal forbids a leading zero unless the value is zero.
    if !prefixed {
        let pure: String = digits
            .chars()
            .filter(|character| *character != '_')
            .collect();
        if pure.len() > 1 && pure.starts_with('0') && pure.bytes().any(|byte| byte != b'0') {
            return None;
        }
    }
    if negative {
        value.checked_neg()
    } else {
        Some(value)
    }
}

/// Accumulate `digits` in `radix`, enforcing PEP 515 underscore placement.
/// `allow_leading_underscore` permits one underscore right after a base
/// prefix (`0x_1f`). Returns `None` for an empty run, a misplaced underscore,
/// an out-of-radix digit, or an `i128` overflow.
fn parse_int_digits(digits: &str, radix: u32, allow_leading_underscore: bool) -> Option<i128> {
    if digits.is_empty() {
        return None;
    }
    let mut value: i128 = 0;
    let mut previous_was_underscore = false;
    let mut previous_was_digit = false;
    let mut any_digit = false;
    for (index, character) in digits.char_indices() {
        if character == '_' {
            let after_prefix = index == 0 && allow_leading_underscore;
            if previous_was_underscore || (!previous_was_digit && !after_prefix) {
                return None;
            }
            previous_was_underscore = true;
            previous_was_digit = false;
            continue;
        }
        let digit = character.to_digit(radix)?;
        value = value.checked_mul(i128::from(radix))?;
        value = value.checked_add(i128::from(digit))?;
        any_digit = true;
        previous_was_digit = true;
        previous_was_underscore = false;
    }
    if previous_was_underscore || !any_digit {
        return None;
    }
    Some(value)
}

/// Re-adopt a live-but-untracked controller (Python
/// `_readopt_live_controller` + `_restore_running_execution_from_config`):
/// rebuild the entry from the on-disk config instead of creating a
/// duplicate over the running qemu.
fn readopt_live_controller(state: &DaemonState, vm_id: &str) -> Result<VmEntry, RpcError> {
    let root = &state.host.settings.execution_root;
    let path = controller_config::controller_config_path(root, vm_id);
    let contents = std::fs::read_to_string(&path)
        .map_err(|error| RpcError::Internal(format!("cannot read {}: {error}", path.display())))?;
    let config = parse_controller_config(&contents)
        .map_err(|error| RpcError::Internal(error.to_string()))?;
    let qemu = match config.vm {
        VmConfiguration::Qemu(qemu) => *qemu,
        VmConfiguration::Firecracker => {
            return Err(RpcError::InvalidBackend(
                "Reattach supports QEMU configurations only, got VMConfiguration".to_string(),
            ));
        }
    };

    // The on-disk vm_index may meanwhile belong to another tracked VM;
    // restoring on it would rewire that VM's networking (Python raises the
    // same refusal).
    if let Some(claimed_by) = state
        .world
        .blocking_read()
        .entries
        .values()
        .find(|entry| entry.vm_hash != vm_id && entry.vm_index == config.vm_index)
        .map(|entry| entry.vm_hash.clone())
    {
        return Err(RpcError::Internal(format!(
            "Cannot re-adopt VM {vm_id}: its on-disk vm_index {} is now claimed by \
             running VM {claimed_by}; refusing to rewire that VM's networking or to \
             create a duplicate, operator intervention required",
            config.vm_index
        )));
    }

    tracing::warn!(
        vm_id,
        "create requested but its controller is already running and untracked; \
         re-adopting it instead of creating a duplicate"
    );

    let gpus = world::rebuild_attached_gpus(&qemu.gpus, &state.host.gpus);
    let port_forwards = ports::load_port_forwards(&state.host.settings.supervisor_database, vm_id)
        .map_err(RpcError::Internal)?;
    // Rebuild the NUMA ledger entry for this live-but-untracked controller
    // from its effective AllowedCPUs drop-in (increment C1); unpinned when
    // no drop-in maps to a node. This registers the VM exactly once: it fires
    // only for a controller NOT currently tracked, disjoint from what the
    // boot-time `reconcile_numa_ledger` pass registers (see that function's
    // invariant), so the two paths never double-count the same VM.
    let (numa_memory_mb, numa_hugepage_size) = config_hugepage_backing(&qemu);
    let numa_node = reconstruct_numa_placement(
        state,
        vm_id,
        qemu.vcpu_count,
        numa_memory_mb,
        numa_hugepage_size,
    );

    let now = now_ns();
    let entry = VmEntry {
        vm_hash: vm_id.to_string(),
        vm_index: config.vm_index,
        config: qemu,
        settings_slice: config.settings,
        times: VmTimes {
            defined_at_ns: now,
            preparing_at_ns: now,
            prepared_at_ns: now,
            ..VmTimes::default()
        },
        adopted_running: true,
        ipv4: None,
        ipv6: None,
        port_forwards,
        gpus,
        spec: None,
        ordinal: 0, // assigned by insert_entry
        is_program: false,
        program: None,
        numa_node,
    };
    {
        let mut world = state.world.blocking_write();
        world.reserved_vm_indices.remove(&entry.vm_index);
        world.insert_entry(entry);
    }

    // _restore_network + started_at + recreate_port_redirect_rules; a
    // failure leaves the VM untracked again (remove the entry), like the
    // Python readopt propagating out of create.
    let restore = (|| -> Result<(), String> {
        if state.host.settings.allow_vm_networking {
            let tap = tap_assignment(state, vm_id)?;
            let _net = net_lock(state);
            if !state.taps.interface_exists(&tap.device_name) {
                state
                    .taps
                    .create_tap(&tap)
                    .map_err(|error| error.to_string())?;
                if let Some(ndp) = &state.ndp {
                    ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, true)?;
                }
            } else if let Some(ndp) = &state.ndp {
                // Prime the ndppd map without touching the service: the
                // on-disk config already covers this running VM.
                ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, false)?;
            }
            nft_setup_vm(state, tap.vm_index, &tap.device_name)?;
        }
        with_entry_mut(state, vm_id, |entry| entry.times.started_at_ns = now_ns());
        recreate_port_redirect_rules(state, vm_id)?;
        Ok(())
    })();
    if let Err(error) = restore {
        // The VM is untracked again. Undo the NUMA ledger reservation
        // reconstruct_numa_placement made above, or a retry's reconstruct (and
        // a restart's reconcile_numa_ledger) would double-count this still-
        // running VM. Release OUTSIDE the world lock, matching
        // delete_tracked_vm's world-then-ledger ordering. Do NOT remove the
        // drop-in: unlike a delete, the controller is still running pinned to
        // it (we only failed to re-adopt it into tracking), so removing it
        // would de-pin a live VM and desync on-disk state from the process.
        let released = {
            let mut world = state.world.blocking_write();
            let removed = world.entries.remove(vm_id);
            if let Some(entry) = &removed {
                world.reserved_vm_indices.insert(entry.vm_index);
            }
            removed.and_then(|entry| {
                entry.numa_node.map(|node| {
                    let (memory_mb, hugepage_size) = config_hugepage_backing(&entry.config);
                    (node, entry.config.vcpu_count, memory_mb, hugepage_size)
                })
            })
        };
        if let Some((node, vcpus, memory_mb, hugepage_size)) = released {
            release_numa_placement(state, node, vcpus, memory_mb, hugepage_size);
        }
        return Err(RpcError::Internal(error));
    }
    // The VM may also be queued for background retry (or given up on): drop
    // the queue entry now that it is tracked again, like the Python
    // `_failed_reattach.pop(vm_id)` after a successful readopt.
    state.world.blocking_write().failed_reattach.remove(vm_id);
    entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))
}

/// `str(PurePosixPath(text))` with the wire convention "." -> ""
/// (proto_convert.py path_from_wire/path_to_wire): purely lexical, like
/// pathlib. Collapses duplicate slashes (preserving POSIX's special
/// exactly-two leading slashes), drops "." components and trailing
/// slashes, keeps "..".
fn normalize_wire_path(text: &str) -> String {
    let root = if text.starts_with("//") && !text.starts_with("///") {
        "//"
    } else if text.starts_with('/') {
        "/"
    } else {
        ""
    };
    let parts: Vec<&str> = text
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect();
    // PurePosixPath("") and PurePosixPath(".") both render "."; the wire
    // convention (path_to_wire) sends "." back as the empty string.
    format!("{root}{}", parts.join("/"))
}

/// Python passes every wire path through pathlib.Path at spec ingestion
/// (create_vm_spec_from_pb), so lexically equivalent spellings compare
/// equal for create-retry idempotency and normalize in the written
/// controller config; apply the same normalization here.
fn normalize_spec_paths(spec: &mut pb::VmSpec) {
    spec.kernel_path = normalize_wire_path(&spec.kernel_path);
    spec.initrd_path = normalize_wire_path(&spec.initrd_path);
    for disk in &mut spec.disks {
        disk.path = normalize_wire_path(&disk.path);
    }
}

/// A readable message out of a caught panic payload.
fn panic_message(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(message) = panic.downcast_ref::<&str>() {
        (*message).to_string()
    } else if let Some(message) = panic.downcast_ref::<String>() {
        message.clone()
    } else {
        "non-string panic payload".to_string()
    }
}

/// CreateVm at the LocalSupervisor layer: the pool-level create plus the
/// event the Python create_vm emits after `_to_vm_info` (DEFINED to the
/// created VM's status, on every successful create INCLUDING the
/// idempotent-retry and readopt returns).
pub fn create_vm(state: &DaemonState, request: pb::VmSpec) -> Result<(VmEntry, bool), RpcError> {
    let (entry, running) = create_vm_inner(state, request)?;
    state.events.emit(
        &entry.vm_hash,
        pb::VmStatus::Defined,
        crate::service::vm_status(&entry.times, running),
    );
    Ok((entry, running))
}

fn create_vm_inner(
    state: &DaemonState,
    mut request: pb::VmSpec,
) -> Result<(VmEntry, bool), RpcError> {
    normalize_spec_paths(&mut request);
    match request.backend() {
        pb::Backend::Qemu => {}
        pb::Backend::Firecracker => {
            if request.persistent {
                // Ephemeral programs landed with increment 4; persistent
                // programs boot under systemd controller units and follow
                // with the controller port (ledgered).
                return Err(RpcError::Unimplemented(
                    "CreateVm for persistent Firecracker programs is not implemented yet \
                     by the Rust supervisor daemon"
                        .to_string(),
                ));
            }
            return create_program_vm(state, request);
        }
        pb::Backend::Unspecified => {
            // Python: BACKEND_FROM_PB[0] raises KeyError -> INTERNAL.
            return Err(RpcError::Internal(
                "unknown backend BACKEND_UNSPECIFIED".to_string(),
            ));
        }
    }
    // Confidential VMs (increment 6) ride the QEMU create path but are NOT
    // started: the controller unit stays down until InitializeConfidential
    // uploads the owner's session certificates. build_qemu_confidential_
    // configuration produces the extra SEV fields; execution.start leaves it
    // in awaiting_confidential_init.
    //
    // SEV-SNP (increment B1) is the exception: it has NO session/godh handshake
    // (secrets are injected at runtime over the attested channel), so there is
    // nothing to await and it starts immediately like a plain VM. It also boots
    // the measured Nix image directly (kernel+initrd), so it takes no cloud-init
    // drive.
    let snp = request
        .tee
        .as_ref()
        .is_some_and(|tee| tee.backend == pb::TeeBackend::SevSnp as i32);
    let confidential = request.tee.is_some();
    // SEV/SEV-ES only: the create-then-await path. SNP does not await.
    let await_session = confidential && !snp;
    if !request.persistent {
        // Python boots this path and fails inside AlephQemuInstance.start()
        // (NotImplementedError -> INTERNAL); refuse up front with the same
        // wire shape.
        return Err(RpcError::Internal(
            "non-persistent QEMU VMs are not supported (AlephQemuInstance starts under systemd only)"
                .to_string(),
        ));
    }
    let vm_id = request.vm_id.clone();

    // Python holds creation_lock across the whole create, including the
    // boot wait; other RPCs proceed.
    let _create_guard = state
        .creation_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let lock = vm_lock(state, &vm_id);
    let _vm_guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Idempotency on a live, tracked VM (times-based for a program entry
    // holding this vm_id: its FIRECRACKER spec then conflicts).
    if let Some(entry) = entry_snapshot(state, &vm_id)
        && entry_running(state, &entry)
        && !entry.is_stopping()
    {
        let entry = same_spec_or_conflict(&entry, &request)?;
        return Ok((entry, true));
    }

    // The VM may be running WITHOUT a live tracked state (failed adoption,
    // or tracked-stopped whose unit came back): decide from the on-disk
    // config plus the unit's definitive state, like _readopt_live_controller.
    let config_path =
        controller_config::controller_config_path(&state.host.settings.execution_root, &vm_id);
    if config_path.exists() {
        let unit = controller_unit_name(&vm_id);
        match state.units.get_active_state(&unit).as_str() {
            // Positively not running: a fresh create is a clean
            // restart-from-disk.
            "inactive" | "failed" | "not-loaded" => {}
            "active" => {
                let entry = readopt_live_controller(state, &vm_id)?;
                let entry = same_spec_or_conflict(&entry, &request)?;
                return Ok((entry, true));
            }
            other => {
                return Err(RpcError::Internal(format!(
                    "Cannot determine the state of controller {unit} (ActiveState: {other}); \
                     refusing to create VM {vm_id} over a possibly live controller, retry later"
                )));
            }
        }
    }

    // Mechanism backstops, atomic with the registration below.
    check_memory_backstop(state, request.memory_mib)?;
    let validated_gpus = validate_spec_gpus(state, &request.gpus)?;
    // Rootfs-disk validation, after the backstops like the Python order
    // (prepare() raises it from require_rootfs) and before any side effect.
    require_rootfs(&request)?;

    // Register the entry (Python registers the execution before prepare so
    // duplicate creates and Health see it), allocating the vm_index and the
    // tap assignment under one world lock.
    let (vm_index, assignment, mut written, stale_numa) = {
        let mut world = state.world.blocking_write();
        // A stale stopped entry is replaced, like the Python
        // `self.executions[vm_id] = execution` overwrite; a dict overwrite
        // keeps the key's insertion position, so the ordinal survives.
        let stale = world.entries.remove(&vm_id);
        let stale_ordinal = stale.as_ref().map(|stale| stale.ordinal);
        // A stopped-then-recreated VM keeps its ledger reservation across the
        // stop (stop never releases, by design); the dropped VmEntry carries
        // a LIVE reservation on `numa_node`. Capture it so we can release it
        // BEFORE the new `place_vm_numa` re-allocates - otherwise the node's
        // vCPUs double-count (increment C1, FIX 2).
        let stale_numa = stale.as_ref().and_then(|stale| {
            stale.numa_node.map(|node| {
                let (memory_mb, hugepage_size) = config_hugepage_backing(&stale.config);
                (node, stale.config.vcpu_count, memory_mb, hugepage_size)
            })
        });
        let vm_index = world
            .unique_vm_index(state.host.settings.start_id_index)
            .map_err(|error| RpcError::Internal(error.to_string()))?;
        let assignment = if state.host.settings.allow_vm_networking {
            let mut ordinal = world.ipv6_dynamic_ordinal;
            let pair = world::derive_tap_assignment(
                &state.host.settings,
                vm_index,
                &vm_id,
                VmType::Instance,
                &mut ordinal,
            )
            .map_err(|error| RpcError::Internal(error.to_string()))?;
            world.ipv6_dynamic_ordinal = ordinal;
            Some(pair)
        } else {
            None
        };

        let interface_name = assignment.as_ref().map(|_| format!("vmtap{vm_index}"));
        let written = build_written_config(state, &request, vm_index, interface_name)?;
        let parsed = parse_controller_config(&written.to_json())
            .map_err(|error| RpcError::Internal(error.to_string()))?;
        let VmConfiguration::Qemu(qemu) = parsed.vm else {
            return Err(RpcError::Internal(
                "the written config did not round-trip as QEMU".to_string(),
            ));
        };
        let now = now_ns();
        let mut entry = VmEntry {
            vm_hash: vm_id.clone(),
            vm_index,
            config: *qemu,
            settings_slice: parsed.settings,
            times: VmTimes {
                defined_at_ns: now,
                preparing_at_ns: now,
                prepared_at_ns: now,
                ..VmTimes::default()
            },
            adopted_running: false,
            ipv4: assignment.as_ref().map(|(ipv4, _)| ipv4.clone()),
            ipv6: assignment.as_ref().map(|(_, ipv6)| ipv6.clone()),
            port_forwards: Vec::new(),
            gpus: validated_gpus,
            spec: Some(request.clone()),
            ordinal: 0, // assigned below
            is_program: false,
            program: None,
            // Set below once the NUMA placement is chosen (increment C1).
            numa_node: None,
        };
        // Increment D2 (ledger 77): create starts the per-tap DHCP server on
        // the request predicate `snp`, while every teardown path keys DHCP
        // cleanup on `config.snp().is_some()`. They must agree, or a started
        // server leaks. The two predicates are derived independently (request
        // TEE backend vs the written-then-parsed config), so assert here that
        // the freshly built config reaches the same SNP verdict; if this ever
        // trips, create's predicate stopped being a superset of `snp()`.
        debug_assert_eq!(
            entry.config.snp().is_some(),
            snp,
            "create's SNP predicate must match the written config's snp()"
        );
        match stale_ordinal {
            Some(ordinal) => {
                entry.ordinal = ordinal;
                world.entries.insert(vm_id.clone(), entry);
            }
            None => world.insert_entry(entry),
        }
        (vm_index, assignment, written, stale_numa)
    };

    let tap = assignment.map(|(ipv4, ipv6)| TapAssignment::new(vm_index, ipv4, ipv6));

    // Release the replaced stale entry's reservation before re-placing, so a
    // stop->recreate does not leak/double-count its vCPUs (increment C1, FIX
    // 2). The drop-in is left in place: `place_vm_numa` + `apply_numa_dropin`
    // below overwrite it (the file is keyed by vm_hash), and a placement
    // failure unwinds without a boot, so no stale pin is left applied.
    if let Some((node, vcpus, memory_mb, hugepage_size)) = stale_numa {
        release_numa_placement(state, node, vcpus, memory_mb, hugepage_size);
    }

    // NUMA placement (increment C1): honor a requested numa_node or pack
    // onto the first node with room, reserving its vCPUs in the ledger
    // before the boot. A placement failure unwinds the just-registered
    // entry, like the boot-failure cleanup below. The chosen cpuset is
    // written as an AllowedCPUs drop-in inside the boot closure.
    let numa_placement =
        match place_vm_numa(state, request.vcpus, request.memory_mib, request.numa_node) {
            Ok(placement) => placement,
            Err(error) => {
                state.world.blocking_write().entries.remove(&vm_id);
                return Err(error);
            }
        };
    if let Some(placement) = &numa_placement {
        let hugepage_size = placement
            .hugepage_size
            .map(|size| size.as_qemu().to_string());
        with_entry_mut(state, &vm_id, |entry| {
            entry.numa_node = Some(placement.node);
            // Keep the in-memory config in lockstep with the written config so
            // a later delete/failed-create releases the SAME pages the allocator
            // reserved (delete derives the release from `entry.config`). Without
            // this the config's hugepage_size stays None and the pool leaks.
            entry.config.numa_node = Some(placement.node);
            entry.config.hugepage_size = hugepage_size.clone();
        });
        // Carry the chosen node (and hugepage size, if any) into the controller
        // config BEFORE it is written to disk below, so the controller binds the
        // VM's memory to that node. build_written_config left these None; a
        // no-placement create never enters this branch, so its bytes stay pre-C2.
        written.vm_configuration.numa_node = Some(placement.node);
        written.vm_configuration.hugepage_size = hugepage_size;
    }

    // qemu_build.py appends settings.DEVELOPER_SSH_KEYS when
    // USE_DEVELOPER_SSH_KEYS is truthy.
    let ssh_authorized_keys = cloudinit::merged_ssh_keys(
        &request.ssh_authorized_keys,
        state.host.settings.use_developer_ssh_keys,
        &state.host.settings.developer_ssh_keys,
    );

    // catch_unwind: a panic inside the boot must take the same cleanup path
    // as an error (tap, nftables and the entry would otherwise leak) and
    // re-report as an internal error. AssertUnwindSafe: the state the
    // closure touches is either re-read under locks afterwards or removed
    // by the cleanup below.
    let boot = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
        if let Some(tap) = &tap {
            let _net = net_lock(state);
            // A leftover interface from a previous life of this vm_index is
            // recreated from scratch, like the create path's
            // interface_exists -> delete -> create_tap sequence.
            if state.taps.interface_exists(&tap.device_name) {
                std::thread::sleep(state.pacing.tap_delete_delay);
                if let Some(ndp) = &state.ndp {
                    ndp.delete_range(&tap.device_name, true)?;
                }
                state
                    .taps
                    .delete_tap(tap)
                    .map_err(|error| error.to_string())?;
            }
            state
                .taps
                .create_tap(tap)
                .map_err(|error| error.to_string())?;
            if let Some(ndp) = &state.ndp {
                ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, true)?;
            }
            nft_setup_vm(state, vm_index, &tap.device_name)?;
            // SNP measured VMs get their IPv4 via a per-tap DHCP server, not
            // cloud-init static config: the measured image DHCPs and its
            // cmdline omits `ip=` for measurement determinism (ledger entry
            // 77). The tap already carries the gateway address (create_tap
            // added host_ipv4_cidr), so dnsmasq can bind and route. Plain and
            // SEV VMs skip this and keep their cloud-init static config.
            if snp {
                let config = dhcp::DhcpConfig::for_snp(
                    &vm_id,
                    tap,
                    state.host.dns_nameservers.as_deref().unwrap_or(&[]),
                    &dhcp_lease_dir(state),
                )?;
                state.dhcp.start(&config)?;
            }
        }

        // The cloud-init seed, then the controller config (same order as
        // build_qemu_configuration + save_controller_configuration). SNP boots
        // the measured Nix image directly and carries no cloud-init drive, so
        // the seed is skipped (build_written_config leaves cloud_init_drive_path
        // unset for SNP; the two must agree).
        if !snp {
            cloudinit::CloudInitDrive {
                execution_root: &state.host.settings.execution_root,
                vm_hash: &vm_id,
                vm_index,
                tap: tap.as_ref(),
                ssh_authorized_keys: &ssh_authorized_keys,
                hostname: &request.hostname,
                has_gpu: !request.gpus.is_empty(),
                dns_nameservers: state.host.dns_nameservers.as_deref(),
                confidential,
            }
            .create_image()?;
        }
        controller_config::save_controller_config(&state.host.settings.execution_root, &written)?;

        // Write the AllowedCPUs drop-in before the controller starts so the
        // pin applies on first boot (increment C1). For SEV/SEV-ES VMs the
        // controller starts later (InitializeConfidential); the drop-in
        // persists on disk and applies then.
        if let Some(placement) = &numa_placement {
            apply_numa_dropin(state, &vm_id, placement)?;
        }

        with_entry_mut(state, &vm_id, |entry| entry.times.starting_at_ns = now_ns());
        let unit = controller_unit_name(&vm_id);
        if await_session {
            // execution.start for a SEV/SEV-ES VM: setup/configure/
            // start_guest_api happen, but `persistent and not is_confidential`
            // is false, so the controller is NOT enabled/started. started_at
            // is stamped here; the VM reports awaiting_confidential_init until
            // InitializeConfidential runs. SNP does NOT take this branch (it
            // has no session to wait for) and starts below like a plain VM.
            with_entry_mut(state, &vm_id, |entry| entry.times.started_at_ns = now_ns());
        } else {
            units::enable_and_start(&*state.units, &unit)?;
            if let Err(error) = wait_for_controller_ready(state, &unit) {
                // non_blocking_wait_for_boot: a failed boot stops and cleans up
                // (stop_and_disable + graceful wait), then the create fails.
                tracing::warn!(unit, error, "controller not running, stopping");
                if let Err(stop_error) = units::stop_and_disable(&*state.units, &unit) {
                    tracing::warn!(unit, stop_error, "failed to stop the failed controller");
                }
                wait_for_controller_stopped(state, &unit);
                return Err(format!("controller failed to start: {error}"));
            }
            with_entry_mut(state, &vm_id, |entry| entry.times.started_at_ns = now_ns());
        }

        // Reuse persisted host ports across restarts; the agent reconciles
        // the rest through AddPortForward.
        let forwards = ports::load_port_forwards(&state.host.settings.supervisor_database, &vm_id)?;
        let has_forwards = !forwards.is_empty();
        with_entry_mut(state, &vm_id, |entry| entry.port_forwards = forwards);
        if has_forwards {
            recreate_port_redirect_rules(state, &vm_id)?;
        }
        Ok(())
    }))
    .unwrap_or_else(|panic| Err(format!("CreateVm panicked: {}", panic_message(&*panic))));

    if let Err(error) = boot {
        // The Python create's except branch: teardown networking, forget
        // the execution, propagate. The controller config and cloud-init
        // seed are left behind, exactly like Python.
        if let Some(tap) = &tap {
            let _net = net_lock(state);
            // Tear the per-tap DHCP server down alongside the tap (SNP only,
            // idempotent): a failed SNP boot must not leave a dnsmasq bound to
            // a tap that is about to be deleted (ledger entry 77).
            if snp
                && let Err(dhcp_error) = state.dhcp.stop(
                    &vm_id,
                    &dhcp::lease_file_path(&dhcp_lease_dir(state), &vm_id),
                )
            {
                tracing::warn!(dhcp_error, "failed to stop the DHCP server during cleanup");
            }
            nft_teardown_vm(state, vm_index);
            std::thread::sleep(state.pacing.tap_delete_delay);
            if let Some(ndp) = &state.ndp
                && let Err(ndp_error) = ndp.delete_range(&tap.device_name, true)
            {
                tracing::warn!(ndp_error, "failed to drop the ndp range during cleanup");
            }
            if let Err(delete_error) = state.taps.delete_tap(tap) {
                tracing::warn!(%delete_error, "failed to delete the tap during cleanup");
            }
        }
        // Release the reserved vCPUs and drop the AllowedCPUs drop-in (if the
        // boot got far enough to write it); the ledger must not leak a
        // reservation for a VM that never came up (increment C1).
        if let Some(placement) = &numa_placement {
            // Return the exact pages this VM reserved (placement.hugepage_size)
            // so a failed create does not leak the node's hugepage pool.
            let memory_mb = request.memory_mib.min(u32::MAX as u64) as u32;
            release_numa_placement(
                state,
                placement.node,
                request.vcpus,
                memory_mb,
                placement.hugepage_size,
            );
            remove_numa_dropin(state, &vm_id);
        }
        state.world.blocking_write().entries.remove(&vm_id);
        return Err(RpcError::Internal(error));
    }

    let entry = entry_snapshot(state, &vm_id).ok_or_else(|| RpcError::NotFound(vm_id.clone()))?;
    let running = unit_active(state, &entry.unit_name());
    Ok((entry, running))
}

// ── Ephemeral Firecracker programs (increment 4) ────────────────────────

/// Python `VmPool._create_firecracker_from_spec` + `VmExecution.start` for
/// a non-persistent program: register, tap when the spec asks for internet
/// (VmType.microvm addressing), boot through the launcher (config JSON,
/// spawn, vsock ready handshake) and record the channel facts. No
/// controller config is written and no persisted port mappings are
/// preloaded (both Python behaviors).
fn create_program_vm(
    state: &DaemonState,
    request: pb::VmSpec,
) -> Result<(VmEntry, bool), RpcError> {
    let Some(guest_channel) = request.guest_channel else {
        // Checked before the creation lock, like the Python method.
        return Err(RpcError::InvalidBackend(
            "Firecracker spec VMs require a guest_channel".to_string(),
        ));
    };
    let vm_id = request.vm_id.clone();

    let _create_guard = state
        .creation_lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let lock = vm_lock(state, &vm_id);
    let _vm_guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    // Idempotency on a live, tracked VM. Unlike the QEMU path there is no
    // readopt probe: ephemeral programs never leave an on-disk config, and
    // the Python method has none either.
    if let Some(entry) = entry_snapshot(state, &vm_id)
        && entry_running(state, &entry)
        && !entry.is_stopping()
    {
        let entry = same_spec_or_conflict(&entry, &request)?;
        return Ok((entry, true));
    }

    // The physical-memory backstop, then the prepare() validations in the
    // Python order (SpecProgramResources.from_spec: kernel, then rootfs).
    check_memory_backstop(state, request.memory_mib)?;
    if request.kernel_path.is_empty() {
        return Err(RpcError::InvalidBackend(
            "A Firecracker spec requires a kernel_path".to_string(),
        ));
    }
    let rootfs_path = require_rootfs(&request)?.path.clone();
    let extra_disks: Vec<(String, bool)> = request
        .disks
        .iter()
        .filter(|disk| disk.role == pb::disk_config::DiskRole::Extra as i32)
        .map(|disk| (disk.path.clone(), disk.readonly))
        .collect();
    let internet_access = request
        .network
        .as_ref()
        .is_some_and(|network| network.internet_access);

    // Register the entry (Python registers the execution before prepare),
    // allocating the vm_index and the microvm tap assignment under one
    // world lock.
    let (vm_index, assignment) = {
        let mut world = state.world.blocking_write();
        let stale_ordinal = world.entries.remove(&vm_id).map(|stale| stale.ordinal);
        let vm_index = world
            .unique_vm_index(state.host.settings.start_id_index)
            .map_err(|error| RpcError::Internal(error.to_string()))?;
        let assignment = if state.host.settings.allow_vm_networking && internet_access {
            let mut ordinal = world.ipv6_dynamic_ordinal;
            let pair = world::derive_tap_assignment(
                &state.host.settings,
                vm_index,
                &vm_id,
                VmType::Microvm,
                &mut ordinal,
            )
            .map_err(|error| RpcError::Internal(error.to_string()))?;
            world.ipv6_dynamic_ordinal = ordinal;
            Some(pair)
        } else {
            None
        };
        let now = now_ns();
        let mut entry = VmEntry {
            vm_hash: vm_id.clone(),
            vm_index,
            config: QemuVmConfig::for_program(
                request.memory_mib,
                assignment.as_ref().map(|_| format!("vmtap{vm_index}")),
            ),
            settings_slice: Default::default(),
            times: VmTimes {
                defined_at_ns: now,
                preparing_at_ns: now,
                prepared_at_ns: now,
                ..VmTimes::default()
            },
            adopted_running: false,
            ipv4: assignment.as_ref().map(|(ipv4, _)| ipv4.clone()),
            ipv6: assignment.as_ref().map(|(_, ipv6)| ipv6.clone()),
            port_forwards: Vec::new(),
            gpus: Vec::new(),
            spec: Some(request.clone()),
            ordinal: 0, // assigned below
            is_program: true,
            program: None,
            // Ephemeral programs are never NUMA-pinned.
            numa_node: None,
        };
        match stale_ordinal {
            Some(ordinal) => {
                entry.ordinal = ordinal;
                world.entries.insert(vm_id.clone(), entry);
            }
            None => world.insert_entry(entry),
        }
        (vm_index, assignment)
    };
    let tap = assignment.map(|(ipv4, ipv6)| TapAssignment::new(vm_index, ipv4, ipv6));

    // catch_unwind for the same reason as the QEMU create: a panic must
    // take the cleanup path, not leak the entry/tap.
    let boot = std::panic::catch_unwind(std::panic::AssertUnwindSafe(
        || -> Result<crate::firecracker::BootedProgram, RpcError> {
            if let Some(tap) = &tap {
                let _net = net_lock(state);
                if state.taps.interface_exists(&tap.device_name) {
                    std::thread::sleep(state.pacing.tap_delete_delay);
                    if let Some(ndp) = &state.ndp {
                        ndp.delete_range(&tap.device_name, true)
                            .map_err(RpcError::Internal)?;
                    }
                    state
                        .taps
                        .delete_tap(tap)
                        .map_err(|error| RpcError::Internal(error.to_string()))?;
                }
                state
                    .taps
                    .create_tap(tap)
                    .map_err(|error| RpcError::Internal(error.to_string()))?;
                if let Some(ndp) = &state.ndp {
                    ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, true)
                        .map_err(RpcError::Internal)?;
                }
                nft_setup_vm(state, vm_index, &tap.device_name).map_err(RpcError::Internal)?;
            }

            // config.py MachineConfig: vcpu_count and mem_size_mib are
            // pydantic PositiveInt, so a non-positive value raises the
            // ValidationError in setup(), after the tap exists and before
            // any spawn. Same point, same INTERNAL outcome, no spawn.
            if request.vcpus == 0 || request.memory_mib == 0 {
                return Err(RpcError::Internal(format!(
                    "invalid machine config: vcpu_count and mem_size_mib must be positive \
                     (got {} vcpus, {} MiB)",
                    request.vcpus, request.memory_mib
                )));
            }

            with_entry_mut(state, &vm_id, |entry| entry.times.starting_at_ns = now_ns());
            // The ready-wait bound is workload policy carried by the spec;
            // settings.INIT_TIMEOUT only covers channels that state none
            // (SpecFirecrackerProgram.__init__). Clamped: a huge configured
            // float must behave like Python's wait_for, not panic.
            let init_timeout = if guest_channel.ready_timeout_secs != 0 {
                Duration::from_secs(u64::from(guest_channel.ready_timeout_secs))
            } else {
                crate::firecracker::duration_from_secs_clamped(
                    state.host.settings.init_timeout.max(0.0),
                )
            };
            let boot_request = ProgramBootRequest {
                vm_index,
                vm_hash: vm_id.clone(),
                kernel_path: request.kernel_path.clone(),
                rootfs_path: rootfs_path.clone(),
                extra_disks: extra_disks.clone(),
                vcpus: request.vcpus,
                memory_mib: request.memory_mib,
                tap_device: tap.as_ref().map(|tap| tap.device_name.clone()),
                ready_port: guest_channel.ready_port,
                init_timeout,
            };
            state
                .programs
                .boot(&boot_request)
                .map_err(|error| match error {
                    ProgramBootError::InitTimeout => {
                        // MicroVMFailedInitError: empty message on the wire.
                        RpcError::MicroVmInit(String::new())
                    }
                    ProgramBootError::Failed(message) => RpcError::Internal(message),
                })
        },
    ))
    .unwrap_or_else(|panic| {
        Err(RpcError::Internal(format!(
            "CreateVm panicked: {}",
            panic_message(&*panic)
        )))
    });

    match boot {
        Ok(booted) => {
            with_entry_mut(state, &vm_id, |entry| {
                entry.times.started_at_ns = now_ns();
                entry.program = Some(ProgramEntry {
                    vsock_path: booted.vsock_path.clone(),
                    ready_payload: booted.ready_payload.clone(),
                    handle: booted.handle.clone(),
                });
            });
            let entry =
                entry_snapshot(state, &vm_id).ok_or_else(|| RpcError::NotFound(vm_id.clone()))?;
            Ok((entry, true))
        }
        Err(error) => {
            // The Python failure path (VmExecution.start's except plus the
            // pool's): the launcher already tore the fvm down; the chain
            // teardown is unconditional and the tap goes when it exists.
            {
                let _net = net_lock(state);
                nft_teardown_vm(state, vm_index);
                if let Some(tap) = &tap {
                    std::thread::sleep(state.pacing.tap_delete_delay);
                    if let Some(ndp) = &state.ndp
                        && let Err(ndp_error) = ndp.delete_range(&tap.device_name, true)
                    {
                        tracing::warn!(ndp_error, "failed to drop the ndp range during cleanup");
                    }
                    if let Err(delete_error) = state.taps.delete_tap(tap) {
                        tracing::warn!(%delete_error, "failed to delete the tap during cleanup");
                    }
                }
            }
            state.world.blocking_write().entries.remove(&vm_id);
            Err(error)
        }
    }
}

/// Python `LocalSupervisor.run_program_code` + `_run_code_over_channel`:
/// one request over the program's guest channel, the raw reply back.
pub fn run_program_code(
    state: &DaemonState,
    vm_id: &str,
    scope_msgpack: &[u8],
    timeout_secs: f64,
) -> Result<Vec<u8>, RpcError> {
    // grpc_server.py:158 msgpack.unpackb-validates the scope BEFORE touching
    // the VM (invalid msgpack aborts INTERNAL even for unknown vm_ids); on
    // success the original bytes are still forwarded untouched (the
    // pass-through of ledger entry 38 is shape-checked, never re-encoded).
    crate::firecracker::validate_msgpack(scope_msgpack).map_err(RpcError::Internal)?;
    // The vm_lock stands in for the Python `becomes_ready` wait: CreateVm
    // holds it through the whole boot, so acquiring it means the boot
    // finished (or failed and removed the entry). Released before the
    // exchange: a long-running program request must not block mutations,
    // and Python holds no lock here either.
    let entry = {
        let lock = vm_lock(state, vm_id);
        let _guard = lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?
    };
    if !entry.is_program {
        return Err(RpcError::InvalidBackend(format!(
            "VM {vm_id} is not a program; code can only be run on programs"
        )));
    }
    let channel = entry
        .program
        .as_ref()
        .map(|program| program.vsock_path.clone())
        .unwrap_or_default();
    if channel.is_empty() {
        return Err(RpcError::Internal(format!(
            "VM {vm_id} exposes no guest channel; cannot run program code"
        )));
    }
    crate::firecracker::run_code_over_channel(&channel, scope_msgpack, timeout_secs).map_err(
        |error| match error {
            // VmInitNotConnectedError("MicroVM may have crashed") -> INTERNAL.
            crate::firecracker::ChannelError::NotConnected => {
                RpcError::Internal("MicroVM may have crashed".to_string())
            }
            // asyncio.TimeoutError: str() is empty -> INTERNAL "".
            crate::firecracker::ChannelError::Timeout => RpcError::Internal(String::new()),
            crate::firecracker::ChannelError::Io(message) => RpcError::Internal(message),
        },
    )
}

// ── RecreateNetwork ─────────────────────────────────────────────────────

/// Python `LocalSupervisor.recreate_network`: flush every aleph chain,
/// re-initialize the base ruleset, recreate the per-VM chains of running
/// VMs and reapply their persisted redirects. Returns the summary dict.
pub fn recreate_network(state: &DaemonState) -> Result<serde_json::Value, RpcError> {
    tracing::info!("Starting network recreation process");

    // Step 1: running VMs with a tap (Python: execution.is_running and
    // execution.vm.tap_interface), in pool insertion order.
    let entries: Vec<VmEntry> = state
        .world
        .blocking_read()
        .ordered_entries()
        .into_iter()
        .cloned()
        .collect();
    let unit_names: Vec<String> = entries.iter().map(|entry| entry.unit_name()).collect();
    let states = state
        .units
        .active_states(&unit_names)
        .unwrap_or_else(|error| {
            tracing::error!(error, "Failed to get services active states");
            unit_names
                .iter()
                .map(|unit| (unit.clone(), false))
                .collect()
        });
    // Rederive missing IP assignments before filtering (ledger entry 24,
    // closed): entries adopted during a bus outage carry no derived IPs
    // (world.rs stamps nothing when unit states are unknown), and without
    // this an operator could not heal their chains through RecreateNetwork.
    // tap_assignment derives from vm_index/vm_hash (both known) and stores
    // the result on the entry.
    let mut entries = entries;
    for entry in &mut entries {
        if entry.ipv4.is_some()
            || !networking_enabled(state, entry)
            || !states.get(&entry.unit_name()).copied().unwrap_or(false)
        {
            continue;
        }
        match tap_assignment(state, &entry.vm_hash) {
            Ok(tap) => {
                entry.ipv4 = Some(tap.ipv4);
                entry.ipv6 = Some(tap.ipv6);
            }
            Err(error) => {
                tracing::warn!(
                    vm_hash = entry.vm_hash,
                    error,
                    "cannot rederive the IP assignment; skipping the VM"
                );
            }
        }
    }
    let running: Vec<&VmEntry> = entries
        .iter()
        .filter(|entry| {
            let running = if entry.is_program {
                // Ephemeral programs have no unit; liveness is times-based.
                entry.times.starting_at_ns != 0 && entry.times.stopping_at_ns == 0
            } else {
                states.get(&entry.unit_name()).copied().unwrap_or(false)
            };
            running && entry.ipv4.is_some() && networking_enabled(state, entry)
        })
        .collect();
    tracing::info!(
        count = running.len(),
        "found running VMs to recreate network rules for"
    );

    // Steps 2-4 hold the host-network lock: the flush-and-rebuild must
    // never interleave with a concurrent create/start's chain setup, which
    // could leave a freshly booted VM with no chains at all (Python's
    // event loop cannot interleave these sections). Released before step 5:
    // recreate_port_redirect_rules takes the same lock itself.
    let (removed_chains, recreated_vms, failed_vms) = {
        let _net = net_lock(state);

        // Step 2: remove every aleph chain (per-VM and supervisor),
        // refetching per chain like the Python remove_chain loop.
        let prefix = chain_prefix(state).to_string();
        let all_chains = nft::get_all_aleph_chains(&nft::fetch_ruleset(&*state.nft), &prefix);
        let mut removed_chains = Vec::new();
        for chain in &all_chains {
            let ruleset = nft::fetch_ruleset(&*state.nft);
            let commands = nft::remove_chain_commands(&ruleset, chain);
            // Python remove_all_aleph_chains: a failed removal lands in
            // failed_chains (a WARN) and is EXCLUDED from removed_chains;
            // only failed_chains stays out of the summary in both daemons.
            let result = if commands.is_empty() {
                Ok(())
            } else {
                state.nft.run_commands(&commands)
            };
            match result {
                Ok(()) => removed_chains.push(chain.clone()),
                Err(error) => {
                    tracing::warn!(chain, error, "failed to remove chain");
                }
            }
        }

        // Step 3: re-initialize the base ruleset.
        initialize_nftables(state).map_err(|error| {
            RpcError::Internal(format!("Failed to initialize network: {error}"))
        })?;

        // Step 4: per-VM chains and rules.
        let mut recreated_vms: Vec<String> = Vec::new();
        let mut failed_vms: Vec<serde_json::Value> = Vec::new();
        for entry in &running {
            let device = format!("vmtap{}", entry.vm_index);
            match nft_setup_vm(state, entry.vm_index, &device) {
                Ok(()) => recreated_vms.push(entry.vm_hash.clone()),
                Err(error) => {
                    tracing::error!(
                        vm_hash = entry.vm_hash,
                        error,
                        "failed to recreate VM network"
                    );
                    failed_vms.push(serde_json::json!({
                        "vm_hash": entry.vm_hash,
                        "error": error,
                    }));
                }
            }
        }
        (removed_chains, recreated_vms, failed_vms)
    };

    // Step 5: reapply persisted port redirects, instances only: the Python
    // loop gates on `execution.is_instance`, so a running program's
    // redirects are NOT reapplied after the flush (the shared wart; a
    // program's chains come back in step 4, its DNAT rules do not).
    // Failures only log, like Python.
    for entry in &running {
        if entry.is_program {
            continue;
        }
        if !recreated_vms.contains(&entry.vm_hash) {
            continue;
        }
        let result = (|| -> Result<(), String> {
            let forwards = ports::load_port_forwards(
                &state.host.settings.supervisor_database,
                &entry.vm_hash,
            )?;
            let has_forwards = !forwards.is_empty();
            with_entry_mut(state, &entry.vm_hash, |entry| {
                entry.port_forwards = forwards
            });
            if has_forwards {
                recreate_port_redirect_rules(state, &entry.vm_hash)?;
            }
            Ok(())
        })();
        if let Err(error) = result {
            tracing::error!(
                vm_hash = entry.vm_hash,
                error,
                "error recreating port redirects"
            );
        }
    }

    tracing::info!(
        removed = removed_chains.len(),
        recreated = recreated_vms.len(),
        failed = failed_vms.len(),
        "network recreation complete"
    );
    Ok(serde_json::json!({
        "success": failed_vms.is_empty(),
        "removed_chains_count": removed_chains.len(),
        "removed_chains": removed_chains,
        "recreated_count": recreated_vms.len(),
        "failed_count": failed_vms.len(),
        "recreated_vms": recreated_vms,
        "failed_vms": failed_vms,
    }))
}

// ── Adoption step 5: the boot-time reconcile ────────────────────────────

/// Ensure the kernel/service state of every VM adopted running:
/// create-if-absent taps, primed ndppd ranges, per-VM nftables chains and
/// persisted port redirects. Never flush-and-rebuild (live connections
/// survive), exactly the `_restore_network` half of the Python reattach. A
/// per-VM failure hides the VM like a failed Python reattach (ledger 13).
pub fn reconcile_boot(state: &DaemonState) {
    if !state.host.settings.allow_vm_networking {
        return;
    }
    let running: Vec<String> = state
        .world
        .blocking_read()
        .ordered_entries()
        .into_iter()
        .filter(|entry| entry.adopted_running)
        .map(|entry| entry.vm_hash.clone())
        .collect();
    for vm_id in running {
        let result = (|| -> Result<(), String> {
            let tap = tap_assignment(state, &vm_id)?;
            {
                let _net = net_lock(state);
                if !state.taps.interface_exists(&tap.device_name) {
                    state
                        .taps
                        .create_tap(&tap)
                        .map_err(|error| error.to_string())?;
                    if let Some(ndp) = &state.ndp {
                        ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, true)?;
                    }
                }
                if let Some(ndp) = &state.ndp
                    && state.taps.interface_exists(&tap.device_name)
                {
                    // Prime the in-memory map without a config rewrite or
                    // service restart: the on-disk ndppd.conf already covers
                    // running VMs (update_service=False in Python).
                    ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, false)?;
                }
                nft_setup_vm(state, tap.vm_index, &tap.device_name)?;
            }
            recreate_port_redirect_rules(state, &vm_id)?;
            Ok(())
        })();
        if let Err(error) = result {
            tracing::warn!(
                vm_id,
                error,
                "boot reconcile failed; hiding the VM like a failed Python reattach"
            );
            let mut world = state.world.blocking_write();
            if let Some(entry) = world.entries.remove(&vm_id) {
                world.reserved_vm_indices.insert(entry.vm_index);
                // Queue it for background retry (run_reattach_retry_loop):
                // a transient cause may clear and let us adopt it without
                // downtime, like the Python `_failed_reattach` queue.
                world
                    .failed_reattach
                    .insert(vm_id, world::FailedReattach::new(entry.vm_index));
            }
        }
    }
}

// ── The reattach retry loop (pool.py run_reattach_retry_loop) ───────────

/// Python `REATTACH_RETRY_INTERVAL_SECONDS`.
pub const REATTACH_RETRY_INTERVAL_SECONDS: u64 = 30;
/// Python `REATTACH_RETRY_MAX_ATTEMPTS`.
pub const REATTACH_RETRY_MAX_ATTEMPTS: u32 = 5;

/// Whether any queued failed reattach still wants a retry pass. The Python
/// loop condition: `any(not state.exhausted for state in _failed_reattach)`.
pub fn has_pending_reattach(state: &DaemonState) -> bool {
    state
        .world
        .blocking_read()
        .failed_reattach
        .values()
        .any(|queued| !queued.exhausted)
}

/// One pass of the Python `_retry_failed_reattachments_once`: re-attempt
/// adoption for every queued VM not yet exhausted. A VM that succeeds is
/// dropped from the queue; one that fails has its attempt count bumped and
/// is marked exhausted at the cap (its controller keeps running, the daemon
/// just cannot manage it; operator intervention required).
pub fn retry_failed_reattachments_once(state: &DaemonState) {
    let queued: Vec<String> = state
        .world
        .blocking_read()
        .failed_reattach
        .keys()
        .cloned()
        .collect();
    for vm_id in queued {
        {
            let mut world = state.world.blocking_write();
            if world.entries.contains_key(&vm_id) {
                // Adopted in the meantime (e.g. by an on-demand create).
                // Checked before the exhausted skip so even a given-up
                // entry is dropped once another path tracks the VM.
                world.failed_reattach.remove(&vm_id);
                continue;
            }
            match world.failed_reattach.get(&vm_id) {
                None => continue,
                Some(queued) if queued.exhausted => continue,
                Some(_) => {}
            }
        }
        // Serialize with CreateVm (and the delete of hidden VMs) so the
        // adoption paths never rebuild the same VM concurrently.
        let _create_guard = state
            .creation_lock
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        {
            let mut world = state.world.blocking_write();
            if world.entries.contains_key(&vm_id) {
                // Adopted while we waited for the lock.
                world.failed_reattach.remove(&vm_id);
                continue;
            }
            if !world.failed_reattach.contains_key(&vm_id) {
                // Deleted while we waited for the lock.
                continue;
            }
        }
        // Liveness gate: the controller was alive at startup, but it may
        // have died since. Restoring a dead one would register a phantom
        // "running" entry (the restore never talks to the guest).
        let unit = controller_unit_name(&vm_id);
        let active_state = state.units.get_active_state(&unit);
        match active_state.as_str() {
            "inactive" | "failed" | "not-loaded" => {
                // Positively dead: clean up the stale unit and stop
                // retrying (the Python `_handle_dead_controller` stop; the
                // on-disk config stays, entry 11's no-destruction rule kept
                // by both daemons on this path).
                tracing::warn!(
                    vm_id,
                    active_state,
                    "controller of queued VM died since startup; cleaning it up \
                     and dropping it from reattach retries"
                );
                if let Err(error) = units::stop_and_disable(&*state.units, &unit) {
                    tracing::warn!(unit, error, "failed to stop/disable the stale controller");
                }
                let mut world = state.world.blocking_write();
                if let Some(queued) = world.failed_reattach.remove(&vm_id) {
                    world.reserved_vm_indices.remove(&queued.vm_index);
                }
            }
            "active" => match readopt_live_controller(state, &vm_id) {
                Ok(_) => {
                    // readopt dropped the queue entry itself.
                    tracing::info!(vm_id, "re-adopted previously-failed VM on retry");
                }
                Err(error) => {
                    tracing::warn!(vm_id, ?error, "reattach retry failed");
                    note_reattach_retry_failure(state, &vm_id);
                }
            },
            // "unknown" (a D-Bus error) or a transitional state
            // (activating/deactivating): not proof of death, so treat it
            // exactly like a failed restore attempt and retry later.
            _ => note_reattach_retry_failure(state, &vm_id),
        }
    }
}

/// Python `_note_reattach_retry_failure`: spend one attempt; mark the VM
/// exhausted at the cap.
fn note_reattach_retry_failure(state: &DaemonState, vm_id: &str) {
    let mut world = state.world.blocking_write();
    let Some(queued) = world.failed_reattach.get_mut(vm_id) else {
        return;
    };
    queued.attempts += 1;
    if queued.attempts >= REATTACH_RETRY_MAX_ATTEMPTS {
        queued.exhausted = true;
        tracing::error!(
            vm_id,
            attempts = queued.attempts,
            "giving up reattaching the VM; its controller is still running but \
             the supervisor cannot manage it; the VM is NOT auto-stopped, \
             operator intervention required"
        );
    } else {
        tracing::warn!(
            vm_id,
            attempts = queued.attempts,
            max = REATTACH_RETRY_MAX_ATTEMPTS,
            "reattach retry failed; will retry"
        );
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use serde_json::Value;

    use super::*;
    use crate::config::Settings;
    use crate::logs::StaticLogSource;
    use crate::service::{HostState, vm_spec_message};
    use crate::tap::{FakeTapBackend, TapBackend};
    use crate::test_fixtures;
    use crate::units::{FakeSystemd, UnitStateSource};

    /// A 64-hex vm_id (the static IPv6 scheme slices it).
    fn hash(fill: char) -> String {
        fill.to_string().repeat(64)
    }

    /// The bare-host nftables fixture: base chains exist, no aleph state,
    /// so get_table_for_hook resolves and every add goes through.
    fn bare_host_ruleset() -> Vec<Value> {
        let fixture: Value = serde_json::from_str(
            &std::fs::read_to_string(test_fixtures::fixtures_dir().join("nftables.json")).unwrap(),
        )
        .unwrap();
        fixture["rulesets"]["bare-host"].as_array().unwrap().clone()
    }

    struct Harness {
        state: Arc<DaemonState>,
        systemd: Arc<FakeSystemd>,
        taps: Arc<FakeTapBackend>,
        dhcp: Arc<crate::dhcp::FakeDhcpBackend>,
        nft: Arc<nft::StaticRuleset>,
        programs: Arc<crate::firecracker::FakeProgramLauncher>,
        _tmp: tempfile::TempDir,
    }

    fn harness() -> Harness {
        harness_with_ruleset(bare_host_ruleset())
    }

    /// The typical-node ruleset of the fixture (aleph chains + one VM).
    fn typical_ruleset() -> Vec<Value> {
        let fixture: Value = serde_json::from_str(
            &std::fs::read_to_string(test_fixtures::fixtures_dir().join("nftables.json")).unwrap(),
        )
        .unwrap();
        fixture["rulesets"]["typical"].as_array().unwrap().clone()
    }

    fn harness_with_ruleset(ruleset: Vec<Value>) -> Harness {
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = Settings::from_vars(
            [(
                "ALEPH_VM_EXECUTION_ROOT".to_string(),
                tmp.path().to_string_lossy().into_owned(),
            )]
            .into_iter(),
        )
        .unwrap();
        settings.allow_vm_networking = true;
        crate::server::prepare_directories(&settings).unwrap();
        ports::ensure_schema(&settings.supervisor_database).unwrap();

        let host = HostState {
            settings,
            host_ipv4: "192.0.2.10".to_string(),
            network_interface: Some("eth0".to_string()),
            gpus: Vec::new(),
            dns_nameservers: Some(vec!["1.1.1.1".to_string()]),
        };
        let systemd = Arc::new(FakeSystemd::new());
        let taps = Arc::new(FakeTapBackend::new());
        let dhcp = Arc::new(crate::dhcp::FakeDhcpBackend::new());
        let nft_executor = Arc::new(nft::StaticRuleset::new(ruleset));
        let programs = Arc::new(crate::firecracker::FakeProgramLauncher::new());
        let mut state = crate::service::DaemonState::hermetic(
            host,
            world::WorldView::default(),
            systemd.clone(),
            Arc::new(StaticLogSource::default()),
        );
        state.nft = nft_executor.clone();
        state.taps = taps.clone();
        state.dhcp = dhcp.clone();
        state.programs = programs.clone();
        Harness {
            state: Arc::new(state),
            systemd,
            taps,
            dhcp,
            nft: nft_executor,
            programs,
            _tmp: tmp,
        }
    }

    fn spec(vm_id: &str, root: &Path) -> pb::VmSpec {
        pb::VmSpec {
            vm_id: vm_id.to_string(),
            backend: pb::Backend::Qemu as i32,
            kernel_path: String::new(),
            initrd_path: String::new(),
            disks: vec![pb::DiskConfig {
                path: root.join("rootfs.qcow2").to_string_lossy().into_owned(),
                readonly: false,
                format: pb::disk_config::Format::Qcow2 as i32,
                role: pb::disk_config::DiskRole::Rootfs as i32,
            }],
            vcpus: 1,
            memory_mib: 256,
            tee: None,
            network: Some(pb::NetworkConfig {
                internet_access: true,
                requested_ipv6: String::new(),
                ipv6_prefix_len: 0,
            }),
            gpus: Vec::new(),
            numa_node: None,
            persistent: true,
            ssh_authorized_keys: vec!["ssh-ed25519 AAAA test@host".to_string()],
            hostname: "itest".to_string(),
            guest_channel: None,
        }
    }

    #[test]
    fn create_boots_a_persistent_qemu_vm_end_to_end() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');
        let request = spec(&vm_id, &root);

        let (entry, running) = create_vm(state, request.clone()).unwrap();
        assert!(running);
        assert_eq!(
            entry.vm_index, 4,
            "the first vm_index is START_ID_INDEX (conf.py default 4)"
        );
        assert_ne!(entry.times.started_at_ns, 0);
        assert_ne!(entry.times.starting_at_ns, 0);
        assert_eq!(entry.times.stopped_at_ns, 0);
        assert_eq!(
            entry.ipv4.as_ref().unwrap().address,
            "172.16.4.2",
            "vm_index 4 in the default pool"
        );

        // The controller unit was enabled and started.
        let unit = controller_unit_name(&vm_id);
        assert_eq!(
            harness.systemd.actions(),
            vec![format!("enable {unit}"), format!("start {unit}")]
        );

        // The tap exists and the artifacts are on disk.
        assert!(harness.taps.interface_exists("vmtap4"));
        assert!(root.join(format!("{vm_id}-controller.json")).exists());
        assert!(root.join(format!("cloud-init-{vm_id}.img")).exists());

        // The written config reparses as the entry's config.
        let written =
            std::fs::read_to_string(root.join(format!("{vm_id}-controller.json"))).unwrap();
        let parsed = parse_controller_config(&written).unwrap();
        assert_eq!(parsed.vm_index, 4);
        let VmConfiguration::Qemu(qemu) = parsed.vm else {
            panic!("the written config must be QEMU");
        };
        assert_eq!(qemu.interface_name.as_deref(), Some("vmtap4"));
        assert_eq!(qemu.mem_size_mb, memsizes::MiB::from(256));

        // GetVmSpec serves the ORIGINAL spec (live-daemon behavior).
        assert_eq!(vm_spec_message(&entry), request);

        // Idempotency: same spec returns the live VM, no second boot.
        let (again, running) = create_vm(state, request.clone()).unwrap();
        assert!(running);
        assert_eq!(again.vm_index, entry.vm_index);
        assert_eq!(harness.systemd.actions().len(), 2, "no second start");

        // A different spec conflicts.
        let mut different = request.clone();
        different.memory_mib = 512;
        match create_vm(state, different) {
            Err(RpcError::AlreadyExists(message)) => {
                assert_eq!(
                    message,
                    format!("VM {vm_id} already exists with a different spec")
                );
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }

        // The nftables batches include the per-VM chains.
        let batches = harness
            .nft
            .batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let text = serde_json::to_string(&batches).unwrap();
        assert!(text.contains("aleph-vm-nat-4"));
        assert!(text.contains("aleph-vm-filter-4"));
    }

    fn confidential_spec(vm_id: &str, root: &Path, firmware: &str) -> pb::VmSpec {
        let mut request = spec(vm_id, root);
        request.tee = Some(pb::TeeConfig {
            backend: pb::TeeBackend::Sev as i32,
            policy: "0x5".to_string(),
            session_dir: String::new(),
            firmware_path: firmware.to_string(),
        });
        request
    }

    #[test]
    fn create_confidential_defines_without_starting_the_unit() {
        // Increment 6: a confidential VM rides the QEMU create path but the
        // controller unit is never enabled/started; it reports
        // awaiting_confidential_init until InitializeConfidential runs.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('c');
        let firmware = root.join("OVMF_CSV.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let request = confidential_spec(&vm_id, &root, &firmware.to_string_lossy());

        let (entry, running) = create_vm(state, request).unwrap();
        assert!(!running, "the unit was never started");
        assert!(
            harness.systemd.actions().is_empty(),
            "no enable/start for a confidential VM, got {:?}",
            harness.systemd.actions()
        );
        // Only the SNP measured image DHCPs; a SEV-ES VM keeps its cloud-init
        // static config, so no per-tap DHCP server is stood up (this guards the
        // startup predicate against being loosened from `snp` to `confidential`,
        // ledger 77).
        assert!(
            harness.dhcp.started().is_empty(),
            "a SEV-ES VM uses cloud-init static config, no DHCP server"
        );
        // starting_at AND started_at are stamped (execution.start's else
        // branch); the reported status is awaiting_confidential_init.
        assert_ne!(entry.times.starting_at_ns, 0);
        assert_ne!(entry.times.started_at_ns, 0);
        let info = crate::service::vm_info_message(&entry, false, now_ns());
        assert!(info.awaiting_confidential_init);
        assert_eq!(info.confidential_mode, pb::ConfidentialMode::SevEs as i32);

        // The written controller config carries the four SEV fields.
        let written =
            std::fs::read_to_string(root.join(format!("{vm_id}-controller.json"))).unwrap();
        let parsed = parse_controller_config(&written).unwrap();
        let VmConfiguration::Qemu(qemu) = parsed.vm else {
            panic!("the written config must be QEMU");
        };
        let confidential = qemu.confidential().expect("the config is confidential");
        assert_eq!(confidential.sev_policy, 5);
        assert_eq!(confidential.ovmf_path, firmware.to_string_lossy());
        assert!(
            confidential
                .sev_session_file
                .ends_with(&format!("{vm_id}/vm_session.b64"))
        );
        assert!(
            confidential
                .sev_dh_cert_file
                .ends_with(&format!("{vm_id}/vm_godh.b64"))
        );
    }

    /// An SEV-SNP measured-boot spec: a raw rootfs plus kernel/initrd and a
    /// SEV_SNP tee config. The rootfs dm-verity sidecars are written next to
    /// the image so `snp_config_slice` can derive the cmdline and hash tree.
    fn snp_spec(vm_id: &str, root: &Path, firmware: &str) -> pb::VmSpec {
        let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
        std::fs::write(&rootfs, b"rootfs").unwrap();
        std::fs::write(format!("{}.roothash", rootfs.display()), b"deadbeef00\n").unwrap();
        std::fs::write(format!("{}.verity", rootfs.display()), b"hashtree").unwrap();
        let mut request = spec(vm_id, root);
        request.kernel_path = root.join("bzImage").to_string_lossy().into_owned();
        request.initrd_path = root.join("initrd").to_string_lossy().into_owned();
        request.disks = vec![pb::DiskConfig {
            path: rootfs.to_string_lossy().into_owned(),
            readonly: true,
            format: pb::disk_config::Format::Raw as i32,
            role: pb::disk_config::DiskRole::Rootfs as i32,
        }];
        request.tee = Some(pb::TeeConfig {
            backend: pb::TeeBackend::SevSnp as i32,
            // Empty policy: the daemon defaults it to 0x30000.
            policy: String::new(),
            session_dir: String::new(),
            firmware_path: firmware.to_string(),
        });
        request
    }

    #[test]
    fn create_snp_starts_immediately_and_writes_the_snp_config() {
        // Increment B1: unlike SEV/SEV-ES, an SNP VM has no session handshake,
        // so it is STARTED at create (not left awaiting_confidential_init), it
        // carries NO cloud-init drive (measured Nix boot), and its controller
        // JSON carries the SNP measured-boot fields.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let request = snp_spec(&vm_id, &root, &firmware.to_string_lossy());

        let (entry, running) = create_vm(state, request).unwrap();
        assert!(running, "an SNP VM starts at create, no session to await");
        let unit = controller_unit_name(&vm_id);
        assert_eq!(
            harness.systemd.actions(),
            vec![format!("enable {unit}"), format!("start {unit}")],
            "the SNP controller unit is enabled and started at create"
        );

        // Reported as SEV-SNP and NOT awaiting init.
        let info = crate::service::vm_info_message(&entry, running, now_ns());
        assert_eq!(info.confidential_mode, pb::ConfidentialMode::SevSnp as i32);
        assert!(!info.awaiting_confidential_init);

        // No cloud-init drive for a measured SNP boot.
        assert!(
            !root.join(format!("cloud-init-{vm_id}.img")).exists(),
            "SNP carries no cloud-init drive"
        );

        // The written controller config carries the SNP measured-boot fields
        // and resolves as SNP (not SEV) on reparse.
        let written =
            std::fs::read_to_string(root.join(format!("{vm_id}-controller.json"))).unwrap();
        let parsed = parse_controller_config(&written).unwrap();
        let VmConfiguration::Qemu(qemu) = parsed.vm else {
            panic!("the written config must be QEMU");
        };
        assert!(
            qemu.confidential().is_none(),
            "SNP must not resolve as a SEV confidential config"
        );
        let snp = qemu.snp().expect("the config resolves as SNP");
        assert_eq!(snp.ovmf_path, firmware.to_string_lossy());
        assert_eq!(snp.sev_policy, 0x30000, "empty policy defaults to 0x30000");
        assert!(snp.kernel_path.ends_with("bzImage"));
        assert!(snp.initrd_path.ends_with("initrd"));
        assert_eq!(
            snp.kernel_cmdline, "console=ttyS0 root=/dev/mapper/verity-root ro roothash=deadbeef00",
            "the measured cmdline is derived from the roothash sidecar"
        );
        // The hash tree device is the first host volume (/dev/vdb), read-only.
        assert!(
            qemu.host_volumes[0]
                .path_on_host
                .ends_with("-rootfs.ext4.verity"),
            "the dm-verity hash tree is the first host volume"
        );
        assert!(qemu.host_volumes[0].read_only);
    }

    #[test]
    fn create_snp_starts_a_per_tap_dhcp_server_for_the_allocated_ip() {
        // Increment D2: the SNP measured image DHCPs (its cmdline omits `ip=`
        // for measurement determinism), so the daemon stands up a per-tap
        // dnsmasq handing the guest EXACTLY its allocated IPv4, with the host
        // tap as the gateway and the daemon's nameservers.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let request = snp_spec(&vm_id, &root, &firmware.to_string_lossy());

        let (entry, running) = create_vm(state, request).unwrap();
        assert!(running);

        // The DHCP server was started exactly once, for this VM's tap, with
        // the allocated guest IP/gateway/netmask and the host nameservers.
        let started = harness.dhcp.started();
        assert_eq!(started.len(), 1, "one DHCP server for the SNP VM");
        let config = &started[0];
        assert_eq!(config.vm_hash, vm_id);
        assert_eq!(config.device_name, format!("vmtap{}", entry.vm_index));
        assert_eq!(config.guest_ip, entry.ipv4.as_ref().unwrap().address);
        assert_eq!(config.gateway, entry.ipv4.as_ref().unwrap().gateway);
        assert_eq!(config.netmask, "255.255.255.0");
        assert_eq!(config.nameservers, vec!["1.1.1.1".to_string()]);
        // The single-address range hands out only the allocated IP.
        assert!(
            config.dnsmasq_args().contains(&format!(
                "--dhcp-range={ip},{ip},255.255.255.0,1h",
                ip = entry.ipv4.as_ref().unwrap().address
            )),
            "the guest can only lease its allocated IP"
        );
        assert!(harness.dhcp.is_running(&vm_id));
    }

    #[test]
    fn create_plain_qemu_starts_no_dhcp_server() {
        // A plain (non-SNP) VM keeps cloud-init static config; the daemon must
        // NOT stand up a DHCP server for it.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');
        let request = spec(&vm_id, &root);

        let (_entry, running) = create_vm(state, request).unwrap();
        assert!(running);
        assert!(
            harness.dhcp.started().is_empty(),
            "a plain VM uses cloud-init static config, no DHCP server"
        );
    }

    #[test]
    fn deleting_an_snp_vm_tears_down_the_dhcp_server() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let request = snp_spec(&vm_id, &root, &firmware.to_string_lossy());

        create_vm(state, request).unwrap();
        assert!(harness.dhcp.is_running(&vm_id));

        delete_vm(state, &vm_id, false, false).unwrap();
        assert!(
            !harness.dhcp.is_running(&vm_id),
            "delete tears the DHCP server down"
        );
        assert_eq!(harness.dhcp.stopped(), vec![vm_id]);
    }

    #[test]
    fn restarting_a_stopped_snp_vm_recreates_the_dhcp_server() {
        // Stop tears the per-tap dnsmasq down with the tap and nft rules;
        // start must stand it back up, or the rebooting measured guest (whose
        // cmdline carries no `ip=`) can never lease its IP and attestation is
        // unreachable.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let request = snp_spec(&vm_id, &root, &firmware.to_string_lossy());

        let (entry, running) = create_vm(state, request).unwrap();
        assert!(running);
        stop_vm(state, &vm_id).unwrap();
        assert!(
            !harness.dhcp.is_running(&vm_id),
            "stop tears the DHCP server down"
        );

        start_vm(state, &vm_id).unwrap();
        assert!(
            harness.dhcp.is_running(&vm_id),
            "start recreates the DHCP server"
        );
        // The second start reissues the same per-tap config: same allocated
        // guest IP on the same tap, so the rebooted guest leases exactly the
        // address the daemon reports in VmInfo.
        let started = harness.dhcp.started();
        assert_eq!(started.len(), 2, "one DHCP start per boot");
        assert_eq!(started[1].vm_hash, vm_id);
        assert_eq!(started[1].device_name, format!("vmtap{}", entry.vm_index));
        assert_eq!(
            started[1].guest_ip,
            entry.ipv4.as_ref().unwrap().address,
            "the restarted server still hands out the allocated IP"
        );
    }

    #[test]
    fn restarting_a_stopped_plain_vm_starts_no_dhcp_server() {
        // The restart path's DHCP recreation is gated on SNP exactly like the
        // create path: a plain VM keeps cloud-init static config across a
        // stop/start cycle and must never gain a DHCP server.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');
        let request = spec(&vm_id, &root);

        create_vm(state, request).unwrap();
        stop_vm(state, &vm_id).unwrap();
        start_vm(state, &vm_id).unwrap();
        assert!(
            harness.dhcp.started().is_empty(),
            "a plain VM never gets a DHCP server, including on restart"
        );
    }

    #[test]
    fn deleting_a_plain_vm_stops_no_dhcp_server() {
        // A plain VM never started a per-tap DHCP server, so its teardown must
        // NOT call dhcp.stop (this guards the `snp().is_some()` teardown gate
        // against being removed, which would spuriously stop a nonexistent
        // server for every plain VM delete, ledger 77).
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        create_vm(state, spec(&vm_id, &root)).unwrap();
        delete_vm(state, &vm_id, false, false).unwrap();
        assert!(
            harness.dhcp.stopped().is_empty(),
            "a plain VM teardown touches no DHCP server, got {:?}",
            harness.dhcp.stopped()
        );
    }

    #[test]
    fn discarding_an_untracked_snp_vm_tears_down_the_dhcp_server() {
        // A live SNP VM whose adoption failed (untracked, config still on disk)
        // ran a per-tap DHCP server. The discard_failed_reattach delete path
        // must stop it too, or aleph-vm-dhcp-<hash>.service (and its lease file)
        // is orphaned (increment D2, ledger 77).
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let request = snp_spec(&vm_id, &root, &firmware.to_string_lossy());

        // Create the SNP VM (writes the config, starts the DHCP server), then
        // simulate a failed adoption by dropping the tracked entry while its
        // controller config stays on disk: DeleteVm now takes the discard path.
        create_vm(state, request).unwrap();
        assert!(harness.dhcp.is_running(&vm_id));
        state.world.blocking_write().entries.remove(&vm_id);

        delete_vm(state, &vm_id, false, false).unwrap();
        assert!(
            !harness.dhcp.is_running(&vm_id),
            "the discard path tears the DHCP server down"
        );
        assert_eq!(harness.dhcp.stopped(), vec![vm_id]);
    }

    #[test]
    fn stopping_an_snp_vm_tears_down_the_dhcp_server() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();
        let request = snp_spec(&vm_id, &root, &firmware.to_string_lossy());

        create_vm(state, request).unwrap();
        stop_vm(state, &vm_id).unwrap();
        assert!(
            !harness.dhcp.is_running(&vm_id),
            "stop tears the DHCP server down"
        );
        assert_eq!(harness.dhcp.stopped(), vec![vm_id]);
    }

    #[test]
    fn a_failed_snp_boot_stops_the_dhcp_server_during_cleanup() {
        // The controller enters "failed": the create's cleanup path must tear
        // the just-started DHCP server down alongside the tap.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        // A systemd whose controller reports "failed" (the same wrapper the
        // plain failed-boot test uses), plus the fake tap and DHCP backends so
        // the cleanup path is observable.
        struct FailingSystemd(Arc<FakeSystemd>);
        impl crate::units::UnitStateSource for FailingSystemd {
            fn active_states(
                &self,
                units: &[String],
            ) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.active_states(units)
            }
            fn controller_units(&self) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.controller_units()
            }
            fn get_active_state(&self, _unit: &str) -> String {
                "failed".to_string()
            }
            fn start(&self, unit: &str) -> Result<(), String> {
                self.0.start(unit)
            }
            fn stop(&self, unit: &str) -> Result<(), String> {
                self.0.stop(unit)
            }
            fn restart(&self, unit: &str) -> Result<(), String> {
                self.0.restart(unit)
            }
            fn enable(&self, unit: &str) -> Result<(), String> {
                self.0.enable(unit)
            }
            fn disable(&self, unit: &str) -> Result<(), String> {
                self.0.disable(unit)
            }
            fn is_enabled(&self, unit: &str) -> bool {
                self.0.is_enabled(unit)
            }
        }
        let dhcp = Arc::new(crate::dhcp::FakeDhcpBackend::new());
        let mut state2 = crate::service::DaemonState::hermetic(
            state.host.clone(),
            world::WorldView::default(),
            Arc::new(FailingSystemd(harness.systemd.clone())),
            Arc::new(StaticLogSource::default()),
        );
        state2.nft = Arc::new(nft::StaticRuleset::new(bare_host_ruleset()));
        state2.taps = harness.taps.clone();
        state2.dhcp = dhcp.clone();
        let state2 = Arc::new(state2);

        let result = create_vm(
            &state2,
            snp_spec(&vm_id, &root, &firmware.to_string_lossy()),
        );
        assert!(result.is_err(), "the SNP boot must fail");
        assert!(
            dhcp.stopped().contains(&vm_id),
            "the cleanup path tears the DHCP server down"
        );
        assert!(!dhcp.is_running(&vm_id));
    }

    #[test]
    fn create_snp_refuses_without_kernel_or_roothash() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        // Missing kernel_path fails closed.
        let mut no_kernel = snp_spec(&hash('d'), &root, &firmware.to_string_lossy());
        no_kernel.kernel_path = String::new();
        assert!(matches!(
            create_vm(state, no_kernel),
            Err(RpcError::InvalidBackend(_))
        ));

        // Missing roothash sidecar fails closed (a measured VM must not boot
        // with a wrong/absent cmdline).
        let vm_id = hash('f');
        let request = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
        std::fs::remove_file(format!("{}.roothash", rootfs.display())).unwrap();
        assert!(matches!(
            create_vm(state, request),
            Err(RpcError::InvalidBackend(_))
        ));
    }

    #[test]
    fn snp_config_slice_rejects_a_malformed_roothash_so_it_cannot_reach_append() {
        // The roothash is spliced verbatim into `-append ...roothash={roothash}`,
        // so the hex-validation guard is the cmdline-injection barrier. Each
        // malformed sidecar must fail closed (InvalidBackend, no SnpSlice), so
        // the injected/partial string can never reach -append. Disabling the
        // guard makes one of these return Ok and this test bites.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        for (label, malformed) in [
            ("injection", "abc ro init=/bin/sh"),
            ("internally-spaced", "dead beef"),
            ("empty-but-present", ""),
        ] {
            let vm_id = hash('g');
            let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
            let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
            std::fs::write(format!("{}.roothash", rootfs.display()), malformed).unwrap();
            match snp_config_slice(state, &spec) {
                Err(RpcError::InvalidBackend(_)) => {}
                other => {
                    panic!("malformed roothash ({label}) must be InvalidBackend, got {other:?}")
                }
            }
        }
    }

    #[test]
    fn snp_config_slice_rejects_an_empty_initrd_path() {
        // The kernel_path side of the `kernel_path.is_empty() ||
        // initrd_path.is_empty()` guard is covered elsewhere; pin the initrd
        // side so a mismeasured (initrd-less) boot fails closed.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        let vm_id = hash('h');
        let mut spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        spec.initrd_path = String::new();
        match snp_config_slice(state, &spec) {
            Err(RpcError::InvalidBackend(_)) => {}
            other => panic!("an empty initrd_path must be InvalidBackend, got {other:?}"),
        }
    }

    #[test]
    fn snp_config_slice_rejects_gpus_so_they_are_not_silently_dropped() {
        // build_snp_argv emits no GPU passthrough devices, so an SNP spec that
        // carries GPUs must fail closed here rather than launch a VM missing the
        // requested hardware. Removing the guard makes this return Ok.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        let vm_id = hash('j');
        let mut spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        spec.gpus = vec![pb::GpuConfig {
            pci_host: "0000:01:00.0".to_string(),
            supports_x_vga: true,
        }];
        match snp_config_slice(state, &spec) {
            Err(RpcError::InvalidBackend(_)) => {}
            other => panic!("an SNP spec with GPUs must be InvalidBackend, got {other:?}"),
        }
    }

    #[test]
    fn snp_config_slice_rejects_an_oversized_roothash_sidecar() {
        // A sidecar larger than the read cap fails closed rather than loading
        // unbounded into RAM. The content is all-hex, so only the size guard can
        // reject it.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        let vm_id = hash('i');
        let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
        let oversized = "a".repeat(MAX_ROOTHASH_SIDECAR_BYTES as usize + 1);
        std::fs::write(format!("{}.roothash", rootfs.display()), oversized).unwrap();
        match snp_config_slice(state, &spec) {
            Err(RpcError::InvalidBackend(_)) => {}
            other => panic!("an oversized roothash sidecar must be InvalidBackend, got {other:?}"),
        }
    }

    #[test]
    fn snp_config_slice_appends_the_workload_roothash_when_the_sidecar_is_present() {
        // The V-PROGRAM workload roothash arrives out-of-band as a
        // {rootfs}.workload_roothash sidecar (the proto is frozen, no wire
        // field). When staged, it must be bound into the measured cmdline so
        // the launch attestation covers the workload volume too.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        let vm_id = hash('k');
        let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
        std::fs::write(
            format!("{}.workload_roothash", rootfs.display()),
            "cafef00d00\n",
        )
        .unwrap();

        let slice = snp_config_slice(state, &spec).unwrap().unwrap();
        assert_eq!(
            slice.kernel_cmdline,
            "console=ttyS0 root=/dev/mapper/verity-root ro roothash=deadbeef00 \
             workload_roothash=cafef00d00",
            "the workload roothash is appended to the measured cmdline"
        );
    }

    #[test]
    fn snp_config_slice_leaves_the_cmdline_unchanged_without_a_workload_sidecar() {
        // Regression guard: a workload-less SNP VM (no
        // {rootfs}.workload_roothash sidecar) must derive the EXACT same
        // cmdline as before the workload mechanism existed, byte for byte, or
        // every existing measured image's attestation breaks.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        let vm_id = hash('l');
        let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());

        let slice = snp_config_slice(state, &spec).unwrap().unwrap();
        assert_eq!(
            slice.kernel_cmdline,
            "console=ttyS0 root=/dev/mapper/verity-root ro roothash=deadbeef00",
            "no workload sidecar must leave the cmdline byte-identical to before"
        );
    }

    #[test]
    fn snp_config_slice_rejects_a_non_hex_workload_roothash() {
        // Like the platform roothash, the workload roothash is spliced
        // verbatim into -append, so it must fail closed on anything but bare
        // hex rather than let an injected/partial string reach the guest.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        let vm_id = hash('m');
        let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
        std::fs::write(
            format!("{}.workload_roothash", rootfs.display()),
            "not hex; init=/bin/sh",
        )
        .unwrap();

        match snp_config_slice(state, &spec) {
            Err(RpcError::InvalidBackend(_)) => {}
            other => panic!("a non-hex workload roothash must be InvalidBackend, got {other:?}"),
        }
    }

    #[test]
    fn snp_config_slice_rejects_an_oversized_workload_roothash_sidecar() {
        // Like the platform roothash, a workload sidecar larger than the read
        // cap fails closed rather than loading unbounded into RAM. The content
        // is all-hex, so only the size guard can reject it.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let firmware = root.join("OVMF.fd");
        std::fs::write(&firmware, b"ovmf").unwrap();

        let vm_id = hash('n');
        let spec = snp_spec(&vm_id, &root, &firmware.to_string_lossy());
        let rootfs = root.join(format!("{vm_id}-rootfs.ext4"));
        let oversized = "a".repeat(MAX_ROOTHASH_SIDECAR_BYTES as usize + 1);
        std::fs::write(format!("{}.workload_roothash", rootfs.display()), oversized).unwrap();
        match snp_config_slice(state, &spec) {
            Err(RpcError::InvalidBackend(_)) => {}
            other => panic!(
                "an oversized workload roothash sidecar must be InvalidBackend, got {other:?}"
            ),
        }
    }

    #[test]
    fn sev_policy_parses_like_python_int_base_zero() {
        // The accept table (each value confirmed against CPython int(x, 0)).
        for (input, expected) in [
            ("0x5", 5u32),
            ("5", 5),
            ("0o17", 0o17),
            ("0b101", 5),
            ("0x1_0", 16),
            ("  0x1_0  ", 16),
            ("0x_10", 16),
            ("0X1F", 31),
            ("+7", 7),
            ("0xFF", 255),
            ("00", 0),
            ("0", 0),
            ("0_0", 0),
            ("4294967295", u32::MAX),
        ] {
            assert_eq!(
                parse_sev_policy(input).unwrap(),
                expected,
                "parse_sev_policy({input:?})"
            );
        }
        // The reject table. Python raises ValueError for the malformed forms
        // (leading-zero decimals, misplaced underscores, non-numeric); the
        // signed/bignum forms Python accepts but a u32 policy cannot hold.
        for input in [
            "010",                        // leading-zero decimal
            "07",                         // leading-zero decimal
            "0755",                       // leading-zero decimal
            "1__0",                       // doubled underscore
            "_10",                        // leading underscore
            "10_",                        // trailing underscore
            "-5",                         // Python: -5 (valid); not representable as u32
            "4294967296",                 // u32::MAX + 1; Python bignum, out of range here
            "99999999999999999999999999", // bignum
            "0x",                         // prefix, no digits
            "0b",                         // prefix, no digits
            "nope",                       // not numeric
            "",                           // empty
        ] {
            assert!(
                matches!(parse_sev_policy(input), Err(RpcError::Internal(_))),
                "parse_sev_policy({input:?}) must be rejected"
            );
        }
    }

    #[test]
    fn create_confidential_without_firmware_is_invalid_backend() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let request = confidential_spec(&hash('d'), &root, "");
        match create_vm(state, request) {
            Err(RpcError::InvalidBackend(message)) => assert_eq!(
                message,
                "Confidential spec has no resolved firmware_path; refusing to build configuration"
            ),
            other => panic!("expected InvalidBackend, got {other:?}"),
        }
    }

    #[test]
    fn create_rejections_mirror_the_python_backstops() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();

        // Memory backstop: an absurd request must exceed physical - reserve.
        let mut request = spec(&hash('b'), &root);
        request.memory_mib = u64::MAX / 2;
        match create_vm(state, request) {
            Err(RpcError::InsufficientResources(message)) => {
                assert!(message.starts_with("Insufficient memory to create VM: required"));
                assert!(message.contains("host_reserved 2048 MiB"));
            }
            other => panic!("expected InsufficientResources, got {other:?}"),
        }

        // GPU validation: an unknown pci_host (the inventory is empty).
        let mut request = spec(&hash('c'), &root);
        request.gpus = vec![pb::GpuConfig {
            pci_host: "0000:99:00.0".to_string(),
            supports_x_vga: true,
        }];
        match create_vm(state, request) {
            Err(RpcError::InsufficientResources(message)) => {
                assert_eq!(
                    message,
                    "No GPU at pci_host '0000:99:00.0' in the host inventory"
                );
            }
            other => panic!("expected InsufficientResources, got {other:?}"),
        }

        // Nothing was left behind by the rejections.
        assert!(state.world.blocking_read().is_empty());
        assert!(harness.taps.devices().is_empty());
    }

    #[test]
    fn a_boot_that_never_goes_active_cleans_up_and_fails() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('d');
        // The fake refuses to activate this unit: start() flips the state
        // to active normally, so pre-seed a unit that starts "failed".
        struct FailingSystemd(Arc<FakeSystemd>);
        impl crate::units::UnitStateSource for FailingSystemd {
            fn active_states(
                &self,
                units: &[String],
            ) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.active_states(units)
            }
            fn controller_units(&self) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.controller_units()
            }
            fn get_active_state(&self, _unit: &str) -> String {
                "failed".to_string()
            }
            fn start(&self, unit: &str) -> Result<(), String> {
                self.0.start(unit)
            }
            fn stop(&self, unit: &str) -> Result<(), String> {
                self.0.stop(unit)
            }
            fn restart(&self, unit: &str) -> Result<(), String> {
                self.0.restart(unit)
            }
            fn enable(&self, unit: &str) -> Result<(), String> {
                self.0.enable(unit)
            }
            fn disable(&self, unit: &str) -> Result<(), String> {
                self.0.disable(unit)
            }
            fn is_enabled(&self, unit: &str) -> bool {
                self.0.is_enabled(unit)
            }
        }
        let mut state2 = crate::service::DaemonState::hermetic(
            state.host.clone(),
            world::WorldView::default(),
            Arc::new(FailingSystemd(harness.systemd.clone())),
            Arc::new(StaticLogSource::default()),
        );
        state2.nft = Arc::new(nft::StaticRuleset::new(bare_host_ruleset()));
        state2.taps = harness.taps.clone();
        let state2 = Arc::new(state2);

        match create_vm(&state2, spec(&vm_id, &root)) {
            Err(RpcError::Internal(message)) => {
                assert!(message.contains("controller service entered 'failed' state"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        // The failed create forgot the entry and removed the tap; the
        // config and cloud-init seed stay behind (Python parity).
        assert!(state2.world.blocking_read().is_empty());
        assert!(!harness.taps.interface_exists("vmtap4"));
        assert!(root.join(format!("{vm_id}-controller.json")).exists());
    }

    #[test]
    fn stop_start_reboot_and_delete_drive_the_unit_and_the_artifacts() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        let unit = controller_unit_name(&vm_id);

        // Stop: unit stopped and disabled, tap gone, entry kept as STOPPED
        // (with the tap addresses still reported, the Python wart).
        let entry = stop_vm(state, &vm_id).unwrap();
        assert_ne!(entry.times.stopped_at_ns, 0);
        assert_ne!(entry.times.stopping_at_ns, 0);
        assert!(entry.ipv4.is_some(), "Python keeps reporting the addresses");
        assert!(!harness.taps.interface_exists("vmtap4"));
        assert_eq!(harness.systemd.get_active_state(&unit), "inactive");
        assert!(!harness.systemd.is_enabled(&unit));

        // Stop again: idempotent (VmExecution.stop early-returns).
        let actions_before = harness.systemd.actions().len();
        stop_vm(state, &vm_id).unwrap();
        assert_eq!(harness.systemd.actions().len(), actions_before);

        // Start: tap recreated, unit restarted, stamps cleared.
        let (entry, running) = start_vm(state, &vm_id).unwrap();
        assert!(running);
        assert_eq!(entry.times.stopped_at_ns, 0);
        assert_ne!(entry.times.started_at_ns, 0);
        assert!(harness.taps.interface_exists("vmtap4"));

        // Start while running: no-op returning the live VM.
        let actions_before = harness.systemd.actions().len();
        let (_, running) = start_vm(state, &vm_id).unwrap();
        assert!(running);
        assert_eq!(harness.systemd.actions().len(), actions_before);

        // Reboot: a unit restart plus a fresh started_at.
        let before = entry.times.started_at_ns;
        std::thread::sleep(Duration::from_millis(2));
        let (entry, running) = reboot_vm(state, &vm_id).unwrap();
        assert!(running);
        assert!(entry.times.started_at_ns >= before);
        assert!(
            harness
                .systemd
                .actions()
                .last()
                .unwrap()
                .starts_with("restart ")
        );

        // Delete: the entry, the config, the seed and the mappings go.
        delete_vm(state, &vm_id, false, false).unwrap();
        assert!(state.world.blocking_read().is_empty());
        assert!(!root.join(format!("{vm_id}-controller.json")).exists());
        assert!(!root.join(format!("cloud-init-{vm_id}.img")).exists());

        // Delete of an unknown VM: NOT_FOUND with the vm_id as message.
        match delete_vm(state, &vm_id, false, false) {
            Err(RpcError::NotFound(id)) => assert_eq!(id, vm_id),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn port_forwards_allocate_persist_and_survive_a_stop_start_cycle() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('f');
        create_vm(state, spec(&vm_id, &root)).unwrap();

        let info = add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: vm_id.clone(),
                host_port: 0,
                vm_port: 22,
                protocol: pb::Protocol::Tcp as i32,
            },
        )
        .unwrap();
        assert_eq!(info.vm_port, 22);
        assert!(info.host_port >= ports::MIN_DYNAMIC_PORT);

        // Adding udp to the same vm_port keeps the host port.
        let info2 = add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: vm_id.clone(),
                host_port: 0,
                vm_port: 22,
                protocol: pb::Protocol::Udp as i32,
            },
        )
        .unwrap();
        assert_eq!(info2.host_port, info.host_port);

        // Persisted rows are readable through the increment 2 reader.
        let stored =
            ports::load_port_forwards(&state.host.settings.supervisor_database, &vm_id).unwrap();
        assert_eq!(
            stored,
            vec![ports::PortForward {
                vm_port: 22,
                host_port: info.host_port,
                tcp: true,
                udp: true,
            }]
        );

        // Removing one protocol keeps the row; removing the last drops it.
        remove_port_forward(state, &vm_id, info.host_port, pb::Protocol::Udp).unwrap();
        let stored =
            ports::load_port_forwards(&state.host.settings.supervisor_database, &vm_id).unwrap();
        assert!(stored[0].tcp && !stored[0].udp);
        remove_port_forward(state, &vm_id, info.host_port, pb::Protocol::Tcp).unwrap();
        assert!(
            ports::load_port_forwards(&state.host.settings.supervisor_database, &vm_id)
                .unwrap()
                .is_empty()
        );

        // A stop clears the in-memory mappings, a start reloads from the
        // store: re-add one and cycle.
        add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: vm_id.clone(),
                host_port: 0,
                vm_port: 8080,
                protocol: pb::Protocol::Tcp as i32,
            },
        )
        .unwrap();
        let entry = stop_vm(state, &vm_id).unwrap();
        assert!(entry.port_forwards.is_empty(), "stop drops the redirects");
        let (entry, _) = start_vm(state, &vm_id).unwrap();
        assert_eq!(entry.port_forwards.len(), 1);
        assert_eq!(entry.port_forwards[0].vm_port, 8080);

        // Unknown VM: NOT_FOUND.
        match add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: hash('9'),
                host_port: 0,
                vm_port: 22,
                protocol: pb::Protocol::Tcp as i32,
            },
        ) {
            Err(RpcError::NotFound(id)) => assert_eq!(id, hash('9')),
            other => panic!("expected NotFound, got {other:?}"),
        }
    }

    #[test]
    fn reinstall_erases_the_rootfs_and_restarts() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('1');
        let request = spec(&vm_id, &root);
        std::fs::write(root.join("rootfs.qcow2"), b"disk").unwrap();
        create_vm(state, request).unwrap();

        let (entry, running) = reinstall_vm(state, &vm_id, true).unwrap();
        assert!(running);
        assert!(
            !root.join("rootfs.qcow2").exists(),
            "reinstall unlinks the rootfs (bug-for-bug: the spec path never \
             recreates it; the controller boots against the missing file)"
        );
        assert_ne!(entry.times.started_at_ns, 0);
    }

    #[test]
    fn delete_discards_an_untracked_on_disk_vm() {
        // The Python discard_failed_reattach port: a VM hidden at adoption
        // still has a config and possibly a live controller; DeleteVm stops
        // and removes it instead of NOT_FOUND.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = test_fixtures::QEMU_HASH;
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        state.world.blocking_write().reserved_vm_indices.insert(3);
        harness
            .systemd
            .set_state(&controller_unit_name(vm_id), "active");

        delete_vm(state, vm_id, false, false).unwrap();
        assert!(!root.join(format!("{vm_id}-controller.json")).exists());
        assert_eq!(
            harness
                .systemd
                .get_active_state(&controller_unit_name(vm_id)),
            "inactive"
        );
        assert!(
            !state.world.blocking_read().reserved_vm_indices.contains(&3),
            "the hidden VM's index claim is released"
        );
    }

    #[test]
    fn delete_reaps_the_backup_registry_entry() {
        // R1/R3: DeleteVm reaps the deleted VM's backup jobs (and its per-VM
        // disk lock) so a completed/failed run no longer lingers in
        // ListBackups after the VM is gone.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');
        create_vm(state, spec(&vm_id, &root)).unwrap();

        // A FAILED backup job for this VM is registered, and its disk lock
        // exists in the registry.
        state.backups.insert_job_for_test(pb::BackupInfo {
            vm_id: vm_id.clone(),
            backup_id: format!("{vm_id}-20260101T000000000000Z"),
            status: pb::BackupStatus::Failed as i32,
            ..Default::default()
        });
        let _lock = state.backups.vm_lock(&vm_id);
        assert_eq!(
            crate::backup::list_backups(state, Some(&vm_id))
                .unwrap()
                .len(),
            1,
            "the FAILED job lists before the delete"
        );

        delete_vm(state, &vm_id, true, false).unwrap();

        // The VM is gone and its backup registry entry with it.
        assert!(
            !state.world.blocking_read().entries.contains_key(&vm_id),
            "the world entry was removed"
        );
        assert!(
            crate::backup::list_backups(state, Some(&vm_id))
                .unwrap()
                .is_empty(),
            "the backup job was reaped by the delete"
        );
    }

    #[test]
    fn create_readopts_a_live_untracked_controller() {
        // Python _readopt_live_controller: a config on disk with an ACTIVE
        // unit and no tracked entry is re-adopted, never built over.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = test_fixtures::QEMU_HASH;
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        harness
            .systemd
            .set_state(&controller_unit_name(vm_id), "active");

        // The retry arrives with a DIFFERENT spec: the VM is re-adopted
        // (tracked again) but the create conflicts.
        let request = spec(vm_id, &root);
        match create_vm(state, request) {
            Err(RpcError::AlreadyExists(_)) => {}
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
        let world = state.world.blocking_read();
        let entry = world.entries.get(vm_id).expect("the VM was re-adopted");
        assert_eq!(entry.vm_index, 3);
        assert_ne!(entry.times.started_at_ns, 0);

        // And the matching spec (the reconstruction) is returned idempotently.
        let reconstructed = vm_spec_message(entry);
        drop(world);
        let (entry, running) = create_vm(state, reconstructed).unwrap();
        assert!(running);
        assert_eq!(entry.vm_index, 3);
    }

    #[test]
    fn create_refuses_a_transitional_controller_state() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = test_fixtures::QEMU_HASH;
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        harness
            .systemd
            .set_state(&controller_unit_name(vm_id), "activating");

        match create_vm(state, spec(vm_id, &root)) {
            Err(RpcError::Internal(message)) => {
                assert!(message.contains("refusing to create VM"));
                assert!(message.contains("ActiveState: activating"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    // ── Review-fix regression tests (increment 3 batch) ──────────────────

    #[test]
    fn concurrent_port_forward_adds_allocate_distinct_host_ports() {
        // B1: with per-VM locks only, two concurrent AddPortForwards for
        // DIFFERENT VMs could both allocate the same host_port (the bind
        // probe is transient); the net_lock serializes allocation through
        // persistence, so the ports must always be distinct.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_a = hash('2');
        let vm_b = hash('3');
        create_vm(state, spec(&vm_a, &root)).unwrap();
        create_vm(state, spec(&vm_b, &root)).unwrap();

        let barrier = std::sync::Barrier::new(2);
        let (port_a, port_b) = std::thread::scope(|scope| {
            let handle_a = scope.spawn(|| {
                barrier.wait();
                add_port_forward(
                    state,
                    &pb::AddPortForwardRequest {
                        vm_id: vm_a.clone(),
                        host_port: 0,
                        vm_port: 22,
                        protocol: pb::Protocol::Tcp as i32,
                    },
                )
                .unwrap()
                .host_port
            });
            let handle_b = scope.spawn(|| {
                barrier.wait();
                add_port_forward(
                    state,
                    &pb::AddPortForwardRequest {
                        vm_id: vm_b.clone(),
                        host_port: 0,
                        vm_port: 22,
                        protocol: pb::Protocol::Tcp as i32,
                    },
                )
                .unwrap()
                .host_port
            });
            (handle_a.join().unwrap(), handle_b.join().unwrap())
        });
        assert_ne!(port_a, port_b, "concurrent allocations must never collide");
    }

    #[test]
    fn a_panicking_boot_takes_the_cleanup_path() {
        // B4: a panic inside the boot closure must clean up like an error
        // (no leaked entry) and report INTERNAL, not unwind past cleanup.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        harness.taps.panic_on_create();
        match create_vm(state, spec(&hash('4'), &root)) {
            Err(RpcError::Internal(message)) => {
                assert!(message.contains("panicked"), "got: {message}");
                assert!(message.contains("injected tap creation panic"));
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        assert!(state.world.blocking_read().is_empty(), "the entry leaked");
        assert!(harness.taps.devices().is_empty());
    }

    #[test]
    fn a_hostile_memory_request_saturates_instead_of_overflowing() {
        // B5: committed + required must saturate; with one VM committed,
        // a u64::MAX request overflowed the sum before the fix.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        create_vm(state, spec(&hash('5'), &root)).unwrap();
        let mut request = spec(&hash('6'), &root);
        request.memory_mib = u64::MAX;
        match create_vm(state, request) {
            Err(RpcError::InsufficientResources(_)) => {}
            other => panic!("expected InsufficientResources, got {other:?}"),
        }
    }

    #[test]
    fn rootfs_disk_validation_matches_the_python_messages() {
        // C1: missing rootfs and duplicate rootfs are InvalidBackendError
        // (INVALID_ARGUMENT + INVALID_BACKEND trailer) with types.py's
        // exact messages, before any side effect.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();

        let mut request = spec(&hash('7'), &root);
        request.disks.clear();
        match create_vm(state, request) {
            Err(RpcError::InvalidBackend(message)) => {
                assert_eq!(message, "CreateVmSpec has no ROOTFS disk");
            }
            other => panic!("expected InvalidBackend, got {other:?}"),
        }

        let mut request = spec(&hash('7'), &root);
        let duplicate = request.disks[0].clone();
        request.disks.push(duplicate);
        match create_vm(state, request) {
            Err(RpcError::InvalidBackend(message)) => {
                assert_eq!(
                    message,
                    "CreateVmSpec has 2 ROOTFS disks, expected at most one"
                );
            }
            other => panic!("expected InvalidBackend, got {other:?}"),
        }

        // No side effects: nothing registered, no tap, no artifacts.
        assert!(state.world.blocking_read().is_empty());
        assert!(harness.taps.devices().is_empty());
        assert!(!root.join(format!("{}-controller.json", hash('7'))).exists());
    }

    #[test]
    fn vms_enumerate_in_creation_order_not_hash_order() {
        // C4: Python iterates executions in insertion order; create 'b'
        // then 'a' and the enumeration must stay [b, a] where a BTreeMap
        // walk would flip it.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        create_vm(state, spec(&hash('b'), &root)).unwrap();
        create_vm(state, spec(&hash('a'), &root)).unwrap();
        let order: Vec<String> = state
            .world
            .blocking_read()
            .ordered_entries()
            .iter()
            .map(|entry| entry.vm_hash.clone())
            .collect();
        assert_eq!(order, vec![hash('b'), hash('a')]);
    }

    #[test]
    fn wire_paths_normalize_like_pathlib() {
        // C6: str(PurePosixPath(...)) semantics with "." -> "" on the wire.
        for (input, expected) in [
            ("/a//b/./c/", "/a/b/c"),
            ("a/./b//", "a/b"),
            ("/a/../b", "/a/../b"),
            ("//a//b", "//a/b"),
            ("///a", "/a"),
            ("/", "/"),
            ("//", "//"),
            ("", ""),
            (".", ""),
            ("./a", "a"),
            ("/tmp/rootfs.qcow2", "/tmp/rootfs.qcow2"),
        ] {
            assert_eq!(normalize_wire_path(input), expected, "input {input:?}");
        }
    }

    #[test]
    fn messy_disk_paths_normalize_in_the_config_and_the_idempotency_check() {
        // C6: Python passes proto paths through pathlib.Path, so
        // "/a//b/./c/" spellings normalize in the written controller
        // config and compare equal on a create retry.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('c');
        let clean = root.join("rootfs.qcow2").to_string_lossy().into_owned();

        let mut request = spec(&vm_id, &root);
        request.disks[0].path = format!("{}//./rootfs.qcow2", root.display());
        let (entry, _) = create_vm(state, request).unwrap();
        assert_eq!(entry.config.image_path, clean, "config path normalized");
        let written =
            std::fs::read_to_string(root.join(format!("{vm_id}-controller.json"))).unwrap();
        assert!(written.contains(&format!("\"image_path\": \"{clean}\"")));
        assert!(!written.contains("//./"));

        // A retry with a DIFFERENT messy spelling of the same path is the
        // same spec: idempotent, not AlreadyExists.
        let mut retry = spec(&vm_id, &root);
        retry.disks[0].path = format!("{}/./rootfs.qcow2/", root.display());
        let (again, running) = create_vm(state, retry).unwrap();
        assert!(running);
        assert_eq!(again.vm_index, entry.vm_index);
    }

    #[test]
    fn stop_tolerates_a_failing_tap_delete_like_python() {
        // C9: Python's TapInterface.delete swallows deletion failures with
        // a warning; StopVm (and the delete that follows) must succeed.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('8');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        harness
            .taps
            .fail_delete("injected: Device or resource busy");
        let entry = stop_vm(state, &vm_id).unwrap();
        assert_ne!(entry.times.stopped_at_ns, 0);
        // The fake still holds the device (delete failed), like a stuck tap.
        assert!(harness.taps.interface_exists("vmtap4"));
        // The follow-up delete also succeeds (stop is already done).
        delete_vm(state, &vm_id, false, false).unwrap();
        assert!(state.world.blocking_read().is_empty());
    }

    #[test]
    fn reinstall_propagates_an_undeletable_rootfs_like_python() {
        // C11: Python's rootfs.unlink() propagates; an immutable rootfs
        // (here: a directory at the path) makes ReinstallVm INTERNAL
        // instead of logging and pretending success.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('d');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        // remove_file on a directory fails whatever the euid.
        std::fs::create_dir(root.join("rootfs.qcow2")).unwrap();
        match reinstall_vm(state, &vm_id, true) {
            Err(RpcError::Internal(message)) => {
                assert!(message.contains("cannot delete the rootfs"), "{message}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn reboot_of_a_stopped_vm_keeps_the_stop_stamps_and_empty_forwards() {
        // C14: Python's reboot_vm restarts the unit and stamps started_at
        // but never clears stopped_at/stopping_at nor reloads
        // mapped_ports, so a rebooted stopped VM still reports STOPPED
        // with no forwards (the shared wart is ledgered).
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: vm_id.clone(),
                host_port: 0,
                vm_port: 22,
                protocol: pb::Protocol::Tcp as i32,
            },
        )
        .unwrap();
        stop_vm(state, &vm_id).unwrap();

        let (entry, running) = reboot_vm(state, &vm_id).unwrap();
        assert!(running, "the unit itself was restarted");
        assert_ne!(entry.times.stopped_at_ns, 0, "stopped_at survives");
        assert_ne!(entry.times.stopping_at_ns, 0, "stopping_at survives");
        assert_ne!(entry.times.started_at_ns, 0);
        assert!(
            entry.port_forwards.is_empty(),
            "mapped_ports are not reloaded on this path"
        );
        // _status_of checks stopped_at first: still STOPPED on the wire.
        let info = crate::service::vm_info_message(&entry, running, now_ns());
        assert_eq!(info.status, pb::VmStatus::Stopped as i32);
        // The tap was NOT recreated (restart-without-network, both daemons).
        assert!(!harness.taps.interface_exists("vmtap4"));
    }

    #[test]
    fn recreate_network_rebuilds_running_vms_and_skips_stopped_ones() {
        // E1: chains of running VMs are rebuilt, stopped VMs are skipped,
        // and the summary carries the Python dict's shape.
        let harness = harness_with_ruleset(typical_ruleset());
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let running_vm = hash('a');
        let stopped_vm = hash('b');
        create_vm(state, spec(&running_vm, &root)).unwrap();
        create_vm(state, spec(&stopped_vm, &root)).unwrap();
        stop_vm(state, &stopped_vm).unwrap();
        // Only the batches recreate_network itself emits matter below.
        harness
            .nft
            .batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clear();

        let summary = recreate_network(state).unwrap();
        assert_eq!(summary["success"], serde_json::json!(true));
        assert_eq!(
            summary["recreated_vms"],
            serde_json::json!([running_vm.clone()])
        );
        assert_eq!(summary["recreated_count"], serde_json::json!(1));
        assert_eq!(summary["failed_count"], serde_json::json!(0));
        assert_eq!(summary["failed_vms"], serde_json::json!([]));
        // The typical fixture carries the supervisor chains and VM 3's; all
        // of them were flushed.
        let removed: Vec<&str> = summary["removed_chains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert!(removed.contains(&"aleph-supervisor-nat"));
        assert!(removed.contains(&"aleph-vm-nat-3"));
        assert_eq!(
            summary["removed_chains_count"],
            serde_json::json!(removed.len())
        );

        // The rebuild emitted the running VM's chains (vm_index 4) and not
        // the stopped one's (vm_index 5).
        let batches = harness
            .nft
            .batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let text = serde_json::to_string(&batches).unwrap();
        assert!(text.contains("aleph-vm-nat-4"));
        assert!(!text.contains("aleph-vm-nat-5"));
    }

    #[test]
    fn recreate_network_excludes_failed_removals_from_removed_chains() {
        // Python remove_all_aleph_chains: a chain whose removal errors goes
        // to failed_chains (a WARN) and must NOT be counted as removed.
        let harness = harness_with_ruleset(typical_ruleset());
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        create_vm(state, spec(&hash('a'), &root)).unwrap();
        harness.nft.fail_batches_containing("aleph-vm-nat-3");

        let summary = recreate_network(state).unwrap();
        let removed: Vec<&str> = summary["removed_chains"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value.as_str().unwrap())
            .collect();
        assert!(
            !removed.contains(&"aleph-vm-nat-3"),
            "a failed removal must not be reported as removed: {removed:?}"
        );
        assert!(removed.contains(&"aleph-supervisor-nat"));
        assert_eq!(
            summary["removed_chains_count"],
            serde_json::json!(removed.len())
        );
        // Like Python, failed REMOVALS do not flip the success flag (only
        // failed per-VM rebuilds do).
        assert_eq!(summary["success"], serde_json::json!(true));
    }

    #[test]
    fn recreate_network_reapplies_persisted_redirects_of_running_vms() {
        // E1: step 5 reloads the store and re-emits the DNAT entities.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('f');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        let info = add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: vm_id.clone(),
                host_port: 0,
                vm_port: 8080,
                protocol: pb::Protocol::Tcp as i32,
            },
        )
        .unwrap();

        let summary = recreate_network(state).unwrap();
        assert_eq!(summary["recreated_vms"], serde_json::json!([vm_id.clone()]));
        let batches = harness
            .nft
            .batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let text = serde_json::to_string(batches.last().unwrap()).unwrap();
        assert!(
            text.contains(&info.host_port.to_string()),
            "the persisted redirect was re-emitted: {text}"
        );
        // The in-memory mapping survived the reload.
        let entry = entry_snapshot(state, &vm_id).unwrap();
        assert_eq!(entry.port_forwards.len(), 1);
        assert_eq!(entry.port_forwards[0].host_port, info.host_port);
    }

    #[test]
    fn start_creates_the_tap_and_chains_before_starting_the_unit() {
        // E2: the shared event log interleaves the fakes; a unit started
        // before its tap exists must fail this ordering assertion.
        let harness = harness();
        let log = crate::test_fixtures::EventLog::new();
        harness.systemd.set_event_log(log.clone());
        harness.taps.set_event_log(log.clone());
        harness.nft.set_event_log(log.clone());

        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('1');
        create_vm(state, spec(&vm_id, &root)).unwrap();

        // The create itself must order tap -> nft -> unit start.
        let events = log.events();
        let tap_created = log.position("tap: create vmtap4");
        let unit_started = log.position("systemd: start ");
        let first_batch = log.position("nft: batch ");
        assert!(
            tap_created < first_batch && first_batch < unit_started,
            "create ordering broken: {events:?}"
        );

        // Stop, then start: the tap and chains must again precede the
        // unit restart.
        stop_vm(state, &vm_id).unwrap();
        let before = log.events().len();
        start_vm(state, &vm_id).unwrap();
        let events: Vec<String> = log.events().split_off(before);
        let tap_created = events
            .iter()
            .position(|event| event.starts_with("tap: create vmtap4"))
            .expect("start must recreate the tap");
        let restarted = events
            .iter()
            .position(|event| event.starts_with("systemd: restart "))
            .expect("start must restart the unit");
        let nft_batch = events
            .iter()
            .position(|event| event.starts_with("nft: batch "))
            .expect("start must reapply the chains");
        assert!(
            tap_created < nft_batch && nft_batch < restarted,
            "start ordering broken: {events:?}"
        );
    }

    #[test]
    fn reinstall_without_wipe_keeps_the_data_volumes() {
        // E5: wipe_volumes=false erases the rootfs only; the writable data
        // volume survives.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('2');
        let data = root.join("data.img");
        std::fs::write(root.join("rootfs.qcow2"), b"disk").unwrap();
        std::fs::write(&data, b"data").unwrap();
        let mut request = spec(&vm_id, &root);
        request.disks.push(pb::DiskConfig {
            path: data.to_string_lossy().into_owned(),
            readonly: false,
            format: pb::disk_config::Format::Raw as i32,
            role: pb::disk_config::DiskRole::Extra as i32,
        });
        create_vm(state, request).unwrap();

        let (_, running) = reinstall_vm(state, &vm_id, false).unwrap();
        assert!(running);
        assert!(!root.join("rootfs.qcow2").exists(), "rootfs erased");
        assert!(data.exists(), "wipe_volumes=false keeps the data volume");
    }

    #[test]
    fn the_erase_loop_skips_read_only_volumes_and_tolerates_missing_files() {
        // E5: erase_volumes(include_data_volumes=True) removes writable
        // volumes, skips read-only ones, and tolerates a vanished file
        // (Python's missing_ok=True).
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('3');
        let writable = root.join("data.img");
        let read_only = root.join("blob.img");
        let vanished = root.join("gone.img");
        std::fs::write(root.join("rootfs.qcow2"), b"disk").unwrap();
        std::fs::write(&writable, b"data").unwrap();
        std::fs::write(&read_only, b"blob").unwrap();
        let mut request = spec(&vm_id, &root);
        for (path, readonly) in [(&writable, false), (&read_only, true), (&vanished, false)] {
            request.disks.push(pb::DiskConfig {
                path: path.to_string_lossy().into_owned(),
                readonly,
                format: pb::disk_config::Format::Raw as i32,
                role: pb::disk_config::DiskRole::Extra as i32,
            });
        }
        create_vm(state, request).unwrap();

        // DeleteVm(wipe=true) drives erase_volumes(false, true).
        delete_vm(state, &vm_id, true, false).unwrap();
        assert!(!writable.exists(), "writable volume erased");
        assert!(read_only.exists(), "read-only volume kept");
        assert!(
            root.join("rootfs.qcow2").exists(),
            "wipe never touches the rootfs"
        );
    }

    #[test]
    fn a_boot_reconcile_failure_hides_the_vm() {
        // E5: reconcile_boot's failure branch parks the VM like a failed
        // Python reattach: removed from the world, its vm_index reserved.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('5');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        // Reshape the entry as an adopted-running one whose tap vanished.
        with_entry_mut(state, &vm_id, |entry| {
            entry.adopted_running = true;
        });
        let tap = TapAssignment::new(
            4,
            state.world.blocking_read().entries[&vm_id]
                .ipv4
                .clone()
                .unwrap(),
            state.world.blocking_read().entries[&vm_id]
                .ipv6
                .clone()
                .unwrap(),
        );
        harness.taps.delete_tap(&tap).unwrap();
        harness.taps.fail_create("injected: cannot create tap");

        reconcile_boot(state);
        let world = state.world.blocking_read();
        assert!(
            !world.entries.contains_key(&vm_id),
            "the failed VM is hidden"
        );
        assert!(
            world.reserved_vm_indices.contains(&4),
            "its vm_index claim is kept out of the allocator"
        );
    }

    #[test]
    fn recreate_redirects_replay_the_python_both_protocols_batch() {
        // C3: the udp-then-tcp protocol order of
        // SUPPORTED_PROTOCOL_FOR_REDIRECT, pinned byte-for-byte against
        // the batch VmExecution.recreate_port_redirect_rules emits for a
        // both-protocols mapping (fixture scenario captured from the real
        // Python code).
        let fixture: Value = serde_json::from_str(
            &std::fs::read_to_string(test_fixtures::fixtures_dir().join("nftables.json")).unwrap(),
        )
        .unwrap();
        let scenario = &fixture["scenarios"]["recreate-redirects-both-protocols"];
        let expected = scenario["batches"].as_array().unwrap().clone();

        let harness = harness_with_ruleset(typical_ruleset());
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        // vm_index 3 == the fixture's VM: give this entry the fixture's
        // index by pre-claiming nothing and creating at START_ID_INDEX=4,
        // then overriding the snapshot the recreate reads.
        let vm_id = hash('9');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        with_entry_mut(state, &vm_id, |entry| {
            entry.vm_index = 3;
            entry.ipv4 = None; // rederive 172.16.3.2 from vm_index 3
            entry.ipv6 = None;
            entry.port_forwards = vec![ports::PortForward {
                vm_port: 8080,
                host_port: 24610,
                tcp: true,
                udp: true,
            }];
        });
        {
            // Only the recreate batch matters for the comparison.
            harness
                .nft
                .batches
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clear();
        }
        recreate_port_redirect_rules(state, &vm_id).unwrap();
        let batches = harness
            .nft
            .batches
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        let batches: Vec<Value> = batches.into_iter().map(Value::Array).collect();
        assert_eq!(
            batches, expected,
            "the recreate batch must match the Python capture exactly \
             (protocol order included)"
        );
    }

    // ── Ephemeral Firecracker programs (increment 4) ─────────────────────

    fn fc_spec(vm_id: &str, root: &Path, internet: bool) -> pb::VmSpec {
        pb::VmSpec {
            vm_id: vm_id.to_string(),
            backend: pb::Backend::Firecracker as i32,
            kernel_path: root.join("vmlinux.bin").to_string_lossy().into_owned(),
            initrd_path: String::new(),
            disks: vec![
                pb::DiskConfig {
                    path: root.join("rootfs.squashfs").to_string_lossy().into_owned(),
                    readonly: true,
                    format: pb::disk_config::Format::Squashfs as i32,
                    role: pb::disk_config::DiskRole::Rootfs as i32,
                },
                pb::DiskConfig {
                    path: root.join("data.img").to_string_lossy().into_owned(),
                    readonly: false,
                    format: pb::disk_config::Format::Raw as i32,
                    role: pb::disk_config::DiskRole::Extra as i32,
                },
            ],
            vcpus: 1,
            memory_mib: 128,
            tee: None,
            network: Some(pb::NetworkConfig {
                internet_access: internet,
                requested_ipv6: String::new(),
                ipv6_prefix_len: 0,
            }),
            gpus: Vec::new(),
            numa_node: None,
            persistent: false,
            ssh_authorized_keys: Vec::new(),
            hostname: String::new(),
            guest_channel: Some(pb::GuestChannel {
                ready_port: 52,
                ready_timeout_secs: 7,
            }),
        }
    }

    #[test]
    fn create_boots_an_ephemeral_program_end_to_end() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');
        let request = fc_spec(&vm_id, &root, true);

        let (entry, running) = create_vm(state, request.clone()).unwrap();
        assert!(running);
        assert!(entry.is_program);
        assert_eq!(entry.vm_index, 4, "the first vm_index is START_ID_INDEX");
        assert_ne!(entry.times.starting_at_ns, 0);
        assert_ne!(entry.times.started_at_ns, 0);
        let program = entry.program.as_ref().expect("the program booted");
        assert_eq!(program.vsock_path, "/tmp/fake-vsock-4");
        assert_eq!(
            program.ready_payload,
            crate::firecracker::FAKE_READY_PAYLOAD
        );

        // The microvm addressing: IPv4 from vm_index 4, IPv6 static scheme
        // with the VmType.microvm prefix hextet 1 (instances use 3).
        assert_eq!(entry.ipv4.as_ref().unwrap().address, "172.16.4.2");
        assert!(
            entry
                .ipv6
                .as_ref()
                .unwrap()
                .network_cidr
                .starts_with("fc00:1:2:3:1:aaaa:aaaa:aaa"),
            "got {:?}",
            entry.ipv6
        );
        assert!(harness.taps.interface_exists("vmtap4"));

        // The launcher got the resolved boot request.
        let boots = harness.programs.boots();
        assert_eq!(boots.len(), 1);
        assert_eq!(boots[0].vm_index, 4);
        assert_eq!(boots[0].vm_hash, vm_id);
        assert!(boots[0].kernel_path.ends_with("vmlinux.bin"));
        assert!(boots[0].rootfs_path.ends_with("rootfs.squashfs"));
        assert_eq!(boots[0].extra_disks.len(), 1);
        assert!(!boots[0].extra_disks[0].1, "the data disk is writable");
        assert_eq!(boots[0].tap_device.as_deref(), Some("vmtap4"));
        assert_eq!(boots[0].ready_port, 52);
        assert_eq!(boots[0].init_timeout, Duration::from_secs(7));

        // No controller config, no cloud-init seed: ephemeral programs
        // leave nothing on disk (they cannot be adopted across restarts).
        assert!(!root.join(format!("{vm_id}-controller.json")).exists());
        assert!(!root.join(format!("cloud-init-{vm_id}.img")).exists());

        // Idempotency: the identical spec returns the live VM, no reboot.
        let (again, running) = create_vm(state, request.clone()).unwrap();
        assert!(running);
        assert_eq!(again.times.started_at_ns, entry.times.started_at_ns);
        assert_eq!(harness.programs.boots().len(), 1, "no second boot");

        // A different spec conflicts.
        let mut different = request;
        different.memory_mib = 512;
        match create_vm(state, different) {
            Err(RpcError::AlreadyExists(message)) => {
                assert_eq!(
                    message,
                    format!("VM {vm_id} already exists with a different spec")
                );
            }
            other => panic!("expected AlreadyExists, got {other:?}"),
        }
    }

    #[test]
    fn ephemeral_create_without_internet_gets_no_tap() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let (entry, running) = create_vm(state, fc_spec(&hash('b'), &root, false)).unwrap();
        assert!(running);
        assert_eq!(entry.ipv4, None);
        assert_eq!(entry.ipv6, None);
        assert!(harness.taps.devices().is_empty());
        let boots = harness.programs.boots();
        assert_eq!(boots[0].tap_device, None);

        // Port-forward mutations on a tap-less program fail INTERNAL (the
        // Python AttributeError on vm.tap_interface).
        match add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: hash('b'),
                host_port: 0,
                vm_port: 8080,
                protocol: pb::Protocol::Tcp as i32,
            },
        ) {
            Err(RpcError::Internal(message)) => {
                assert!(message.contains("no tap interface"), "{message}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn ephemeral_create_rejections_match_the_python_prepare_order() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();

        // No guest channel: InvalidBackendError, before any lock or check.
        let mut request = fc_spec(&hash('c'), &root, false);
        request.guest_channel = None;
        match create_vm(state, request) {
            Err(RpcError::InvalidBackend(message)) => {
                assert_eq!(message, "Firecracker spec VMs require a guest_channel");
            }
            other => panic!("expected InvalidBackend, got {other:?}"),
        }

        // The memory backstop fires before the kernel validation.
        let mut request = fc_spec(&hash('c'), &root, false);
        request.kernel_path = String::new();
        request.memory_mib = u64::MAX / 2;
        match create_vm(state, request) {
            Err(RpcError::InsufficientResources(_)) => {}
            other => panic!("expected InsufficientResources, got {other:?}"),
        }

        // Kernel validation (SpecProgramResources.from_spec).
        let mut request = fc_spec(&hash('c'), &root, false);
        request.kernel_path = String::new();
        match create_vm(state, request) {
            Err(RpcError::InvalidBackend(message)) => {
                assert_eq!(message, "A Firecracker spec requires a kernel_path");
            }
            other => panic!("expected InvalidBackend, got {other:?}"),
        }

        // Rootfs validation (require_rootfs), after the kernel check.
        let mut request = fc_spec(&hash('c'), &root, false);
        request.disks.clear();
        match create_vm(state, request) {
            Err(RpcError::InvalidBackend(message)) => {
                assert_eq!(message, "CreateVmSpec has no ROOTFS disk");
            }
            other => panic!("expected InvalidBackend, got {other:?}"),
        }

        // Persistent programs: UNIMPLEMENTED (controller port territory).
        let mut request = fc_spec(&hash('c'), &root, false);
        request.persistent = true;
        match create_vm(state, request) {
            Err(RpcError::Unimplemented(_)) => {}
            other => panic!("expected Unimplemented, got {other:?}"),
        }

        // Nothing was left behind.
        assert!(state.world.blocking_read().is_empty());
        assert!(harness.programs.boots().is_empty());
    }

    #[test]
    fn a_failed_program_boot_cleans_up_and_maps_the_init_error() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        harness
            .programs
            .fail_next(crate::firecracker::ProgramBootError::InitTimeout);
        match create_vm(state, fc_spec(&hash('d'), &root, true)) {
            // MicroVMFailedInitError: an EMPTY message on the wire.
            Err(RpcError::MicroVmInit(message)) => assert_eq!(message, ""),
            other => panic!("expected MicroVmInit, got {other:?}"),
        }
        assert!(state.world.blocking_read().is_empty(), "the entry leaked");
        assert!(
            !harness.taps.interface_exists("vmtap4"),
            "the tap was cleaned up"
        );
    }

    #[test]
    fn ephemeral_stop_and_start_answer_unimplemented_and_leave_the_vm_alone() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        create_vm(state, fc_spec(&vm_id, &root, false)).unwrap();

        match stop_vm(state, &vm_id) {
            Err(RpcError::Unimplemented(message)) => {
                assert_eq!(
                    message,
                    "Stopping an ephemeral VM is not supported; the cycle is DeleteVm + CreateVm"
                );
            }
            other => panic!("expected Unimplemented, got {other:?}"),
        }
        match start_vm(state, &vm_id) {
            Err(RpcError::Unimplemented(message)) => {
                assert_eq!(
                    message,
                    "Starting an ephemeral VM is not supported; the cycle is DeleteVm + CreateVm"
                );
            }
            other => panic!("expected Unimplemented, got {other:?}"),
        }
        // The failed calls did not break the VM.
        let entry = entry_snapshot(state, &vm_id).unwrap();
        assert!(entry_running(state, &entry));
        assert!(harness.programs.teardowns().is_empty());
    }

    #[test]
    fn ephemeral_delete_tears_down_the_process_ports_tap_and_entry() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('f');
        let mut events = state.events.subscribe();
        create_vm(state, fc_spec(&vm_id, &root, true)).unwrap();
        let info = add_port_forward(
            state,
            &pb::AddPortForwardRequest {
                vm_id: vm_id.clone(),
                host_port: 0,
                vm_port: 8080,
                protocol: pb::Protocol::Tcp as i32,
            },
        )
        .unwrap();
        assert!(info.host_port >= ports::MIN_DYNAMIC_PORT);

        delete_vm(state, &vm_id, false, false).unwrap();
        assert!(state.world.blocking_read().is_empty());
        assert_eq!(harness.programs.teardowns(), vec![vm_id.clone()]);
        assert!(!harness.taps.interface_exists("vmtap4"));
        // Non-persistent VMs drop their persisted mappings on stop
        // (record_usage), keep_port_mappings notwithstanding.
        assert!(
            ports::load_port_forwards(&state.host.settings.supervisor_database, &vm_id)
                .unwrap()
                .is_empty()
        );

        // Double delete: NOT_FOUND with the vm_id as message.
        match delete_vm(state, &vm_id, false, false) {
            Err(RpcError::NotFound(id)) => assert_eq!(id, vm_id),
            other => panic!("expected NotFound, got {other:?}"),
        }

        // Events: create then the delete's down transition.
        let mut seen = Vec::new();
        while let Ok(event) = events.try_recv() {
            seen.push((event.old_status, event.new_status));
        }
        use pb::VmStatus::{Defined, Running, Stopped};
        let pair = |old: pb::VmStatus, new: pb::VmStatus| (old as i32, new as i32);
        assert_eq!(seen, vec![pair(Defined, Running), pair(Running, Stopped)]);
    }

    #[test]
    fn ephemeral_reboot_recreates_from_the_held_spec() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('0');
        create_vm(state, fc_spec(&vm_id, &root, true)).unwrap();
        let mut events = state.events.subscribe();

        let (entry, running) = reboot_vm(state, &vm_id).unwrap();
        assert!(running);
        assert!(entry.is_program);
        assert_ne!(entry.times.started_at_ns, 0);
        assert_eq!(
            harness.programs.boots().len(),
            2,
            "the reboot is a real recreation from the held spec"
        );
        assert_eq!(harness.programs.teardowns(), vec![vm_id.clone()]);

        // The down-then-up pair, without a create event (the Python reboot
        // calls the pool directly, not the emitting create_vm).
        let mut seen = Vec::new();
        while let Ok(event) = events.try_recv() {
            seen.push((event.old_status, event.new_status));
        }
        use pb::VmStatus::{Running, Stopped};
        let pair = |old: pb::VmStatus, new: pb::VmStatus| (old as i32, new as i32);
        assert_eq!(seen, vec![pair(Running, Stopped), pair(Stopped, Running)]);
    }

    #[test]
    fn ephemeral_reinstall_erases_the_rootfs_and_preserves_extra_disks() {
        // Python's erase_volumes crashes on programs after the rootfs step
        // (SpecProgramResources has no `volumes`, models.py:653); the Rust
        // daemon pins the same disk outcome (rootfs gone, extra disks
        // untouched) but answers success (ledger entry 43).
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('1');
        std::fs::write(root.join("rootfs.squashfs"), b"squash").unwrap();
        std::fs::write(root.join("data.img"), b"data").unwrap();
        create_vm(state, fc_spec(&vm_id, &root, false)).unwrap();

        let (entry, running) = reinstall_vm(state, &vm_id, true).unwrap();
        assert!(!running);
        assert_ne!(entry.times.stopped_at_ns, 0);
        assert!(!root.join("rootfs.squashfs").exists());
        assert!(
            root.join("data.img").exists(),
            "extra disks are never reached by the Python erase"
        );
        // The agent re-creates through the create path; the VM is gone.
        assert!(state.world.blocking_read().is_empty());
        assert_eq!(harness.programs.teardowns(), vec![vm_id]);
    }

    #[test]
    fn ephemeral_delete_with_wipe_leaves_every_disk_alone() {
        // DeleteVm(wipe=true) on a program: Python crashes before touching
        // any disk (erase_volumes starts at the data volumes for a delete);
        // the Rust daemon succeeds with the same disk outcome.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('4');
        std::fs::write(root.join("rootfs.squashfs"), b"squash").unwrap();
        std::fs::write(root.join("data.img"), b"data").unwrap();
        create_vm(state, fc_spec(&vm_id, &root, false)).unwrap();

        delete_vm(state, &vm_id, true, false).unwrap();
        assert!(state.world.blocking_read().is_empty());
        assert!(
            root.join("rootfs.squashfs").exists(),
            "a delete-wipe never includes the rootfs"
        );
        assert!(
            root.join("data.img").exists(),
            "extra disks are never reached by the Python erase"
        );
    }

    #[test]
    fn a_non_positive_machine_config_fails_before_any_spawn() {
        // config.py MachineConfig vcpu_count/mem_size_mib are PositiveInt:
        // pydantic raises in setup(), after the tap and before the spawn.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        for (vcpus, memory_mib) in [(0u32, 128u64), (1, 0)] {
            let mut request = fc_spec(&hash('5'), &root, true);
            request.vcpus = vcpus;
            request.memory_mib = memory_mib;
            match create_vm(state, request) {
                Err(RpcError::Internal(message)) => {
                    assert!(message.contains("must be positive"), "got {message:?}");
                }
                other => panic!("expected Internal, got {other:?}"),
            }
        }
        assert!(
            harness.programs.boots().is_empty(),
            "the validation must fire before the launcher"
        );
        assert!(state.world.blocking_read().is_empty(), "the entry leaked");
        assert!(
            !harness.taps.interface_exists("vmtap4"),
            "the tap was cleaned up like any failed boot"
        );
    }

    #[test]
    fn run_program_code_gates_match_the_python_messages() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();

        // Unknown VM: NOT_FOUND.
        match run_program_code(state, &hash('9'), b"\x80", 5.0) {
            Err(RpcError::NotFound(id)) => assert_eq!(id, hash('9')),
            other => panic!("expected NotFound, got {other:?}"),
        }

        // A QEMU VM is not a program.
        let vm_id = hash('2');
        create_vm(state, spec(&vm_id, &root)).unwrap();
        match run_program_code(state, &vm_id, b"\x80", 5.0) {
            Err(RpcError::InvalidBackend(message)) => {
                assert_eq!(
                    message,
                    format!("VM {vm_id} is not a program; code can only be run on programs")
                );
            }
            other => panic!("expected InvalidBackend, got {other:?}"),
        }

        // A program whose channel is unreachable (the fake path does not
        // exist): the VmInitNotConnectedError message.
        let program_id = hash('3');
        create_vm(state, fc_spec(&program_id, &root, false)).unwrap();
        match run_program_code(state, &program_id, b"\x80", 5.0) {
            Err(RpcError::Internal(message)) => {
                assert_eq!(message, "MicroVM may have crashed");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
    }

    #[test]
    fn run_program_code_validates_the_scope_before_touching_the_vm() {
        // grpc_server.py:158: msgpack.unpackb runs before the VM lookup, so
        // an invalid scope aborts INTERNAL even for an unknown vm_id (not
        // NOT_FOUND), and the VM is never touched.
        let harness = harness();
        let state = &harness.state;
        for scope in [
            &b"\x81\xa4path"[..], // truncated map
            &b"\x80\x80"[..],     // ExtraData: trailing bytes
            &b"\x81\x01\x01"[..], // strict_map_key: int key
            &b""[..],             // no object at all
        ] {
            match run_program_code(state, &hash('9'), scope, 5.0) {
                Err(RpcError::Internal(message)) => {
                    assert!(
                        message.starts_with("invalid msgpack payload"),
                        "got {message:?}"
                    );
                }
                other => panic!("expected Internal for {scope:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn run_program_code_round_trips_over_a_live_guest_channel() {
        // End-to-end at the cargo tier: a created program whose fake vsock
        // path is served by a fake runtime speaking the real wire shape
        // (Firecracker's "OK <port>\n" vsock ack, then the reply until
        // EOF). The CI Firecracker leg is the real gate; this pins the
        // daemon half of the exchange against a live socket.
        use std::io::{Read, Write};
        use std::os::unix::net::UnixListener;

        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let program_id = hash('6');
        create_vm(state, fc_spec(&program_id, &root, false)).unwrap();
        let channel = state.world.blocking_read().entries[&program_id]
            .program
            .as_ref()
            .unwrap()
            .vsock_path
            .clone();
        let _ = std::fs::remove_file(&channel);
        let listener = UnixListener::bind(&channel).unwrap();
        let runtime = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = vec![0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            request.truncate(read);
            stream.write_all(b"OK 52\n").unwrap();
            stream.write_all(b"program-reply").unwrap();
            request
        });

        let scope = b"\x81\xa4path\xa1/";
        let reply = run_program_code(state, &program_id, scope, 5.0).unwrap();
        assert_eq!(reply, b"program-reply");
        let request = runtime.join().unwrap();
        let mut expected = b"CONNECT 52\n".to_vec();
        expected.extend_from_slice(b"\x81\xa5scope");
        expected.extend_from_slice(scope);
        assert_eq!(request, expected, "the scope bytes pass through raw");
        let _ = std::fs::remove_file(&channel);
    }

    // ── WatchEvents emissions ────────────────────────────────────────────

    #[test]
    fn lifecycle_mutations_emit_the_python_event_sequence() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('e');
        let mut events = state.events.subscribe();

        create_vm(state, spec(&vm_id, &root)).unwrap();
        stop_vm(state, &vm_id).unwrap();
        // Idempotent stop: Python emits (STOPPED, STOPPED).
        stop_vm(state, &vm_id).unwrap();
        start_vm(state, &vm_id).unwrap();
        // Start while running: the short circuit emits nothing.
        start_vm(state, &vm_id).unwrap();
        reboot_vm(state, &vm_id).unwrap();
        delete_vm(state, &vm_id, false, false).unwrap();

        let mut seen = Vec::new();
        let mut timestamps = Vec::new();
        while let Ok(event) = events.try_recv() {
            assert_eq!(event.vm_id, vm_id);
            seen.push((event.old_status, event.new_status));
            timestamps.push(event.timestamp_ns);
        }
        use pb::VmStatus::{Defined, Running, Stopped};
        let pair = |old: pb::VmStatus, new: pb::VmStatus| (old as i32, new as i32);
        assert_eq!(
            seen,
            vec![
                pair(Defined, Running), // create
                pair(Running, Stopped), // stop
                pair(Stopped, Stopped), // idempotent stop
                pair(Stopped, Running), // start
                pair(Running, Stopped), // reboot, down
                pair(Stopped, Running), // reboot, up
                pair(Running, Stopped), // delete
            ]
        );
        let mut sorted = timestamps.clone();
        sorted.sort_unstable();
        assert_eq!(timestamps, sorted, "event timestamps are monotone");
    }

    #[test]
    fn an_idempotent_create_retry_also_emits() {
        // Python create_vm emits after every successful pool return,
        // including the idempotent retry of a live VM.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('f');
        let request = spec(&vm_id, &root);
        create_vm(state, request.clone()).unwrap();

        let mut events = state.events.subscribe();
        create_vm(state, request.clone()).unwrap();
        let event = events.try_recv().unwrap();
        assert_eq!(event.old_status, pb::VmStatus::Defined as i32);
        assert_eq!(event.new_status, pb::VmStatus::Running as i32);

        // A failed create (conflicting spec) emits nothing.
        let mut different = request;
        different.memory_mib = 512;
        assert!(create_vm(state, different).is_err());
        assert!(events.try_recv().is_err());
    }

    // ── Reattach retry loop (ledger entry 23, closed with increment 4) ──

    /// A hidden VM as adoption leaves it: config on disk, vm_index claim
    /// reserved, queued for background retry.
    fn seed_hidden_vm(harness: &Harness) -> String {
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = test_fixtures::QEMU_HASH.to_string();
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        let mut world = state.world.blocking_write();
        world.reserved_vm_indices.insert(3);
        world
            .failed_reattach
            .insert(vm_id.clone(), world::FailedReattach::new(3));
        vm_id
    }

    #[test]
    fn the_retry_pass_readopts_a_live_hidden_vm() {
        let harness = harness();
        let state = &harness.state;
        let vm_id = seed_hidden_vm(&harness);
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "active");
        assert!(has_pending_reattach(state));

        retry_failed_reattachments_once(state);

        let world = state.world.blocking_read();
        let entry = world.entries.get(&vm_id).expect("the VM was re-adopted");
        assert_eq!(entry.vm_index, 3);
        assert_ne!(entry.times.started_at_ns, 0);
        assert!(world.failed_reattach.is_empty(), "the queue entry is gone");
        assert!(
            !world.reserved_vm_indices.contains(&3),
            "the adopted entry owns its index again"
        );
        assert!(harness.taps.interface_exists("vmtap3"));
        drop(world);
        assert!(!has_pending_reattach(state));
    }

    #[test]
    fn the_retry_pass_cleans_up_a_dead_hidden_vm() {
        // Python: a queued controller that died since startup is stopped,
        // disabled and dropped from the retries; the on-disk config stays
        // (no destruction, entry 11's rule).
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = seed_hidden_vm(&harness);
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "inactive");

        retry_failed_reattachments_once(state);

        let world = state.world.blocking_read();
        assert!(world.entries.is_empty(), "a dead VM is never resurrected");
        assert!(world.failed_reattach.is_empty());
        assert!(
            !world.reserved_vm_indices.contains(&3),
            "the dead controller's index claim is released"
        );
        assert!(
            root.join(format!("{vm_id}-controller.json")).exists(),
            "the definition is never destroyed on this path"
        );
        assert!(!harness.systemd.is_enabled(&controller_unit_name(&vm_id)));
    }

    #[test]
    fn retries_exhaust_after_the_attempt_cap() {
        // A transitional state is not proof of death: each pass spends one
        // attempt; at the cap the VM is exhausted and left alone, its index
        // claim intact (the controller may still be running).
        let harness = harness();
        let state = &harness.state;
        let vm_id = seed_hidden_vm(&harness);
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "activating");

        for _ in 0..10 {
            retry_failed_reattachments_once(state);
        }

        let world = state.world.blocking_read();
        let queued = world.failed_reattach.get(&vm_id).expect("still queued");
        assert!(queued.exhausted);
        assert_eq!(
            queued.attempts, REATTACH_RETRY_MAX_ATTEMPTS,
            "attempts stop counting once exhausted"
        );
        assert!(
            world.reserved_vm_indices.contains(&3),
            "an exhausted VM keeps its vm_index claim out of the allocator"
        );
        drop(world);
        assert!(
            !has_pending_reattach(state),
            "the retry loop terminates once everything is exhausted"
        );
    }

    #[test]
    fn a_failed_retry_bumps_the_attempt_count() {
        // A live controller whose restore fails (here: the tap creation)
        // stays queued with a bumped attempt count.
        let harness = harness();
        let state = &harness.state;
        let vm_id = seed_hidden_vm(&harness);
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "active");
        harness.taps.fail_create("injected tap failure");

        retry_failed_reattachments_once(state);

        let world = state.world.blocking_read();
        assert!(world.entries.is_empty());
        let queued = world.failed_reattach.get(&vm_id).expect("still queued");
        assert_eq!(queued.attempts, 2);
        assert!(!queued.exhausted);
        assert!(
            world.reserved_vm_indices.contains(&3),
            "the failed restore re-reserves the index"
        );
    }

    #[test]
    fn delete_of_a_queued_hidden_vm_dequeues_it() {
        // The discard_failed_reattach port: DeleteVm on a queued hidden VM
        // stops the controller, drops the definition and the queue entry,
        // so the retry loop cannot resurrect a deleted VM.
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = seed_hidden_vm(&harness);
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "active");

        delete_vm(state, &vm_id, false, false).unwrap();

        let world = state.world.blocking_read();
        assert!(world.failed_reattach.is_empty());
        assert!(!world.reserved_vm_indices.contains(&3));
        assert!(!root.join(format!("{vm_id}-controller.json")).exists());
        assert_eq!(
            harness
                .systemd
                .get_active_state(&controller_unit_name(&vm_id)),
            "inactive"
        );
        drop(world);
        // The queue is empty: a follow-up pass has nothing to resurrect.
        retry_failed_reattachments_once(state);
        assert!(state.world.blocking_read().entries.is_empty());
    }

    #[test]
    fn a_failed_boot_reconcile_queues_the_vm_for_retry() {
        let harness = harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = test_fixtures::QEMU_HASH.to_string();
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "active");
        let adopted = world::build_world_view(
            &state.host.settings,
            harness.systemd.as_ref(),
            &state.host.gpus,
        );
        *state.world.blocking_write() = adopted;
        harness.taps.fail_create("injected tap failure");

        reconcile_boot(state);

        let world = state.world.blocking_read();
        assert!(world.entries.is_empty(), "the VM is hidden");
        assert!(world.reserved_vm_indices.contains(&3));
        let queued = world.failed_reattach.get(&vm_id).expect("queued for retry");
        assert_eq!(queued.attempts, 1);
    }

    // ── RecreateNetwork IP rederivation (ledger entry 24, closed) ───────

    #[test]
    fn recreate_network_rederives_ips_after_a_bus_outage_adoption() {
        // Entries adopted while the bus was unreachable carry no derived
        // IPs; RecreateNetwork must rederive them (from vm_index/vm_hash)
        // and rebuild their chains instead of skipping them.
        let harness = harness_with_ruleset(typical_ruleset());
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = test_fixtures::QEMU_HASH.to_string();
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        let adopted = world::build_world_view(
            &state.host.settings,
            &crate::units::UnreachableBus,
            &state.host.gpus,
        );
        *state.world.blocking_write() = adopted;
        {
            let world = state.world.blocking_read();
            assert_eq!(world.entries[&vm_id].ipv4, None, "bus-outage adoption");
        }
        // The bus answers now and the unit is active.
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "active");

        let summary = recreate_network(state).unwrap();
        assert_eq!(summary["recreated_count"], 1);
        assert_eq!(summary["recreated_vms"][0], vm_id);
        assert_eq!(summary["success"], true);

        let world = state.world.blocking_read();
        let entry = &world.entries[&vm_id];
        assert_eq!(
            entry.ipv4.as_ref().map(|pair| pair.address.as_str()),
            Some("172.16.3.2"),
            "the assignment was rederived from vm_index 3"
        );
        assert!(entry.ipv6.is_some());
    }

    // ── NUMA placement + CPU pinning (Phase 3 increment C1) ─────────────

    /// A 2-node topology: node 0 = cpus 0-3, node 1 = cpus 4-7.
    fn two_node_topology() -> crate::numa::NumaTopology {
        crate::numa::NumaTopology {
            nodes: vec![
                crate::numa::NumaNode {
                    id: 0,
                    cpus: (0..4).collect(),
                    total_2m_hugepages: 0,
                    total_1g_hugepages: 0,
                    total_ram_mb: 64_000,
                },
                crate::numa::NumaNode {
                    id: 1,
                    cpus: (4..8).collect(),
                    total_2m_hugepages: 0,
                    total_1g_hugepages: 0,
                    total_ram_mb: 32_000,
                },
            ],
        }
    }

    /// A host whose systemd unit directory points at a writable temp path (so
    /// the AllowedCPUs drop-in can be written) with VM networking allowed. The
    /// temp dir is returned so the caller keeps it alive.
    fn numa_host() -> (HostState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = Settings::from_vars(
            [(
                "ALEPH_VM_EXECUTION_ROOT".to_string(),
                tmp.path().to_string_lossy().into_owned(),
            )]
            .into_iter(),
        )
        .unwrap();
        settings.allow_vm_networking = true;
        settings.systemd_unit_dir = tmp.path().join("systemd");
        crate::server::prepare_directories(&settings).unwrap();
        ports::ensure_schema(&settings.supervisor_database).unwrap();

        let host = HostState {
            settings,
            host_ipv4: "192.0.2.10".to_string(),
            network_interface: Some("eth0".to_string()),
            gpus: Vec::new(),
            dns_nameservers: Some(vec!["1.1.1.1".to_string()]),
        };
        (host, tmp)
    }

    /// A single-node topology: node 0 = cpus 0-15. Every CONFIG_NUMA host
    /// exposes exactly this on a single socket; placement must stay inert.
    fn one_node_topology() -> crate::numa::NumaTopology {
        crate::numa::NumaTopology {
            nodes: vec![crate::numa::NumaNode {
                id: 0,
                cpus: (0..16).collect(),
                total_2m_hugepages: 0,
                total_1g_hugepages: 0,
                total_ram_mb: 128_000,
            }],
        }
    }

    /// A harness like [`harness`] with the given NUMA topology installed and
    /// the systemd unit directory pointed at a writable temp path (so the
    /// AllowedCPUs drop-in can be written).
    fn numa_harness_with(topology: crate::numa::NumaTopology) -> Harness {
        let (host, tmp) = numa_host();
        let systemd = Arc::new(FakeSystemd::new());
        let taps = Arc::new(FakeTapBackend::new());
        let dhcp = Arc::new(crate::dhcp::FakeDhcpBackend::new());
        let nft_executor = Arc::new(nft::StaticRuleset::new(bare_host_ruleset()));
        let programs = Arc::new(crate::firecracker::FakeProgramLauncher::new());
        let mut state = crate::service::DaemonState::hermetic(
            host,
            world::WorldView::default(),
            systemd.clone(),
            Arc::new(StaticLogSource::default()),
        );
        state.nft = nft_executor.clone();
        state.taps = taps.clone();
        state.dhcp = dhcp.clone();
        state.programs = programs.clone();
        state.with_numa_topology(topology);
        Harness {
            state: Arc::new(state),
            systemd,
            taps,
            dhcp,
            nft: nft_executor,
            programs,
            _tmp: tmp,
        }
    }

    /// The default two-node NUMA harness.
    fn numa_harness() -> Harness {
        numa_harness_with(two_node_topology())
    }

    /// A two-node topology whose nodes carry real 2M/1G hugepage pools, for the
    /// C2 hugepage selection tests.
    fn two_node_topology_with_hugepages() -> crate::numa::NumaTopology {
        crate::numa::NumaTopology {
            nodes: vec![
                crate::numa::NumaNode {
                    id: 0,
                    cpus: (0..4).collect(),
                    total_2m_hugepages: 2000,
                    total_1g_hugepages: 4,
                    total_ram_mb: 64_000,
                },
                crate::numa::NumaNode {
                    id: 1,
                    cpus: (4..8).collect(),
                    total_2m_hugepages: 2000,
                    total_1g_hugepages: 0,
                    total_ram_mb: 64_000,
                },
            ],
        }
    }

    /// A two-node NUMA harness with `ALEPH_VM_NUMA_HUGEPAGES` enabled and nodes
    /// carrying hugepage pools, so the allocator selects a page size.
    fn numa_hugepages_harness() -> Harness {
        let (mut host, tmp) = numa_host();
        host.settings.numa_hugepages = true;
        let systemd = Arc::new(FakeSystemd::new());
        let taps = Arc::new(FakeTapBackend::new());
        let dhcp = Arc::new(crate::dhcp::FakeDhcpBackend::new());
        let nft_executor = Arc::new(nft::StaticRuleset::new(bare_host_ruleset()));
        let programs = Arc::new(crate::firecracker::FakeProgramLauncher::new());
        let mut state = crate::service::DaemonState::hermetic(
            host,
            world::WorldView::default(),
            systemd.clone(),
            Arc::new(StaticLogSource::default()),
        );
        state.nft = nft_executor.clone();
        state.taps = taps.clone();
        state.dhcp = dhcp.clone();
        state.programs = programs.clone();
        state.with_numa_topology(two_node_topology_with_hugepages());
        Harness {
            state: Arc::new(state),
            systemd,
            taps,
            dhcp,
            nft: nft_executor,
            programs,
            _tmp: tmp,
        }
    }

    /// Read the on-disk controller config JSON a create wrote.
    fn written_config_json(state: &DaemonState, vm_id: &str) -> String {
        let path =
            controller_config::controller_config_path(&state.host.settings.execution_root, vm_id);
        std::fs::read_to_string(path).expect("controller config was written")
    }

    fn allocated(state: &DaemonState, node: u32) -> u32 {
        state
            .numa_ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allocated_vcpus(node)
    }

    fn allocated_2m(state: &DaemonState, node: u32) -> u32 {
        state
            .numa_ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allocated_2m_pages(node)
    }

    fn allocated_1g(state: &DaemonState, node: u32) -> u32 {
        state
            .numa_ledger
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .allocated_1g_pages(node)
    }

    /// Insert an adopted-running QEMU entry (as build_world_view would) with
    /// the given vCPU count and no recorded NUMA placement.
    fn insert_adopted(state: &DaemonState, vm_id: &str, vcpus: u32, vm_index: i64) {
        let mut config = QemuVmConfig::for_program(256, Some(format!("vmtap{vm_index}")));
        config.vcpu_count = vcpus;
        let entry = VmEntry {
            vm_hash: vm_id.to_string(),
            vm_index,
            config,
            settings_slice: Default::default(),
            times: VmTimes {
                started_at_ns: 1_000,
                ..VmTimes::default()
            },
            adopted_running: true,
            ipv4: None,
            ipv6: None,
            port_forwards: Vec::new(),
            gpus: Vec::new(),
            spec: None,
            ordinal: 0,
            is_program: false,
            program: None,
            numa_node: None,
        };
        state.world.blocking_write().insert_entry(entry);
    }

    #[test]
    fn create_pins_vcpus_pack_first_and_reports_effective_placement() {
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        let (entry, running) = create_vm(state, spec(&vm_id, &root)).unwrap();
        assert!(running);
        // Pack-first: the first VM lands on node 0 (cpus 0-3).
        assert_eq!(entry.numa_node, Some(0));

        // VmInfo carries the effective placement.
        let info = crate::service::vm_info_message(&entry, running, now_ns());
        assert_eq!(info.numa_node, Some(0));

        // The AllowedCPUs drop-in was written with node 0's cpuset.
        assert_eq!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm_id),
            Some("0-3".to_string())
        );

        // A daemon-reload preceded the enable/start so the pin applies.
        let unit = controller_unit_name(&vm_id);
        assert_eq!(
            harness.systemd.actions(),
            vec![
                "daemon-reload".to_string(),
                format!("enable {unit}"),
                format!("start {unit}"),
            ]
        );

        // The ledger reserved one vCPU on node 0.
        assert_eq!(allocated(state, 0), 1);
        assert_eq!(allocated(state, 1), 0);
    }

    #[test]
    fn create_honors_a_requested_numa_node() {
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');
        let mut request = spec(&vm_id, &root);
        request.numa_node = Some(1);

        let (entry, _) = create_vm(state, request).unwrap();
        // Honored even though node 0 (pack-first) had room.
        assert_eq!(entry.numa_node, Some(1));
        assert_eq!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm_id),
            Some("4-7".to_string())
        );
        assert_eq!(allocated(state, 0), 0);
        assert_eq!(allocated(state, 1), 1);
    }

    #[test]
    fn create_writes_numa_node_into_the_controller_config() {
        // C2: a placed VM's controller config binds memory to the node. With
        // hugepages OFF (the default), no hugepage_size / hugetlb is written.
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        let (entry, _) = create_vm(state, spec(&vm_id, &root)).unwrap();
        assert_eq!(entry.numa_node, Some(0));

        let json = written_config_json(state, &vm_id);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let vm = &value["vm_configuration"];
        assert_eq!(vm["numa_node"], serde_json::json!(0));
        assert!(
            vm.get("hugepage_size").is_none(),
            "hugepages off: no hugepage_size written: {json}"
        );
    }

    #[test]
    fn create_on_a_single_node_host_writes_no_numa_node() {
        // Parity: a single-node (or non-NUMA) host places nothing, so the
        // written config carries no numa_node / hugepage_size and its bytes
        // stay identical to pre-C2.
        let harness = numa_harness_with(one_node_topology());
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        let (entry, _) = create_vm(state, spec(&vm_id, &root)).unwrap();
        assert_eq!(entry.numa_node, None);

        let json = written_config_json(state, &vm_id);
        assert!(
            !json.contains("numa_node") && !json.contains("hugepage_size"),
            "no NUMA fields on a single-node host: {json}"
        );
    }

    #[test]
    fn create_with_hugepages_enabled_selects_a_page_size() {
        // C2 opt-in: with ALEPH_VM_NUMA_HUGEPAGES on and hugepages reserved on
        // the node, a placed VM's config carries a hugepage_size. The default
        // spec is 256 MB (not 1G-aligned), so 2M is selected.
        let harness = numa_hugepages_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        create_vm(state, spec(&vm_id, &root)).unwrap();
        let json = written_config_json(state, &vm_id);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let vm = &value["vm_configuration"];
        assert_eq!(vm["numa_node"], serde_json::json!(0));
        assert_eq!(
            vm["hugepage_size"],
            serde_json::json!("2M"),
            "256 MB is not 1G-aligned, so 2M pages are chosen: {json}"
        );
    }

    #[test]
    fn create_with_hugepage_pools_but_setting_off_writes_no_hugepage_size() {
        // FIX 2 (opt-in gate): a host with operator-pre-reserved hugepage pools
        // but ALEPH_VM_NUMA_HUGEPAGES OFF must NOT emit hugepages. This pins the
        // gate `let uses_hugepages = state.host.settings.numa_hugepages;`:
        // mutating it to `true` here would select 2M (the pools are present) and
        // write a hugepage_size, which this test forbids -> the mutation dies.
        let harness = numa_harness_with(two_node_topology_with_hugepages());
        let state = &harness.state;
        assert!(
            !state.host.settings.numa_hugepages,
            "the setting is off (the default) even though pools are present"
        );
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        let (entry, _) = create_vm(state, spec(&vm_id, &root)).unwrap();
        assert_eq!(entry.numa_node, Some(0), "still placed (vCPU binding)");

        let json = written_config_json(state, &vm_id);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let vm = &value["vm_configuration"];
        assert_eq!(vm["numa_node"], serde_json::json!(0));
        assert!(
            vm.get("hugepage_size").is_none(),
            "setting off: no hugepage_size against the operator opt-out: {json}"
        );
        // No hugetlb can reach the argv: it is only ever emitted from
        // hugepage_size, which is absent. Guard against a stray literal too.
        assert!(
            !json.contains("hugetlb"),
            "no hugetlb literal in the written config: {json}"
        );
        // The 2M pool was never touched.
        assert_eq!(allocated_2m(state, 0), 0);
        assert_eq!(allocated_1g(state, 0), 0);
    }

    #[test]
    fn create_then_delete_returns_hugepages_no_leak() {
        // FIX 1: with hugepages enabled, a create reserves pages and a delete
        // returns them to the node's pool (pre-create value), no monotonic leak.
        let harness = numa_hugepages_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        let pre = allocated_2m(state, 0);
        create_vm(state, spec(&vm_id, &root)).unwrap();
        // 256 MB spec -> 2M pages: 256.div_ceil(2) = 128 pages reserved.
        assert_eq!(
            allocated_2m(state, 0),
            pre + 128,
            "pages reserved on create"
        );

        delete_vm(state, &vm_id, false, false).unwrap();
        assert_eq!(
            allocated_2m(state, 0),
            pre,
            "delete returned the reserved pages: no leak"
        );
        assert_eq!(allocated(state, 0), 0, "and the vCPU reservation is freed");
    }

    #[test]
    fn failed_create_with_hugepages_releases_the_pages() {
        // FIX 1: a create that fails AFTER the hugepage reservation must return
        // the reserved pages, not leak them.
        let (mut host, _tmp) = numa_host();
        host.settings.numa_hugepages = true;
        struct FailingSystemd(Arc<FakeSystemd>);
        impl crate::units::UnitStateSource for FailingSystemd {
            fn active_states(
                &self,
                units: &[String],
            ) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.active_states(units)
            }
            fn controller_units(&self) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.controller_units()
            }
            fn get_active_state(&self, _unit: &str) -> String {
                "failed".to_string()
            }
            fn start(&self, unit: &str) -> Result<(), String> {
                self.0.start(unit)
            }
            fn stop(&self, unit: &str) -> Result<(), String> {
                self.0.stop(unit)
            }
            fn restart(&self, unit: &str) -> Result<(), String> {
                self.0.restart(unit)
            }
            fn enable(&self, unit: &str) -> Result<(), String> {
                self.0.enable(unit)
            }
            fn disable(&self, unit: &str) -> Result<(), String> {
                self.0.disable(unit)
            }
            fn is_enabled(&self, unit: &str) -> bool {
                self.0.is_enabled(unit)
            }
        }
        let systemd = Arc::new(FakeSystemd::new());
        let mut state = crate::service::DaemonState::hermetic(
            host,
            world::WorldView::default(),
            Arc::new(FailingSystemd(systemd.clone())),
            Arc::new(StaticLogSource::default()),
        );
        state.nft = Arc::new(nft::StaticRuleset::new(bare_host_ruleset()));
        state.taps = Arc::new(FakeTapBackend::new());
        state.with_numa_topology(two_node_topology_with_hugepages());
        let state = Arc::new(state);
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        match create_vm(&state, spec(&vm_id, &root)) {
            Err(RpcError::Internal(message)) => {
                assert!(message.contains("controller failed to start"), "{message}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        assert_eq!(
            allocated_2m(&state, 0),
            0,
            "the reserved pages were returned on the failed create"
        );
        assert_eq!(allocated(&state, 0), 0, "and the vCPUs did not leak");
    }

    #[test]
    fn reconcile_reregisters_a_hugepage_backed_vms_pages() {
        // FIX 1: adoption/reconcile of a hugepage-backed VM must re-register its
        // page usage from the written config, so the pool is NOT reset to 0
        // across a daemon restart (which would over-commit the pages).
        let harness = numa_hugepages_harness();
        let state = &harness.state;
        let unit_dir = state.host.settings.systemd_unit_dir.clone();
        let vm_id = hash('c');

        // An adopted VM: 2048 MB, 1G-backed, 2 vCPUs, pinned to node 0.
        let mut config = QemuVmConfig::for_program(2048, Some("vmtap9".to_string()));
        config.vcpu_count = 2;
        config.numa_node = Some(0);
        config.hugepage_size = Some("1G".to_string());
        let entry = VmEntry {
            vm_hash: vm_id.clone(),
            vm_index: 9,
            config,
            settings_slice: Default::default(),
            times: VmTimes {
                started_at_ns: 1_000,
                ..VmTimes::default()
            },
            adopted_running: true,
            ipv4: None,
            ipv6: None,
            port_forwards: Vec::new(),
            gpus: Vec::new(),
            spec: None,
            ordinal: 0,
            is_program: false,
            program: None,
            numa_node: None,
        };
        state.world.blocking_write().insert_entry(entry);
        crate::numa::write_cpuset_dropin(&unit_dir, &vm_id, "0-3").unwrap();

        reconcile_numa_ledger(state);

        assert_eq!(entry_snapshot(state, &vm_id).unwrap().numa_node, Some(0));
        assert_eq!(allocated(state, 0), 2, "vCPUs re-registered");
        assert_eq!(
            allocated_1g(state, 0),
            2,
            "the 1G pages were re-registered (2048 MB / 1024), pool not reset to 0"
        );
    }

    #[test]
    fn create_rejects_an_invalid_requested_numa_node() {
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');
        let mut request = spec(&vm_id, &root);
        request.numa_node = Some(9); // no such node

        match create_vm(state, request) {
            Err(RpcError::InvalidBackend(message)) => {
                assert!(
                    message.contains("9"),
                    "message names the bad node: {message}"
                );
            }
            other => panic!("expected InvalidBackend, got {other:?}"),
        }
        // No entry left behind and no reservation leaked.
        assert!(entry_snapshot(state, &vm_id).is_none());
        assert_eq!(allocated(state, 0), 0);
        assert_eq!(allocated(state, 1), 0);
        // No drop-in was written.
        assert!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm_id)
                .is_none()
        );
    }

    #[test]
    fn delete_releases_the_reservation_and_removes_the_dropin() {
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        create_vm(state, spec(&vm_id, &root)).unwrap();
        assert_eq!(allocated(state, 0), 1);

        delete_vm(state, &vm_id, false, false).unwrap();
        assert_eq!(allocated(state, 0), 0, "the vCPU reservation is freed");
        assert!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm_id)
                .is_none(),
            "the drop-in is gone"
        );
    }

    #[test]
    fn remove_numa_dropin_reloads_only_when_a_dropin_was_removed() {
        // No drop-in on disk (the unpinned common case, e.g. a program VM):
        // removal is a no-op and must not pay for a systemd daemon-reload,
        // even with placement active. The hidden-VM and tracked delete paths
        // call remove_numa_dropin unconditionally, so this keeps every
        // unpinned delete cheap.
        let active = numa_harness();
        remove_numa_dropin(&active.state, &hash('a'));
        assert!(
            !active
                .systemd
                .actions()
                .iter()
                .any(|action| action.contains("daemon-reload")),
            "no drop-in on disk must not daemon-reload, got: {:?}",
            active.systemd.actions()
        );

        // A leftover drop-in is removed and reloaded even when placement is
        // inert (single-node host): a pin written under an earlier topology
        // must not outlive its VM, and the reload drops the property from an
        // already-loaded unit.
        let single_node = crate::numa::NumaTopology {
            nodes: vec![crate::numa::NumaNode {
                id: 0,
                cpus: (0..8).collect(),
                total_2m_hugepages: 0,
                total_1g_hugepages: 0,
                total_ram_mb: 64_000,
            }],
        };
        let inert = numa_harness_with(single_node);
        let unit_dir = inert.state.host.settings.systemd_unit_dir.clone();
        crate::numa::write_cpuset_dropin(&unit_dir, &hash('a'), "0-3").unwrap();
        remove_numa_dropin(&inert.state, &hash('a'));
        assert!(
            crate::numa::read_cpuset_dropin(&unit_dir, &hash('a')).is_none(),
            "the stale drop-in is removed on an inert host"
        );
        assert!(
            inert
                .systemd
                .actions()
                .iter()
                .any(|action| action.contains("daemon-reload")),
            "removing an actual drop-in reloads, got: {:?}",
            inert.systemd.actions()
        );
    }

    #[test]
    fn delete_removes_the_dropin_of_a_vm_reconciled_as_unpinned() {
        // A drop-in whose cpuset matches no node after a topology change
        // between restarts leaves the VM reconciled as unpinned
        // (numa_node None). Delete must still remove the file: systemd
        // would apply it to a future controller with the same vm_hash.
        let harness = numa_harness();
        let state = &harness.state;
        let unit_dir = state.host.settings.systemd_unit_dir.clone();
        let vm_id = hash('a');

        insert_adopted(state, &vm_id, 2, 9);
        crate::numa::write_cpuset_dropin(&unit_dir, &vm_id, "0-1").unwrap();
        reconcile_numa_ledger(state);
        assert_eq!(entry_snapshot(state, &vm_id).unwrap().numa_node, None);

        delete_vm(state, &vm_id, false, false).unwrap();
        assert!(
            crate::numa::read_cpuset_dropin(&unit_dir, &vm_id).is_none(),
            "the stale drop-in must not outlive the VM"
        );
        assert_eq!(allocated(state, 0), 0, "nothing was ever reserved");
    }

    #[test]
    fn reconcile_treats_unknown_placement_as_unpinned_and_reregisters_known() {
        let harness = numa_harness();
        let state = &harness.state;
        let unit_dir = state.host.settings.systemd_unit_dir.clone();
        let pinned = hash('c');
        let unpinned = hash('b');

        insert_adopted(state, &pinned, 2, 9);
        insert_adopted(state, &unpinned, 3, 10);
        // The pinned VM has an effective AllowedCPUs drop-in (node 0); the
        // unpinned one (a pre-NUMA adoption) has none.
        crate::numa::write_cpuset_dropin(&unit_dir, &pinned, "0-3").unwrap();

        reconcile_numa_ledger(state);

        assert_eq!(entry_snapshot(state, &pinned).unwrap().numa_node, Some(0));
        assert_eq!(
            entry_snapshot(state, &unpinned).unwrap().numa_node,
            None,
            "an adopted VM with no drop-in is unpinned, not node 0"
        );
        // Only the pinned VM's vCPUs count against the ledger.
        assert_eq!(allocated(state, 0), 2);
        assert_eq!(allocated(state, 1), 0);
    }

    #[test]
    fn single_node_host_is_inert_for_placement_and_pinning() {
        // FIX 1: a one-node host (every CONFIG_NUMA box has node0) must behave
        // exactly like a non-NUMA host: no placement, no drop-in, no
        // daemon-reload, no reservation, and VmInfo.numa_node stays None. The
        // topology is STILL reported (HostInfo.numa_nodes) for the one node.
        let harness = numa_harness_with(one_node_topology());
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        // Reporting is retained even though placement is inert.
        assert!(!state.numa.is_placement_active());
        assert_eq!(
            state.numa.nodes.len(),
            1,
            "the single node is still reported"
        );

        let (entry, running) = create_vm(state, spec(&vm_id, &root)).unwrap();
        assert!(running);
        assert_eq!(entry.numa_node, None, "no placement on a single-node host");

        let info = crate::service::vm_info_message(&entry, running, now_ns());
        assert_eq!(info.numa_node, None);

        // No AllowedCPUs drop-in, no reservation.
        assert!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm_id)
                .is_none(),
            "a single-node host writes no drop-in"
        );
        assert_eq!(allocated(state, 0), 0);

        // No daemon-reload preceded the enable/start (the drop-in path is
        // never entered): just enable + start, exactly as before C1.
        let unit = controller_unit_name(&vm_id);
        assert_eq!(
            harness.systemd.actions(),
            vec![format!("enable {unit}"), format!("start {unit}")],
        );
    }

    #[test]
    fn two_vms_pack_first_then_spill_to_node_one() {
        // FIX 7: at the lifecycle level, VM1 fills node 0 and VM2 lands on
        // node 1 with node 1's cpuset and its own drop-in.
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();

        let vm1 = hash('a');
        let mut req1 = spec(&vm1, &root);
        req1.vcpus = 4; // fills node 0 (cpus 0-3)
        let (entry1, _) = create_vm(state, req1).unwrap();
        assert_eq!(entry1.numa_node, Some(0));
        assert_eq!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm1),
            Some("0-3".to_string())
        );

        let vm2 = hash('b');
        let (entry2, _) = create_vm(state, spec(&vm2, &root)).unwrap();
        assert_eq!(
            entry2.numa_node,
            Some(1),
            "node 0 full, VM2 spills to node 1"
        );
        assert_eq!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm2),
            Some("4-7".to_string()),
            "VM2 is pinned to node 1's cpuset"
        );
        assert_eq!(allocated(state, 0), 4);
        assert_eq!(allocated(state, 1), 1);
    }

    #[test]
    fn stop_keeps_the_numa_reservation() {
        // FIX 7 characterization: stop must NOT release the reservation (and
        // start must not re-place); the node's allocated count is unchanged
        // across a stop.
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        create_vm(state, spec(&vm_id, &root)).unwrap();
        assert_eq!(allocated(state, 0), 1);

        stop_vm(state, &vm_id).unwrap();
        assert_eq!(
            allocated(state, 0),
            1,
            "stop keeps the reservation (delete releases, not stop)"
        );
    }

    #[test]
    fn recreate_over_a_stopped_vm_does_not_double_count() {
        // FIX 2: create -> stop (keeps the entry + reservation) -> create the
        // same hash. The stale entry's LIVE reservation must be released
        // before the new placement re-allocates, so the node does not
        // double-count.
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        create_vm(state, spec(&vm_id, &root)).unwrap();
        assert_eq!(allocated(state, 0), 1);

        stop_vm(state, &vm_id).unwrap();
        assert_eq!(allocated(state, 0), 1, "stop keeps the reservation");

        // Re-create the same VM: the stale reservation is released and a fresh
        // one is taken, netting the SAME count (not two).
        let (entry, _) = create_vm(state, spec(&vm_id, &root)).unwrap();
        assert_eq!(entry.numa_node, Some(0));
        assert_eq!(
            allocated(state, 0),
            1,
            "the node's vCPUs did not double across stop->recreate"
        );
        assert_eq!(allocated(state, 1), 0);
    }

    #[test]
    fn a_boot_failure_after_placement_releases_the_reservation_and_dropin() {
        // FIX 7: a create that fails AFTER place_vm_numa must release the
        // reserved vCPUs and remove the drop-in, leaving the ledger at zero.
        let (host, _tmp) = numa_host();
        // A systemd whose controller never goes active: start records the
        // action but the state reads back "failed", failing the boot.
        struct FailingSystemd(Arc<FakeSystemd>);
        impl crate::units::UnitStateSource for FailingSystemd {
            fn active_states(
                &self,
                units: &[String],
            ) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.active_states(units)
            }
            fn controller_units(&self) -> Result<std::collections::HashMap<String, bool>, String> {
                self.0.controller_units()
            }
            fn get_active_state(&self, _unit: &str) -> String {
                "failed".to_string()
            }
            fn start(&self, unit: &str) -> Result<(), String> {
                self.0.start(unit)
            }
            fn stop(&self, unit: &str) -> Result<(), String> {
                self.0.stop(unit)
            }
            fn restart(&self, unit: &str) -> Result<(), String> {
                self.0.restart(unit)
            }
            fn enable(&self, unit: &str) -> Result<(), String> {
                self.0.enable(unit)
            }
            fn disable(&self, unit: &str) -> Result<(), String> {
                self.0.disable(unit)
            }
            fn is_enabled(&self, unit: &str) -> bool {
                self.0.is_enabled(unit)
            }
        }
        let systemd = Arc::new(FakeSystemd::new());
        let mut state = crate::service::DaemonState::hermetic(
            host,
            world::WorldView::default(),
            Arc::new(FailingSystemd(systemd.clone())),
            Arc::new(StaticLogSource::default()),
        );
        state.nft = Arc::new(nft::StaticRuleset::new(bare_host_ruleset()));
        state.taps = Arc::new(FakeTapBackend::new());
        state.with_numa_topology(two_node_topology());
        let state = Arc::new(state);
        let root = state.host.settings.execution_root.clone();
        let vm_id = hash('a');

        match create_vm(&state, spec(&vm_id, &root)) {
            Err(RpcError::Internal(message)) => {
                assert!(message.contains("controller failed to start"), "{message}");
            }
            other => panic!("expected Internal, got {other:?}"),
        }
        // The reservation was released and the drop-in removed: no leak.
        assert_eq!(allocated(&state, 0), 0, "the reservation did not leak");
        assert!(
            crate::numa::read_cpuset_dropin(&state.host.settings.systemd_unit_dir, &vm_id)
                .is_none(),
            "the drop-in was removed on the failed boot"
        );
        assert!(state.world.blocking_read().entries.is_empty());
    }

    #[test]
    fn deleting_a_hidden_vm_does_not_release_the_ledger() {
        // FIX 3: a hidden VM (adoption failed, never in world.entries) was
        // NEVER registered by reconcile_numa_ledger, so its delete must NOT
        // release any vCPUs (that would steal capacity from co-located VMs).
        // The drop-in file is still removed for cleanliness.
        let harness = numa_harness();
        let state = &harness.state;
        let unit_dir = state.host.settings.systemd_unit_dir.clone();
        let vm_id = seed_hidden_vm(&harness);

        // A co-located, legitimately-tracked VM holds 3 vCPUs on node 0.
        {
            let mut ledger = state
                .numa_ledger
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            ledger.register(0, 3, 0, None);
        }
        // The hidden VM has an on-disk drop-in mapping to node 0.
        crate::numa::write_cpuset_dropin(&unit_dir, &vm_id, "0-3").unwrap();
        harness
            .systemd
            .set_state(&controller_unit_name(&vm_id), "inactive");

        delete_vm(state, &vm_id, false, false).unwrap();

        assert_eq!(
            allocated(state, 0),
            3,
            "the hidden delete did not touch the co-located reservation"
        );
        assert!(
            crate::numa::read_cpuset_dropin(&unit_dir, &vm_id).is_none(),
            "the hidden VM's drop-in was still removed"
        );
    }

    #[test]
    fn readopt_reconstructs_the_pin_and_counts_it_once() {
        // FIX 4: re-adopting a live-but-untracked controller with a pinned
        // drop-in stamps entry.numa_node and registers its vCPUs exactly once
        // (this path is disjoint from reconcile_numa_ledger).
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let unit_dir = state.host.settings.systemd_unit_dir.clone();
        let vm_id = test_fixtures::QEMU_HASH;
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        // The live controller is pinned to node 1 (cpus 4-7); the fixture is a
        // 2-vCPU VM.
        crate::numa::write_cpuset_dropin(&unit_dir, vm_id, "4-7").unwrap();
        harness
            .systemd
            .set_state(&controller_unit_name(vm_id), "active");

        // A create for the same hash re-adopts it (a differing spec conflicts,
        // but the re-adoption + ledger registration still happen).
        let _ = create_vm(state, spec(vm_id, &root));

        let entry = entry_snapshot(state, vm_id).expect("the VM was re-adopted");
        assert_eq!(entry.numa_node, Some(1), "the pin was reconstructed");
        assert_eq!(
            allocated(state, 1),
            2,
            "the re-adopted VM's vCPUs are counted exactly once"
        );
        assert_eq!(allocated(state, 0), 0);
    }

    #[test]
    fn readopt_restore_failure_releases_the_reservation_but_keeps_the_dropin() {
        // Regression: if readopt's network restore fails AFTER
        // reconstruct_numa_placement has registered the VM, the ledger
        // reservation must be released, or a retry's reconstruct (and a
        // restart's reconcile_numa_ledger) would double-count this still-running
        // VM. The drop-in must NOT be removed: the controller is still running
        // pinned to it; we only failed to re-adopt it into tracking.
        let harness = numa_harness();
        let state = &harness.state;
        let root = state.host.settings.execution_root.clone();
        let unit_dir = state.host.settings.systemd_unit_dir.clone();
        let vm_id = test_fixtures::QEMU_HASH;
        std::fs::copy(
            test_fixtures::fixtures_dir().join(format!("{vm_id}-controller.json")),
            root.join(format!("{vm_id}-controller.json")),
        )
        .unwrap();
        // Live controller pinned to node 1 (cpus 4-7); a 2-vCPU fixture.
        crate::numa::write_cpuset_dropin(&unit_dir, vm_id, "4-7").unwrap();
        harness
            .systemd
            .set_state(&controller_unit_name(vm_id), "active");
        // Fail the network restore that runs after placement is reconstructed.
        harness.taps.fail_create("injected tap failure");

        let _ = create_vm(state, spec(vm_id, &root));

        assert!(
            entry_snapshot(state, vm_id).is_none(),
            "the failed readopt leaves the VM untracked again"
        );
        assert_eq!(
            allocated(state, 1),
            0,
            "the reservation is released on the failed restore, so a retry cannot double-count it"
        );
        assert_eq!(allocated(state, 0), 0);
        assert_eq!(
            crate::numa::read_cpuset_dropin(&unit_dir, vm_id).as_deref(),
            Some("4-7"),
            "the still-running controller's drop-in must NOT be removed on a failed readopt"
        );
    }
}
