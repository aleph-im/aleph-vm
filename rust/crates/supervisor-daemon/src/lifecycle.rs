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
    self, VmConfiguration, WrittenControllerConfig, WrittenControllerSettings, WrittenGpu,
    WrittenHostVolume, WrittenQemuVmConfiguration, parse_controller_config,
};
use crate::service::DaemonState;
use crate::tap::TapAssignment;
use crate::units::{self, controller_unit_name};
use crate::world::{self, AttachedGpu, VmEntry, VmTimes, now_ns};
use crate::{checks, cloudinit, nft, ports};

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
    let mut world = state.world.blocking_write();
    let mut ordinal = world.ipv6_dynamic_ordinal;
    let (ipv4, ipv6) =
        world::derive_tap_assignment(&state.host.settings, entry.vm_index, vm_id, &mut ordinal)?;
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
                tracing::warn!(vm_id, error, "cannot delete the tap interface, continuing");
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
            state.taps.create_tap(&tap).map_err(RpcError::Internal)?;
            if let Some(ndp) = &state.ndp {
                ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, true)
                    .map_err(RpcError::Internal)?;
            }
        }
        // Even when the interface survived, the nftables rules may have
        // been flushed; always re-apply (create-if-absent).
        nft_setup_vm(state, entry.vm_index, &tap.device_name).map_err(RpcError::Internal)?;
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
    if entry_snapshot(state, vm_id).is_none() {
        return Err(RpcError::NotFound(vm_id.into()));
    }
    stop_vm_execution(state, vm_id)?;
    entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))
}

pub fn start_vm(state: &DaemonState, vm_id: &str) -> Result<(VmEntry, bool), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if unit_active(state, &entry.unit_name()) {
        return Ok((entry, true));
    }
    start_vm_execution(state, vm_id)?;
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let running = unit_active(state, &entry.unit_name());
    Ok((entry, running))
}

pub fn reboot_vm(state: &DaemonState, vm_id: &str) -> Result<(VmEntry, bool), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let unit = entry.unit_name();
    // RestartUnit only queues a job: wait until the unit is confirmed
    // active so the reported status is truthful.
    state.units.restart(&unit).map_err(RpcError::Internal)?;
    wait_for_controller_ready(state, &unit).map_err(RpcError::Internal)?;
    with_entry_mut(state, vm_id, |entry| entry.times.started_at_ns = now_ns());
    let entry = entry_snapshot(state, vm_id).ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let running = unit_active(state, &unit);
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
    stop_vm_execution(state, vm_id)?;
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
    if include_rootfs {
        let rootfs = std::path::Path::new(&entry.config.image_path);
        if rootfs.exists() {
            tracing::info!(path = %rootfs.display(), "deleting rootfs");
            std::fs::remove_file(rootfs).map_err(|error| {
                format!("cannot delete the rootfs {}: {error}", rootfs.display())
            })?;
        }
    }
    if include_data_volumes {
        for volume in &entry.config.host_volumes {
            if volume.read_only {
                continue;
            }
            tracing::info!(path = volume.path_on_host, "deleting volume");
            if let Err(error) = std::fs::remove_file(&volume.path_on_host)
                && error.kind() != std::io::ErrorKind::NotFound
            {
                return Err(format!(
                    "cannot delete the volume {}: {error}",
                    volume.path_on_host
                ));
            }
        }
    }
    Ok(())
}

pub fn delete_vm(
    state: &DaemonState,
    vm_id: &str,
    wipe: bool,
    keep_port_mappings: bool,
) -> Result<(), RpcError> {
    let lock = vm_lock(state, vm_id);
    let _guard = lock
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = &state.host.settings.execution_root;

    let Some(entry) = entry_snapshot(state, vm_id) else {
        // Python `discard_failed_reattach`: a VM the daemon never adopted
        // (hidden at boot) may still have a live controller and an on-disk
        // definition; honor the delete by stopping and removing both,
        // instead of letting NOT_FOUND leave an unmanageable instance.
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
        // Release the hidden VM's vm_index claim before the config goes.
        if let Ok(contents) = std::fs::read_to_string(&config_path)
            && let Ok(config) = parse_controller_config(&contents)
        {
            state
                .world
                .blocking_write()
                .reserved_vm_indices
                .remove(&config.vm_index);
        }
        controller_config::remove_controller_configuration(root, vm_id)
            .map_err(RpcError::Internal)?;
        return Ok(());
    };

    stop_vm_execution(state, vm_id)?;
    state.world.blocking_write().entries.remove(vm_id);
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
        .map(|entry| entry.config.mem_size_mb)
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
    let host_volumes = spec
        .disks
        .iter()
        .filter(|disk| disk.role == pb::disk_config::DiskRole::Extra as i32)
        .map(|disk| WrittenHostVolume {
            // The guest mount point never crosses the boundary; QemuVM
            // never consumed the field, written empty since the spec path.
            mount: String::new(),
            path_on_host: disk.path.clone(),
            read_only: disk.readonly,
        })
        .collect();
    let gpus = spec
        .gpus
        .iter()
        .map(|gpu| WrittenGpu {
            pci_host: gpu.pci_host.clone(),
            supports_x_vga: gpu.supports_x_vga,
        })
        .collect();
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
            cloud_init_drive_path: Some(
                root.join(format!("cloud-init-{vm_hash}.img"))
                    .to_string_lossy()
                    .into_owned(),
            ),
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
        },
        hypervisor: "qemu",
    })
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
                state.taps.create_tap(&tap)?;
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
        let mut world = state.world.blocking_write();
        if let Some(entry) = world.entries.remove(vm_id) {
            world.reserved_vm_indices.insert(entry.vm_index);
        }
        return Err(RpcError::Internal(error));
    }
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

pub fn create_vm(
    state: &DaemonState,
    mut request: pb::VmSpec,
) -> Result<(VmEntry, bool), RpcError> {
    normalize_spec_paths(&mut request);
    match request.backend() {
        pb::Backend::Qemu => {}
        pb::Backend::Firecracker => {
            return Err(RpcError::Unimplemented(
                "CreateVm for Firecracker programs is not implemented yet by the Rust \
                 supervisor daemon (increment 4 ports the ephemeral launcher)"
                    .to_string(),
            ));
        }
        pb::Backend::Unspecified => {
            // Python: BACKEND_FROM_PB[0] raises KeyError -> INTERNAL.
            return Err(RpcError::Internal(
                "unknown backend BACKEND_UNSPECIFIED".to_string(),
            ));
        }
    }
    if request.tee.is_some() {
        return Err(RpcError::Unimplemented(
            "CreateVm for confidential VMs is not implemented yet by the Rust supervisor \
             daemon (increment 6 ports the confidential mutations)"
                .to_string(),
        ));
    }
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

    // Idempotency on a live, tracked VM.
    if let Some(entry) = entry_snapshot(state, &vm_id)
        && unit_active(state, &entry.unit_name())
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
    let (vm_index, assignment, written) = {
        let mut world = state.world.blocking_write();
        // A stale stopped entry is replaced, like the Python
        // `self.executions[vm_id] = execution` overwrite; a dict overwrite
        // keeps the key's insertion position, so the ordinal survives.
        let stale_ordinal = world.entries.remove(&vm_id).map(|stale| stale.ordinal);
        let vm_index = world
            .unique_vm_index(state.host.settings.start_id_index)
            .map_err(RpcError::Internal)?;
        let assignment = if state.host.settings.allow_vm_networking {
            let mut ordinal = world.ipv6_dynamic_ordinal;
            let pair =
                world::derive_tap_assignment(&state.host.settings, vm_index, &vm_id, &mut ordinal)
                    .map_err(RpcError::Internal)?;
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
        };
        match stale_ordinal {
            Some(ordinal) => {
                entry.ordinal = ordinal;
                world.entries.insert(vm_id.clone(), entry);
            }
            None => world.insert_entry(entry),
        }
        (vm_index, assignment, written)
    };

    let tap = assignment.map(|(ipv4, ipv6)| TapAssignment::new(vm_index, ipv4, ipv6));

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
                state.taps.delete_tap(tap)?;
            }
            state.taps.create_tap(tap)?;
            if let Some(ndp) = &state.ndp {
                ndp.add_range(&tap.device_name, &tap.ipv6.network_cidr, true)?;
            }
            nft_setup_vm(state, vm_index, &tap.device_name)?;
        }

        // The cloud-init seed, then the controller config (same order as
        // build_qemu_configuration + save_controller_configuration).
        cloudinit::CloudInitDrive {
            execution_root: &state.host.settings.execution_root,
            vm_hash: &vm_id,
            vm_index,
            tap: tap.as_ref(),
            ssh_authorized_keys: &ssh_authorized_keys,
            hostname: &request.hostname,
            has_gpu: !request.gpus.is_empty(),
            dns_nameservers: state.host.dns_nameservers.as_deref(),
        }
        .create_image()?;
        controller_config::save_controller_config(&state.host.settings.execution_root, &written)?;

        with_entry_mut(state, &vm_id, |entry| entry.times.starting_at_ns = now_ns());
        let unit = controller_unit_name(&vm_id);
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
            nft_teardown_vm(state, vm_index);
            std::thread::sleep(state.pacing.tap_delete_delay);
            if let Some(ndp) = &state.ndp
                && let Err(ndp_error) = ndp.delete_range(&tap.device_name, true)
            {
                tracing::warn!(ndp_error, "failed to drop the ndp range during cleanup");
            }
            if let Err(delete_error) = state.taps.delete_tap(tap) {
                tracing::warn!(delete_error, "failed to delete the tap during cleanup");
            }
        }
        state.world.blocking_write().entries.remove(&vm_id);
        return Err(RpcError::Internal(error));
    }

    let entry = entry_snapshot(state, &vm_id).ok_or_else(|| RpcError::NotFound(vm_id.clone()))?;
    let running = unit_active(state, &entry.unit_name());
    Ok((entry, running))
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
    let running: Vec<&VmEntry> = entries
        .iter()
        .filter(|entry| {
            states.get(&entry.unit_name()).copied().unwrap_or(false)
                && entry.ipv4.is_some()
                && networking_enabled(state, entry)
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
            nft::run_commands_logged(&*state.nft, &commands);
            removed_chains.push(chain.clone());
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

    // Step 5: reapply persisted port redirects (instances only; every
    // adopted VM is one). Failures only log, like Python.
    for entry in &running {
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
                    state.taps.create_tap(&tap)?;
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
            }
        }
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
        nft: Arc<nft::StaticRuleset>,
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
        let nft_executor = Arc::new(nft::StaticRuleset::new(ruleset));
        let mut state = crate::service::DaemonState::hermetic(
            host,
            world::WorldView::default(),
            systemd.clone(),
            Arc::new(StaticLogSource::default()),
        );
        state.nft = nft_executor.clone();
        state.taps = taps.clone();
        Harness {
            state: Arc::new(state),
            systemd,
            taps,
            nft: nft_executor,
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
        assert_eq!(qemu.mem_size_mb, 256);

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
}
