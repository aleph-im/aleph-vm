//! The Supervisor gRPC service (the full contract, increments 1-6).
//!
//! Health, GetHostInfo, GetVm, GetVmSpec, ListVms, ListPortForwards and
//! GetLogs are field-for-field ports of the Python LocalSupervisor
//! as observed after a daemon restart:
//! the pool state is the world view rebuilt from disk/systemd/sqlite
//! (src/world.rs), unit liveness is queried live per RPC like
//! `_is_running`/`_running_states`, and the VmSpec served for an adopted VM
//! is the `spec_from_controller_configuration` reconstruction the restarted
//! Python daemon holds. The lifecycle mutations live in src/lifecycle.rs, guest
//! quiescence in src/quiesce.rs and the confidential mutations in
//! src/confidential.rs; all run on the blocking pool. The only remaining
//! UNIMPLEMENTED path is a persistent Firecracker CreateVm,
//! which aborts the Python way (grpc-status UNIMPLEMENTED plus a serialized
//! ErrorDetail, wire code INTERNAL, in the `aleph-supervisor-error-bin`
//! trailer; the Python client keys the exception type on the status code).

use std::collections::{HashMap, HashSet};
use std::pin::Pin;
use std::sync::Arc;

use prost::Message;
use supervisor_proto::ERROR_TRAILER_KEY;
use supervisor_proto::pb;
use supervisor_proto::pb::supervisor_server::Supervisor;
use tokio_stream::{Stream, StreamExt};
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Code, Request, Response, Status};

use crate::config::Settings;
use crate::error::DaemonError;
use crate::logs::{LogSource, LogStream};
use crate::lspci::GpuDevice;
use crate::units::{UnitLiveness, UnitStateSource};
use crate::world::{VmEntry, VmTimes, WorldView, now_ns};
use crate::{host, lspci, net};

/// AMDSEVPolicy.SEV_ES: the policy bit that upgrades a SEV launch to
/// SEV-ES (the Python `_confidential_mode` reads the same bit).
const SEV_ES_POLICY_BIT: u32 = 0x4;

/// Host facts resolved once at daemon startup, exactly when the Python
/// daemon resolves them: host_ipv4 at Network construction (pool.__init__),
/// the GPU inventory in pool.setup(), DNS in settings.setup(). A failure
/// aborts startup, as it does in Python.
#[derive(Debug, Clone)]
pub struct HostState {
    pub settings: Settings,
    /// Primary IPv4 of the external interface; empty when host networking is
    /// disabled (ALLOW_VM_NETWORKING=false, where the Python pool has no
    /// Network object).
    pub host_ipv4: String,
    /// The resolved external interface name, `settings.NETWORK_INTERFACE`
    /// after conf.py setup(); None only when host networking is off and no
    /// default route exists.
    pub network_interface: Option<String>,
    /// Raw lspci inventory; empty unless ENABLE_GPU_SUPPORT is set.
    pub gpus: Vec<GpuDevice>,
    /// conf.py DNS_NAMESERVERS after setup(): the configured list, or the
    /// resolver-derived one; feeds the cloud-init network config.
    pub dns_nameservers: Option<Vec<String>>,
}

impl HostState {
    pub fn initialize(settings: Settings) -> Result<Self, DaemonError> {
        // conf.py setup(): NETWORK_INTERFACE defaults to the default-route
        // interface, resolved regardless of ALLOW_VM_NETWORKING (DNS
        // detection uses it too); only host_ipv4 requires it to exist.
        let network_interface = match &settings.network_interface {
            Some(name) => Some(name.clone()),
            None => net::default_interface()?,
        };
        let host_ipv4 = if settings.allow_vm_networking {
            let interface = network_interface
                .as_deref()
                .ok_or(DaemonError::NoNetworkInterface)?;
            let address = net::get_interface_ipv4(interface)?;
            tracing::info!(interface, address, "resolved host IPv4");
            address
        } else {
            String::new()
        };

        // conf.py setup(): DNS_NAMESERVERS resolves through DNS_RESOLUTION
        // when unset; a failure aborts startup, like the Python setup().
        let dns_nameservers = match (&settings.dns_nameservers, &network_interface) {
            (Some(configured), _) => Some(configured.clone()),
            (None, Some(interface)) => {
                Some(net::obtain_dns_ips(settings.dns_resolution, interface)?)
            }
            (None, None) => None,
        };

        let gpus = if settings.enable_gpu_support {
            let gpus = lspci::get_gpu_devices()?;
            tracing::info!(count = gpus.len(), "detected vfio-bound GPU devices");
            gpus
        } else {
            Vec::new()
        };

        Ok(Self {
            settings,
            host_ipv4,
            network_interface,
            gpus,
            dns_nameservers,
        })
    }
}

/// Everything the RPC handlers read: the boot-time host facts, the world
/// view, and the host-dependency seams (systemd, journald, nftables, tap
/// devices, ndppd).
pub struct DaemonState {
    pub host: HostState,
    pub world: tokio::sync::RwLock<WorldView>,
    pub units: Arc<dyn UnitStateSource>,
    pub logs: Arc<dyn LogSource>,
    pub nft: Arc<dyn crate::nft::NftExecutor>,
    pub taps: Arc<dyn crate::tap::TapBackend>,
    /// Per-tap DHCP for SEV-SNP measured VMs: the measured image DHCPs
    /// (nix/init.sh udhcpc) and its
    /// cmdline omits `ip=` for measurement determinism, so the daemon serves
    /// the guest its allocated IPv4 over a single-address dnsmasq on the tap.
    /// Only the SNP path uses this; plain and SEV VMs keep cloud-init static
    /// config.
    pub dhcp: Arc<dyn crate::dhcp::DhcpBackend>,
    /// Present when host networking and USE_NDP_PROXY are both on, like the
    /// Python `Network.ndp_proxy`.
    pub ndp: Option<Arc<crate::ndppd::NdpProxy>>,
    /// The fast host-port allocation cursor (Python module global).
    pub port_cursor: crate::ports::PortCursor,
    /// Python `pool.creation_lock`: one create at a time, held across the
    /// whole boot wait.
    pub creation_lock: std::sync::Mutex<()>,
    /// Per-VM mutation locks (the Python per-execution lock granularity).
    pub vm_locks: std::sync::Mutex<HashMap<String, Arc<std::sync::Mutex<()>>>>,
    /// One coarse lock over every host-network mutation: host-port
    /// allocation-through-persistence (two concurrent AddPortForwards for
    /// different VMs must never both allocate the same host_port and leave
    /// a live DNAT rule behind when the loser's DB save hits the partial
    /// unique index), tap/nftables setup and teardown, and RecreateNetwork's
    /// flush-and-rebuild (which must never race a create/start's chain
    /// setup). Python needs none of this: its event loop serializes these
    /// sections between awaits. Lock order: creation_lock, then a vm_lock,
    /// then net_lock; net_lock is innermost and never held while acquiring
    /// the others, and never held across the long systemd waits.
    pub net_lock: std::sync::Mutex<()>,
    /// Poll/sleep pacing for the lifecycle waits; tests shrink it.
    pub pacing: crate::lifecycle::Pacing,
    /// Lifecycle event fan-out behind WatchEvents (the Python
    /// `_event_queues` set).
    pub events: crate::events::EventHub,
    /// The ephemeral Firecracker launcher (increment 4): programs are
    /// direct children of the daemon, spawned and reaped through this seam.
    pub programs: Arc<dyn crate::firecracker::ProgramLauncher>,
    /// Bounds concurrent StreamLogs follows. Each live follow pins one
    /// blocking-pool thread for its whole lifetime; unbounded, ~512
    /// concurrent follows would exhaust tokio's blocking pool and starve
    /// every lifecycle RPC that hops through spawn_blocking. The cap stays
    /// far below the pool size; the excess request is rejected
    /// RESOURCE_EXHAUSTED. Python, one asyncio task per stream, accepts
    /// follows unboundedly and has no such thread to run out of.
    pub log_follows: Arc<tokio::sync::Semaphore>,
    /// Guests frozen through FreezeGuest (the Python `_frozen_guests`),
    /// each with the QGA socket that froze it and the generation its
    /// auto-thaw timer was armed with.
    pub frozen_guests: crate::quiesce::FrozenGuests,
    /// Host NUMA topology detected once at startup, reported in
    /// `HostInfo.numa_nodes` (Phase 3 increment C1). Empty when detection
    /// was unavailable, which makes NUMA placement inert.
    pub numa: crate::numa::NumaTopology,
    /// The supervisor-side pack-first placement ledger: per-node vCPU
    /// tracking for `AllowedCPUs` pinning. In-memory; rebuilt at boot from
    /// each adopted VM's effective placement (its `AllowedCPUs` drop-in).
    pub numa_ledger: std::sync::Mutex<crate::numa::NumaAllocator>,
    /// The last CC mode probe of each card, keyed by pci_host. Populated
    /// at startup and by `refresh_cc_modes` (called from `get_host_info`)
    /// for every NVIDIA card no VM currently owns, and by the SEV-SNP GPU
    /// gate when a create probes its cards. A card an adopted confidential
    /// VM owns is entered as CC-on without a read, on the gate's word. A
    /// card never probed has no entry; a card whose last probe failed has
    /// an entry with no mode, which advertises nothing and holds the retry
    /// off until the entry goes stale, which happens sooner than it does
    /// for a decoded mode (see `gpu_cc::CcCacheWindows`).
    pub gpu_cc_modes: std::sync::Mutex<HashMap<String, crate::gpu_cc::ProbedCcMode>>,
    /// How a card's CC mode is read: the BAR0 register in production,
    /// `gpu_cc::no_probe` on hermetic state so tests never open sysfs.
    pub gpu_cc_probe: crate::gpu_cc::CcProbe,
    /// What the last CC-mode sweep ran against and when, so `GetHostInfo`
    /// (reachable from the public `/about` endpoints) cannot drive an
    /// unbounded rate of register reads: see `refresh_cc_modes`.
    pub gpu_cc_sweep: std::sync::Mutex<CcSweep>,
    /// Held for the length of one CC mode refresh pass, so a burst of
    /// GetHostInfo calls costs one pass and the callers behind it read
    /// what it wrote. Two passes running at once would also corrupt the
    /// host's runtime-PM setting: both can read `power/control` before
    /// either writes it, and the second would then restore "on".
    pub gpu_cc_refresh: std::sync::Mutex<()>,
}

/// The attached set the last CC-mode sweep saw, and when it ran. A sweep
/// against an unchanged set within the shortest of the cache windows
/// (`gpu_cc::CcCacheWindows::shortest`) is skipped whole, which is the
/// cheap outer gate over the per-card freshness check inside. It is the
/// shortest window and not the longest because one decision covers every
/// card here, so it must not outlive the tier of the card that ages out
/// first.
#[derive(Debug, Default)]
pub struct CcSweep {
    pub attached: HashSet<String>,
    pub at: Option<std::time::Instant>,
}

/// See [`DaemonState::log_follows`].
pub const MAX_CONCURRENT_LOG_FOLLOWS: usize = 64;

impl DaemonState {
    /// State over hermetic in-memory seams: unit tests and callers that
    /// override individual seams afterwards.
    pub fn hermetic(
        host: HostState,
        world: WorldView,
        units: Arc<dyn UnitStateSource>,
        logs: Arc<dyn LogSource>,
    ) -> Self {
        Self {
            host,
            world: tokio::sync::RwLock::new(world),
            units,
            logs,
            nft: Arc::new(crate::nft::StaticRuleset::default()),
            taps: Arc::new(crate::tap::FakeTapBackend::new()),
            dhcp: Arc::new(crate::dhcp::FakeDhcpBackend::new()),
            ndp: None,
            port_cursor: crate::ports::PortCursor::default(),
            creation_lock: std::sync::Mutex::new(()),
            vm_locks: std::sync::Mutex::new(HashMap::new()),
            net_lock: std::sync::Mutex::new(()),
            pacing: crate::lifecycle::Pacing::instant(),
            events: crate::events::EventHub::default(),
            programs: Arc::new(crate::firecracker::FakeProgramLauncher::new()),
            log_follows: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LOG_FOLLOWS)),
            frozen_guests: crate::quiesce::FrozenGuests::default(),
            // No NUMA topology by default: placement is inert unless a test
            // installs one (via `with_numa_topology`).
            numa: crate::numa::NumaTopology::empty(),
            numa_ledger: std::sync::Mutex::new(crate::numa::NumaAllocator::new(
                crate::numa::NumaTopology::empty(),
            )),
            gpu_cc_modes: std::sync::Mutex::new(HashMap::new()),
            gpu_cc_probe: crate::gpu_cc::no_probe,
            gpu_cc_sweep: std::sync::Mutex::new(CcSweep::default()),
            gpu_cc_refresh: std::sync::Mutex::new(()),
        }
    }

    /// Install a NUMA topology on hermetic test state: sets both the
    /// reported topology and a fresh pack-first ledger over it.
    #[cfg(test)]
    pub fn with_numa_topology(&mut self, topology: crate::numa::NumaTopology) {
        self.numa_ledger = std::sync::Mutex::new(crate::numa::NumaAllocator::new(topology.clone()));
        self.numa = topology;
    }
}

/// Map a detected NUMA topology to the proto `NumaNode` list reported by
/// `GetHostInfo` (increment C1): node id -> index, cpu count -> cpu_count,
/// RAM MB -> memory_mib. Empty when detection was unavailable, as before C1.
fn numa_nodes_proto(topology: &crate::numa::NumaTopology) -> Vec<pb::NumaNode> {
    topology
        .nodes
        .iter()
        .map(|node| pb::NumaNode {
            index: node.id,
            cpu_count: node.cpus.len() as u32,
            memory_mib: node.total_ram_mb,
        })
        .collect()
}

pub struct SupervisorService {
    state: Arc<DaemonState>,
}

impl SupervisorService {
    pub fn new(state: Arc<DaemonState>) -> Self {
        Self { state }
    }

    async fn host_info(&self) -> Result<pb::HostInfo, DaemonError> {
        let (kernel_version, hostname) = host::uname_release_and_nodename()?;
        // Available = inventory minus the GPUs the world view's controller
        // configs attach. Post-#1023 Python rebuilds the attachments for
        // VMs adopted running; the config union here also withholds
        // adopted-STOPPED VMs' cards, which Python destroys at startup and
        // this daemon keeps. Reporting an attached card as available is how
        // a restart invites a double attachment.
        let attached: HashSet<String> = {
            let world = self.state.world.read().await;
            attached_gpus(&world)
                .map(|(pci_host, _)| pci_host.to_string())
                .collect()
        };
        // Refresh every unattached NVIDIA card whose CC mode has gone
        // stale before reporting the inventory, so a freshly-idled card's
        // mode is current. Cards answered within the freshness window are
        // served from the cache and not read at all, which matters because
        // the agent calls this for every unauthenticated capability
        // request. mmap of a BAR is a blocking syscall; run it off the
        // tokio worker.
        // refresh_cc_modes takes its own world read guard and keeps it for
        // the whole probe: the `attached` snapshot above can go stale the
        // moment a concurrent CreateVm registers a card, and the probe gate
        // must never trust a snapshot it no longer holds the lock for. It
        // also skips the sweep when nothing changed hands within the
        // freshness window, and reads no card whose own answer is still
        // fresh, so a public poller cannot turn every request into a
        // register read.
        {
            let state = self.state.clone();
            tokio::task::spawn_blocking(move || refresh_cc_modes(&state))
                .await
                .map_err(|error| {
                    DaemonError::Internal(format!("the GPU CC probe task failed: {error}"))
                })?;
        }
        let annotated_gpus: Vec<GpuDevice> = self
            .state
            .host
            .gpus
            .iter()
            .cloned()
            .map(|mut gpu| {
                gpu.cc_mode = cc_mode_of(&self.state, &gpu.pci_host);
                gpu.arch = crate::gpu_cc::arch_from_device_id(&gpu.device_id);
                gpu
            })
            .collect();
        let inventory_json = gpu_json(&annotated_gpus)?;
        let available: Vec<&GpuDevice> = annotated_gpus
            .iter()
            .filter(|gpu| !attached.contains(&gpu.pci_host))
            .collect();
        let available_json = serde_json::to_string(&available).map_err(|error| {
            DaemonError::Internal(format!("GPU inventory serialization failed: {error}"))
        })?;
        // statvfs can block indefinitely on a hung backing device; run it on
        // the blocking pool so it cannot pin a tokio worker and take Health
        // down with it. The /proc/meminfo and uname reads stay inline: they
        // are instant in-kernel lookups.
        //
        // Python parity for VMs: calculate_available_disk adds each
        // execution's get_disk_usage_delta, which is 0 for every adopted
        // (spec-built, message-free) execution, so free space alone is
        // still the exact post-restart figure.
        let volume_pools = self.state.host.settings.all_volume_pools();
        let available_disk_bytes =
            tokio::task::spawn_blocking(move || host::available_disk_bytes_pooled(&volume_pools))
                .await
                .map_err(|error| {
                    DaemonError::Internal(format!("the statvfs task failed: {error}"))
                })?;
        // NUMA topology (increment C1): one proto NumaNode per detected node.
        // Empty when detection was unavailable, as it was before C1.
        let numa_nodes = numa_nodes_proto(&self.state.numa);
        Ok(pb::HostInfo {
            // Only the fields LocalSupervisor.get_host_info fills, plus
            // sev_snp_supported (increment B1, the SNP host capability check)
            // and numa_nodes (increment C1); the rest keep their proto
            // defaults, exactly like the Python HostInfo dataclass defaults
            // (cpu_architecture, cpu_vendor, cpu_model, frequencies, memory
            // type, the narrow gpus list and the remaining SEV/TDX flags
            // still ride empty).
            cpu_count: host::cpu_count(),
            memory_mib: host::memory_total_mib()?,
            kernel_version,
            hostname,
            host_ipv4: self.state.host.host_ipv4.clone(),
            available_disk_bytes,
            gpu_inventory_json: inventory_json,
            available_gpus_json: available_json,
            sev_snp_supported: crate::checks::check_amd_sev_snp_supported(),
            numa_nodes,
            ..Default::default()
        })
    }

    /// The VmInfo a mutation RPC answers with. The mutation settled the
    /// unit itself (started it and waited for it to be ready, stopped it,
    /// or deliberately left it down until the owner uploads the session
    /// certificates), so it hands the mapping no unit observation: a fresh
    /// query would only repeat what the path already knows, and spontaneous
    /// death is what the read paths (GetVm, ListVms) are there to notice.
    fn mutated_vm_info(&self, entry: &VmEntry, running: bool) -> pb::VmInfo {
        vm_info_message(&self.state, entry, running, UnitLiveness::Unknown, now_ns())
    }

    /// Live state of one entry's controller unit, off the runtime threads
    /// (the Python `_is_running` D-Bus query equivalent). A bus failure
    /// degrades to `Unknown`: it stays "not running" like the Python
    /// `get_services_active_states` parity behavior, and
    /// it must never read as death, which is a claim only an answering bus
    /// can support.
    async fn unit_liveness(&self, unit: String) -> Result<UnitLiveness, Status> {
        let units = self.state.units.clone();
        tokio::task::spawn_blocking(
            move || match units.unit_states(std::slice::from_ref(&unit)) {
                Ok(states) => states.get(&unit).copied().unwrap_or(UnitLiveness::Unknown),
                Err(error) => {
                    tracing::error!(%error, "Failed to get services active states");
                    UnitLiveness::Unknown
                }
            },
        )
        .await
        .map_err(|error| {
            internal_status(DaemonError::Internal(format!(
                "the unit-state task failed: {error}"
            )))
        })
    }

    /// Live states for every entry, one batched query (the Python
    /// `_running_states` ListUnits call, pushed off the loop like
    /// `asyncio.to_thread` in list_vms). Bus failures degrade to
    /// all-`Unknown`, for the reason in [`Self::unit_liveness`].
    async fn units_liveness(
        &self,
        unit_names: Vec<String>,
    ) -> Result<HashMap<String, UnitLiveness>, Status> {
        let units = self.state.units.clone();
        tokio::task::spawn_blocking(move || match units.unit_states(&unit_names) {
            Ok(states) => states,
            Err(error) => {
                tracing::error!(%error, "Failed to get services active states");
                unit_names
                    .iter()
                    .map(|unit| (unit.clone(), UnitLiveness::Unknown))
                    .collect()
            }
        })
        .await
        .map_err(|error| {
            internal_status(DaemonError::Internal(format!(
                "the unit-state task failed: {error}"
            )))
        })
    }
}

fn gpu_json(gpus: &[GpuDevice]) -> Result<String, DaemonError> {
    serde_json::to_string(gpus).map_err(|error| {
        DaemonError::Internal(format!("GPU inventory serialization failed: {error}"))
    })
}

/// Every GPU the world view's controller configs attach, each paired with
/// whether a live confidential guest vouches for its CC mode. Two callers
/// need the same walk: the inventory subtracts these cards from what it
/// advertises as available, and the CC refresh skips them, taking the
/// create gate's answer for the vouched ones.
///
/// The flag needs the VM to be confidential AND live, a start with no stop
/// after it. A stopped VM's QEMU is gone, so its card is idle hardware an
/// operator can re-mode and the gate's reading no longer holds; the card is
/// still attached, so it is still subtracted and still never read. "Live"
/// is not just the absence of a stop: an entry that was never started (a
/// Defined one, or one adopted while the systemd bus was unreachable, where
/// no stage timestamp but defined_at is set) has no guest holding its card
/// either, and the adopted case is precisely where the daemon cannot tell
/// whether the guest is alive.
fn attached_gpus(world: &WorldView) -> impl Iterator<Item = (&str, bool)> {
    world.entries.values().flat_map(|entry| {
        let live = entry.times.started_at_ns != 0 && entry.times.stopped_at_ns == 0;
        let vouched_cc_on = entry.config.snp().is_some() && live;
        entry
            .config
            .gpus
            .iter()
            .map(move |gpu| (gpu.pci_host.as_str(), vouched_cc_on))
    })
}

/// The cached CC mode of one card, if it has been probed successfully.
pub fn cc_mode_of(state: &DaemonState, pci_host: &str) -> Option<crate::gpu_cc::CcMode> {
    state
        .gpu_cc_modes
        .lock()
        .expect("gpu_cc_modes poisoned")
        .get(pci_host)
        .and_then(|probed| probed.mode)
}

/// Probe every NVIDIA card no VM owns whose last answer has gone stale, and
/// remember what it said. A card that becomes attached keeps its last value
/// (the register is never read under a guest). A probe that errors, or that
/// reads a register encoding with no mode, replaces the card's answer with
/// "no mode": whatever it advertised before is no longer known to be true,
/// and an unknown card advertises nothing. A card a confidential guest owns
/// gets its mode from the create gate that admitted it, with no read at
/// all. Runs on the blocking pool: mmap of a BAR is a syscall against
/// device memory.
pub fn refresh_cc_modes(state: &DaemonState) {
    let windows = crate::gpu_cc::CcCacheWindows::with_mode_ttl(std::time::Duration::from_secs(
        state.host.settings.gpu_cc_mode_ttl,
    ));
    refresh_cc_modes_with(state, state.gpu_cc_probe, windows);
}

/// `refresh_cc_modes` over an explicit probe and explicit cache windows, so
/// unit tests can hand in a closure that records what was probed and decide
/// whether the last sweep and each card's last answer count as fresh.
///
/// One pass at a time. The pass lock is taken before the world guard (a
/// waiter must not sit on a read guard), so a burst of GetHostInfo calls
/// costs one pass and the callers behind it find the entries it wrote.
/// Overlapping passes would be worse than wasteful: both can read
/// `power/control` before either writes it, and the second would then
/// remember "on" as the value to put back, pinning the card awake for
/// good.
///
/// The world read guard is held across the whole loop, not just while the
/// attached set is collected: CreateVm registers a VM's cards in the world
/// view under the write lock before it boots anything, so under this guard
/// a card is either already attached (and skipped) or cannot become
/// attached until the probe is done. That is what makes "never read under
/// a guest" hold rather than merely likely, and it is why the probes
/// cannot be moved outside the guard.
///
/// The guard is not cheap to hold any more: resuming a runtime-suspended
/// card costs up to the 200 ms resume budget, so a pass can hold it for
/// (stale suspended cards) x 200 ms, and tokio's RwLock is
/// write-preferring, so a CreateVm arriving mid-pass waits that long. What
/// keeps that off the hot path is the freshness window below: a given card
/// is read at most once per the window its own last answer falls under,
/// whatever the request rate.
///
/// Two gates, over different windows. The outer one skips the sweep whole
/// when it last ran against the same attached set less than
/// `windows.shortest()` ago. It is one decision for every card at once, so
/// it cannot be allowed to outlive the shortest tier any of them is held
/// under: gated on the long window instead, a card cached as unreadable
/// would sit behind the pass gate for an hour, and the short tier that is
/// meant to bring it back within the minute would never be reached. The
/// inner one skips any single card whose own last answer is fresh under
/// its own tier, and that is where the long window for a decoded mode
/// actually pays. Walking the cache to check every entry against its own
/// tier before skipping the pass would be equally correct and buy nothing
/// back, since the per-card gate walks the same cards anyway; the price of
/// the short outer gate is one walk over the inventory with no register
/// reads per short window. Host info is served on an unauthenticated path,
/// and reading device memory once per request is both a needless cost and
/// a lever an outsider gets to pull; both windows bound that the same way,
/// and the mode itself only changes when an operator runs NVIDIA's tool
/// against an idle card, which no request can do. Neither the create gate
/// nor the start comes through here: both always read the card.
fn refresh_cc_modes_with(
    state: &DaemonState,
    probe: impl Fn(&str, &str) -> Result<Option<crate::gpu_cc::CcMode>, DaemonError>,
    windows: crate::gpu_cc::CcCacheWindows,
) {
    let _pass = state
        .gpu_cc_refresh
        .lock()
        .expect("gpu_cc_refresh poisoned");
    let world = state.world.blocking_read();
    let mut attached: HashSet<String> = HashSet::new();
    // The subset a live confidential guest owns. Those cards have a known
    // mode without any read: a card enters an SEV-SNP VM only after the
    // create gate or the start has read CC-on from it, and the mode cannot
    // change while the guest holds the card (switching it takes a reset of a
    // free card).
    // A daemon that adopts such a VM at boot has an empty cache and will
    // never probe the card, so without this its mode would stay empty for
    // the VM's whole life. Plain passthrough VMs went through no gate and
    // get nothing.
    //
    // A stopped VM gets nothing either, even an SEV-SNP one: its QEMU is
    // gone, so the card is idle hardware an operator can re-mode, and the
    // gate's word about it has expired. The card stays out of the sweep
    // (it is still in `attached`, the config still claims it), and the
    // stop itself dropped whatever the cache held about it, so a stopped
    // VM's card advertises nothing until it is started again or the VM is
    // deleted and the card is read as free. The start is what re-reads the
    // hardware and seeds the cache, under the same rule the create gate
    // applies; the seed below only ever restates an answer the start
    // already took from the card, for as long as the guest holds it.
    //
    // What counts as live is `attached_gpus`'s rule: a start with no stop
    // after it, so a never-started or bus-unreachable adopted entry is not
    // seeded either.
    let mut known_cc_on: HashSet<String> = HashSet::new();
    for (pci_host, vouched_cc_on) in attached_gpus(&world) {
        attached.insert(pci_host.to_string());
        if vouched_cc_on {
            known_cc_on.insert(pci_host.to_string());
        }
    }
    {
        let sweep = state.gpu_cc_sweep.lock().expect("gpu_cc_sweep poisoned");
        if let Some(at) = sweep.at
            && sweep.attached == attached
            && at.elapsed() < windows.shortest()
        {
            // Nothing changed hands since that sweep, so it already seeded
            // every confidential VM's cards and read every free one, and no
            // card's answer can have aged out of even the shortest window
            // in between.
            return;
        }
    }
    for gpu in &state.host.gpus {
        if gpu.vendor != "NVIDIA" {
            continue;
        }
        if attached.contains(&gpu.pci_host) {
            if known_cc_on.contains(&gpu.pci_host) {
                state
                    .gpu_cc_modes
                    .lock()
                    .expect("gpu_cc_modes poisoned")
                    .entry(gpu.pci_host.clone())
                    .or_insert_with(|| {
                        crate::gpu_cc::ProbedCcMode::now(Some(crate::gpu_cc::CcMode::On))
                    });
            }
            continue;
        }
        let fresh = state
            .gpu_cc_modes
            .lock()
            .expect("gpu_cc_modes poisoned")
            .get(&gpu.pci_host)
            .is_some_and(|probed| probed.is_fresh(windows));
        if fresh {
            continue;
        }
        let mode = match probe(&gpu.pci_host, &gpu.device_id) {
            Ok(mode) => mode,
            Err(error) => {
                tracing::warn!(pci_host = %gpu.pci_host, %error, "GPU CC mode probe failed");
                None
            }
        };
        state
            .gpu_cc_modes
            .lock()
            .expect("gpu_cc_modes poisoned")
            .insert(gpu.pci_host.clone(), crate::gpu_cc::ProbedCcMode::now(mode));
    }
    let mut sweep = state.gpu_cc_sweep.lock().expect("gpu_cc_sweep poisoned");
    sweep.attached = attached;
    sweep.at = Some(std::time::Instant::now());
}

// ── World view to wire mapping ──────────────────────────────────────────

/// `_status_of`: the times short-circuit the live flag, plus the FAILED arm
/// the Python daemon never had.
///
/// `unit` is what systemd last said about the VM's controller, and it is
/// only ever [`UnitLiveness::Dead`] when the daemon positively observed the
/// unit down; every caller that cannot judge (an ephemeral program runs no
/// unit, a confidential VM waits for its owner's session before one is
/// started, the bus did not answer) passes `Unknown`. A VM the daemon has
/// seen alive (`started_at_ns` is stamped once the controller is confirmed
/// ready, and at adoption for a VM already running) whose unit is now down
/// without anyone stopping it is a guest that died on its own: reporting it
/// BOOTING for ever, as the port did, leaves the agent's reconciler holding
/// it live and never rebuilding it.
pub(crate) fn vm_status(times: &VmTimes, running: bool, unit: UnitLiveness) -> pb::VmStatus {
    if times.stopped_at_ns != 0 {
        pb::VmStatus::Stopped
    } else if times.stopping_at_ns != 0 {
        pb::VmStatus::Stopping
    } else if running {
        pb::VmStatus::Running
    } else if times.started_at_ns != 0 && unit == UnitLiveness::Dead {
        pb::VmStatus::Failed
    } else if times.starting_at_ns != 0 {
        pb::VmStatus::Booting
    } else {
        pb::VmStatus::Defined
    }
}

/// `is_awaiting_confidential_init`, ported literally: confidential (SEV /
/// SEV-ES only, via the session/godh slot), persistent (every adopted VM
/// is), started but neither stopping nor observed running. SNP has no
/// session handshake, so it is never awaiting: it starts at create.
pub(crate) fn awaiting_confidential_init(entry: &VmEntry, running: bool) -> bool {
    entry.config.confidential().is_some()
        && entry.times.started_at_ns != 0
        && entry.times.stopping_at_ns == 0
        && !running
}

/// What an observed unit state says about `entry`'s guest.
///
/// Three kinds of VM have a down unit for a reason of their own, and reading
/// death into it would condemn a healthy VM. An ephemeral program runs under
/// no controller unit at all. A SEV / SEV-ES VM's controller is deliberately
/// held down until its owner uploads the session certificates. And a VM in
/// the middle of a reboot has a restart job in flight, which takes the unit
/// down and back up with nothing stamped in between. All three report
/// `Unknown`, which leaves the status exactly where it was before the dead
/// unit arm existed.
///
/// The session blindness has a cost: a SEV / SEV-ES guest that dies after
/// its session was uploaded is still not reported FAILED, because nothing
/// distinguishes that from a VM that never got its session. SEV-SNP, which
/// has no session and boots at create, is judged like any other VM.
pub(crate) fn guest_liveness(entry: &VmEntry, unit: UnitLiveness) -> UnitLiveness {
    if entry.is_program || entry.restarting || awaiting_confidential_init(entry, unit.is_active()) {
        UnitLiveness::Unknown
    } else {
        unit
    }
}

/// `_to_vm_info` for an adopted execution.
pub fn vm_info_message(
    state: &DaemonState,
    entry: &VmEntry,
    running: bool,
    unit: UnitLiveness,
    now_ns: u64,
) -> pb::VmInfo {
    let times = &entry.times;
    // `_uptime_secs`: seconds since started_at while running, else 0.
    let uptime_secs = if running && times.started_at_ns != 0 {
        now_ns.saturating_sub(times.started_at_ns) / 1_000_000_000
    } else {
        0
    };
    let confidential = entry.config.confidential();
    let snp = entry.config.snp();
    let confidential_mode = if snp.is_some() {
        pb::ConfidentialMode::SevSnp
    } else {
        match &confidential {
            None => pb::ConfidentialMode::None,
            Some(config) if config.sev_policy & SEV_ES_POLICY_BIT != 0 => {
                pb::ConfidentialMode::SevEs
            }
            Some(_) => pb::ConfidentialMode::Sev,
        }
    };
    let awaiting_confidential_init = awaiting_confidential_init(entry, running);
    let ip = |pair: &Option<crate::world::IpPair>| {
        pair.as_ref()
            .map(|pair| pb::IpAssignment {
                address: pair.address.clone(),
                network_cidr: pair.network_cidr.clone(),
                gateway: pair.gateway.clone(),
            })
            .unwrap_or_default()
    };
    // `_backend_of`: the VMM only (FIRECRACKER for programs, QEMU
    // otherwise); confidential computing rides confidential_mode.
    let backend = if entry.is_program {
        pb::Backend::Firecracker
    } else {
        pb::Backend::Qemu
    };
    pb::VmInfo {
        vm_id: entry.vm_hash.clone(),
        status: vm_status(times, running, guest_liveness(entry, unit)) as i32,
        ipv4: Some(ip(&entry.ipv4)),
        ipv6: Some(ip(&entry.ipv6)),
        uptime_secs,
        backend: backend as i32,
        // Effective NUMA placement (increment C1): the node the supervisor
        // pinned this VM to, or None when placement is inert/unpinned.
        numa_node: entry.numa_node,
        status_message: String::new(),
        defined_at_ns: times.defined_at_ns,
        preparing_at_ns: times.preparing_at_ns,
        prepared_at_ns: times.prepared_at_ns,
        starting_at_ns: times.starting_at_ns,
        started_at_ns: times.started_at_ns,
        stopping_at_ns: times.stopping_at_ns,
        stopped_at_ns: times.stopped_at_ns,
        confidential_mode: confidential_mode as i32,
        // `_to_vm_info` maps execution.gpus: rebuilt at adoption for
        // running VMs (post-#1023 Python) and set
        // from the validated request at create. `model` rides empty: the
        // Python HostGPU carries model=None on both paths.
        gpus: entry
            .gpus
            .iter()
            .map(|gpu| pb::GpuDevice {
                pci_host: gpu.pci_host.clone(),
                device_id: gpu.device_id.clone(),
                model: String::new(),
                supports_x_vga: gpu.supports_x_vga,
                cc_mode: cc_mode_of(state, &gpu.pci_host)
                    .map(|mode| mode.to_string())
                    .unwrap_or_default(),
                arch: crate::gpu_cc::arch_from_device_id(&gpu.device_id)
                    .map(|arch| arch.to_string())
                    .unwrap_or_default(),
            })
            .collect(),
        // `_guest_channel_path` / `_guest_ready_payload`: the MicroVM
        // facts for programs, empty otherwise.
        guest_channel_path: entry
            .program
            .as_ref()
            .map(|program| program.vsock_path.clone())
            .unwrap_or_default(),
        guest_ready_payload: entry
            .program
            .as_ref()
            .map(|program| program.ready_payload.clone())
            .unwrap_or_default(),
        awaiting_confidential_init,
    }
}

/// The VmSpec served by GetVmSpec (and compared by CreateVm idempotency):
/// the original spec for VMs created on this daemon instance
/// (`execution.vm_spec` in a live Python daemon), otherwise the
/// `spec_from_controller_configuration` + `create_vm_spec_to_pb`
/// reconstruction a restarted Python daemon holds for adopted VMs.
pub fn vm_spec_message(entry: &VmEntry) -> pb::VmSpec {
    if let Some(spec) = &entry.spec {
        return spec.clone();
    }
    let config = &entry.config;
    let mut disks = vec![pb::DiskConfig {
        path: config.image_path.clone(),
        readonly: false,
        format: pb::disk_config::Format::Qcow2 as i32,
        role: pb::disk_config::DiskRole::Rootfs as i32,
    }];
    disks.extend(config.host_volumes.iter().map(|volume| pb::DiskConfig {
        path: volume.path_on_host.clone(),
        readonly: volume.read_only,
        format: pb::disk_config::Format::Raw as i32,
        role: pb::disk_config::DiskRole::Extra as i32,
    }));
    // Reconstruct the TeeConfig the agent sent, so an adopted confidential VM
    // round-trips through GetVmSpec and compares equal on an idempotent
    // re-create. A SEV/SEV-ES config resolves via `confidential()`; an SEV-SNP
    // config resolves via `snp()` (mutually exclusive: SNP carries no
    // session/godh). The measured cmdline is echoed back only for the
    // opaque-cmdline arm, where the agent supplied it (identified by the
    // writable-rootfs `image_format`); the verity arm's cmdline is
    // daemon-derived from the roothash sidecar, so the agent never sends it.
    let tee = config
        .confidential()
        .map(|confidential| pb::TeeConfig {
            backend: pb::TeeBackend::Sev as i32,
            // Python: hex(vm_cfg.sev_policy), e.g. "0x5".
            policy: format!("{:#x}", confidential.sev_policy),
            // Python: sev_session_file.parent (where initialize_confidential
            // wrote the owner's certificates).
            session_dir: std::path::Path::new(&confidential.sev_session_file)
                .parent()
                .map(|parent| parent.to_string_lossy().into_owned())
                .unwrap_or_default(),
            firmware_path: confidential.ovmf_path.clone(),
            kernel_cmdline: String::new(),
            cpu_model: String::new(),
        })
        .or_else(|| {
            config.snp().map(|snp| pb::TeeConfig {
                backend: pb::TeeBackend::SevSnp as i32,
                policy: format!("{:#x}", snp.sev_policy),
                // SNP has no session/godh handshake.
                session_dir: String::new(),
                firmware_path: snp.ovmf_path.clone(),
                kernel_cmdline: if config.image_format.is_some() {
                    snp.kernel_cmdline.clone()
                } else {
                    String::new()
                },
                cpu_model: snp.cpu_model.clone().unwrap_or_default(),
            })
        });
    // Echo back the assigned static /124 the agent supplied (persisted as
    // `guest_ipv6_cidr`), so an adopted static-policy VM compares equal on an
    // idempotent re-create. Absent (empty) under the dynamic policy, matching
    // the agent, which does not compute an address there.
    let (requested_ipv6, ipv6_prefix_len) = match &config.guest_ipv6_cidr {
        Some(cidr) => {
            let prefix = cidr
                .rsplit_once('/')
                .and_then(|(_, len)| len.parse().ok())
                .unwrap_or(0);
            (cidr.clone(), prefix)
        }
        None => (String::new(), 0),
    };
    pb::VmSpec {
        vm_id: entry.vm_hash.clone(),
        backend: pb::Backend::Qemu as i32,
        kernel_path: String::new(),
        initrd_path: String::new(),
        disks,
        vcpus: config.vcpu_count,
        memory_mib: config.mem_size_mb.count(),
        tee,
        network: Some(pb::NetworkConfig {
            // Python: bool(vm_cfg.interface_name).
            internet_access: config
                .interface_name
                .as_deref()
                .is_some_and(|name| !name.is_empty()),
            requested_ipv6,
            ipv6_prefix_len,
        }),
        gpus: config
            .gpus
            .iter()
            .map(|gpu| pb::GpuConfig {
                pci_host: gpu.pci_host.clone(),
                supports_x_vga: gpu.supports_x_vga,
            })
            .collect(),
        numa_node: None,
        persistent: true,
        ssh_authorized_keys: Vec::new(),
        hostname: String::new(),
        guest_channel: None,
    }
}

/// `_mapped_to_infos`: one PortForwardInfo per active protocol, TCP first.
fn port_forward_messages(entry: &VmEntry) -> Vec<pb::PortForwardInfo> {
    let mut infos = Vec::new();
    for forward in &entry.port_forwards {
        for (active, protocol) in [
            (forward.tcp, pb::Protocol::Tcp),
            (forward.udp, pb::Protocol::Udp),
        ] {
            if active {
                infos.push(pb::PortForwardInfo {
                    vm_id: entry.vm_hash.clone(),
                    host_port: forward.host_port,
                    vm_port: forward.vm_port,
                    protocol: protocol as i32,
                });
            }
        }
    }
    infos
}

/// Server cap on GetLogs history: the proto documents max_lines 0 as
/// "unlimited (subject to server cap)"; Python has no cap today and buffers
/// the whole journal, which an operator can turn into a memory exhaustion
/// of the daemon with one request.
const GET_LOGS_SERVER_CAP: u32 = 10_000;

/// The `-n` bound handed to journalctl. `-n` keeps the LAST n entries, so
/// it is only correct when the caller wants the tail (`from_tail`) or a
/// capped "everything" (max_lines == 0). A head read (from_tail=false,
/// max_lines > 0) must scan from the start and slice after parsing, the
/// Python `chunks[:max_lines]`; `-n` there would return the wrong entries.
fn journal_tail_bound(max_lines: u32, from_tail: bool) -> Option<u32> {
    if max_lines == 0 {
        Some(GET_LOGS_SERVER_CAP)
    } else if from_tail {
        Some(max_lines)
    } else {
        None
    }
}

fn log_chunk_message(entry: crate::logs::LogEntry) -> pb::LogChunk {
    pb::LogChunk {
        // Python: whole seconds * 1e9 + microseconds * 1000, which is
        // the journal's microsecond timestamp times 1000.
        timestamp_ns: entry.timestamp_us * 1_000,
        line: entry.message,
        source: match entry.source {
            LogStream::Stdout => pb::log_chunk::LogSource::Stdout as i32,
            LogStream::Stderr => pb::log_chunk::LogSource::Stderr as i32,
        },
    }
}

fn log_chunks(entries: Vec<crate::logs::LogEntry>) -> Vec<pb::LogChunk> {
    entries.into_iter().map(log_chunk_message).collect()
}

/// Wraps the StreamLogs channel so dropping the response stream (the client
/// went away) stops the underlying journal follow, the Python `finally:
/// unregister_queue` equivalent. The semaphore permit rides along: the
/// follow slot frees when the stream is dropped.
struct StreamWithCleanup<S> {
    inner: S,
    stopper: Arc<dyn crate::logs::LogFollowStopper>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl<S: Stream + Unpin> Stream for StreamWithCleanup<S> {
    type Item = S::Item;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        Pin::new(&mut self.inner).poll_next(context)
    }
}

impl<S> Drop for StreamWithCleanup<S> {
    fn drop(&mut self) {
        self.stopper.stop();
    }
}

// ── Error statuses ──────────────────────────────────────────────────────

/// Attach the serialized ErrorDetail trailer the Python `_abort` sends, so
/// the agent rebuilds the exact SupervisorError subclass.
fn status_with_error_detail(code: Code, error_code: pb::ErrorCode, message: String) -> Status {
    let detail = pb::ErrorDetail {
        code: error_code as i32,
        message: message.clone(),
        vm_id: String::new(),
    };
    let mut metadata = MetadataMap::new();
    metadata.insert_bin(
        ERROR_TRAILER_KEY,
        MetadataValue::from_bytes(&detail.encode_to_vec()),
    );
    Status::with_metadata(code, message, metadata)
}

/// The Python catch-all: translating_errors() re-raises anything internal as
/// InternalSupervisorError, which _abort maps to grpc INTERNAL plus an
/// ErrorCode.INTERNAL trailer.
fn internal_status(error: DaemonError) -> Status {
    tracing::error!(%error, "aborting RPC with INTERNAL");
    status_with_error_detail(Code::Internal, pb::ErrorCode::Internal, error.to_string())
}

/// The Python `VmNotFoundError(vm_id)` abort: grpc NOT_FOUND, message =
/// the vm_id itself (str(error)), ErrorCode.VM_NOT_FOUND in the trailer.
fn vm_not_found_status(vm_id: &str) -> Status {
    status_with_error_detail(Code::NotFound, pb::ErrorCode::VmNotFound, vm_id.to_string())
}

/// The lifecycle error vocabulary onto the Python STATUS_CODE_BY_ERROR
/// table (grpc_server.py) plus the matching ErrorDetail trailer codes.
fn rpc_error_status(error: crate::lifecycle::RpcError) -> Status {
    use crate::lifecycle::RpcError;
    match error {
        RpcError::NotFound(vm_id) => vm_not_found_status(&vm_id),
        RpcError::AlreadyExists(message) => {
            status_with_error_detail(Code::AlreadyExists, pb::ErrorCode::VmAlreadyExists, message)
        }
        RpcError::InsufficientResources(message) => status_with_error_detail(
            Code::ResourceExhausted,
            pb::ErrorCode::InsufficientResources,
            message,
        ),
        RpcError::InvalidBackend(message) => status_with_error_detail(
            Code::InvalidArgument,
            pb::ErrorCode::InvalidBackend,
            message,
        ),
        RpcError::MicroVmInit(message) => {
            // MicroVMInitError: INTERNAL with the MICROVM_INIT_FAILED
            // trailer (grpc_server.py STATUS_CODE_BY_ERROR).
            status_with_error_detail(Code::Internal, pb::ErrorCode::MicrovmInitFailed, message)
        }
        RpcError::Unimplemented(message) => {
            // NotImplementedSupervisorError: UNIMPLEMENTED, trailer INTERNAL.
            status_with_error_detail(Code::Unimplemented, pb::ErrorCode::Internal, message)
        }
        RpcError::Internal(message) => internal_status(DaemonError::Internal(message)),
    }
}

// The unimplemented methods are written out explicitly (no macro): tonic's
// async_trait attribute rewrites the impl block before declarative macros
// expand, so generated `async fn`s would not be desugared. Explicit bodies
// also make the remaining port surface grep-able.
#[tonic::async_trait]
impl Supervisor for SupervisorService {
    // ── Host ──
    async fn health(
        &self,
        _request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        // LocalSupervisor.health: always OK, vm_count = len(pool.executions)
        // (here: the world view rebuilt at boot).
        let vm_count = self.state.world.read().await.len() as u32;
        Ok(Response::new(pb::HealthResponse {
            status: pb::HealthStatus::Ok as i32,
            vm_count,
        }))
    }

    async fn get_host_info(
        &self,
        _request: Request<pb::GetHostInfoRequest>,
    ) -> Result<Response<pb::HostInfo>, Status> {
        self.host_info()
            .await
            .map(Response::new)
            .map_err(internal_status)
    }

    // ── VM lifecycle (persistent QEMU; ephemeral programs are increment
    // 4, confidential creation increment 6) ──
    async fn create_vm(
        &self,
        request: Request<pb::VmSpec>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let state = self.state.clone();
        let spec = request.into_inner();
        let (entry, running) =
            run_lifecycle(move || crate::lifecycle::create_vm(&state, spec)).await?;
        Ok(Response::new(self.mutated_vm_info(&entry, running)))
    }

    async fn get_vm(
        &self,
        request: Request<pb::GetVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let vm_id = request.into_inner().vm_id;
        // Clone the entry out and release the lock BEFORE the unit-state
        // query: increment 3 adds writers, and a read guard held across a
        // D-Bus round trip would park them behind it.
        let entry = {
            let world = self.state.world.read().await;
            match world.entries.get(&vm_id) {
                Some(entry) => entry.clone(),
                None => return Err(vm_not_found_status(&vm_id)),
            }
        };
        // Python _is_running: systemd for persistent VMs, times for
        // ephemeral programs.
        let (running, unit) = if entry.is_program {
            (
                entry.times.starting_at_ns != 0 && entry.times.stopping_at_ns == 0,
                UnitLiveness::Unknown,
            )
        } else {
            let unit = self.unit_liveness(entry.unit_name()).await?;
            (unit.is_active(), unit)
        };
        let info = vm_info_message(&self.state, &entry, running, unit, now_ns());
        self.state.events.observe(&entry.vm_hash, info.status());
        Ok(Response::new(info))
    }

    async fn get_vm_spec(
        &self,
        request: Request<pb::GetVmSpecRequest>,
    ) -> Result<Response<pb::VmSpec>, Status> {
        let vm_id = request.into_inner().vm_id;
        let world = self.state.world.read().await;
        let Some(entry) = world.entries.get(&vm_id) else {
            return Err(vm_not_found_status(&vm_id));
        };
        Ok(Response::new(vm_spec_message(entry)))
    }

    async fn list_vms(
        &self,
        _request: Request<pb::ListVmsRequest>,
    ) -> Result<Response<pb::ListVmsResponse>, Status> {
        // Snapshot the entries and release the lock BEFORE the batched
        // unit-state query (see get_vm). Insertion order (sorted adoption,
        // then creation order), like the Python pool's dict.
        let entries: Vec<VmEntry> = {
            let world = self.state.world.read().await;
            world.ordered_entries().into_iter().cloned().collect()
        };
        // One batched query covers the persistent VMs (`_running_states`);
        // ephemeral programs are times-based, no unit to ask about.
        let unit_names: Vec<String> = entries
            .iter()
            .filter(|entry| !entry.is_program)
            .map(|entry| entry.unit_name())
            .collect();
        let states = self.units_liveness(unit_names).await?;
        let now = now_ns();
        let vms: Vec<pb::VmInfo> = entries
            .iter()
            .map(|entry| {
                let (running, unit) = if entry.is_program {
                    (
                        entry.times.starting_at_ns != 0 && entry.times.stopping_at_ns == 0,
                        UnitLiveness::Unknown,
                    )
                } else {
                    let unit = states
                        .get(&entry.unit_name())
                        .copied()
                        .unwrap_or(UnitLiveness::Unknown);
                    (unit.is_active(), unit)
                };
                vm_info_message(&self.state, entry, running, unit, now)
            })
            .collect();
        for info in &vms {
            self.state.events.observe(&info.vm_id, info.status());
        }
        Ok(Response::new(pb::ListVmsResponse { vms }))
    }

    async fn delete_vm(
        &self,
        request: Request<pb::DeleteVmRequest>,
    ) -> Result<Response<pb::DeleteVmResponse>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        run_lifecycle(move || {
            crate::lifecycle::delete_vm(&state, &request.vm_id, request.keep_port_mappings)
        })
        .await?;
        Ok(Response::new(pb::DeleteVmResponse {}))
    }

    async fn stop_vm(
        &self,
        request: Request<pb::StopVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        let entry = run_lifecycle(move || crate::lifecycle::stop_vm(&state, &vm_id)).await?;
        // Python stop_vm reports running=False unconditionally.
        Ok(Response::new(self.mutated_vm_info(&entry, false)))
    }

    async fn start_vm(
        &self,
        request: Request<pb::StartVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        let (entry, running) =
            run_lifecycle(move || crate::lifecycle::start_vm(&state, &vm_id)).await?;
        Ok(Response::new(self.mutated_vm_info(&entry, running)))
    }

    async fn reboot_vm(
        &self,
        request: Request<pb::RebootVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        let (entry, running) =
            run_lifecycle(move || crate::lifecycle::reboot_vm(&state, &vm_id)).await?;
        Ok(Response::new(self.mutated_vm_info(&entry, running)))
    }

    async fn run_program_code(
        &self,
        request: Request<pb::RunProgramCodeRequest>,
    ) -> Result<Response<pb::RunProgramCodeResponse>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        let reply = run_lifecycle(move || {
            crate::lifecycle::run_program_code(
                &state,
                &request.vm_id,
                &request.scope_msgpack,
                request.timeout_secs,
            )
        })
        .await?;
        Ok(Response::new(pb::RunProgramCodeResponse { reply }))
    }

    async fn add_port_forward(
        &self,
        request: Request<pb::AddPortForwardRequest>,
    ) -> Result<Response<pb::PortForwardInfo>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        let info =
            run_lifecycle(move || crate::lifecycle::add_port_forward(&state, &request)).await?;
        Ok(Response::new(info))
    }

    async fn remove_port_forward(
        &self,
        request: Request<pb::RemovePortForwardRequest>,
    ) -> Result<Response<pb::RemovePortForwardResponse>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        run_lifecycle(move || {
            crate::lifecycle::remove_port_forward(
                &state,
                &request.vm_id,
                request.host_port,
                request.protocol(),
            )
        })
        .await?;
        Ok(Response::new(pb::RemovePortForwardResponse {}))
    }

    async fn list_port_forwards(
        &self,
        request: Request<pb::ListPortForwardsRequest>,
    ) -> Result<Response<pb::ListPortForwardsResponse>, Status> {
        let vm_id = request.into_inner().vm_id;
        let world = self.state.world.read().await;
        let forwards = if vm_id.is_empty() {
            // Insertion order, like the Python pool.executions.values() walk.
            world
                .ordered_entries()
                .into_iter()
                .flat_map(port_forward_messages)
                .collect()
        } else {
            let Some(entry) = world.entries.get(&vm_id) else {
                return Err(vm_not_found_status(&vm_id));
            };
            port_forward_messages(entry)
        };
        Ok(Response::new(pb::ListPortForwardsResponse { forwards }))
    }

    // ── Events ──
    type WatchEventsStream = Pin<Box<dyn Stream<Item = Result<pb::VmEvent, Status>> + Send>>;

    async fn watch_events(
        &self,
        _request: Request<pb::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        // Python watch_events: register a queue and stream it until the
        // client disconnects; no replay (snapshot with ListVms first, as
        // the proto documents). Dropping the stream unsubscribes.
        let receiver = self.state.events.subscribe();
        let stream = tokio_stream::wrappers::UnboundedReceiverStream::new(receiver).map(Ok);
        Ok(Response::new(Box::pin(stream)))
    }

    // ── Logs (StreamLogs lands in increment 4) ──
    async fn get_logs(
        &self,
        request: Request<pb::GetLogsRequest>,
    ) -> Result<Response<pb::GetLogsResponse>, Status> {
        // Python get_logs performs no existence check: an unknown VM (or a
        // VM that never logged) yields an empty history, not NOT_FOUND.
        let request = request.into_inner();
        let stdout_id = format!("vm-{}-stdout", request.vm_id);
        let stderr_id = format!("vm-{}-stderr", request.vm_id);
        // Bound the subprocess output at the source where -n keeps the
        // right entries; the head path still slices after parsing (Python
        // ordering semantics, see journal_tail_bound).
        let tail_bound = journal_tail_bound(request.max_lines, request.from_tail);
        let logs = self.state.logs.clone();
        let history = tokio::task::spawn_blocking(move || {
            logs.read_history(&stdout_id, &stderr_id, tail_bound)
        })
        .await
        .map_err(|error| {
            internal_status(DaemonError::Internal(format!(
                "the journal task failed: {error}"
            )))
        })?
        .map_err(|error| internal_status(DaemonError::Internal(error.to_string())))?;
        let mut lines = log_chunks(history);
        let max_lines = request.max_lines as usize;
        if max_lines > 0 && lines.len() > max_lines {
            if request.from_tail {
                // Python: chunks[-max_lines:]. Normally a no-op: journalctl
                // already got -n max_lines for tail reads (journal_tail_bound).
                // Kept as defense-in-depth against a source that over-returns.
                lines.drain(..lines.len() - max_lines);
            } else {
                // Python: chunks[:max_lines].
                lines.truncate(max_lines);
            }
        }
        Ok(Response::new(pb::GetLogsResponse { lines }))
    }

    type StreamLogsStream = Pin<Box<dyn Stream<Item = Result<pb::LogChunk, Status>> + Send>>;

    async fn stream_logs(
        &self,
        request: Request<pb::StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        let request = request.into_inner();
        let stdout_id = format!("vm-{}-stdout", request.vm_id);
        let stderr_id = format!("vm-{}-stderr", request.vm_id);
        let known = self
            .state
            .world
            .read()
            .await
            .entries
            .contains_key(&request.vm_id);

        if !known {
            // Python: the live phase requires a tracked execution; an
            // unknown (or deleted) VM's stream ends after the optional
            // history, it is NOT an error.
            if !request.include_history {
                return Ok(Response::new(Box::pin(tokio_stream::empty())));
            }
            let logs = self.state.logs.clone();
            let history = tokio::task::spawn_blocking(move || {
                // Server-capped like GetLogs max_lines=0, so a replay
                // cannot buffer the whole journal.
                logs.read_history(&stdout_id, &stderr_id, Some(GET_LOGS_SERVER_CAP))
            })
            .await
            .map_err(|error| {
                internal_status(DaemonError::Internal(format!(
                    "the journal task failed: {error}"
                )))
            })?
            .map_err(|error| internal_status(DaemonError::Internal(error.to_string())))?;
            let chunks: Vec<Result<pb::LogChunk, Status>> =
                log_chunks(history).into_iter().map(Ok).collect();
            return Ok(Response::new(Box::pin(tokio_stream::iter(chunks))));
        }

        // Each live follow pins one blocking-pool thread; the semaphore
        // rejects follows beyond the cap instead of letting them starve the
        // pool (see DaemonState::log_follows).
        let permit = match self.state.log_follows.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                return Err(status_with_error_detail(
                    Code::ResourceExhausted,
                    pb::ErrorCode::InsufficientResources,
                    format!(
                        "too many concurrent log streams (limit {MAX_CONCURRENT_LOG_FOLLOWS}); \
                         retry later or use GetLogs"
                    ),
                ));
            }
        };

        // One journalctl --follow serves both phases gap-free: the bounded
        // history replay (the same server cap) when asked, then
        // live entries until the client goes away.
        let last_lines = if request.include_history {
            GET_LOGS_SERVER_CAP
        } else {
            0
        };
        let logs = self.state.logs.clone();
        let (mut reader, stopper) =
            tokio::task::spawn_blocking(move || logs.follow(&stdout_id, &stderr_id, last_lines))
                .await
                .map_err(|error| {
                    internal_status(DaemonError::Internal(format!(
                        "the journal task failed: {error}"
                    )))
                })?
                .map_err(|error| internal_status(DaemonError::Internal(error.to_string())))?;
        let (sender, receiver) = tokio::sync::mpsc::channel::<Result<pb::LogChunk, Status>>(16);
        let pump_stopper = stopper.clone();
        tokio::task::spawn_blocking(move || {
            while let Some(entry) = reader.next_entry() {
                if sender.blocking_send(Ok(log_chunk_message(entry))).is_err() {
                    // The client dropped the stream mid-send.
                    break;
                }
            }
            // Every pump exit path stops (kills AND reaps) the subprocess:
            // the reader's own EOF-path wait never runs again after a
            // mid-send break, and stop() is idempotent when the cleanup
            // guard already fired.
            pump_stopper.stop();
        });
        let stream = StreamWithCleanup {
            inner: tokio_stream::wrappers::ReceiverStream::new(receiver),
            stopper,
            _permit: permit,
        };
        Ok(Response::new(Box::pin(stream)))
    }

    // ── Guest quiescence ──
    async fn freeze_guest(
        &self,
        request: Request<pb::FreezeGuestRequest>,
    ) -> Result<Response<pb::FreezeGuestResponse>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        let outcome = {
            let state = state.clone();
            let vm_id = vm_id.clone();
            run_lifecycle(move || crate::quiesce::freeze_guest(&state, &vm_id)).await?
        };
        if let crate::quiesce::FreezeOutcome::Frozen(generation) = outcome {
            // The freeze deadline: an agent that dies mid-copy must not
            // leave a guest with its filesystems frozen. Clamped like the
            // other float-seconds settings, so a crafted value cannot
            // panic Duration::from_secs_f64 and instead never fires, the
            // way asyncio.wait_for treats it.
            let timeout_secs = state.host.settings.guest_freeze_timeout;
            let timeout = std::time::Duration::from_secs_f64(timeout_secs.clamp(0.0, 3.15e9));
            tokio::spawn(async move {
                tokio::time::sleep(timeout).await;
                let _ = tokio::task::spawn_blocking(move || {
                    crate::quiesce::auto_thaw(&state, &vm_id, generation, timeout_secs)
                })
                .await;
            });
        }
        Ok(Response::new(pb::FreezeGuestResponse {
            frozen: outcome.frozen(),
        }))
    }

    async fn thaw_guest(
        &self,
        request: Request<pb::ThawGuestRequest>,
    ) -> Result<Response<pb::ThawGuestResponse>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        run_lifecycle(move || crate::quiesce::thaw_guest(&state, &vm_id)).await?;
        Ok(Response::new(pb::ThawGuestResponse {}))
    }

    // ── Confidential (increment 6) ──
    async fn initialize_confidential(
        &self,
        request: Request<pb::InitializeConfidentialRequest>,
    ) -> Result<Response<pb::InitializeConfidentialResponse>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        run_lifecycle(move || {
            crate::confidential::initialize_confidential(
                &state,
                &request.vm_id,
                &request.session_bytes,
                &request.godh_bytes,
            )
        })
        .await?;
        Ok(Response::new(pb::InitializeConfidentialResponse {}))
    }

    async fn get_measurement(
        &self,
        request: Request<pb::GetMeasurementRequest>,
    ) -> Result<Response<pb::Measurement>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        let measurement =
            run_lifecycle(move || crate::confidential::get_measurement(&state, &vm_id)).await?;
        Ok(Response::new(measurement))
    }

    async fn inject_secret(
        &self,
        request: Request<pb::InjectSecretRequest>,
    ) -> Result<Response<pb::InjectSecretResponse>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        run_lifecycle(move || {
            crate::confidential::inject_secret(
                &state,
                &request.vm_id,
                &request.secret_header_bytes,
                &request.secret_bytes,
            )
        })
        .await?;
        Ok(Response::new(pb::InjectSecretResponse {}))
    }

    // ── Network ──
    async fn recreate_network(
        &self,
        _request: Request<pb::RecreateNetworkRequest>,
    ) -> Result<Response<pb::RecreateNetworkResponse>, Status> {
        let state = self.state.clone();
        let summary = run_lifecycle(move || crate::lifecycle::recreate_network(&state)).await?;
        Ok(Response::new(pb::RecreateNetworkResponse {
            summary_json: summary.to_string(),
        }))
    }
}

/// Run one blocking lifecycle operation on the blocking pool and map its
/// error vocabulary onto the wire statuses. Mirrors the Python daemon,
/// where these flows run on the event loop but block it only at await
/// points; here they own a thread for their whole duration.
///
/// Thread budget: a long-poll lifecycle RPC (the 60s boot wait, the 75s
/// graceful-stop wait) occupies one blocking-pool thread for its whole
/// duration. Tokio's blocking pool defaults to 512 threads, and the agent
/// serializes per VM, so the realistic concurrency (a handful of VMs in
/// transition) never approaches the bound; accepted for increment 3.
async fn run_lifecycle<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, crate::lifecycle::RpcError> + Send + 'static,
) -> Result<T, Status> {
    tokio::task::spawn_blocking(operation)
        .await
        .map_err(|error| {
            internal_status(DaemonError::Internal(format!(
                "the lifecycle task failed: {error}"
            )))
        })?
        .map_err(rpc_error_status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_config::{VmConfiguration, parse_controller_config};
    use crate::ports::PortForward;
    use crate::test_fixtures;
    use crate::world::IpPair;

    fn fixture_entry(vm_hash: &str, running: bool) -> VmEntry {
        let path = test_fixtures::fixtures_dir().join(format!("{vm_hash}-controller.json"));
        let config = parse_controller_config(&std::fs::read_to_string(path).unwrap()).unwrap();
        let VmConfiguration::Qemu(qemu) = config.vm else {
            panic!("fixtures are QEMU configs");
        };
        let mut times = VmTimes {
            defined_at_ns: 1_000_000_000_000,
            ..VmTimes::default()
        };
        if running {
            times.preparing_at_ns = 1_000_000_001_000;
            times.prepared_at_ns = 1_000_000_002_000;
            times.started_at_ns = 1_000_000_003_000;
        } else {
            times.stopped_at_ns = times.defined_at_ns;
        }
        VmEntry {
            vm_hash: vm_hash.to_string(),
            vm_index: config.vm_index,
            config: *qemu,
            settings_slice: config.settings,
            times,
            adopted_running: running,
            restarting: false,
            ipv4: running.then(|| IpPair {
                address: "172.16.3.2".to_string(),
                network_cidr: "172.16.3.0/24".to_string(),
                gateway: "172.16.3.1".to_string(),
            }),
            ipv6: None,
            port_forwards: if running {
                vec![PortForward {
                    vm_port: 22,
                    host_port: 24000,
                    tcp: true,
                    udp: true,
                }]
            } else {
                Vec::new()
            },
            gpus: Vec::new(),
            spec: None,
            ordinal: 0,
            is_program: false,
            program: None,
            numa_node: None,
        }
    }

    /// A DaemonState with no probed CC modes, for tests that only care
    /// about `vm_info_message`'s non-GPU fields.
    fn empty_state() -> DaemonState {
        DaemonState::hermetic(
            HostState {
                settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
                host_ipv4: String::new(),
                network_interface: None,
                gpus: Vec::new(),
                dns_nameservers: None,
            },
            WorldView::default(),
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        )
    }

    #[test]
    fn refresh_cc_modes_gates_the_probe_on_a_fresh_attached_set() {
        // Two NVIDIA cards in the inventory; one is attached to a VM's
        // config in the world view. The probe must never run against the
        // attached card, and the attached set must come from the world
        // view under the function's own read guard, not a caller-supplied
        // snapshot (a concurrent CreateVm can attach a card between a
        // snapshot taken before spawn_blocking and the probe running on it).
        let host = HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: vec![
                GpuDevice {
                    vendor: "NVIDIA".to_string(),
                    device_name: "GB202 [GeForce RTX 5090]".to_string(),
                    device_class: "0300".to_string(),
                    pci_host: "06:00.0".to_string(),
                    device_id: "10de:2b85".to_string(),
                    cc_mode: None,
                    arch: None,
                },
                GpuDevice {
                    vendor: "NVIDIA".to_string(),
                    device_name: "GB202 [GeForce RTX 5090]".to_string(),
                    device_class: "0300".to_string(),
                    pci_host: "07:00.0".to_string(),
                    device_id: "10de:2b85".to_string(),
                    cc_mode: None,
                    arch: None,
                },
            ],
            dns_nameservers: None,
        };
        let mut entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        entry.config.gpus = vec![crate::controller_config::QemuGpu {
            pci_host: "06:00.0".to_string(),
            supports_x_vga: true,
        }];
        let mut world = WorldView::default();
        world.insert_entry(entry);
        let state = DaemonState::hermetic(
            host,
            world,
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        );

        let probed: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        refresh_cc_modes_with(
            &state,
            |pci_host, _device_id| {
                probed.lock().unwrap().push(pci_host.to_string());
                Ok(Some(crate::gpu_cc::CcMode::On))
            },
            default_windows(),
        );

        assert_eq!(
            probed.into_inner().unwrap(),
            vec!["07:00.0".to_string()],
            "only the unattached card is probed"
        );
        let cache = state.gpu_cc_modes.lock().unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.get("07:00.0").map(|probed| probed.mode),
            Some(Some(crate::gpu_cc::CcMode::On))
        );
        assert_eq!(cache.get("06:00.0"), None);
    }

    #[test]
    fn refresh_cc_modes_forgets_a_card_whose_probe_no_longer_answers() {
        // Two free cards, both cached as CC-on from an earlier probe. One
        // now fails to probe, the other reads a register encoding with no
        // mode. Neither may keep advertising the stale value: a scheduler
        // trusting it would place a confidential workload on a card the
        // host can no longer vouch for.
        let card = |pci_host: &str| GpuDevice {
            vendor: "NVIDIA".to_string(),
            device_name: "GB202 [GeForce RTX 5090]".to_string(),
            device_class: "0300".to_string(),
            pci_host: pci_host.to_string(),
            device_id: "10de:2b85".to_string(),
            cc_mode: None,
            arch: None,
        };
        let host = HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: vec![card("06:00.0"), card("07:00.0")],
            dns_nameservers: None,
        };
        let state = DaemonState::hermetic(
            host,
            WorldView::default(),
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        );
        {
            let mut cache = state.gpu_cc_modes.lock().unwrap();
            let on = crate::gpu_cc::ProbedCcMode::now(Some(crate::gpu_cc::CcMode::On));
            cache.insert("06:00.0".to_string(), on);
            cache.insert("07:00.0".to_string(), on);
        }

        refresh_cc_modes_with(
            &state,
            |pci_host, _device_id| match pci_host {
                "06:00.0" => Err(DaemonError::GpuUnreadable {
                    pci_host: pci_host.to_string(),
                }),
                _ => Ok(None),
            },
            // The cached answers are seconds old, so only zero-length
            // windows make the refresh read the cards again.
            expired_windows(),
        );

        let cache = state.gpu_cc_modes.lock().unwrap();
        assert!(
            cache.values().all(|probed| probed.mode.is_none()),
            "a failed or modeless probe must drop the stale mode: {cache:?}"
        );
    }

    /// One unprobed Blackwell card at `pci_host`.
    fn nvidia_card(pci_host: &str) -> GpuDevice {
        GpuDevice {
            vendor: "NVIDIA".to_string(),
            device_name: "GB202 [GeForce RTX 5090]".to_string(),
            device_class: "0300".to_string(),
            pci_host: pci_host.to_string(),
            device_id: "10de:2b85".to_string(),
            cc_mode: None,
            arch: None,
        }
    }

    /// Two free NVIDIA cards and nothing attached: the fixture both
    /// freshness tests below build on.
    fn two_free_cards() -> DaemonState {
        let host = HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: vec![nvidia_card("06:00.0"), nvidia_card("07:00.0")],
            dns_nameservers: None,
        };
        DaemonState::hermetic(
            host,
            WorldView::default(),
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        )
    }

    #[test]
    fn refresh_cc_modes_repeats_a_sweep_only_when_a_card_changed_hands_or_the_ttl_passed() {
        // A public poller hitting GetHostInfo must not turn every request
        // into a register read: a sweep against the same attached set
        // within the shortest window is skipped whole, before any card is
        // looked at. A card changing hands, or the windows passing, brings
        // the next sweep back.
        let state = two_free_cards();
        let probes = std::sync::atomic::AtomicUsize::new(0);
        let counting = |_: &str, _: &str| {
            probes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Some(crate::gpu_cc::CcMode::On))
        };

        refresh_cc_modes_with(&state, counting, default_windows());
        refresh_cc_modes_with(&state, counting, default_windows());
        assert_eq!(
            probes.load(std::sync::atomic::Ordering::SeqCst),
            2,
            "the second sweep inside the pass window against the same attached set is skipped"
        );

        // A card changes hands: the sweep runs again, over the free card
        // only, and that card's own answer is a decoded mode, fresh for
        // the long window, so nothing is read.
        let mut entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        entry.config.gpus = vec![crate::controller_config::QemuGpu {
            pci_host: "06:00.0".to_string(),
            supports_x_vga: true,
        }];
        state.world.blocking_write().insert_entry(entry);
        refresh_cc_modes_with(&state, counting, default_windows());
        assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 2);

        // Zero-length windows mean every sweep runs and every card is read.
        refresh_cc_modes_with(&state, counting, expired_windows());
        assert_eq!(probes.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[test]
    fn refresh_cc_modes_serves_a_fresh_answer_without_reading_the_card() {
        // GetHostInfo refreshes on every call and the agent calls it for
        // every unauthenticated /about/capability request. Without a TTL
        // any internet client could make the host mmap the BAR of every
        // idle NVIDIA card it has, as often as it likes. A probe that
        // failed is remembered too: a card that cannot be read must not be
        // retried on every request either. The per-card window is what
        // holds when the sweep gate lets a pass through, so the sweep is
        // forced to run every time here.
        let state = two_free_cards();

        let probed: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        let probe = |pci_host: &str, _device_id: &str| {
            probed.lock().unwrap().push(pci_host.to_string());
            match pci_host {
                "06:00.0" => Ok(Some(crate::gpu_cc::CcMode::On)),
                _ => Err(DaemonError::GpuUnreadable {
                    pci_host: pci_host.to_string(),
                }),
            }
        };

        refresh_cc_modes_with(&state, probe, default_windows());
        force_next_sweep(&state);
        refresh_cc_modes_with(&state, probe, default_windows());
        let after_two_refreshes = probed.lock().unwrap().clone();
        assert_eq!(
            after_two_refreshes.len(),
            2,
            "the second refresh must be served from the cache: {after_two_refreshes:?}"
        );
        assert_eq!(
            cc_mode_of(&state, "06:00.0"),
            Some(crate::gpu_cc::CcMode::On)
        );
        assert_eq!(
            cc_mode_of(&state, "07:00.0"),
            None,
            "a card whose probe failed advertises nothing"
        );

        // An entry past its TTL is read again, both the mode and the failure.
        refresh_cc_modes_with(&state, probe, expired_windows());
        assert_eq!(probed.into_inner().unwrap().len(), 4);
    }

    /// Drop the record of the last sweep so the next `refresh_cc_modes_with`
    /// walks the cards whatever its windows are, leaving only the per-card
    /// freshness check between a card and its register.
    fn force_next_sweep(state: &DaemonState) {
        state.gpu_cc_sweep.lock().unwrap().at = None;
    }

    /// The windows a daemon runs with out of the box: the default long
    /// tier for a decoded mode, the fixed short one for an answer with no
    /// mode.
    fn default_windows() -> crate::gpu_cc::CcCacheWindows {
        crate::gpu_cc::CcCacheWindows::with_mode_ttl(std::time::Duration::from_secs(
            crate::gpu_cc::DEFAULT_CC_MODE_TTL_SECS,
        ))
    }

    /// Windows that hold nothing, so every sweep runs and every card is
    /// read again.
    fn expired_windows() -> crate::gpu_cc::CcCacheWindows {
        crate::gpu_cc::CcCacheWindows {
            mode: std::time::Duration::ZERO,
            unreadable: std::time::Duration::ZERO,
        }
    }

    /// A cached answer of `mode` that a probe gave `age` ago.
    fn aged_answer(
        mode: Option<crate::gpu_cc::CcMode>,
        age: std::time::Duration,
    ) -> crate::gpu_cc::ProbedCcMode {
        crate::gpu_cc::ProbedCcMode {
            mode,
            probed_at: std::time::Instant::now()
                .checked_sub(age)
                .expect("the process started after the ages used here"),
        }
    }

    #[test]
    fn a_pass_rereads_the_unreadable_card_and_leaves_the_known_one_alone() {
        // The point of the two tiers. Both cards were last read a minute
        // and a second ago: the one that answered with a mode is still
        // good for the rest of the long window, while the one that could
        // not be read (a card being reset reads all ones) has aged out of
        // the short one and must be tried again, rather than staying
        // hidden until the long window passes. The pass gate has to let
        // this sweep through for that to be reachable, which is why it
        // runs on the shortest window.
        let state = two_free_cards();
        let age = std::time::Duration::from_secs(61);
        {
            let mut cache = state.gpu_cc_modes.lock().unwrap();
            cache.insert(
                "06:00.0".to_string(),
                aged_answer(Some(crate::gpu_cc::CcMode::On), age),
            );
            cache.insert("07:00.0".to_string(), aged_answer(None, age));
        }
        state.gpu_cc_sweep.lock().unwrap().at = Some(
            std::time::Instant::now()
                .checked_sub(age)
                .expect("the process started after the ages used here"),
        );

        let probed: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
        refresh_cc_modes_with(
            &state,
            |pci_host, _device_id| {
                probed.lock().unwrap().push(pci_host.to_string());
                Ok(Some(crate::gpu_cc::CcMode::Off))
            },
            default_windows(),
        );

        assert_eq!(
            probed.into_inner().unwrap(),
            vec!["07:00.0".to_string()],
            "only the card that could not be read is tried again"
        );
        assert_eq!(
            cc_mode_of(&state, "07:00.0"),
            Some(crate::gpu_cc::CcMode::Off),
            "the retry replaces the empty answer"
        );
        assert_eq!(
            cc_mode_of(&state, "06:00.0"),
            Some(crate::gpu_cc::CcMode::On),
            "the card with a known mode keeps the answer it had"
        );
    }

    /// An adopted VM holding one card: SNP (measured-boot slice present)
    /// or plain QEMU passthrough, which is the distinction the seeding
    /// turns on.
    #[test]
    fn concurrent_refreshes_read_a_card_once_and_leave_its_power_setting_alone() {
        // Two GetHostInfo calls landing together used to run two full
        // passes over the same cards. Both could read power/control before
        // either wrote it, so the second remembered "on" as the value to
        // restore and the card stayed pinned awake after the probes, with
        // the host's own runtime-PM setting lost.
        let sysfs = tempfile::tempdir().unwrap();
        let device_dir = sysfs.path().join("0000:06:00.0");
        std::fs::create_dir_all(device_dir.join("power")).unwrap();
        // The fixture card never actually resumes, so a probe holds the
        // pass for its whole (short) resume budget: plenty of overlap for
        // a second pass to start if anything let it.
        std::fs::write(device_dir.join("power/runtime_status"), "suspended\n").unwrap();
        std::fs::write(device_dir.join("power/control"), "auto\n").unwrap();
        let mut bytes = vec![0u8; 0x1000];
        bytes[0x590..0x594].copy_from_slice(&1u32.to_le_bytes());
        std::fs::write(device_dir.join("resource0"), &bytes).unwrap();

        let host = HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: vec![nvidia_card("06:00.0")],
            dns_nameservers: None,
        };
        let state = DaemonState::hermetic(
            host,
            WorldView::default(),
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        );

        let reads = std::sync::atomic::AtomicUsize::new(0);
        let devices_dir = sysfs.path().to_path_buf();
        let probe = |pci_host: &str, device_id: &str| {
            reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            crate::gpu_cc::probe_cc_mode_in(
                &crate::gpu_cc::sysfs_device_dir_under(&devices_dir, pci_host),
                pci_host,
                device_id,
                std::time::Duration::from_millis(50),
            )
        };
        std::thread::scope(|scope| {
            for _ in 0..2 {
                scope.spawn(|| refresh_cc_modes_with(&state, probe, default_windows()));
            }
        });

        assert_eq!(
            reads.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the second pass must wait for the first and then find the answer fresh"
        );
        assert_eq!(
            std::fs::read_to_string(device_dir.join("power/control"))
                .unwrap()
                .trim(),
            "auto",
            "the host's runtime-PM setting must survive concurrent passes"
        );
        assert_eq!(
            cc_mode_of(&state, "06:00.0"),
            Some(crate::gpu_cc::CcMode::On)
        );
    }

    fn adopted_entry_holding(vm_hash: &str, pci_host: &str, snp: bool) -> VmEntry {
        let mut entry = fixture_entry(vm_hash, true);
        if snp {
            let json = r#"{
                "vm_id": 9, "vm_hash": "abcd", "settings": {},
                "hypervisor": "qemu",
                "vm_configuration": {
                    "qemu_bin_path": "/usr/bin/qemu-system-x86_64",
                    "image_path": "/img/rootfs.ext4",
                    "monitor_socket_path": "/m.sock", "qmp_socket_path": "/q.sock",
                    "vcpu_count": 2, "mem_size_mb": 2048,
                    "host_volumes": [], "gpus": [],
                    "sev_snp": true,
                    "ovmf_path": "/img/OVMF.fd",
                    "sev_policy": 196608,
                    "kernel_path": "/img/bzImage",
                    "initrd_path": "/img/initrd",
                    "kernel_cmdline": "console=ttyS0 root=/dev/mapper/verity-root ro"
                }
            }"#;
            let config = crate::controller_config::parse_controller_config(json).unwrap();
            let crate::controller_config::VmConfiguration::Qemu(qemu) = config.vm else {
                panic!("the payload is a QEMU configuration");
            };
            entry.config = *qemu;
        }
        entry.config.gpus = vec![crate::controller_config::QemuGpu {
            pci_host: pci_host.to_string(),
            supports_x_vga: true,
        }];
        entry.gpus = vec![crate::world::AttachedGpu {
            pci_host: pci_host.to_string(),
            device_id: "10de:2b85".to_string(),
            supports_x_vga: true,
        }];
        entry
    }

    #[test]
    fn an_adopted_snp_vms_card_reports_cc_on_without_reading_the_card() {
        // A restart leaves the cache empty, and a card a guest owns is
        // never probed (its register belongs to the guest), so a
        // confidential VM adopted at boot used to report no cc_mode for
        // the rest of its life. It does not need a probe: the create gate
        // admits a card into an SNP VM only after reading CC-on from it,
        // and nothing can change the mode while the guest holds the card.
        // A plain passthrough VM went through no such gate, so its card
        // stays unknown.
        let host = HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: vec![nvidia_card("06:00.0"), nvidia_card("07:00.0")],
            dns_nameservers: None,
        };
        let snp_entry = adopted_entry_holding(test_fixtures::QEMU_HASH, "06:00.0", true);
        let mut world = WorldView::default();
        world.insert_entry(snp_entry.clone());
        world.insert_entry(adopted_entry_holding(
            test_fixtures::GPU_HASH,
            "07:00.0",
            false,
        ));
        let state = DaemonState::hermetic(
            host,
            world,
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        );

        // Any read of a card a guest owns is a bug, so the probe panics.
        refresh_cc_modes_with(
            &state,
            |pci_host: &str, _device_id: &str| {
                panic!("an attached card must never be probed: {pci_host}")
            },
            default_windows(),
        );

        assert_eq!(
            cc_mode_of(&state, "06:00.0"),
            Some(crate::gpu_cc::CcMode::On),
            "the confidential VM's card is known CC-on"
        );
        assert_eq!(
            cc_mode_of(&state, "07:00.0"),
            None,
            "a plain passthrough card went through no gate and stays unknown"
        );
        // The VM's own report, which is where the empty mode showed.
        let info = vm_info_message(
            &state,
            &snp_entry,
            true,
            UnitLiveness::Active,
            snp_entry.times.started_at_ns,
        );
        assert_eq!(info.gpus.len(), 1);
        assert_eq!(info.gpus[0].cc_mode, "on");
        assert_eq!(
            info.gpus[0].arch, "blackwell",
            "the architecture comes from the device id, not from a probe"
        );
    }

    #[test]
    fn a_stopped_snp_vms_card_is_not_seeded_cc_on() {
        // The seed rests on the card being under a live guest: nothing can
        // switch its mode there, so the create gate's reading still holds.
        // A stopped VM's QEMU is gone and the card is idle hardware an
        // operator can re-mode, so the gate's word has expired and the
        // card must advertise nothing rather than a mode the host cannot
        // vouch for. It is still claimed by the entry's config, so it is
        // not read either.
        let mut snp_entry = adopted_entry_holding(test_fixtures::QEMU_HASH, "06:00.0", true);
        snp_entry.times.started_at_ns = 0;
        snp_entry.times.stopped_at_ns = snp_entry.times.defined_at_ns;
        let host = HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: vec![nvidia_card("06:00.0")],
            dns_nameservers: None,
        };
        let mut world = WorldView::default();
        world.insert_entry(snp_entry);
        let state = DaemonState::hermetic(
            host,
            world,
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        );

        refresh_cc_modes_with(
            &state,
            |pci_host: &str, _device_id: &str| {
                panic!("a card an entry still claims must never be probed: {pci_host}")
            },
            default_windows(),
        );

        assert_eq!(
            cc_mode_of(&state, "06:00.0"),
            None,
            "a stopped confidential VM's card advertises nothing"
        );
    }

    #[test]
    fn a_never_started_snp_vms_card_is_not_seeded_cc_on() {
        // An entry adopted while the systemd bus was unreachable carries no
        // stop stamp, but no start either, and the daemon does not know
        // whether its guest is alive. A never-started Defined entry looks
        // the same. Neither is proof that a guest is holding the card's
        // mode still, so neither gets the seed.
        let mut snp_entry = adopted_entry_holding(test_fixtures::QEMU_HASH, "06:00.0", true);
        snp_entry.times = crate::world::VmTimes {
            defined_at_ns: snp_entry.times.defined_at_ns,
            ..Default::default()
        };
        let host = HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: vec![nvidia_card("06:00.0")],
            dns_nameservers: None,
        };
        let mut world = WorldView::default();
        world.insert_entry(snp_entry);
        let state = DaemonState::hermetic(
            host,
            world,
            Arc::new(crate::units::StaticUnitStates::default()),
            Arc::new(crate::logs::StaticLogSource::new(Vec::new())),
        );

        refresh_cc_modes_with(
            &state,
            |pci_host: &str, _device_id: &str| {
                panic!("a card an entry still claims must never be probed: {pci_host}")
            },
            default_windows(),
        );

        assert_eq!(
            cc_mode_of(&state, "06:00.0"),
            None,
            "a card whose guest may never have run advertises nothing"
        );
    }

    #[test]
    fn a_running_adopted_vm_maps_like_the_python_to_vm_info() {
        let entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        let now = entry.times.started_at_ns + 7_500_000_000;
        let info = vm_info_message(&empty_state(), &entry, true, UnitLiveness::Active, now);
        assert_eq!(info.status, pb::VmStatus::Running as i32);
        assert_eq!(info.uptime_secs, 7, "int(total_seconds()) truncates");
        assert_eq!(info.backend, pb::Backend::Qemu as i32);
        assert_eq!(info.vm_id, test_fixtures::QEMU_HASH);
        assert_eq!(info.ipv4.as_ref().unwrap().address, "172.16.3.2");
        assert_eq!(info.starting_at_ns, 0);
        assert_ne!(info.started_at_ns, 0);
        assert_eq!(info.confidential_mode, pb::ConfidentialMode::None as i32);
        assert!(!info.awaiting_confidential_init);
        assert!(info.gpus.is_empty());
        assert_eq!(info.numa_node, None);
    }

    #[test]
    fn an_entry_seen_inactive_at_boot_stays_stopped_whatever_the_live_unit_says() {
        // R2 case 1: the bus ANSWERED at boot and the unit was inactive:
        // stopped_at was stamped at adoption, and _status_of checks
        // stopped_at first, so even a unit appearing later cannot resurrect
        // the entry (Python behaves the same for a VM stopped through
        // StopVm whose unit is started manually; a deliberate parity
        // wart).
        let entry = fixture_entry(test_fixtures::QEMU_HASH, false);
        for live in [false, true] {
            let unit = if live {
                UnitLiveness::Active
            } else {
                UnitLiveness::Dead
            };
            let info = vm_info_message(&empty_state(), &entry, live, unit, now_ns());
            assert_eq!(info.status, pb::VmStatus::Stopped as i32);
            assert_eq!(info.uptime_secs, 0);
        }
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert_eq!(info.ipv4, Some(pb::IpAssignment::default()));
        assert_eq!(info.ipv6, Some(pb::IpAssignment::default()));
    }

    #[test]
    fn an_entry_adopted_under_a_bus_failure_follows_the_live_unit_state() {
        // R2 case 2: the bus did NOT answer at boot, so nothing was
        // stamped (no stopped_at, no started_at). Once the bus recovers,
        // an active unit reports RUNNING; an inactive one falls through
        // _status_of to DEFINED, never a permanent STOPPED.
        let mut entry = fixture_entry(test_fixtures::QEMU_HASH, false);
        entry.times = VmTimes {
            defined_at_ns: entry.times.defined_at_ns,
            ..VmTimes::default()
        };
        let info = vm_info_message(&empty_state(), &entry, true, UnitLiveness::Active, now_ns());
        assert_eq!(info.status, pb::VmStatus::Running as i32);
        assert_eq!(info.uptime_secs, 0, "no started_at was ever stamped");
        // A dead unit under an entry the daemon never saw alive is not a
        // death it can claim: the bus outage left started_at unstamped, so
        // the status falls through to DEFINED rather than FAILED.
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert_eq!(info.status, pb::VmStatus::Defined as i32);
    }

    #[test]
    fn a_running_adopted_vm_whose_unit_died_reports_failed() {
        // The restore path sets neither starting_at nor stopped_at, so this
        // entry used to fall through to DEFINED, which the agent's
        // allocation reconciler counts as live: a guest whose QEMU exited on
        // its own was never rebuilt. The unit state settles it instead.
        let entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert_eq!(info.status, pb::VmStatus::Failed as i32);
        assert_eq!(info.uptime_secs, 0);
        // A unit still on its way up is a VM booting, not one that died.
        let info = vm_info_message(
            &empty_state(),
            &entry,
            false,
            UnitLiveness::Transitional,
            now_ns(),
        );
        assert_eq!(info.status, pb::VmStatus::Defined as i32);
        // And an unanswered bus concludes nothing at all.
        let info = vm_info_message(
            &empty_state(),
            &entry,
            false,
            UnitLiveness::Unknown,
            now_ns(),
        );
        assert_eq!(info.status, pb::VmStatus::Defined as i32);
    }

    #[test]
    fn a_started_vm_whose_unit_died_reports_failed_instead_of_booting_for_ever() {
        // The created-and-started shape: starting_at stamped, then
        // started_at once the controller was confirmed ready. A unit that
        // goes down afterwards without a StopVm is a guest that died, and
        // reporting BOOTING for ever left the agent holding it live.
        let mut entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        entry.times.starting_at_ns = entry.times.prepared_at_ns;
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert_eq!(info.status, pb::VmStatus::Failed as i32);
        let info = vm_info_message(
            &empty_state(),
            &entry,
            false,
            UnitLiveness::Transitional,
            now_ns(),
        );
        assert_eq!(info.status, pb::VmStatus::Booting as i32);
        let info = vm_info_message(&empty_state(), &entry, true, UnitLiveness::Active, now_ns());
        assert_eq!(info.status, pb::VmStatus::Running as i32);
    }

    #[test]
    fn an_explicitly_stopped_vm_stays_stopped_under_a_dead_unit() {
        // The stop stamps come first: a VM the operator stopped has a dead
        // unit by definition and must not be reported as a crash the agent
        // rebuilds.
        let mut entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        entry.times.stopping_at_ns = entry.times.started_at_ns + 1_000;
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert_eq!(info.status, pb::VmStatus::Stopping as i32);
        entry.times.stopped_at_ns = entry.times.stopping_at_ns + 1_000;
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert_eq!(info.status, pb::VmStatus::Stopped as i32);
    }

    #[test]
    fn a_confidential_vm_awaiting_its_session_is_never_reported_failed() {
        // A SEV / SEV-ES controller is deliberately held down until the
        // owner uploads the session certificates, so its unit is dead by
        // design and says nothing about a guest.
        let mut entry = fixture_entry(test_fixtures::CONFIDENTIAL_HASH, true);
        entry.times.starting_at_ns = entry.times.prepared_at_ns;
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert!(info.awaiting_confidential_init);
        assert_eq!(info.status, pb::VmStatus::Booting as i32);
    }

    #[test]
    fn an_ephemeral_program_ignores_the_unit_state() {
        // A program runs under no controller unit; its times are the whole
        // truth, and a stray unit lookup must not condemn it.
        let mut entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        entry.is_program = true;
        entry.times.starting_at_ns = entry.times.prepared_at_ns;
        let info = vm_info_message(&empty_state(), &entry, true, UnitLiveness::Dead, now_ns());
        assert_eq!(info.status, pb::VmStatus::Running as i32);
    }

    #[test]
    fn confidential_mode_follows_the_sev_policy_bit() {
        let entry = fixture_entry(test_fixtures::CONFIDENTIAL_HASH, true);
        // The fixture's policy is 0x5: the SEV_ES bit (0x4) is set.
        let info = vm_info_message(&empty_state(), &entry, true, UnitLiveness::Active, now_ns());
        assert_eq!(info.confidential_mode, pb::ConfidentialMode::SevEs as i32);
        assert!(!info.awaiting_confidential_init);
        // A confidential VM with a dead unit but started_at set is
        // "awaiting init" in Python's formula; port it literally.
        let info = vm_info_message(&empty_state(), &entry, false, UnitLiveness::Dead, now_ns());
        assert!(info.awaiting_confidential_init);
    }

    #[test]
    fn vm_spec_mirrors_spec_from_controller_configuration() {
        let entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        let spec = vm_spec_message(&entry);
        assert_eq!(spec.vm_id, test_fixtures::QEMU_HASH);
        assert_eq!(spec.backend, pb::Backend::Qemu as i32);
        assert_eq!(spec.kernel_path, "");
        assert_eq!(spec.initrd_path, "");
        assert_eq!(spec.vcpus, 2);
        assert_eq!(spec.memory_mib, 2048);
        assert!(spec.persistent);
        assert_eq!(spec.tee, None);
        assert_eq!(spec.numa_node, None);
        assert!(spec.network.as_ref().unwrap().internet_access);
        assert_eq!(spec.disks.len(), 2, "rootfs plus one host volume");
        assert_eq!(spec.disks[0].role, pb::disk_config::DiskRole::Rootfs as i32);
        assert_eq!(spec.disks[0].format, pb::disk_config::Format::Qcow2 as i32);
        assert!(!spec.disks[0].readonly);
        assert_eq!(spec.disks[1].role, pb::disk_config::DiskRole::Extra as i32);
        assert_eq!(spec.disks[1].format, pb::disk_config::Format::Raw as i32);
    }

    #[test]
    fn a_confidential_spec_rebuilds_the_tee_config() {
        let entry = fixture_entry(test_fixtures::CONFIDENTIAL_HASH, true);
        let spec = vm_spec_message(&entry);
        let tee = spec.tee.expect("confidential specs carry a TeeConfig");
        assert_eq!(tee.backend, pb::TeeBackend::Sev as i32);
        assert_eq!(tee.policy, "0x5");
        assert!(tee.firmware_path.ends_with("OVMF_CSV.fd"));
        assert!(tee.session_dir.ends_with(test_fixtures::CONFIDENTIAL_HASH));
        assert!(!tee.session_dir.ends_with("vm_session.b64"));
    }

    #[test]
    fn port_forwards_expand_per_protocol_tcp_first() {
        let entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        let infos = port_forward_messages(&entry);
        assert_eq!(infos.len(), 2);
        assert_eq!(infos[0].protocol, pb::Protocol::Tcp as i32);
        assert_eq!(infos[1].protocol, pb::Protocol::Udp as i32);
        assert_eq!(infos[0].host_port, 24000);
        assert_eq!(infos[0].vm_port, 22);
    }

    #[test]
    fn log_history_maps_and_slices_like_python() {
        use crate::logs::LogEntry;
        let entries = vec![
            LogEntry {
                timestamp_us: 1_000_001,
                message: "one".into(),
                source: LogStream::Stdout,
            },
            LogEntry {
                timestamp_us: 1_000_002,
                message: "two".into(),
                source: LogStream::Stderr,
            },
            LogEntry {
                timestamp_us: 1_000_003,
                message: "three".into(),
                source: LogStream::Stdout,
            },
        ];
        let chunks = log_chunks(entries);
        assert_eq!(chunks[0].timestamp_ns, 1_000_001_000);
        assert_eq!(chunks[0].source, pb::log_chunk::LogSource::Stdout as i32);
        assert_eq!(chunks[1].source, pb::log_chunk::LogSource::Stderr as i32);
        assert_eq!(chunks.len(), 3);
    }

    fn test_host_state() -> HostState {
        HostState {
            settings: crate::config::Settings::from_vars(std::iter::empty()).unwrap(),
            host_ipv4: String::new(),
            network_interface: None,
            gpus: Vec::new(),
            dns_nameservers: None,
        }
    }

    fn log_fixture_entries() -> Vec<crate::logs::LogEntry> {
        vec![
            crate::logs::LogEntry {
                timestamp_us: 1_000_001,
                message: "one".into(),
                source: LogStream::Stdout,
            },
            crate::logs::LogEntry {
                timestamp_us: 1_000_002,
                message: "two".into(),
                source: LogStream::Stderr,
            },
            crate::logs::LogEntry {
                timestamp_us: 1_000_003,
                message: "three".into(),
                source: LogStream::Stdout,
            },
        ]
    }

    async fn collect_chunks(
        stream: &mut (impl Stream<Item = Result<pb::LogChunk, Status>> + Unpin),
    ) -> Vec<pb::LogChunk> {
        let mut chunks = Vec::new();
        while let Some(item) = stream.next().await {
            chunks.push(item.unwrap());
        }
        chunks
    }

    #[tokio::test]
    async fn stream_logs_replays_bounded_history_then_the_live_feed() {
        use crate::logs::StaticLogSource;
        use crate::units::StaticUnitStates;
        let mut world = WorldView::default();
        world.insert_entry(fixture_entry(test_fixtures::QEMU_HASH, true));
        let state = Arc::new(DaemonState::hermetic(
            test_host_state(),
            world,
            Arc::new(StaticUnitStates::default()),
            Arc::new(StaticLogSource::new(log_fixture_entries())),
        ));
        let service = SupervisorService::new(state);

        // include_history: the follow starts with the bounded history (the
        // fake ends after it; the real journalctl keeps following).
        let mut stream = service
            .stream_logs(Request::new(pb::StreamLogsRequest {
                vm_id: test_fixtures::QEMU_HASH.to_string(),
                include_history: true,
            }))
            .await
            .unwrap()
            .into_inner();
        let chunks = collect_chunks(&mut stream).await;
        assert_eq!(
            chunks.iter().map(|c| c.line.as_str()).collect::<Vec<_>>(),
            vec!["one", "two", "three"]
        );
        assert_eq!(chunks[0].timestamp_ns, 1_000_001_000);
        assert_eq!(chunks[1].source, pb::log_chunk::LogSource::Stderr as i32);

        // include_history=false: only new lines from now (the fake has
        // none, so the stream ends empty).
        let mut stream = service
            .stream_logs(Request::new(pb::StreamLogsRequest {
                vm_id: test_fixtures::QEMU_HASH.to_string(),
                include_history: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(collect_chunks(&mut stream).await.is_empty());
    }

    #[test]
    fn numa_nodes_proto_maps_the_detected_topology() {
        // The GetHostInfo reporting path (increment C1) maps each detected NUMA
        // node to one proto NumaNode: id -> index, cpu count -> cpu_count, RAM
        // MB -> memory_mib. Pure, independent of the placement path and host IO.
        let topology = crate::numa::NumaTopology {
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
        };

        let nodes = numa_nodes_proto(&topology);

        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].index, 0);
        assert_eq!(nodes[0].cpu_count, 4);
        assert_eq!(nodes[0].memory_mib, 64_000);
        assert_eq!(nodes[1].index, 1);
        assert_eq!(nodes[1].cpu_count, 4);
        assert_eq!(nodes[1].memory_mib, 32_000);
        // An empty topology reports no nodes (pre-C1 behavior).
        assert!(numa_nodes_proto(&crate::numa::NumaTopology::empty()).is_empty());
    }

    #[tokio::test]
    async fn stream_logs_for_an_unknown_vm_ends_instead_of_erroring() {
        use crate::logs::StaticLogSource;
        use crate::units::StaticUnitStates;
        // Python: an unknown (or deleted) VM yields the optional journald
        // history, then the stream ends; never NOT_FOUND.
        let state = Arc::new(DaemonState::hermetic(
            test_host_state(),
            WorldView::default(),
            Arc::new(StaticUnitStates::default()),
            Arc::new(StaticLogSource::new(log_fixture_entries())),
        ));
        let service = SupervisorService::new(state);

        let mut stream = service
            .stream_logs(Request::new(pb::StreamLogsRequest {
                vm_id: "1".repeat(64),
                include_history: false,
            }))
            .await
            .unwrap()
            .into_inner();
        assert!(collect_chunks(&mut stream).await.is_empty());

        let mut stream = service
            .stream_logs(Request::new(pb::StreamLogsRequest {
                vm_id: "1".repeat(64),
                include_history: true,
            }))
            .await
            .unwrap()
            .into_inner();
        let chunks = collect_chunks(&mut stream).await;
        assert_eq!(chunks.len(), 3, "a deleted VM's history is still served");
    }

    /// A LogSource whose follows are controllable from the test: optional
    /// canned entries, then either an immediate end or a block until the
    /// stopper fires; every stop() call is counted.
    struct ControlledFollowSource {
        entries: Vec<crate::logs::LogEntry>,
        hang_after_entries: bool,
        stops: Arc<std::sync::atomic::AtomicUsize>,
    }

    struct ControlledFollowReader {
        entries: std::vec::IntoIter<crate::logs::LogEntry>,
        hang: bool,
        stopped: Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::logs::LogFollowReader for ControlledFollowReader {
        fn next_entry(&mut self) -> Option<crate::logs::LogEntry> {
            if let Some(entry) = self.entries.next() {
                return Some(entry);
            }
            while self.hang && !self.stopped.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::sleep(std::time::Duration::from_millis(2));
            }
            None
        }
    }

    struct RecordingStopper {
        stopped: Arc<std::sync::atomic::AtomicBool>,
        stops: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::logs::LogFollowStopper for RecordingStopper {
        fn stop(&self) {
            self.stops.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.stopped
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl crate::logs::LogSource for ControlledFollowSource {
        fn read_history(
            &self,
            _stdout_id: &str,
            _stderr_id: &str,
            _last_lines: Option<u32>,
        ) -> Result<Vec<crate::logs::LogEntry>, crate::logs::LogsError> {
            Ok(Vec::new())
        }

        fn follow(
            &self,
            _stdout_id: &str,
            _stderr_id: &str,
            _last_lines: u32,
        ) -> Result<crate::logs::LogFollow, crate::logs::LogsError> {
            let stopped = Arc::new(std::sync::atomic::AtomicBool::new(false));
            Ok((
                Box::new(ControlledFollowReader {
                    entries: self.entries.clone().into_iter(),
                    hang: self.hang_after_entries,
                    stopped: stopped.clone(),
                }),
                Arc::new(RecordingStopper {
                    stopped,
                    stops: self.stops.clone(),
                }),
            ))
        }
    }

    fn stream_service(
        source: ControlledFollowSource,
        max_follows: usize,
    ) -> (SupervisorService, Arc<std::sync::atomic::AtomicUsize>) {
        use crate::units::StaticUnitStates;
        let stops = source.stops.clone();
        let mut world = WorldView::default();
        world.insert_entry(fixture_entry(test_fixtures::QEMU_HASH, true));
        let mut state = DaemonState::hermetic(
            test_host_state(),
            world,
            Arc::new(StaticUnitStates::default()),
            Arc::new(source),
        );
        state.log_follows = Arc::new(tokio::sync::Semaphore::new(max_follows));
        (SupervisorService::new(Arc::new(state)), stops)
    }

    fn follow_request() -> Request<pb::StreamLogsRequest> {
        Request::new(pb::StreamLogsRequest {
            vm_id: test_fixtures::QEMU_HASH.to_string(),
            include_history: false,
        })
    }

    #[tokio::test]
    async fn stream_logs_rejects_follows_beyond_the_cap() {
        // R1: each live follow pins one blocking-pool thread; beyond the
        // semaphore cap the request is rejected RESOURCE_EXHAUSTED instead
        // of starving the pool, and a freed slot serves again.
        let (service, _stops) = stream_service(
            ControlledFollowSource {
                entries: Vec::new(),
                hang_after_entries: true,
                stops: Arc::default(),
            },
            1,
        );
        let first = service.stream_logs(follow_request()).await.unwrap();
        let error = match service.stream_logs(follow_request()).await {
            Err(status) => status,
            Ok(_) => panic!("the second follow must be rejected"),
        };
        assert_eq!(error.code(), Code::ResourceExhausted);

        // Dropping the stream frees the slot.
        drop(first);
        let third = service.stream_logs(follow_request()).await;
        assert!(third.is_ok(), "a freed slot must serve again");
    }

    #[tokio::test]
    async fn dropping_a_log_stream_stops_the_underlying_follow() {
        // C2, the StreamWithCleanup::drop path: the client goes away while
        // the follow is blocked; only the drop guard can stop (kill and
        // reap) the subprocess.
        let (service, stops) = stream_service(
            ControlledFollowSource {
                entries: Vec::new(),
                hang_after_entries: true,
                stops: Arc::default(),
            },
            MAX_CONCURRENT_LOG_FOLLOWS,
        );
        let stream = service.stream_logs(follow_request()).await.unwrap();
        assert_eq!(stops.load(std::sync::atomic::Ordering::SeqCst), 0);
        drop(stream);
        assert!(
            stops.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "dropping the response stream must stop the follow"
        );
    }

    #[tokio::test]
    async fn a_finished_pump_stops_the_follow_without_a_client_drop() {
        // C2, the pump-exit path: when the reader ends (journalctl exited
        // on its own), the pump itself must stop/reap the subprocess even
        // though the client still holds the stream.
        let (service, stops) = stream_service(
            ControlledFollowSource {
                entries: log_fixture_entries(),
                hang_after_entries: false,
                stops: Arc::default(),
            },
            MAX_CONCURRENT_LOG_FOLLOWS,
        );
        let mut stream = service
            .stream_logs(follow_request())
            .await
            .unwrap()
            .into_inner();
        let chunks = collect_chunks(&mut stream).await;
        assert_eq!(chunks.len(), 3);
        // The channel closed, so the pump already ran its exit cleanup; the
        // stream itself has NOT been dropped yet.
        assert_eq!(
            stops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the pump exit path must stop the follow"
        );
        drop(stream);
    }

    #[tokio::test]
    async fn watch_events_streams_hub_emissions() {
        use crate::logs::StaticLogSource;
        use crate::units::StaticUnitStates;
        let state = Arc::new(DaemonState::hermetic(
            test_host_state(),
            WorldView::default(),
            Arc::new(StaticUnitStates::default()),
            Arc::new(StaticLogSource::default()),
        ));
        let service = SupervisorService::new(state.clone());
        let mut stream = service
            .watch_events(Request::new(pb::WatchEventsRequest {}))
            .await
            .unwrap()
            .into_inner();
        state
            .events
            .emit("aa", pb::VmStatus::Defined, pb::VmStatus::Running);
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.vm_id, "aa");
        assert_eq!(event.old_status, pb::VmStatus::Defined as i32);
        assert_eq!(event.new_status, pb::VmStatus::Running as i32);
    }

    #[tokio::test]
    async fn a_list_that_finds_a_dead_unit_reports_failed_and_announces_it_once() {
        // The whole point of the FAILED arm: the agent's allocation
        // reconciler counts BOOTING and DEFINED as live, so a guest whose
        // QEMU exited on its own used to sit in the supervisor's list for
        // ever and never be rebuilt. ListVms is where the daemon notices.
        use crate::logs::StaticLogSource;
        use crate::units::FakeSystemd;
        let entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        let unit = entry.unit_name();
        let mut world = WorldView::default();
        world.insert_entry(entry);
        let systemd = Arc::new(FakeSystemd::with_active_vms(&[test_fixtures::QEMU_HASH]));
        let state = Arc::new(DaemonState::hermetic(
            test_host_state(),
            world,
            systemd.clone(),
            Arc::new(StaticLogSource::default()),
        ));
        let service = SupervisorService::new(state.clone());
        let mut stream = service
            .watch_events(Request::new(pb::WatchEventsRequest {}))
            .await
            .unwrap()
            .into_inner();

        async fn list(service: &SupervisorService) -> Vec<pb::VmInfo> {
            service
                .list_vms(Request::new(pb::ListVmsRequest {}))
                .await
                .unwrap()
                .into_inner()
                .vms
        }
        let vms = list(&service).await;
        assert_eq!(vms[0].status, pb::VmStatus::Running as i32);

        systemd.set_state(&unit, "failed");
        let vms = list(&service).await;
        assert_eq!(vms[0].status, pb::VmStatus::Failed as i32);
        let event = stream.next().await.unwrap().unwrap();
        assert_eq!(event.vm_id, test_fixtures::QEMU_HASH);
        assert_eq!(event.old_status, pb::VmStatus::Running as i32);
        assert_eq!(event.new_status, pb::VmStatus::Failed as i32);

        // A second list still reports FAILED, and says so without repeating
        // the announcement: the agent polls this call.
        let vms = list(&service).await;
        assert_eq!(vms[0].status, pb::VmStatus::Failed as i32);
        // GetVm agrees, and is not a second announcement either.
        let info = service
            .get_vm(Request::new(pb::GetVmRequest {
                vm_id: test_fixtures::QEMU_HASH.to_string(),
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(info.status, pb::VmStatus::Failed as i32);
        // A sentinel proves the reads queued nothing behind the one death:
        // the next event off the stream is this one, not a repeat.
        state
            .events
            .emit("sentinel", pb::VmStatus::Defined, pb::VmStatus::Running);
        assert_eq!(stream.next().await.unwrap().unwrap().vm_id, "sentinel");
    }

    #[test]
    fn the_journal_subprocess_is_bounded_except_for_head_reads() {
        // "unlimited" requests get the server cap, tail requests pass
        // their own bound, and head reads
        // cannot use -n (it keeps the LAST n entries) so they slice after
        // parsing instead.
        assert_eq!(journal_tail_bound(0, false), Some(GET_LOGS_SERVER_CAP));
        assert_eq!(journal_tail_bound(0, true), Some(GET_LOGS_SERVER_CAP));
        assert_eq!(journal_tail_bound(50, true), Some(50));
        assert_eq!(journal_tail_bound(50, false), None);
    }
}
