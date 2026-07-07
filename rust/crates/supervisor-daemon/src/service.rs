//! The Supervisor gRPC service, increments 1-3.
//!
//! Health, GetHostInfo, GetVm, GetVmSpec, ListVms, ListPortForwards and
//! GetLogs are field-for-field ports of the Python LocalSupervisor
//! (src/aleph/vm/supervisor/local.py) as observed after a daemon restart:
//! the pool state is the world view rebuilt from disk/systemd/sqlite
//! (src/world.rs), unit liveness is queried live per RPC like
//! `_is_running`/`_running_states`, and the VmSpec served for an adopted VM
//! is the `spec_from_controller_configuration` reconstruction
//! (src/aleph/vm/supervisor/qemu_build.py) the restarted Python daemon
//! holds. The lifecycle mutations live in src/lifecycle.rs and run on the
//! blocking pool. Every other RPC aborts UNIMPLEMENTED the way the Python `_abort`
//! does for NotImplementedSupervisorError: grpc-status UNIMPLEMENTED plus a
//! serialized ErrorDetail (code INTERNAL, the wire code of
//! NotImplementedSupervisorError) in the `aleph-supervisor-error-bin`
//! trailer. The Python client maps UNIMPLEMENTED to
//! NotImplementedSupervisorError before reading the trailer, so both
//! encodings agree.

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
use crate::units::UnitStateSource;
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
            (None, Some(interface)) => Some(
                net::obtain_dns_ips(settings.dns_resolution, interface)
                    .map_err(DaemonError::Internal)?,
            ),
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
    /// RESOURCE_EXHAUSTED (Rust-only bound, ledger entry 44).
    pub log_follows: Arc<tokio::sync::Semaphore>,
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
            ndp: None,
            port_cursor: crate::ports::PortCursor::default(),
            creation_lock: std::sync::Mutex::new(()),
            vm_locks: std::sync::Mutex::new(HashMap::new()),
            net_lock: std::sync::Mutex::new(()),
            pacing: crate::lifecycle::Pacing::instant(),
            events: crate::events::EventHub::default(),
            programs: Arc::new(crate::firecracker::FakeProgramLauncher::new()),
            log_follows: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_LOG_FOLLOWS)),
        }
    }
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
        let inventory_json = gpu_json(&self.state.host.gpus)?;
        // Available = inventory minus the GPUs the world view's controller
        // configs attach (ledger entry 14, closed: post-#1023 Python
        // rebuilds the attachments for VMs adopted running; the config
        // union here also withholds adopted-STOPPED VMs' cards, which
        // Python destroys at startup, entry 11).
        let attached: HashSet<String> = {
            let world = self.state.world.read().await;
            world
                .entries
                .values()
                .flat_map(|entry| entry.config.gpus.iter().map(|gpu| gpu.pci_host.clone()))
                .collect()
        };
        let available: Vec<&GpuDevice> = self
            .state
            .host
            .gpus
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
        let volumes_dir = self.state.host.settings.persistent_volumes_dir.clone();
        let available_disk_bytes =
            tokio::task::spawn_blocking(move || host::available_disk_bytes(&volumes_dir))
                .await
                .map_err(|error| {
                    DaemonError::Internal(format!("the statvfs task failed: {error}"))
                })??;
        Ok(pb::HostInfo {
            // Only the fields LocalSupervisor.get_host_info fills; the rest
            // keep their proto defaults, exactly like the Python HostInfo
            // dataclass defaults (cpu_architecture, cpu_vendor, cpu_model,
            // frequencies, memory type, NUMA topology, the narrow gpus list
            // and the SEV/TDX flags all ride empty today).
            cpu_count: host::cpu_count(),
            memory_mib: host::memory_total_mib()?,
            kernel_version,
            hostname,
            host_ipv4: self.state.host.host_ipv4.clone(),
            available_disk_bytes,
            gpu_inventory_json: inventory_json,
            available_gpus_json: available_json,
            ..Default::default()
        })
    }

    /// Live active flag for one entry's controller unit, off the runtime
    /// threads (the Python `_is_running` D-Bus query equivalent). A bus
    /// failure degrades to "inactive", the Python
    /// `get_services_active_states` parity behavior (ledger entry 13).
    async fn unit_running(&self, unit: String) -> Result<bool, Status> {
        let units = self.state.units.clone();
        tokio::task::spawn_blocking(move || {
            match units.active_states(std::slice::from_ref(&unit)) {
                Ok(states) => states.get(&unit).copied().unwrap_or(false),
                Err(error) => {
                    tracing::error!(error, "Failed to get services active states");
                    false
                }
            }
        })
        .await
        .map_err(|error| {
            internal_status(DaemonError::Internal(format!(
                "the unit-state task failed: {error}"
            )))
        })
    }

    /// Live active flags for every entry, one batched query (the Python
    /// `_running_states` ListUnits call, pushed off the loop like
    /// `asyncio.to_thread` in list_vms). Bus failures degrade to
    /// all-inactive, like the Python method (ledger entry 13).
    async fn units_running(
        &self,
        unit_names: Vec<String>,
    ) -> Result<HashMap<String, bool>, Status> {
        let units = self.state.units.clone();
        tokio::task::spawn_blocking(move || match units.active_states(&unit_names) {
            Ok(states) => states,
            Err(error) => {
                tracing::error!(error, "Failed to get services active states");
                unit_names
                    .iter()
                    .map(|unit| (unit.clone(), false))
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

// ── World view to wire mapping ──────────────────────────────────────────

/// `_status_of`, ported literally: the times short-circuit the live flag.
pub(crate) fn vm_status(times: &VmTimes, running: bool) -> pb::VmStatus {
    if times.stopped_at_ns != 0 {
        pb::VmStatus::Stopped
    } else if times.stopping_at_ns != 0 {
        pb::VmStatus::Stopping
    } else if running {
        pb::VmStatus::Running
    } else if times.starting_at_ns != 0 {
        pb::VmStatus::Booting
    } else {
        pb::VmStatus::Defined
    }
}

/// `_to_vm_info` for an adopted execution.
pub fn vm_info_message(entry: &VmEntry, running: bool, now_ns: u64) -> pb::VmInfo {
    let times = &entry.times;
    // `_uptime_secs`: seconds since started_at while running, else 0.
    let uptime_secs = if running && times.started_at_ns != 0 {
        now_ns.saturating_sub(times.started_at_ns) / 1_000_000_000
    } else {
        0
    };
    let confidential = entry.config.confidential();
    let confidential_mode = match &confidential {
        None => pb::ConfidentialMode::None,
        Some(config) if config.sev_policy & SEV_ES_POLICY_BIT != 0 => pb::ConfidentialMode::SevEs,
        Some(_) => pb::ConfidentialMode::Sev,
    };
    // `is_awaiting_confidential_init`, ported literally: confidential,
    // persistent (every adopted VM is), started but neither stopping nor
    // observed running.
    let awaiting_confidential_init =
        confidential.is_some() && times.started_at_ns != 0 && times.stopping_at_ns == 0 && !running;
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
        status: vm_status(times, running) as i32,
        ipv4: Some(ip(&entry.ipv4)),
        ipv6: Some(ip(&entry.ipv6)),
        uptime_secs,
        backend: backend as i32,
        numa_node: None,
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
        // running VMs (post-#1023 Python; ledger entry 14, closed) and set
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
    let tee = config.confidential().map(|confidential| pb::TeeConfig {
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
    });
    pb::VmSpec {
        vm_id: entry.vm_hash.clone(),
        backend: pb::Backend::Qemu as i32,
        kernel_path: String::new(),
        initrd_path: String::new(),
        disks,
        vcpus: config.vcpu_count,
        memory_mib: config.mem_size_mb,
        tee,
        network: Some(pb::NetworkConfig {
            // Python: bool(vm_cfg.interface_name).
            internet_access: config
                .interface_name
                .as_deref()
                .is_some_and(|name| !name.is_empty()),
            requested_ipv6: String::new(),
            ipv6_prefix_len: 0,
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

/// Rust-only server cap on GetLogs history (ledger entry 16): the proto
/// documents max_lines 0 as "unlimited (subject to server cap)"; Python has
/// no cap today and buffers the whole journal.
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

/// UNIMPLEMENTED with the trailer NotImplementedSupervisorError carries
/// (wire code INTERNAL; the status code alone distinguishes it, which is
/// what the Python client keys on).
fn unimplemented_status(rpc: &str) -> Status {
    let message = format!(
        "{rpc} is not implemented yet by the Rust supervisor daemon (increment 3 serves the host, read-only and persistent lifecycle RPCs)"
    );
    status_with_error_detail(Code::Unimplemented, pb::ErrorCode::Internal, message)
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

type UnimplementedStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

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
        Ok(Response::new(vm_info_message(&entry, running, now_ns())))
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
        let running = if entry.is_program {
            entry.times.starting_at_ns != 0 && entry.times.stopping_at_ns == 0
        } else {
            self.unit_running(entry.unit_name()).await?
        };
        Ok(Response::new(vm_info_message(&entry, running, now_ns())))
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
        let states = self.units_running(unit_names).await?;
        let now = now_ns();
        let vms = entries
            .iter()
            .map(|entry| {
                let running = if entry.is_program {
                    entry.times.starting_at_ns != 0 && entry.times.stopping_at_ns == 0
                } else {
                    states.get(&entry.unit_name()).copied().unwrap_or(false)
                };
                vm_info_message(entry, running, now)
            })
            .collect();
        Ok(Response::new(pb::ListVmsResponse { vms }))
    }

    async fn delete_vm(
        &self,
        request: Request<pb::DeleteVmRequest>,
    ) -> Result<Response<pb::DeleteVmResponse>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        run_lifecycle(move || {
            crate::lifecycle::delete_vm(
                &state,
                &request.vm_id,
                request.wipe,
                request.keep_port_mappings,
            )
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
        Ok(Response::new(vm_info_message(&entry, false, now_ns())))
    }

    async fn start_vm(
        &self,
        request: Request<pb::StartVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        let (entry, running) =
            run_lifecycle(move || crate::lifecycle::start_vm(&state, &vm_id)).await?;
        Ok(Response::new(vm_info_message(&entry, running, now_ns())))
    }

    async fn reboot_vm(
        &self,
        request: Request<pb::RebootVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let state = self.state.clone();
        let vm_id = request.into_inner().vm_id;
        let (entry, running) =
            run_lifecycle(move || crate::lifecycle::reboot_vm(&state, &vm_id)).await?;
        Ok(Response::new(vm_info_message(&entry, running, now_ns())))
    }

    async fn reinstall_vm(
        &self,
        request: Request<pb::ReinstallVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        let state = self.state.clone();
        let request = request.into_inner();
        // `optional bool`: an unset field takes the Python ABC's default
        // (wipe_volumes=True), as the proto documents.
        let wipe_volumes = request.wipe_volumes.unwrap_or(true);
        let (entry, running) = run_lifecycle(move || {
            crate::lifecycle::reinstall_vm(&state, &request.vm_id, wipe_volumes)
        })
        .await?;
        Ok(Response::new(vm_info_message(&entry, running, now_ns())))
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

    async fn restore_from_image(
        &self,
        _request: Request<pb::RestoreFromImageRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("RestoreFromImage"))
    }

    // ── Port forwarding ──
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
        .map_err(|error| internal_status(DaemonError::Internal(error)))?;
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
                // Server-capped like GetLogs max_lines=0 (ledger entry 16).
                logs.read_history(&stdout_id, &stderr_id, Some(GET_LOGS_SERVER_CAP))
            })
            .await
            .map_err(|error| {
                internal_status(DaemonError::Internal(format!(
                    "the journal task failed: {error}"
                )))
            })?
            .map_err(|error| internal_status(DaemonError::Internal(error)))?;
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
        // history replay (server cap, ledger entry 16) when asked, then
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
                .map_err(|error| internal_status(DaemonError::Internal(error)))?;
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

    // ── Backups (increment 5) ──
    async fn start_backup(
        &self,
        _request: Request<pb::StartBackupRequest>,
    ) -> Result<Response<pb::BackupInfo>, Status> {
        Err(unimplemented_status("StartBackup"))
    }

    async fn get_backup_status(
        &self,
        _request: Request<pb::GetBackupStatusRequest>,
    ) -> Result<Response<pb::BackupInfo>, Status> {
        Err(unimplemented_status("GetBackupStatus"))
    }

    async fn list_backups(
        &self,
        _request: Request<pb::ListBackupsRequest>,
    ) -> Result<Response<pb::ListBackupsResponse>, Status> {
        Err(unimplemented_status("ListBackups"))
    }

    type DownloadBackupStream = UnimplementedStream<pb::BackupChunk>;

    async fn download_backup(
        &self,
        _request: Request<pb::DownloadBackupRequest>,
    ) -> Result<Response<Self::DownloadBackupStream>, Status> {
        Err(unimplemented_status("DownloadBackup"))
    }

    async fn delete_backup(
        &self,
        _request: Request<pb::DeleteBackupRequest>,
    ) -> Result<Response<pb::DeleteBackupResponse>, Status> {
        Err(unimplemented_status("DeleteBackup"))
    }

    async fn restore_backup(
        &self,
        _request: Request<pb::RestoreBackupRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("RestoreBackup"))
    }

    // ── Confidential (increment 6) ──
    async fn initialize_confidential(
        &self,
        _request: Request<pb::InitializeConfidentialRequest>,
    ) -> Result<Response<pb::InitializeConfidentialResponse>, Status> {
        Err(unimplemented_status("InitializeConfidential"))
    }

    async fn get_measurement(
        &self,
        _request: Request<pb::GetMeasurementRequest>,
    ) -> Result<Response<pb::Measurement>, Status> {
        Err(unimplemented_status("GetMeasurement"))
    }

    async fn inject_secret(
        &self,
        _request: Request<pb::InjectSecretRequest>,
    ) -> Result<Response<pb::InjectSecretResponse>, Status> {
        Err(unimplemented_status("InjectSecret"))
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
        }
    }

    #[test]
    fn a_running_adopted_vm_maps_like_the_python_to_vm_info() {
        let entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        let now = entry.times.started_at_ns + 7_500_000_000;
        let info = vm_info_message(&entry, true, now);
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
        // StopVm whose unit is started manually; the deliberate parity
        // wart of ledger entry 11).
        let entry = fixture_entry(test_fixtures::QEMU_HASH, false);
        for live in [false, true] {
            let info = vm_info_message(&entry, live, now_ns());
            assert_eq!(info.status, pb::VmStatus::Stopped as i32);
            assert_eq!(info.uptime_secs, 0);
        }
        let info = vm_info_message(&entry, false, now_ns());
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
        let info = vm_info_message(&entry, true, now_ns());
        assert_eq!(info.status, pb::VmStatus::Running as i32);
        assert_eq!(info.uptime_secs, 0, "no started_at was ever stamped");
        let info = vm_info_message(&entry, false, now_ns());
        assert_eq!(info.status, pb::VmStatus::Defined as i32);
    }

    #[test]
    fn a_running_adopted_vm_whose_unit_died_reports_defined() {
        // The Python wart, ported: the restore path never sets starting_at
        // or stopped_at, so a dead unit falls through _status_of to DEFINED.
        let entry = fixture_entry(test_fixtures::QEMU_HASH, true);
        let info = vm_info_message(&entry, false, now_ns());
        assert_eq!(info.status, pb::VmStatus::Defined as i32);
        assert_eq!(info.uptime_secs, 0);
    }

    #[test]
    fn confidential_mode_follows_the_sev_policy_bit() {
        let entry = fixture_entry(test_fixtures::CONFIDENTIAL_HASH, true);
        // The fixture's policy is 0x5: the SEV_ES bit (0x4) is set.
        let info = vm_info_message(&entry, true, now_ns());
        assert_eq!(info.confidential_mode, pb::ConfidentialMode::SevEs as i32);
        assert!(!info.awaiting_confidential_init);
        // A confidential VM with a dead unit but started_at set is
        // "awaiting init" in Python's formula; port it literally.
        let info = vm_info_message(&entry, false, now_ns());
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
        ) -> Result<Vec<crate::logs::LogEntry>, String> {
            Ok(Vec::new())
        }

        fn follow(
            &self,
            _stdout_id: &str,
            _stderr_id: &str,
            _last_lines: u32,
        ) -> Result<crate::logs::LogFollow, String> {
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

    #[test]
    fn the_journal_subprocess_is_bounded_except_for_head_reads() {
        // R3: "unlimited" requests get the Rust-only server cap (ledger
        // entry 16), tail requests pass their own bound, and head reads
        // cannot use -n (it keeps the LAST n entries) so they slice after
        // parsing instead.
        assert_eq!(journal_tail_bound(0, false), Some(GET_LOGS_SERVER_CAP));
        assert_eq!(journal_tail_bound(0, true), Some(GET_LOGS_SERVER_CAP));
        assert_eq!(journal_tail_bound(50, true), Some(50));
        assert_eq!(journal_tail_bound(50, false), None);
    }
}
