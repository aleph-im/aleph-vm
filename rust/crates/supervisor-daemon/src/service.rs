//! The Supervisor gRPC service, increment 1.
//!
//! Health and GetHostInfo are field-for-field ports of the Python
//! LocalSupervisor (src/aleph/vm/supervisor/local.py). Every other RPC
//! aborts UNIMPLEMENTED the way the Python `_abort` does for
//! NotImplementedSupervisorError: grpc-status UNIMPLEMENTED plus a
//! serialized ErrorDetail (code INTERNAL, the wire code of
//! NotImplementedSupervisorError) in the `aleph-supervisor-error-bin`
//! trailer. The Python client maps UNIMPLEMENTED to
//! NotImplementedSupervisorError before reading the trailer, so both
//! encodings agree.

use std::pin::Pin;
use std::sync::Arc;

use prost::Message;
use supervisor_proto::ERROR_TRAILER_KEY;
use supervisor_proto::pb;
use supervisor_proto::pb::supervisor_server::Supervisor;
use tokio_stream::Stream;
use tonic::metadata::{MetadataMap, MetadataValue};
use tonic::{Code, Request, Response, Status};

use crate::config::Settings;
use crate::error::DaemonError;
use crate::lspci::GpuDevice;
use crate::{host, lspci, net};

/// Host facts resolved once at daemon startup, exactly when the Python
/// daemon resolves them: host_ipv4 at Network construction (pool.__init__),
/// the GPU inventory in pool.setup(). A failure aborts startup, as it does
/// in Python.
#[derive(Debug, Clone)]
pub struct HostState {
    pub settings: Settings,
    /// Primary IPv4 of the external interface; empty when host networking is
    /// disabled (ALLOW_VM_NETWORKING=false, where the Python pool has no
    /// Network object).
    pub host_ipv4: String,
    /// Raw lspci inventory; empty unless ENABLE_GPU_SUPPORT is set.
    pub gpus: Vec<GpuDevice>,
}

impl HostState {
    pub fn initialize(settings: Settings) -> Result<Self, DaemonError> {
        let host_ipv4 = if settings.allow_vm_networking {
            let interface = match &settings.network_interface {
                Some(name) => name.clone(),
                // conf.py setup(): NETWORK_INTERFACE defaults to the default
                // route interface; check() aborts when there is none.
                None => net::default_interface()?.ok_or(DaemonError::NoNetworkInterface)?,
            };
            let address = net::get_interface_ipv4(&interface)?;
            tracing::info!(interface, address, "resolved host IPv4");
            address
        } else {
            String::new()
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
            gpus,
        })
    }
}

pub struct SupervisorService {
    state: Arc<HostState>,
}

impl SupervisorService {
    pub fn new(state: Arc<HostState>) -> Self {
        Self { state }
    }

    async fn host_info(&self) -> Result<pb::HostInfo, DaemonError> {
        let (kernel_version, hostname) = host::uname_release_and_nodename()?;
        let inventory_json = gpu_json(&self.state.gpus)?;
        // No VM holds a GPU in increment 1 (there are no VMs), so the
        // available list equals the inventory, as in
        // VmPool.get_available_gpus with no executions.
        let available_json = inventory_json.clone();
        // statvfs can block indefinitely on a hung backing device; run it on
        // the blocking pool so it cannot pin a tokio worker and take Health
        // down with it. The /proc/meminfo and uname reads stay inline: they
        // are instant in-kernel lookups.
        let volumes_dir = self.state.settings.persistent_volumes_dir.clone();
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
            host_ipv4: self.state.host_ipv4.clone(),
            available_disk_bytes,
            gpu_inventory_json: inventory_json,
            available_gpus_json: available_json,
            ..Default::default()
        })
    }
}

fn gpu_json(gpus: &[GpuDevice]) -> Result<String, DaemonError> {
    serde_json::to_string(gpus).map_err(|error| {
        DaemonError::Internal(format!("GPU inventory serialization failed: {error}"))
    })
}

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

/// UNIMPLEMENTED with the trailer NotImplementedSupervisorError carries
/// (wire code INTERNAL; the status code alone distinguishes it, which is
/// what the Python client keys on).
fn unimplemented_status(rpc: &str) -> Status {
    let message = format!(
        "{rpc} is not implemented yet by the Rust supervisor daemon (increment 1 serves Health and GetHostInfo)"
    );
    status_with_error_detail(Code::Unimplemented, pb::ErrorCode::Internal, message)
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
        // (always zero in increment 1: the daemon runs no VMs yet).
        Ok(Response::new(pb::HealthResponse {
            status: pb::HealthStatus::Ok as i32,
            vm_count: 0,
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

    // ── VM lifecycle (increments 2-4) ──
    async fn create_vm(
        &self,
        _request: Request<pb::VmSpec>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("CreateVm"))
    }

    async fn get_vm(
        &self,
        _request: Request<pb::GetVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("GetVm"))
    }

    async fn get_vm_spec(
        &self,
        _request: Request<pb::GetVmSpecRequest>,
    ) -> Result<Response<pb::VmSpec>, Status> {
        Err(unimplemented_status("GetVmSpec"))
    }

    async fn list_vms(
        &self,
        _request: Request<pb::ListVmsRequest>,
    ) -> Result<Response<pb::ListVmsResponse>, Status> {
        Err(unimplemented_status("ListVms"))
    }

    async fn delete_vm(
        &self,
        _request: Request<pb::DeleteVmRequest>,
    ) -> Result<Response<pb::DeleteVmResponse>, Status> {
        Err(unimplemented_status("DeleteVm"))
    }

    async fn stop_vm(
        &self,
        _request: Request<pb::StopVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("StopVm"))
    }

    async fn start_vm(
        &self,
        _request: Request<pb::StartVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("StartVm"))
    }

    async fn reboot_vm(
        &self,
        _request: Request<pb::RebootVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("RebootVm"))
    }

    async fn reinstall_vm(
        &self,
        _request: Request<pb::ReinstallVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("ReinstallVm"))
    }

    async fn run_program_code(
        &self,
        _request: Request<pb::RunProgramCodeRequest>,
    ) -> Result<Response<pb::RunProgramCodeResponse>, Status> {
        Err(unimplemented_status("RunProgramCode"))
    }

    async fn restore_from_image(
        &self,
        _request: Request<pb::RestoreFromImageRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(unimplemented_status("RestoreFromImage"))
    }

    // ── Port forwarding (increment 3) ──
    async fn add_port_forward(
        &self,
        _request: Request<pb::AddPortForwardRequest>,
    ) -> Result<Response<pb::PortForwardInfo>, Status> {
        Err(unimplemented_status("AddPortForward"))
    }

    async fn remove_port_forward(
        &self,
        _request: Request<pb::RemovePortForwardRequest>,
    ) -> Result<Response<pb::RemovePortForwardResponse>, Status> {
        Err(unimplemented_status("RemovePortForward"))
    }

    async fn list_port_forwards(
        &self,
        _request: Request<pb::ListPortForwardsRequest>,
    ) -> Result<Response<pb::ListPortForwardsResponse>, Status> {
        Err(unimplemented_status("ListPortForwards"))
    }

    // ── Events (increment 4) ──
    type WatchEventsStream = UnimplementedStream<pb::VmEvent>;

    async fn watch_events(
        &self,
        _request: Request<pb::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        Err(unimplemented_status("WatchEvents"))
    }

    // ── Logs (increments 2 and 4) ──
    async fn get_logs(
        &self,
        _request: Request<pb::GetLogsRequest>,
    ) -> Result<Response<pb::GetLogsResponse>, Status> {
        Err(unimplemented_status("GetLogs"))
    }

    type StreamLogsStream = UnimplementedStream<pb::LogChunk>;

    async fn stream_logs(
        &self,
        _request: Request<pb::StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        Err(unimplemented_status("StreamLogs"))
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

    // ── Network (increment 3) ──
    async fn recreate_network(
        &self,
        _request: Request<pb::RecreateNetworkRequest>,
    ) -> Result<Response<pb::RecreateNetworkResponse>, Status> {
        Err(unimplemented_status("RecreateNetwork"))
    }
}
