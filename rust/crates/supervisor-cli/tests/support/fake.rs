//! In-process fake supervisor: canned data behind the real tonic server
//! codegen, served on a temp-dir Unix socket. The CLI-relevant RPCs return
//! the struct's canned fields; everything else answers UNIMPLEMENTED.
//!
//! The unimplemented methods are written out explicitly (no macro): tonic's
//! async_trait attribute rewrites the impl block before declarative macros
//! expand, so generated `async fn`s would not be desugared (matches the
//! daemon's own service.rs).

use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use prost::Message as _;
use supervisor_proto::pb::supervisor_server::{Supervisor, SupervisorServer};
use supervisor_proto::{ERROR_TRAILER_KEY, pb};
use tokio_stream::Stream;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status};

type BoxStream<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

#[derive(Default)]
#[allow(dead_code)] // fields used by Tasks 6-9
pub struct FakeSupervisor {
    pub host: pb::HostInfo,
    pub vms: Vec<pb::VmInfo>,
    pub spec: Option<pb::VmSpec>,
    pub forwards: Vec<pb::PortForwardInfo>,
    pub logs: Vec<pb::LogChunk>,
    pub events: Vec<pb::VmEvent>,
    /// vm_ids DeleteVm was called with; tests clone the Arc before spawn.
    pub deleted: Arc<Mutex<Vec<String>>>,
    /// Every GetLogsRequest received; tests assert tail/from_tail mapping.
    pub log_requests: Arc<Mutex<Vec<pb::GetLogsRequest>>>,
}

impl FakeSupervisor {
    #[allow(dead_code)] // used from Task 6 on
    fn find_vm(&self, vm_id: &str) -> Option<&pb::VmInfo> {
        self.vms.iter().find(|vm| vm.vm_id == vm_id)
    }
}

/// NOT_FOUND with the same ErrorDetail trailer the real daemon attaches,
/// so the CLI's trailer decoding is exercised end-to-end.
#[allow(dead_code)] // used from Task 6 on
fn not_found(vm_id: &str) -> Status {
    let message = format!("no VM with id {vm_id}");
    let detail = pb::ErrorDetail {
        code: pb::ErrorCode::VmNotFound as i32,
        message: message.clone(),
        vm_id: vm_id.to_string(),
    };
    let mut metadata = tonic::metadata::MetadataMap::new();
    metadata.insert_bin(
        ERROR_TRAILER_KEY,
        tonic::metadata::MetadataValue::from_bytes(&detail.encode_to_vec()),
    );
    Status::with_metadata(tonic::Code::NotFound, message, metadata)
}

#[tonic::async_trait]
impl Supervisor for FakeSupervisor {
    async fn health(
        &self,
        _request: Request<pb::HealthRequest>,
    ) -> Result<Response<pb::HealthResponse>, Status> {
        Ok(Response::new(pb::HealthResponse {
            status: pb::HealthStatus::Ok as i32,
            vm_count: self.vms.len() as u32,
        }))
    }

    async fn get_host_info(
        &self,
        _request: Request<pb::GetHostInfoRequest>,
    ) -> Result<Response<pb::HostInfo>, Status> {
        Ok(Response::new(self.host.clone()))
    }

    async fn create_vm(
        &self,
        _request: Request<pb::VmSpec>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn get_vm(
        &self,
        _request: Request<pb::GetVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn get_vm_spec(
        &self,
        _request: Request<pb::GetVmSpecRequest>,
    ) -> Result<Response<pb::VmSpec>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn list_vms(
        &self,
        _request: Request<pb::ListVmsRequest>,
    ) -> Result<Response<pb::ListVmsResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn delete_vm(
        &self,
        _request: Request<pb::DeleteVmRequest>,
    ) -> Result<Response<pb::DeleteVmResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn stop_vm(
        &self,
        _request: Request<pb::StopVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn start_vm(
        &self,
        _request: Request<pb::StartVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn reboot_vm(
        &self,
        _request: Request<pb::RebootVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn reinstall_vm(
        &self,
        _request: Request<pb::ReinstallVmRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn run_program_code(
        &self,
        _request: Request<pb::RunProgramCodeRequest>,
    ) -> Result<Response<pb::RunProgramCodeResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn restore_from_image(
        &self,
        _request: Request<pb::RestoreFromImageRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn add_port_forward(
        &self,
        _request: Request<pb::AddPortForwardRequest>,
    ) -> Result<Response<pb::PortForwardInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn remove_port_forward(
        &self,
        _request: Request<pb::RemovePortForwardRequest>,
    ) -> Result<Response<pb::RemovePortForwardResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn list_port_forwards(
        &self,
        _request: Request<pb::ListPortForwardsRequest>,
    ) -> Result<Response<pb::ListPortForwardsResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn get_logs(
        &self,
        _request: Request<pb::GetLogsRequest>,
    ) -> Result<Response<pb::GetLogsResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn start_backup(
        &self,
        _request: Request<pb::StartBackupRequest>,
    ) -> Result<Response<pb::BackupInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn get_backup_status(
        &self,
        _request: Request<pb::GetBackupStatusRequest>,
    ) -> Result<Response<pb::BackupInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn list_backups(
        &self,
        _request: Request<pb::ListBackupsRequest>,
    ) -> Result<Response<pb::ListBackupsResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn delete_backup(
        &self,
        _request: Request<pb::DeleteBackupRequest>,
    ) -> Result<Response<pb::DeleteBackupResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn restore_backup(
        &self,
        _request: Request<pb::RestoreBackupRequest>,
    ) -> Result<Response<pb::VmInfo>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn initialize_confidential(
        &self,
        _request: Request<pb::InitializeConfidentialRequest>,
    ) -> Result<Response<pb::InitializeConfidentialResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn get_measurement(
        &self,
        _request: Request<pb::GetMeasurementRequest>,
    ) -> Result<Response<pb::Measurement>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn inject_secret(
        &self,
        _request: Request<pb::InjectSecretRequest>,
    ) -> Result<Response<pb::InjectSecretResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    async fn recreate_network(
        &self,
        _request: Request<pb::RecreateNetworkRequest>,
    ) -> Result<Response<pb::RecreateNetworkResponse>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    type WatchEventsStream = BoxStream<pb::VmEvent>;
    async fn watch_events(
        &self,
        _request: Request<pb::WatchEventsRequest>,
    ) -> Result<Response<Self::WatchEventsStream>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    type StreamLogsStream = BoxStream<pb::LogChunk>;
    async fn stream_logs(
        &self,
        _request: Request<pb::StreamLogsRequest>,
    ) -> Result<Response<Self::StreamLogsStream>, Status> {
        Err(Status::unimplemented("not faked"))
    }

    type DownloadBackupStream = BoxStream<pb::BackupChunk>;
    async fn download_backup(
        &self,
        _request: Request<pb::DownloadBackupRequest>,
    ) -> Result<Response<Self::DownloadBackupStream>, Status> {
        Err(Status::unimplemented("not faked"))
    }
}

/// Serve `fake` on a socket in a fresh temp dir. The TempDir keeps the
/// socket alive for the test's lifetime; the server task ends with the
/// runtime.
pub async fn spawn(fake: FakeSupervisor) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("supervisor.sock");
    let listener = tokio::net::UnixListener::bind(&path).expect("bind test socket");
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(SupervisorServer::new(fake))
            .serve_with_incoming(UnixListenerStream::new(listener))
            .await
            .expect("fake supervisor server");
    });
    (dir, path)
}
