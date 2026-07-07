//! In-crate integration test: boot the server on a temp-dir socket and drive
//! it through a real tonic client over the Unix socket, no Python involved.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use prost::Message;
use supervisor_daemon::config::Settings;
use supervisor_daemon::logs::StaticLogSource;
use supervisor_daemon::server::{self, SocketGuard};
use supervisor_daemon::service::{DaemonState, HostState};
use supervisor_daemon::units::StaticUnitStates;
use supervisor_daemon::world::WorldView;
use supervisor_proto::ERROR_TRAILER_KEY;
use supervisor_proto::pb;
use supervisor_proto::pb::supervisor_client::SupervisorClient;
use tonic::Code;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

fn test_settings(root: &Path) -> Settings {
    let mut settings = Settings::from_vars(
        [(
            "ALEPH_VM_EXECUTION_ROOT".to_string(),
            root.to_string_lossy().into_owned(),
        )]
        .into_iter(),
    )
    .unwrap();
    // Hermetic: no dependency on the test host's routing table. The
    // Python parity for this configuration is host_ipv4 == "".
    settings.allow_vm_networking = false;
    settings
}

fn empty_daemon_state(settings: Settings) -> Arc<DaemonState> {
    let host = HostState::initialize(settings).unwrap();
    Arc::new(DaemonState::hermetic(
        host,
        WorldView::default(),
        Arc::new(StaticUnitStates::default()),
        Arc::new(StaticLogSource::default()),
    ))
}

async fn connect(socket_path: PathBuf) -> Channel {
    // The URI is ignored; every connection goes to the Unix socket.
    Endpoint::try_from("http://socket.invalid")
        .unwrap()
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = socket_path.clone();
            async move {
                Ok::<_, std::io::Error>(TokioIo::new(tokio::net::UnixStream::connect(path).await?))
            }
        }))
        .await
        .expect("failed to connect to the daemon socket")
}

async fn wait_for_socket(path: &Path) {
    use std::os::unix::fs::FileTypeExt;
    for _ in 0..200 {
        // A stale regular file may still sit at the path until the server
        // task replaces it; wait for an actual socket.
        if std::fs::metadata(path).is_ok_and(|meta| meta.file_type().is_socket()) {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("socket {} did not appear", path.display());
}

#[tokio::test]
async fn serves_health_and_host_info_on_a_unix_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let settings = test_settings(tmp.path());
    let socket_path = settings.supervisor_grpc_socket.clone();

    server::prepare_directories(&settings).unwrap();
    assert!(settings.persistent_volumes_dir.is_dir());

    // A stale socket from a "previous run" must be unlinked, not a bind error.
    std::fs::write(&socket_path, b"stale").unwrap();

    let state = empty_daemon_state(settings);
    let guard = Arc::new(SocketGuard::new(socket_path.clone()));
    // The same first-signal channel main.rs feeds serve with (its SIGTERM
    // handler flips it to true).
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let server_task = tokio::spawn(server::serve(state, guard, shutdown_rx));

    wait_for_socket(&socket_path).await;
    let mode = std::fs::metadata(&socket_path)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o700, "socket must be chmod 0700");

    let mut client = SupervisorClient::new(connect(socket_path.clone()).await);

    // Health: always OK with zero VMs, like a fresh Python daemon.
    let health = client
        .health(pb::HealthRequest {})
        .await
        .unwrap()
        .into_inner();
    assert_eq!(health.status, pb::HealthStatus::Ok as i32);
    assert_eq!(health.vm_count, 0);

    // GetHostInfo: the increment 1 fields are filled, the others stay at
    // their proto defaults (the Python daemon leaves them empty too).
    let info = client
        .get_host_info(pb::GetHostInfoRequest {})
        .await
        .unwrap()
        .into_inner();
    assert!(info.cpu_count >= 1);
    assert!(info.memory_mib > 0);
    assert!(!info.kernel_version.is_empty());
    assert!(!info.hostname.is_empty());
    assert!(info.available_disk_bytes > 0);
    assert_eq!(
        info.host_ipv4, "",
        "networking disabled means empty host_ipv4"
    );
    assert_eq!(info.gpu_inventory_json, "[]");
    assert_eq!(info.available_gpus_json, "[]");
    assert_eq!(info.cpu_architecture, "");
    assert_eq!(info.cpu_vendor, "");
    assert_eq!(info.cpu_model, "");
    assert_eq!(info.cpu_frequency_mhz, 0);
    assert_eq!(info.memory_type, "");
    assert_eq!(info.memory_clock_mhz, 0);
    assert!(info.numa_nodes.is_empty());
    assert!(info.gpus.is_empty());
    assert!(!info.sev_supported);
    assert!(!info.sev_es_supported);
    assert!(!info.sev_snp_supported);
    assert!(!info.tdx_supported);

    // Unported RPCs: UNIMPLEMENTED with the ErrorDetail trailer the Python
    // _abort attaches (wire code INTERNAL for NotImplementedSupervisorError).
    let status = client
        .start_backup(pb::StartBackupRequest::default())
        .await
        .expect_err("StartBackup must be unimplemented until increment 5");
    assert_eq!(status.code(), Code::Unimplemented);
    let trailer = status
        .metadata()
        .get_bin(ERROR_TRAILER_KEY)
        .expect("the ErrorDetail trailer must be attached");
    let detail = pb::ErrorDetail::decode(trailer.to_bytes().unwrap().as_ref()).unwrap();
    assert_eq!(detail.code, pb::ErrorCode::Internal as i32);
    assert!(detail.message.contains("StartBackup"));

    // CreateVm with an unspecified backend: the Python BACKEND_FROM_PB
    // KeyError surfaces as INTERNAL.
    let status = client
        .create_vm(pb::VmSpec::default())
        .await
        .expect_err("an unspecified backend must fail");
    assert_eq!(status.code(), Code::Internal);

    // CreateVm for a Firecracker program: increment 4, UNIMPLEMENTED.
    let status = client
        .create_vm(pb::VmSpec {
            backend: pb::Backend::Firecracker as i32,
            ..Default::default()
        })
        .await
        .expect_err("Firecracker creation is increment 4");
    assert_eq!(status.code(), Code::Unimplemented);

    // Graceful shutdown unlinks the socket.
    shutdown_tx.send(true).unwrap();
    server_task.await.unwrap().unwrap();
    assert!(!socket_path.exists(), "socket must be unlinked on shutdown");
}
