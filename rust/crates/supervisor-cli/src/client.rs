//! Socket-path resolution and the UDS gRPC client plumbing.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use hyper_util::rt::TokioIo;
use prost::Message as _;
use supervisor_proto::{ERROR_TRAILER_KEY, pb};
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

const DEFAULT_EXECUTION_ROOT: &str = "/var/lib/aleph/vm";
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub type SupervisorClient = pb::supervisor_client::SupervisorClient<Channel>;

/// Connect to the supervisor over its Unix socket. The endpoint URI is a
/// placeholder tonic requires; every connection goes to the socket.
///
/// `request_timeout` bounds each RPC so a wedged supervisor (the kernel
/// queues UDS connections even when the daemon never accepts) cannot hang
/// the CLI forever. None for streaming commands, which run indefinitely.
pub async fn connect(
    path: &Path,
    request_timeout: Option<Duration>,
) -> anyhow::Result<SupervisorClient> {
    let socket = path.to_path_buf();
    let mut endpoint = Endpoint::try_from("http://socket.invalid")
        .context("static endpoint")?
        .connect_timeout(CONNECT_TIMEOUT);
    if let Some(timeout) = request_timeout {
        endpoint = endpoint.timeout(timeout);
    }
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let socket = socket.clone();
            async move {
                Ok::<_, std::io::Error>(TokioIo::new(
                    tokio::net::UnixStream::connect(socket).await?,
                ))
            }
        }))
        .await
        .with_context(|| {
            format!(
                "cannot reach the supervisor at {}, is it running?",
                path.display()
            )
        })?;
    Ok(SupervisorClient::new(channel))
}

/// Render a gRPC error for stderr: status code, message, and the ErrorCode
/// from the ErrorDetail trailer when the supervisor attached one.
pub fn format_status(status: &tonic::Status) -> String {
    let mut text = format!("{:?}: {}", status.code(), status.message());
    if let Some(value) = status.metadata().get_bin(ERROR_TRAILER_KEY)
        && let Ok(bytes) = value.to_bytes()
        && let Ok(detail) = pb::ErrorDetail::decode(bytes.as_ref())
    {
        let code = pb::ErrorCode::try_from(detail.code).unwrap_or(pb::ErrorCode::Unspecified);
        text.push_str(&format!(" [{}]", code.as_str_name()));
    }
    text
}

/// The `map_err` every handler uses on an RPC call.
pub fn status_error(status: tonic::Status) -> anyhow::Error {
    anyhow::anyhow!(format_status(&status))
}

/// Resolve the supervisor socket path: `--socket` flag, then
/// ALEPH_VM_SUPERVISOR_GRPC_SOCKET, then ALEPH_VM_EXECUTION_ROOT/
/// supervisor.sock, then /var/lib/aleph/vm/supervisor.sock. Empty env
/// values count as unset, matching the daemon's settings resolution.
pub fn resolve_socket_path(flag: Option<PathBuf>, env: impl Fn(&str) -> Option<String>) -> PathBuf {
    if let Some(path) = flag {
        return path;
    }
    if let Some(path) = env("ALEPH_VM_SUPERVISOR_GRPC_SOCKET").filter(|v| !v.is_empty()) {
        return PathBuf::from(path);
    }
    let root = env("ALEPH_VM_EXECUTION_ROOT")
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_EXECUTION_ROOT.to_string());
    PathBuf::from(root).join("supervisor.sock")
}

#[cfg(test)]
mod tests {
    use super::*;
    use supervisor_proto::{ERROR_TRAILER_KEY, pb};

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn flag_wins_over_everything() {
        let resolved = resolve_socket_path(Some("/tmp/x.sock".into()), |_| {
            Some("/should/not/win".to_string())
        });
        assert_eq!(resolved, PathBuf::from("/tmp/x.sock"));
    }

    #[test]
    fn socket_env_beats_execution_root() {
        let env = |name: &str| match name {
            "ALEPH_VM_SUPERVISOR_GRPC_SOCKET" => Some("/run/sup.sock".to_string()),
            "ALEPH_VM_EXECUTION_ROOT" => Some("/data".to_string()),
            _ => None,
        };
        assert_eq!(
            resolve_socket_path(None, env),
            PathBuf::from("/run/sup.sock")
        );
    }

    #[test]
    fn execution_root_derives_the_socket_path() {
        let env = |name: &str| (name == "ALEPH_VM_EXECUTION_ROOT").then(|| "/data".to_string());
        assert_eq!(
            resolve_socket_path(None, env),
            PathBuf::from("/data/supervisor.sock")
        );
    }

    #[test]
    fn empty_env_values_count_as_unset() {
        let env = |_: &str| Some(String::new());
        assert_eq!(
            resolve_socket_path(None, env),
            PathBuf::from("/var/lib/aleph/vm/supervisor.sock")
        );
    }

    #[test]
    fn defaults_without_flag_or_env() {
        assert_eq!(
            resolve_socket_path(None, no_env),
            PathBuf::from("/var/lib/aleph/vm/supervisor.sock")
        );
    }

    #[tokio::test]
    async fn connect_reports_a_missing_socket_clearly() {
        let error = connect(std::path::Path::new("/nonexistent/supervisor.sock"), None)
            .await
            .unwrap_err();
        let text = format!("{error:#}");
        assert!(text.contains("/nonexistent/supervisor.sock"), "{text}");
        assert!(text.contains("is it running"), "{text}");
    }

    #[test]
    fn format_status_includes_the_error_detail_trailer() {
        let detail = pb::ErrorDetail {
            code: pb::ErrorCode::VmNotFound as i32,
            message: "no VM with id ghost".to_string(),
            vm_id: "ghost".to_string(),
        };
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert_bin(
            ERROR_TRAILER_KEY,
            tonic::metadata::MetadataValue::from_bytes(&detail.encode_to_vec()),
        );
        let status =
            tonic::Status::with_metadata(tonic::Code::NotFound, "no VM with id ghost", metadata);
        assert_eq!(
            format_status(&status),
            "NotFound: no VM with id ghost [ERROR_CODE_VM_NOT_FOUND]"
        );
    }

    #[test]
    fn format_status_without_trailer_is_code_and_message() {
        let status = tonic::Status::unavailable("socket closed");
        assert_eq!(format_status(&status), "Unavailable: socket closed");
    }
}
