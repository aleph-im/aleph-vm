//! Unix socket lifecycle and the tonic server.
//!
//! Same lifecycle as the Python daemon (src/aleph/vm/supervisor/daemon.py):
//! mkdir the socket parent, unlink a stale socket, serve, unlink on exit.
//! Day-one improvements over Python (design doc section 3):
//! - the socket is bound under umask 0o077, so it is never observable with
//!   permissive modes, and chmod 0700 afterwards as a backstop; the agent
//!   runs as root too and nothing else may connect.
//! - the shutdown unlink is identity-checked: it only removes the socket
//!   inode this daemon bound, never one a newer instance re-bound at the
//!   same path.

use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use supervisor_proto::pb::supervisor_server::SupervisorServer;
use tokio_stream::wrappers::UnixListenerStream;

use crate::config::Settings;
use crate::error::DaemonError;
use crate::service::{DaemonState, SupervisorService};

/// How long in-flight RPCs get to finish after the first shutdown signal,
/// matching the Python daemon's `server.stop(grace=5)`.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// The directories the Python settings.setup() slice creates before the pool
/// starts: EXECUTION_ROOT and PERSISTENT_VOLUMES_DIR (the latter is also the
/// statvfs target of GetHostInfo.available_disk_bytes).
pub fn prepare_directories(settings: &Settings) -> Result<(), DaemonError> {
    std::fs::create_dir_all(&settings.execution_root)?;
    std::fs::create_dir_all(&settings.persistent_volumes_dir)?;
    Ok(())
}

/// Owns the socket path and remembers which inode this daemon bound, so
/// shutdown never unlinks a socket that a newer daemon instance re-bound at
/// the same path (the Python daemon unlinks unconditionally and has that
/// bug). `cleanup` is idempotent: shared between the serve path and the
/// second-signal fast exit, it runs the unlink exactly once.
pub struct SocketGuard {
    path: PathBuf,
    /// An O_PATH descriptor of the socket we bound. Holding it open pins the
    /// on-disk inode for the guard's whole lifetime, so a (st_dev, st_ino)
    /// match at cleanup time genuinely means the path still holds our
    /// socket: filesystems reuse freed inode numbers (observed on the ext4
    /// CI runners), so comparing against numbers recorded at bind time is
    /// not enough. O_PATH, not the listener's own descriptor: fstat on a
    /// socket fd reports the anonymous sockfs inode, never the path's.
    bound: OnceLock<std::fs::File>,
    cleaned: AtomicBool,
}

impl SocketGuard {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            bound: OnceLock::new(),
            cleaned: AtomicBool::new(false),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record the identity of the socket we just bound by opening the path
    /// with O_PATH (a plain open(2) fails on sockets; O_PATH works on any
    /// file type and pins the inode without I/O access).
    pub fn record_identity(&self) -> Result<(), DaemonError> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(&self.path)?;
        let _ = self.bound.set(file);
        Ok(())
    }

    /// Unlink the socket if, and only if, the path still holds the inode we
    /// bound. Runs at most once; later calls are no-ops.
    pub fn cleanup(&self) {
        if self.cleaned.swap(true, Ordering::SeqCst) {
            return;
        }
        let Some(bound) = self.bound.get() else {
            // Never bound: nothing of ours can sit at the path.
            return;
        };
        let (dev, ino) = match bound.metadata() {
            Ok(metadata) => (metadata.dev(), metadata.ino()),
            Err(error) => {
                tracing::warn!(%error, "could not fstat our own supervisor socket");
                return;
            }
        };
        match std::fs::metadata(&self.path) {
            Ok(metadata) if (metadata.dev(), metadata.ino()) == (dev, ino) => {
                if let Err(error) = std::fs::remove_file(&self.path)
                    && error.kind() != std::io::ErrorKind::NotFound
                {
                    tracing::warn!(%error, "could not unlink the supervisor socket");
                }
            }
            Ok(_) => {
                tracing::warn!(
                    "not unlinking {}: the socket is no longer ours (a newer daemon instance owns it)",
                    self.path.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                tracing::warn!(%error, "could not stat the supervisor socket before unlinking");
            }
        }
    }
}

/// Bind the supervisor socket and serve until `shutdown` flips to true.
/// After the flip, in-flight RPCs get [`SHUTDOWN_GRACE`] to finish (the
/// Python daemon's `server.stop(grace=5)`), then the server is dropped.
/// Either way the socket is removed (identity-checked) exactly once.
pub async fn serve(
    state: Arc<DaemonState>,
    guard: Arc<SocketGuard>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), DaemonError> {
    let socket_path = guard.path().to_path_buf();

    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if socket_path.exists() {
        // A previous daemon left its socket behind; a fresh bind needs it
        // gone. Unconditional on purpose, like the Python run_daemon: at
        // this point nothing at the path can be ours.
        std::fs::remove_file(&socket_path)?;
    }

    // Bind under a restrictive umask so the socket never transits through a
    // world-connectable state; the chmod below is only a backstop.
    // SAFETY: umask cannot fail and only affects this process.
    let old_umask = unsafe { libc::umask(0o077) };
    let bind_result = tokio::net::UnixListener::bind(&socket_path);
    unsafe { libc::umask(old_umask) };
    let listener = bind_result?;

    // Remember which inode we bound: the shutdown unlink must only ever
    // remove our own socket.
    if let Err(error) = guard.record_identity() {
        let _ = std::fs::remove_file(&socket_path);
        return Err(error);
    }

    if let Err(error) =
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o700))
    {
        // Do not leave a bound socket behind on the error path.
        guard.cleanup();
        return Err(error.into());
    }

    tracing::info!(
        "Supervisor gRPC server listening on unix:{}",
        socket_path.display()
    );

    let service = SupervisorServer::new(SupervisorService::new(state));
    let serve_future = tonic::transport::Server::builder()
        .add_service(service)
        .serve_with_incoming_shutdown(UnixListenerStream::new(listener), {
            let mut shutdown = shutdown.clone();
            async move {
                // A closed channel also means shutdown.
                let _ = shutdown.wait_for(|stop| *stop).await;
            }
        });
    tokio::pin!(serve_future);

    // Grace watchdog, Python parity: daemon.py calls server.stop(grace=5),
    // giving in-flight RPCs five seconds after the first signal before the
    // server stops waiting for them. Here the sleep arm wins the select and
    // the serve future (with any remaining connections) is dropped.
    let result = tokio::select! {
        result = &mut serve_future => result.map_err(DaemonError::from),
        _ = async {
            let _ = shutdown.wait_for(|stop| *stop).await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => {
            tracing::warn!(
                "in-flight RPCs still running after the {}s shutdown grace, stopping anyway",
                SHUTDOWN_GRACE.as_secs()
            );
            Ok(())
        }
    };

    tracing::info!("Stopping the supervisor gRPC server (VMs keep running)");
    // Runs on the serve-error path too, and exactly once even if the
    // second-signal handler races us.
    guard.cleanup();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cleanup_unlinks_our_own_file_exactly_once() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("supervisor.sock");
        std::fs::write(&path, b"ours").unwrap();

        let guard = SocketGuard::new(path.clone());
        guard.record_identity().unwrap();
        guard.cleanup();
        assert!(!path.exists(), "our own socket must be unlinked");

        // A second cleanup is a no-op, even if the path was reused meanwhile.
        std::fs::write(&path, b"someone else").unwrap();
        guard.cleanup();
        assert!(path.exists(), "cleanup must run at most once");
    }

    #[test]
    fn cleanup_leaves_a_replaced_socket_alone() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("supervisor.sock");
        std::fs::write(&path, b"ours").unwrap();

        let guard = SocketGuard::new(path.clone());
        guard.record_identity().unwrap();

        // A newer daemon instance re-binds the path. The new file's inode is
        // guaranteed distinct: the guard's O_PATH descriptor keeps the old
        // inode alive, and two live inodes never share a number (the
        // previous stat-based check flaked on CI when ext4 reused the freed
        // inode number).
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"newer instance").unwrap();

        guard.cleanup();
        assert!(path.exists(), "a socket we do not own must not be unlinked");
    }

    #[test]
    fn cleanup_without_a_recorded_identity_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("supervisor.sock");
        std::fs::write(&path, b"not ours").unwrap();

        let guard = SocketGuard::new(path.clone());
        guard.cleanup();
        assert!(path.exists(), "nothing was bound, nothing may be removed");
    }
}
