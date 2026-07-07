//! Socket-path resolution and (from Task 3) the UDS gRPC client plumbing.

use std::path::PathBuf;

const DEFAULT_EXECUTION_ROOT: &str = "/var/lib/aleph/vm";

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
}
