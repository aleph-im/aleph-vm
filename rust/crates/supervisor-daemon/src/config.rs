//! The daemon slice of the aleph-vm settings.
//!
//! Reads the same `ALEPH_VM_*` environment variables as the Python
//! `Settings` (src/aleph/vm/conf.py), case-insensitively like
//! pydantic-settings (`env_prefix="ALEPH_VM_", case_sensitive=False`), with
//! the same defaults. Only the slice increments 1 and 2 need is modeled:
//! the socket/paths pair, the GetHostInfo knobs (host networking for
//! host_ipv4, GPU support for the lspci inventory, the persistent volumes
//! directory for available disk), the supervisor database and the network
//! address pools the adopted-VM IP assignments derive from.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::error::DaemonError;

/// Environment prefix, mirroring pydantic's `env_prefix="ALEPH_VM_"`.
pub const ENV_PREFIX: &str = "ALEPH_VM_";

/// conf.py IPv6AllocationPolicy: how VM IPv6 subnets are assigned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ipv6AllocationPolicy {
    /// Compute the subnet from the VM item hash (production default).
    Static,
    /// Iterate through the pool's subnets (testing/CI).
    Dynamic,
}

#[derive(Debug, Clone)]
pub struct Settings {
    /// conf.py EXECUTION_ROOT, default /var/lib/aleph/vm.
    pub execution_root: PathBuf,
    /// conf.py SUPERVISOR_GRPC_SOCKET, default {EXECUTION_ROOT}/supervisor.sock.
    pub supervisor_grpc_socket: PathBuf,
    /// conf.py PERSISTENT_VOLUMES_DIR, default {EXECUTION_ROOT}/volumes/persistent.
    pub persistent_volumes_dir: PathBuf,
    /// conf.py ALLOW_VM_NETWORKING, default true. When false the Python pool
    /// has no Network object and host_ipv4 is served empty.
    pub allow_vm_networking: bool,
    /// conf.py NETWORK_INTERFACE, default None (auto-detect the default
    /// route interface, conf.py get_default_interface()).
    pub network_interface: Option<String>,
    /// conf.py ENABLE_GPU_SUPPORT, default false. When false the Python pool
    /// never runs the lspci inventory.
    pub enable_gpu_support: bool,
    /// conf.py SUPERVISOR_DATABASE, default {EXECUTION_ROOT}/supervisor.sqlite3.
    pub supervisor_database: PathBuf,
    /// conf.py IPV4_ADDRESS_POOL, default "172.16.0.0/12".
    pub ipv4_address_pool: String,
    /// conf.py IPV4_NETWORK_PREFIX_LENGTH, default 24.
    pub ipv4_network_prefix_length: u8,
    /// conf.py IPV6_ADDRESS_POOL, default "fc00:1:2:3::/64".
    pub ipv6_address_pool: String,
    /// conf.py IPV6_ALLOCATION_POLICY, default static.
    pub ipv6_allocation_policy: Ipv6AllocationPolicy,
    /// conf.py IPV6_SUBNET_PREFIX, default 124.
    pub ipv6_subnet_prefix: u8,
}

impl Settings {
    /// Read settings from the process environment.
    ///
    /// vars_os, not vars: `std::env::vars()` panics if any environment
    /// variable anywhere in the process holds non-UTF8 bytes. Such entries
    /// cannot be valid ALEPH_VM_* settings, so they are skipped.
    pub fn from_env() -> Result<Self, DaemonError> {
        Self::from_vars(std::env::vars_os().filter_map(|(key, value)| {
            match (key.into_string(), value.into_string()) {
                (Ok(key), Ok(value)) => Some((key, value)),
                (key, _) => {
                    let key = match &key {
                        Ok(key) => key.clone(),
                        Err(os_key) => os_key.to_string_lossy().into_owned(),
                    };
                    tracing::debug!(key, "skipping non-UTF8 environment variable");
                    None
                }
            }
        }))
    }

    /// Read settings from an explicit variable set (unit-testable, no
    /// process-global state). Later duplicates win, like the environment.
    pub fn from_vars(vars: impl Iterator<Item = (String, String)>) -> Result<Self, DaemonError> {
        let env = EnvSlice::new(vars);

        let execution_root = env
            .get("EXECUTION_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/lib/aleph/vm"));
        let supervisor_grpc_socket = match env.get("SUPERVISOR_GRPC_SOCKET") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => execution_root.join("supervisor.sock"),
        };
        let persistent_volumes_dir = match env.get("PERSISTENT_VOLUMES_DIR") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => execution_root.join("volumes").join("persistent"),
        };
        let allow_vm_networking = env.get_bool("ALLOW_VM_NETWORKING")?.unwrap_or(true);
        let enable_gpu_support = env.get_bool("ENABLE_GPU_SUPPORT")?.unwrap_or(false);
        // Python treats an empty NETWORK_INTERFACE as unset (`if not
        // self.NETWORK_INTERFACE: auto-detect`).
        let network_interface = env.get("NETWORK_INTERFACE").filter(|name| !name.is_empty());
        // conf.py setup(): SUPERVISOR_DATABASE defaults to
        // EXECUTION_ROOT/supervisor.sqlite3 when unset (or emptied).
        let supervisor_database = match env.get("SUPERVISOR_DATABASE") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => execution_root.join("supervisor.sqlite3"),
        };
        let ipv4_address_pool = env
            .get("IPV4_ADDRESS_POOL")
            .unwrap_or_else(|| "172.16.0.0/12".to_string());
        let ipv4_network_prefix_length = env.get_int("IPV4_NETWORK_PREFIX_LENGTH")?.unwrap_or(24);
        let ipv6_address_pool = env
            .get("IPV6_ADDRESS_POOL")
            .unwrap_or_else(|| "fc00:1:2:3::/64".to_string());
        let ipv6_allocation_policy = match env.get("IPV6_ALLOCATION_POLICY") {
            None => Ipv6AllocationPolicy::Static,
            // pydantic matches the str-enum values exactly, case-sensitive.
            Some(value) if value == "static" => Ipv6AllocationPolicy::Static,
            Some(value) if value == "dynamic" => Ipv6AllocationPolicy::Dynamic,
            Some(value) => {
                return Err(DaemonError::InvalidSetting {
                    key: format!("{ENV_PREFIX}IPV6_ALLOCATION_POLICY"),
                    value,
                    expected: "static or dynamic",
                });
            }
        };
        let ipv6_subnet_prefix = env.get_int("IPV6_SUBNET_PREFIX")?.unwrap_or(124);

        Ok(Self {
            execution_root,
            supervisor_grpc_socket,
            persistent_volumes_dir,
            allow_vm_networking,
            network_interface,
            enable_gpu_support,
            supervisor_database,
            ipv4_address_pool,
            ipv4_network_prefix_length,
            ipv6_address_pool,
            ipv6_allocation_policy,
            ipv6_subnet_prefix,
        })
    }
}

/// Case-insensitive view over `ALEPH_VM_*` variables.
struct EnvSlice {
    values: HashMap<String, String>,
}

impl EnvSlice {
    fn new(vars: impl Iterator<Item = (String, String)>) -> Self {
        let values = vars
            .filter_map(|(key, value)| {
                let upper = key.to_ascii_uppercase();
                upper.starts_with(ENV_PREFIX).then_some((upper, value))
            })
            .collect();
        Self { values }
    }

    fn get(&self, name: &str) -> Option<String> {
        self.values.get(&format!("{ENV_PREFIX}{name}")).cloned()
    }

    /// Boolean parsing with pydantic's accepted spellings.
    fn get_bool(&self, name: &str) -> Result<Option<bool>, DaemonError> {
        self.get(name)
            .map(|value| {
                parse_bool(&value).ok_or_else(|| DaemonError::InvalidBool {
                    key: format!("{ENV_PREFIX}{name}"),
                    value,
                })
            })
            .transpose()
    }

    /// Integer parsing; an unparseable value is a startup error, as it is
    /// for pydantic's int fields.
    fn get_int(&self, name: &str) -> Result<Option<u8>, DaemonError> {
        self.get(name)
            .map(|value| {
                value
                    .trim()
                    .parse()
                    .map_err(|_| DaemonError::InvalidSetting {
                        key: format!("{ENV_PREFIX}{name}"),
                        value,
                        expected: "an integer",
                    })
            })
            .transpose()
    }
}

/// The boolean spellings pydantic v2 accepts, case-insensitive.
pub fn parse_bool(value: &str) -> Option<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "t" | "yes" | "y" | "on" | "1" => Some(true),
        "false" | "f" | "no" | "n" | "off" | "0" => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Iterator<Item = (String, String)> + use<> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    #[test]
    fn defaults_mirror_conf_py() {
        let settings = Settings::from_vars(vars(&[])).unwrap();
        assert_eq!(settings.execution_root, PathBuf::from("/var/lib/aleph/vm"));
        assert_eq!(
            settings.supervisor_grpc_socket,
            PathBuf::from("/var/lib/aleph/vm/supervisor.sock")
        );
        assert_eq!(
            settings.persistent_volumes_dir,
            PathBuf::from("/var/lib/aleph/vm/volumes/persistent")
        );
        assert!(settings.allow_vm_networking);
        assert!(!settings.enable_gpu_support);
        assert_eq!(settings.network_interface, None);
        assert_eq!(
            settings.supervisor_database,
            PathBuf::from("/var/lib/aleph/vm/supervisor.sqlite3")
        );
        assert_eq!(settings.ipv4_address_pool, "172.16.0.0/12");
        assert_eq!(settings.ipv4_network_prefix_length, 24);
        assert_eq!(settings.ipv6_address_pool, "fc00:1:2:3::/64");
        assert_eq!(
            settings.ipv6_allocation_policy,
            Ipv6AllocationPolicy::Static
        );
        assert_eq!(settings.ipv6_subnet_prefix, 124);
    }

    #[test]
    fn network_pool_settings_are_read() {
        let settings = Settings::from_vars(vars(&[
            ("ALEPH_VM_IPV4_ADDRESS_POOL", "10.0.0.0/8"),
            ("ALEPH_VM_IPV4_NETWORK_PREFIX_LENGTH", "26"),
            ("ALEPH_VM_IPV6_ADDRESS_POOL", "2001:db8::/64"),
            ("ALEPH_VM_IPV6_ALLOCATION_POLICY", "dynamic"),
            ("ALEPH_VM_IPV6_SUBNET_PREFIX", "126"),
            ("ALEPH_VM_SUPERVISOR_DATABASE", "/tmp/db.sqlite3"),
        ]))
        .unwrap();
        assert_eq!(settings.ipv4_address_pool, "10.0.0.0/8");
        assert_eq!(settings.ipv4_network_prefix_length, 26);
        assert_eq!(settings.ipv6_address_pool, "2001:db8::/64");
        assert_eq!(
            settings.ipv6_allocation_policy,
            Ipv6AllocationPolicy::Dynamic
        );
        assert_eq!(settings.ipv6_subnet_prefix, 126);
        assert_eq!(
            settings.supervisor_database,
            PathBuf::from("/tmp/db.sqlite3")
        );
    }

    #[test]
    fn invalid_policy_and_int_are_errors() {
        let error = Settings::from_vars(vars(&[("ALEPH_VM_IPV6_ALLOCATION_POLICY", "Static")]))
            .unwrap_err();
        assert!(error.to_string().contains("IPV6_ALLOCATION_POLICY"));
        let error =
            Settings::from_vars(vars(&[("ALEPH_VM_IPV6_SUBNET_PREFIX", "many")])).unwrap_err();
        assert!(error.to_string().contains("IPV6_SUBNET_PREFIX"));
    }

    #[test]
    fn database_default_follows_execution_root() {
        let settings = Settings::from_vars(vars(&[
            ("ALEPH_VM_EXECUTION_ROOT", "/tmp/exec"),
            ("ALEPH_VM_SUPERVISOR_DATABASE", ""),
        ]))
        .unwrap();
        assert_eq!(
            settings.supervisor_database,
            PathBuf::from("/tmp/exec/supervisor.sqlite3")
        );
    }

    #[test]
    fn socket_default_follows_execution_root() {
        let settings =
            Settings::from_vars(vars(&[("ALEPH_VM_EXECUTION_ROOT", "/tmp/exec")])).unwrap();
        assert_eq!(
            settings.supervisor_grpc_socket,
            PathBuf::from("/tmp/exec/supervisor.sock")
        );
        assert_eq!(
            settings.persistent_volumes_dir,
            PathBuf::from("/tmp/exec/volumes/persistent")
        );
    }

    #[test]
    fn explicit_socket_wins_over_derived_default() {
        let settings = Settings::from_vars(vars(&[
            ("ALEPH_VM_EXECUTION_ROOT", "/tmp/exec"),
            ("ALEPH_VM_SUPERVISOR_GRPC_SOCKET", "/run/other.sock"),
        ]))
        .unwrap();
        assert_eq!(
            settings.supervisor_grpc_socket,
            PathBuf::from("/run/other.sock")
        );
    }

    #[test]
    fn keys_are_case_insensitive_like_pydantic_settings() {
        let settings = Settings::from_vars(vars(&[
            ("aleph_vm_execution_root", "/tmp/lower"),
            ("Aleph_Vm_Enable_Gpu_Support", "True"),
        ]))
        .unwrap();
        assert_eq!(settings.execution_root, PathBuf::from("/tmp/lower"));
        assert!(settings.enable_gpu_support);
    }

    #[test]
    fn bool_spellings_match_pydantic() {
        for value in ["1", "true", "TRUE", "t", "yes", "y", "on", "On"] {
            assert_eq!(parse_bool(value), Some(true), "{value}");
        }
        for value in ["0", "false", "False", "f", "no", "n", "off", "OFF"] {
            assert_eq!(parse_bool(value), Some(false), "{value}");
        }
        assert_eq!(parse_bool("maybe"), None);
        assert_eq!(parse_bool(""), None);
    }

    #[test]
    fn invalid_bool_is_an_error() {
        let error =
            Settings::from_vars(vars(&[("ALEPH_VM_ALLOW_VM_NETWORKING", "maybe")])).unwrap_err();
        assert!(error.to_string().contains("ALEPH_VM_ALLOW_VM_NETWORKING"));
    }

    #[test]
    fn empty_network_interface_means_unset() {
        let settings = Settings::from_vars(vars(&[("ALEPH_VM_NETWORK_INTERFACE", "")])).unwrap();
        assert_eq!(settings.network_interface, None);
        let settings =
            Settings::from_vars(vars(&[("ALEPH_VM_NETWORK_INTERFACE", "eth0")])).unwrap();
        assert_eq!(settings.network_interface.as_deref(), Some("eth0"));
    }

    #[test]
    fn unrelated_variables_are_ignored() {
        let settings = Settings::from_vars(vars(&[
            ("PATH", "/usr/bin"),
            ("EXECUTION_ROOT", "/not/prefixed"),
        ]))
        .unwrap();
        assert_eq!(settings.execution_root, PathBuf::from("/var/lib/aleph/vm"));
    }
}
