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
    /// conf.py BACKUP_DIRECTORY, default {EXECUTION_ROOT}/backups (increment 5).
    pub backup_directory: PathBuf,
    /// conf.py CONFIDENTIAL_SESSION_DIRECTORY, default {EXECUTION_ROOT}/sessions
    /// (increment 6): where InitializeConfidential writes the owner's session
    /// certificates and confidential CreateVm points the controller config.
    pub confidential_session_directory: PathBuf,
    /// conf.py ENABLE_CONFIDENTIAL_COMPUTING, default false (check()
    /// preconditions: SEV_CTL_PATH plus the SEV/SEV-ES kernel-module gates).
    pub enable_confidential_computing: bool,
    /// conf.py SEV_CTL_PATH, default /opt/sevctl.
    pub sev_ctl_path: PathBuf,
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
    /// conf.py EXECUTION_DATABASE, default {EXECUTION_ROOT}/executions.sqlite3:
    /// the pre-split agent store, read once at boot by the legacy
    /// port-mapping migration.
    pub execution_database: PathBuf,
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
    /// conf.py IPV6_FORWARDING_ENABLED, default true.
    pub ipv6_forwarding_enabled: bool,
    /// conf.py USE_NDP_PROXY, default true.
    pub use_ndp_proxy: bool,
    /// conf.py NFTABLES_CHAIN_PREFIX, default "aleph".
    pub nftables_chain_prefix: String,
    /// conf.py START_ID_INDEX, default 4 (first vm_index handed out).
    pub start_id_index: i64,
    /// conf.py HOST_MEMORY_RESERVED_MIB, default 2048 (the create-time
    /// physical-memory backstop).
    pub host_memory_reserved_mib: u64,
    /// conf.py ENABLE_QEMU_SUPPORT, default true (check() preconditions).
    pub enable_qemu_support: bool,
    /// conf.py USE_JAILER, default true: run ephemeral Firecracker programs
    /// under the jailer (production).
    pub use_jailer: bool,
    /// conf.py INIT_TIMEOUT, default 20.0: how long the ephemeral boot waits
    /// for the guest's ready signal when the spec states no bound.
    pub init_timeout: f64,
    /// conf.py PRINT_SYSTEM_LOGS, default true: wire the Firecracker process
    /// output to journald (vm-{hash}-stdout/-stderr) and enable the guest
    /// console.
    pub print_system_logs: bool,
    /// conf.py FIRECRACKER_PATH, default /opt/firecracker/firecracker.
    pub firecracker_path: PathBuf,
    /// conf.py JAILER_PATH, default /opt/firecracker/jailer.
    pub jailer_path: PathBuf,
    /// conf.py LINUX_PATH, default /opt/firecracker/vmlinux.bin.
    pub linux_path: PathBuf,
    /// conf.py JAILER_BASE_DIR; like the pydantic __init__, an unset (or
    /// emptied) value derives EXECUTION_ROOT/jailer, so it always holds a
    /// path (it is written into every controller config).
    pub jailer_base_dir: PathBuf,
    /// conf.py DNS_NAMESERVERS, default None (resolved at startup through
    /// DNS_RESOLUTION when host networking is on; pydantic parses the env
    /// value as a JSON list).
    pub dns_nameservers: Option<Vec<String>>,
    /// conf.py DNS_RESOLUTION, default detect.
    pub dns_resolution: DnsResolution,
    /// conf.py DEVELOPER_SSH_KEYS, default [] (pydantic parses the env
    /// value as a JSON list).
    pub developer_ssh_keys: Vec<String>,
    /// conf.py USE_DEVELOPER_SSH_KEYS, default False. The pydantic type is
    /// `Literal[False] | object`, so bool-shaped env values coerce and
    /// anything else stays a string whose TRUTHINESS gates the key merge:
    /// unset, "" and false spellings are off, everything else is on
    /// (ALEPH_VM_USE_DEVELOPER_SSH_KEYS=true IS truthy despite the conf.py
    /// comment claiming env vars cannot set it).
    pub use_developer_ssh_keys: bool,

    /// Directory that holds systemd unit files and per-instance `.service.d`
    /// drop-in directories (default `/etc/systemd/system`). The supervisor
    /// writes each VM's NUMA `AllowedCPUs=` drop-in under here; tests point
    /// it at a temporary directory. Rust-only (NUMA has no Python oracle).
    pub systemd_unit_dir: PathBuf,

    /// ALEPH_VM_NUMA_HUGEPAGES, default false. When true (and the host has
    /// more than one NUMA node), the daemon reserves 2M hugepages per node at
    /// boot and backs each placed VM's memory with hugepages (increment C2).
    /// Reserving hugepages writes host-wide `nr_hugepages`, a real memory
    /// reservation, so it is OPT-IN: with it off, C2 delivers only the
    /// regular-page NUMA memory binding. Rust-only (no Python oracle).
    pub numa_hugepages: bool,

    /// ALEPH_VM_NUMA_HUGEPAGES_HEADROOM_MB, default
    /// [`crate::hugepages::DEFAULT_HEADROOM_MB`] (8192). Per-node floor of
    /// regular RAM (MB) kept out of the boot 2M hugepage reservation so the
    /// host is never starved. Only read when `numa_hugepages` is on.
    /// Rust-only (no Python oracle).
    pub numa_hugepages_headroom_mb: u32,

    /// ALEPH_VM_NUMA_HUGEPAGES_LIMIT_MB, default unset. Optional global cap
    /// (MB, split evenly across nodes) on the boot 2M hugepage reservation;
    /// unset bounds the reservation by total RAM minus the per-node headroom.
    /// Only read when `numa_hugepages` is on. Rust-only (no Python oracle).
    pub numa_hugepages_limit_mb: Option<u64>,
}

/// conf.py DnsResolver: how DNS_NAMESERVERS is derived when unset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsResolution {
    /// Try resolvectl, fall back to /etc/resolv.conf.
    Detect,
    /// Parse /etc/resolv.conf.
    ResolvConf,
    /// `resolvectl dns -i <interface>`.
    Resolvectl,
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
        // conf.py setup(): BACKUP_DIRECTORY defaults to EXECUTION_ROOT/backups,
        // CONFIDENTIAL_SESSION_DIRECTORY to EXECUTION_ROOT/sessions, when unset
        // (or emptied, matching the empty-string-is-unset family, entry 4).
        let backup_directory = match env.get("BACKUP_DIRECTORY") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => execution_root.join("backups"),
        };
        let confidential_session_directory = match env.get("CONFIDENTIAL_SESSION_DIRECTORY") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => execution_root.join("sessions"),
        };
        let enable_confidential_computing = env
            .get_bool("ENABLE_CONFIDENTIAL_COMPUTING")?
            .unwrap_or(false);
        let sev_ctl_path = env
            .get("SEV_CTL_PATH")
            .filter(|path| !path.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/sevctl"));
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
        // conf.py setup(): EXECUTION_DATABASE defaults to
        // EXECUTION_ROOT/executions.sqlite3 when unset (or emptied).
        let execution_database = match env.get("EXECUTION_DATABASE") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => execution_root.join("executions.sqlite3"),
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
        let ipv6_forwarding_enabled = env.get_bool("IPV6_FORWARDING_ENABLED")?.unwrap_or(true);
        let use_ndp_proxy = env.get_bool("USE_NDP_PROXY")?.unwrap_or(true);
        let nftables_chain_prefix = env
            .get("NFTABLES_CHAIN_PREFIX")
            .unwrap_or_else(|| "aleph".to_string());
        let start_id_index = env.get_i64("START_ID_INDEX")?.unwrap_or(4);
        let host_memory_reserved_mib = env
            .get_i64("HOST_MEMORY_RESERVED_MIB")?
            .map(|value| u64::try_from(value).unwrap_or(0))
            .unwrap_or(2048);
        let enable_qemu_support = env.get_bool("ENABLE_QEMU_SUPPORT")?.unwrap_or(true);
        let use_jailer = env.get_bool("USE_JAILER")?.unwrap_or(true);
        let init_timeout = env.get_f64("INIT_TIMEOUT")?.unwrap_or(20.0);
        let print_system_logs = env.get_bool("PRINT_SYSTEM_LOGS")?.unwrap_or(true);
        let firecracker_path = env
            .get("FIRECRACKER_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/firecracker/firecracker"));
        let jailer_path = env
            .get("JAILER_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/firecracker/jailer"));
        let linux_path = env
            .get("LINUX_PATH")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/opt/firecracker/vmlinux.bin"));
        let jailer_base_dir = match env.get("JAILER_BASE_DIR") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => execution_root.join("jailer"),
        };
        // pydantic parses list-typed env vars as JSON.
        let dns_nameservers = match env.get("DNS_NAMESERVERS") {
            None => None,
            Some(value) => Some(serde_json::from_str::<Vec<String>>(&value).map_err(|_| {
                DaemonError::InvalidSetting {
                    key: format!("{ENV_PREFIX}DNS_NAMESERVERS"),
                    value,
                    expected: "a JSON list of addresses",
                }
            })?),
        };
        // pydantic list-typed setting: JSON, `null` reads as the [] default
        // (a None DEVELOPER_SSH_KEYS would crash Python's `keys += None`).
        let developer_ssh_keys = match env.get("DEVELOPER_SSH_KEYS") {
            None => Vec::new(),
            Some(value) => serde_json::from_str::<Option<Vec<String>>>(&value)
                .map_err(|_| DaemonError::InvalidSetting {
                    key: format!("{ENV_PREFIX}DEVELOPER_SSH_KEYS"),
                    value,
                    expected: "a JSON list of SSH public keys",
                })?
                .unwrap_or_default(),
        };
        // `Literal[False] | object` truthiness (see the field comment).
        let use_developer_ssh_keys = match env.get("USE_DEVELOPER_SSH_KEYS") {
            None => false,
            Some(value) => parse_bool(&value).unwrap_or(!value.is_empty()),
        };
        let systemd_unit_dir = match env.get("SYSTEMD_UNIT_DIR") {
            Some(path) if !path.is_empty() => PathBuf::from(path),
            _ => PathBuf::from("/etc/systemd/system"),
        };
        let numa_hugepages = env.get_bool("NUMA_HUGEPAGES")?.unwrap_or(false);
        let numa_hugepages_headroom_mb = env
            .get_u32("NUMA_HUGEPAGES_HEADROOM_MB")?
            .unwrap_or(crate::hugepages::DEFAULT_HEADROOM_MB);
        let numa_hugepages_limit_mb = env.get_u64("NUMA_HUGEPAGES_LIMIT_MB")?;
        let dns_resolution = match env.get("DNS_RESOLUTION") {
            None => DnsResolution::Detect,
            Some(value) if value == "detect" => DnsResolution::Detect,
            Some(value) if value == "resolv.conf" => DnsResolution::ResolvConf,
            Some(value) if value == "resolvectl" => DnsResolution::Resolvectl,
            Some(value) => {
                return Err(DaemonError::InvalidSetting {
                    key: format!("{ENV_PREFIX}DNS_RESOLUTION"),
                    value,
                    expected: "detect, resolv.conf or resolvectl",
                });
            }
        };

        Ok(Self {
            execution_root,
            supervisor_grpc_socket,
            persistent_volumes_dir,
            backup_directory,
            confidential_session_directory,
            enable_confidential_computing,
            sev_ctl_path,
            allow_vm_networking,
            network_interface,
            enable_gpu_support,
            supervisor_database,
            execution_database,
            ipv4_address_pool,
            ipv4_network_prefix_length,
            ipv6_address_pool,
            ipv6_allocation_policy,
            ipv6_subnet_prefix,
            ipv6_forwarding_enabled,
            use_ndp_proxy,
            nftables_chain_prefix,
            start_id_index,
            host_memory_reserved_mib,
            enable_qemu_support,
            use_jailer,
            init_timeout,
            print_system_logs,
            firecracker_path,
            jailer_path,
            linux_path,
            jailer_base_dir,
            dns_nameservers,
            dns_resolution,
            developer_ssh_keys,
            use_developer_ssh_keys,
            systemd_unit_dir,
            numa_hugepages,
            numa_hugepages_headroom_mb,
            numa_hugepages_limit_mb,
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

    /// Like [`Self::get_int`] for u32 settings.
    fn get_u32(&self, name: &str) -> Result<Option<u32>, DaemonError> {
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

    /// Like [`Self::get_int`] for u64 settings.
    fn get_u64(&self, name: &str) -> Result<Option<u64>, DaemonError> {
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

    /// Like [`Self::get_int`] for wider integer settings.
    fn get_i64(&self, name: &str) -> Result<Option<i64>, DaemonError> {
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

    /// Float parsing; an unparseable value is a startup error, as it is
    /// for pydantic's float fields.
    fn get_f64(&self, name: &str) -> Result<Option<f64>, DaemonError> {
        self.get(name)
            .map(|value| {
                value
                    .trim()
                    .parse()
                    .map_err(|_| DaemonError::InvalidSetting {
                        key: format!("{ENV_PREFIX}{name}"),
                        value,
                        expected: "a number",
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
    fn numa_hugepages_is_opt_in() {
        // Off unless explicitly enabled; the pydantic bool spellings apply.
        assert!(!Settings::from_vars(vars(&[])).unwrap().numa_hugepages);
        assert!(
            Settings::from_vars(vars(&[("ALEPH_VM_NUMA_HUGEPAGES", "true")]))
                .unwrap()
                .numa_hugepages
        );
        assert!(
            !Settings::from_vars(vars(&[("ALEPH_VM_NUMA_HUGEPAGES", "false")]))
                .unwrap()
                .numa_hugepages
        );
        // A non-bool value is a hard error (get_bool), like the other flags.
        assert!(Settings::from_vars(vars(&[("ALEPH_VM_NUMA_HUGEPAGES", "maybe")])).is_err());
    }

    #[test]
    fn numa_hugepages_headroom_and_limit_are_configurable() {
        // Defaults: the hugepages module's headroom floor, no global limit.
        let defaults = Settings::from_vars(vars(&[])).unwrap();
        assert_eq!(
            defaults.numa_hugepages_headroom_mb,
            crate::hugepages::DEFAULT_HEADROOM_MB
        );
        assert_eq!(defaults.numa_hugepages_limit_mb, None);

        let tuned = Settings::from_vars(vars(&[
            ("ALEPH_VM_NUMA_HUGEPAGES_HEADROOM_MB", "2048"),
            ("ALEPH_VM_NUMA_HUGEPAGES_LIMIT_MB", "32768"),
        ]))
        .unwrap();
        assert_eq!(tuned.numa_hugepages_headroom_mb, 2048);
        assert_eq!(tuned.numa_hugepages_limit_mb, Some(32768));

        // A non-integer (or negative) value is a hard error, like the other
        // int settings.
        assert!(
            Settings::from_vars(vars(&[("ALEPH_VM_NUMA_HUGEPAGES_HEADROOM_MB", "lots")])).is_err()
        );
        assert!(Settings::from_vars(vars(&[("ALEPH_VM_NUMA_HUGEPAGES_LIMIT_MB", "-1")])).is_err());
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
        assert!(settings.ipv6_forwarding_enabled);
        assert!(settings.use_ndp_proxy);
        // NUMA hugepage reservation is OFF by default (a real host memory
        // reservation must be opt-in).
        assert!(!settings.numa_hugepages);
        assert_eq!(settings.nftables_chain_prefix, "aleph");
        assert_eq!(settings.start_id_index, 4);
        assert_eq!(settings.host_memory_reserved_mib, 2048);
        assert!(settings.enable_qemu_support);
        assert_eq!(
            settings.firecracker_path,
            PathBuf::from("/opt/firecracker/firecracker")
        );
        assert_eq!(
            settings.jailer_path,
            PathBuf::from("/opt/firecracker/jailer")
        );
        assert_eq!(
            settings.linux_path,
            PathBuf::from("/opt/firecracker/vmlinux.bin")
        );
        assert_eq!(
            settings.jailer_base_dir,
            PathBuf::from("/var/lib/aleph/vm/jailer")
        );
        assert_eq!(settings.dns_nameservers, None);
        assert_eq!(settings.dns_resolution, DnsResolution::Detect);
        assert_eq!(
            settings.execution_database,
            PathBuf::from("/var/lib/aleph/vm/executions.sqlite3")
        );
        assert!(settings.developer_ssh_keys.is_empty());
        assert!(!settings.use_developer_ssh_keys);
    }

    #[test]
    fn developer_ssh_key_settings_follow_the_pydantic_semantics() {
        let settings = Settings::from_vars(vars(&[
            ("ALEPH_VM_DEVELOPER_SSH_KEYS", "[\"ssh-ed25519 AAAA dev\"]"),
            ("ALEPH_VM_USE_DEVELOPER_SSH_KEYS", "true"),
        ]))
        .unwrap();
        assert_eq!(
            settings.developer_ssh_keys,
            vec!["ssh-ed25519 AAAA dev".to_string()]
        );
        assert!(
            settings.use_developer_ssh_keys,
            "env true IS truthy despite the conf.py comment"
        );

        // False spellings and the empty string are off (bool coercion and
        // Python string falsiness respectively); other strings land in the
        // `object` branch and are truthy.
        for (value, expected) in [
            ("false", false),
            ("0", false),
            ("", false),
            ("banana", true),
        ] {
            let settings =
                Settings::from_vars(vars(&[("ALEPH_VM_USE_DEVELOPER_SSH_KEYS", value)])).unwrap();
            assert_eq!(settings.use_developer_ssh_keys, expected, "{value:?}");
        }

        // JSON null reads as the [] default; invalid JSON is a startup error.
        let settings =
            Settings::from_vars(vars(&[("ALEPH_VM_DEVELOPER_SSH_KEYS", "null")])).unwrap();
        assert!(settings.developer_ssh_keys.is_empty());
        let error =
            Settings::from_vars(vars(&[("ALEPH_VM_DEVELOPER_SSH_KEYS", "not-json")])).unwrap_err();
        assert!(error.to_string().contains("DEVELOPER_SSH_KEYS"));
    }

    #[test]
    fn execution_database_default_follows_execution_root() {
        let settings = Settings::from_vars(vars(&[
            ("ALEPH_VM_EXECUTION_ROOT", "/tmp/exec"),
            ("ALEPH_VM_EXECUTION_DATABASE", ""),
        ]))
        .unwrap();
        assert_eq!(
            settings.execution_database,
            PathBuf::from("/tmp/exec/executions.sqlite3")
        );
        let settings = Settings::from_vars(vars(&[(
            "ALEPH_VM_EXECUTION_DATABASE",
            "/tmp/legacy.sqlite3",
        )]))
        .unwrap();
        assert_eq!(
            settings.execution_database,
            PathBuf::from("/tmp/legacy.sqlite3")
        );
    }

    #[test]
    fn increment_3_settings_are_read() {
        let settings = Settings::from_vars(vars(&[
            ("ALEPH_VM_IPV6_FORWARDING_ENABLED", "false"),
            ("ALEPH_VM_USE_NDP_PROXY", "false"),
            ("ALEPH_VM_NFTABLES_CHAIN_PREFIX", "test"),
            ("ALEPH_VM_START_ID_INDEX", "10"),
            ("ALEPH_VM_HOST_MEMORY_RESERVED_MIB", "512"),
            ("ALEPH_VM_ENABLE_QEMU_SUPPORT", "false"),
            ("ALEPH_VM_FIRECRACKER_PATH", "/tmp/fc"),
            ("ALEPH_VM_JAILER_PATH", "/tmp/jail"),
            ("ALEPH_VM_LINUX_PATH", "/tmp/vmlinux"),
            ("ALEPH_VM_JAILER_BASE_DIR", "/tmp/jbd"),
            ("ALEPH_VM_DNS_NAMESERVERS", "[\"1.1.1.1\", \"8.8.8.8\"]"),
            ("ALEPH_VM_DNS_RESOLUTION", "resolv.conf"),
        ]))
        .unwrap();
        assert!(!settings.ipv6_forwarding_enabled);
        assert!(!settings.use_ndp_proxy);
        assert_eq!(settings.nftables_chain_prefix, "test");
        assert_eq!(settings.start_id_index, 10);
        assert_eq!(settings.host_memory_reserved_mib, 512);
        assert!(!settings.enable_qemu_support);
        assert_eq!(settings.firecracker_path, PathBuf::from("/tmp/fc"));
        assert_eq!(settings.jailer_base_dir, PathBuf::from("/tmp/jbd"));
        assert_eq!(
            settings.dns_nameservers,
            Some(vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()])
        );
        assert_eq!(settings.dns_resolution, DnsResolution::ResolvConf);

        // pydantic list parsing: a non-JSON value is a startup error.
        let error =
            Settings::from_vars(vars(&[("ALEPH_VM_DNS_NAMESERVERS", "1.1.1.1")])).unwrap_err();
        assert!(error.to_string().contains("DNS_NAMESERVERS"));
        let error = Settings::from_vars(vars(&[("ALEPH_VM_DNS_RESOLUTION", "guess")])).unwrap_err();
        assert!(error.to_string().contains("DNS_RESOLUTION"));
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
