//! Reader for the on-disk controller configuration files
//! (`{EXECUTION_ROOT}/{vm_hash}-controller.json`).
//!
//! The JSON shape is defined by the pydantic models in
//! `src/aleph/vm/supervisor_interface/configuration.py`: `Configuration`
//! wrapping the `ControllerSettings` slice and a `vm_configuration` union
//! (`QemuConfidentialVMConfiguration | QemuVMConfiguration | VMConfiguration`).
//!
//! This crate (increment A1) drives the NON-CONFIDENTIAL persistent QEMU
//! path only. The parser recognises the QEMU shape, exposes the confidential
//! slice so the dispatcher can reject it (that is increment A2), and carries
//! a Firecracker payload as an unsupported variant. The confidential-vs-plain
//! resolution mirrors the daemon's `controller_config` reader: a QEMU payload
//! is confidential exactly when `ovmf_path`, `sev_session_file`,
//! `sev_dh_cert_file` and `sev_policy` all appear.
//!
//! Field names and defaults match the pydantic models so a config written by
//! the Python supervisor (or the Rust daemon writer) parses unchanged. The
//! pydantic `MiB` field only ever serializes as a bare integer (it is an
//! `int` subclass), so `mem_size_mb` is read strictly as [`memsizes::MiB`]:
//! a float, negative or string is a parse error, never coerced.

use std::path::PathBuf;

use memsizes::MiB;
use serde::{Deserialize, Serialize};

/// A failure to read or parse a controller config file. Every variant
/// reproduces a message the deleted `ConfigError(String)` newtype used to
/// build inline via `format!`, so the rendered text is unchanged.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("invalid QemuVMConfiguration JSON: {source}")]
    InvalidQemuJson { source: serde_json::Error },

    #[error("cannot read {}: {source}", .path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("invalid Configuration JSON: {source}")]
    InvalidJson { source: serde_json::Error },

    #[error("unknown hypervisor {value:?}")]
    UnknownHypervisor { value: String },

    #[error(
        "vm_configuration fits no union member: not QEMU ({qemu_error}); \
         not Firecracker ({firecracker_error})"
    )]
    NoUnionMember {
        qemu_error: serde_json::Error,
        firecracker_error: serde_json::Error,
    },
}

/// The `IPv6AllocationPolicy` str-enum, validated like pydantic (an unknown
/// value is an error, not a fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum AllocationPolicy {
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "dynamic")]
    Dynamic,
}

/// The `HypervisorType` str-enum. `Configuration.hypervisor` defaults to
/// `firecracker` in the pydantic model, so a config with the field absent is
/// treated as Firecracker (which the A1 dispatcher rejects, matching Python's
/// firecracker-first precedence in `execute_persistent_vm`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum HypervisorType {
    #[serde(rename = "qemu")]
    Qemu,
    #[serde(rename = "firecracker")]
    Firecracker,
}

/// `ControllerSettings`: the node-settings slice a controller reads. Defaults
/// mirror conf.py so a key absent from an old dump falls back instead of
/// failing (`extra="ignore"`, defaulted fields). The field order and names
/// match the pydantic model so `--print-settings` reproduces
/// `model_dump_json(indent=4)`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct ControllerSettings {
    #[serde(rename = "JAILER_BASE_DIR")]
    pub jailer_base_dir: Option<String>,
    #[serde(rename = "NETWORK_INTERFACE")]
    pub network_interface: Option<String>,
    #[serde(rename = "IPV4_ADDRESS_POOL")]
    pub ipv4_address_pool: String,
    #[serde(rename = "IPV4_NETWORK_PREFIX_LENGTH")]
    pub ipv4_network_prefix_length: u8,
    #[serde(rename = "IPV6_ADDRESS_POOL")]
    pub ipv6_address_pool: String,
    #[serde(rename = "IPV6_ALLOCATION_POLICY")]
    pub ipv6_allocation_policy: AllocationPolicy,
    #[serde(rename = "IPV6_SUBNET_PREFIX")]
    pub ipv6_subnet_prefix: u8,
    #[serde(rename = "IPV6_FORWARDING_ENABLED")]
    pub ipv6_forwarding_enabled: bool,
    #[serde(rename = "USE_NDP_PROXY")]
    pub use_ndp_proxy: bool,
}

impl Default for ControllerSettings {
    fn default() -> Self {
        Self {
            jailer_base_dir: None,
            network_interface: None,
            ipv4_address_pool: "172.16.0.0/12".to_string(),
            ipv4_network_prefix_length: 24,
            ipv6_address_pool: "fc00:1:2:3::/64".to_string(),
            ipv6_allocation_policy: AllocationPolicy::Static,
            ipv6_subnet_prefix: 124,
            ipv6_forwarding_enabled: true,
            use_ndp_proxy: true,
        }
    }
}

impl ControllerSettings {
    /// Python `config.settings.model_dump_json(indent=4)`: the slice as a
    /// 4-space-indented JSON object, fields in declaration order, `None`
    /// rendered as `null` (model_dump_json does not drop it here).
    pub fn to_print_json(&self) -> String {
        let mut buffer = Vec::new();
        let formatter = serde_json::ser::PrettyFormatter::with_indent(b"    ");
        let mut serializer = serde_json::Serializer::with_formatter(&mut buffer, formatter);
        self.serialize(&mut serializer)
            .expect("controller settings always serialize");
        String::from_utf8(buffer).expect("serde_json emits UTF-8")
    }
}

/// One `QemuVMHostVolume` entry. `mount` is carried for shape completeness
/// only; QemuVM never consumed it.
#[derive(Debug, Clone, Deserialize)]
pub struct HostVolume {
    #[serde(default)]
    #[allow(dead_code)]
    pub mount: String,
    pub path_on_host: String,
    pub read_only: bool,
}

/// One `QemuGPU` entry. `supports_x_vga` defaults to true like the pydantic
/// field (backward compatibility with configs that predate it).
#[derive(Debug, Clone, Deserialize)]
pub struct Gpu {
    pub pci_host: String,
    #[serde(default = "default_true")]
    pub supports_x_vga: bool,
}

fn default_true() -> bool {
    true
}

/// `QemuVMConfiguration` / `QemuConfidentialVMConfiguration`. The plain fields
/// are shared; the confidential four are optional and resolved by
/// [`QemuConfig::is_confidential`].
#[derive(Debug, Clone, Deserialize)]
pub struct QemuConfig {
    pub qemu_bin_path: String,
    #[serde(default)]
    pub cloud_init_drive_path: Option<String>,
    pub image_path: String,
    pub monitor_socket_path: String,
    pub qmp_socket_path: String,
    #[serde(default)]
    pub qga_socket_path: Option<String>,
    pub vcpu_count: u32,
    pub mem_size_mb: MiB,
    #[serde(default)]
    pub interface_name: Option<String>,
    pub host_volumes: Vec<HostVolume>,
    pub gpus: Vec<Gpu>,

    // Confidential slice: all four present means the payload is a
    // QemuConfidentialVMConfiguration (out of scope for increment A1).
    #[serde(default)]
    pub ovmf_path: Option<String>,
    #[serde(default)]
    pub sev_session_file: Option<String>,
    #[serde(default)]
    pub sev_dh_cert_file: Option<String>,
    #[serde(default)]
    pub sev_policy: Option<u32>,

    // SEV-SNP slice (increment B1). SNP is a measured DIRECT-KERNEL boot with
    // no session/godh handshake, so it does NOT carry the SEV `is_confidential`
    // four; `sev_snp: true` is the explicit backend marker the daemon writes.
    // When set, `ovmf_path` (measured OVMF), `sev_policy` (SNP policy),
    // `kernel_path`, `initrd_path` and `kernel_cmdline` (the exact measured
    // append, roothash included) are all present. These are Rust-only fields
    // (the Python controller has no SNP path); a Python controller reading such
    // a config ignores them (`extra="ignore"`).
    #[serde(default)]
    pub sev_snp: Option<bool>,
    #[serde(default)]
    pub kernel_path: Option<String>,
    #[serde(default)]
    pub initrd_path: Option<String>,
    #[serde(default)]
    pub kernel_cmdline: Option<String>,

    /// QEMU CPU model for the measured SNP launch, written by the daemon from
    /// the spec. A measurement input; `None` (a config written before this
    /// field existed) means `EPYC-v4`.
    #[serde(default)]
    pub cpu_model: Option<String>,

    // NUMA memory binding (increment C2), Rust-only. Present exactly when the
    // supervisor placed this VM on a NUMA node (a >1-node host); the argv then
    // binds guest RAM to that host node (`host-nodes={node},policy=bind`) via a
    // memory-backend. Absent for single-node / no-NUMA / unplaced VMs, which
    // keeps their argv byte-identical to pre-C2 (parity). A Python controller
    // reading such a config ignores it (`extra="ignore"`).
    #[serde(default)]
    pub numa_node: Option<u32>,
    // Hugepage backing for the memory backend (increment C2), Rust-only and
    // OPT-IN. Holds the QEMU `hugetlbsize` literal ("1G" or "2M") the daemon's
    // allocator selected; absent means regular pages (no `hugetlb=on`). Only
    // ever set alongside `numa_node`.
    #[serde(default)]
    pub hugepage_size: Option<String>,

    // Opaque-cmdline SEV-SNP rootfs override, Rust-only. Written TOGETHER (or
    // not at all, `extra="ignore"` on the Python side means an old-controller
    // config simply never carries them) for an SNP VM whose measured cmdline
    // came from the agent: that VM boots a WRITABLE rootfs (no dm-verity), so
    // `build_snp_argv` needs the image's format and read-only flag instead of
    // assuming the default raw/verity shape. See [`Self::rootfs_override`],
    // which resolves the pair and fails closed on a half-populated one.
    #[serde(default)]
    pub image_format: Option<String>,
    #[serde(default)]
    pub image_readonly: Option<bool>,
}

/// The resolved rootfs-disk override [`QemuConfig::rootfs_override`] produces
/// from the `image_format` / `image_readonly` pair. The daemon writes both
/// keys together or neither (see the fields' doc comment); a config with only
/// one is malformed, so this is a three-way tuple match rather than an
/// independent `Option::map` per field, which could not tell "no override"
/// (both absent) apart from "half a pair" (exactly one present). Mirrors the
/// all-or-nothing shape of [`QemuConfig::is_confidential`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RootfsOverride {
    /// Neither key present: the caller renders the default raw/verity token.
    Default,
    /// Both keys present: `(image_format, image_readonly)`.
    Writable(String, bool),
    /// Exactly one key present. The writer always sets both together, so
    /// this can only mean a corrupt or hand-edited config; callers must fail
    /// closed rather than guess which half is right (see main.rs's
    /// `select_run_target`, which refuses to dispatch this into
    /// `build_snp_argv`).
    Malformed,
}

impl QemuConfig {
    /// Parse the `vm_configuration` object of a controller config.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(json).map_err(|source| ConfigError::InvalidQemuJson { source })
    }

    /// True when this is a `QemuConfidentialVMConfiguration` (all four
    /// confidential fields present). The A1 dispatcher rejects these; A2 runs
    /// them via `build_confidential_argv`. SNP configs are NOT confidential in
    /// this sense (they carry no session/godh), so this stays false for them
    /// and the two paths never overlap.
    pub fn is_confidential(&self) -> bool {
        self.ovmf_path.is_some()
            && self.sev_session_file.is_some()
            && self.sev_dh_cert_file.is_some()
            && self.sev_policy.is_some()
    }

    /// True when this is a COMPLETE SEV-SNP measured-boot payload (increment
    /// B1): the `sev_snp: true` marker AND every field `build_snp_argv`
    /// `.expect()`s (`ovmf_path`, `sev_policy`, `kernel_path`, `initrd_path`,
    /// `kernel_cmdline`). Mirrors [`Self::is_confidential`]'s all-fields pattern
    /// so the dispatcher only routes to `build_snp_argv` when the invariant its
    /// `.expect()`s rely on actually holds. A marker-set-but-partial config is
    /// deliberately NOT snp here (it is [`Self::is_snp_marked`] instead), so it
    /// cannot be misdispatched into the SNP builder and panic; the dispatcher
    /// turns that case into a clean refusal. This agrees with the daemon-side
    /// `QemuVmConfig::snp` soft-fail (marker set, a field missing -> `None`).
    pub fn is_snp(&self) -> bool {
        self.sev_snp == Some(true)
            && self.ovmf_path.is_some()
            && self.sev_policy.is_some()
            && self.kernel_path.is_some()
            && self.initrd_path.is_some()
            && self.kernel_cmdline.is_some()
    }

    /// True when the SNP backend marker (`sev_snp: true`) is set, REGARDLESS of
    /// whether the measured-boot fields are complete. The dispatcher uses this
    /// to tell a partial SNP config (marker set, a field missing) apart from a
    /// genuine plain/SEV config: a partial SNP config must be a clean refusal,
    /// never a silent plain or SEV launch.
    pub fn is_snp_marked(&self) -> bool {
        self.sev_snp == Some(true)
    }

    /// Resolve the `image_format` / `image_readonly` pair into a
    /// [`RootfsOverride`]. See that type's doc comment for the three-way
    /// resolution and why a plain `Option<(String, bool)>` cannot represent
    /// the malformed (half-populated) case distinctly from "no override".
    pub fn rootfs_override(&self) -> RootfsOverride {
        match (self.image_format.as_deref(), self.image_readonly) {
            (None, None) => RootfsOverride::Default,
            (Some(format), Some(readonly)) => {
                RootfsOverride::Writable(format.to_string(), readonly)
            }
            _ => RootfsOverride::Malformed,
        }
    }
}

/// The resolved `vm_configuration` union member.
#[derive(Debug, Clone)]
pub enum VmConfiguration {
    Qemu(Box<QemuConfig>),
    /// A `VMConfiguration` (Firecracker) payload. A1 handles QEMU only; the
    /// dispatcher rejects this variant.
    Firecracker,
}

/// The `VMConfiguration` (Firecracker) shape, deserialized only to decide
/// whether a non-QEMU payload is a valid union member (pydantic parity).
#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct FirecrackerShape {
    use_jailer: bool,
    firecracker_bin_path: String,
    jailer_bin_path: String,
    config_file_path: String,
    init_timeout: f64,
}

/// The top-level `Configuration` model.
#[derive(Debug, Clone)]
pub struct Configuration {
    /// `Configuration.vm_id`: the vm_index (drives the `vmtap{vm_id}` name).
    pub vm_id: i64,
    /// `Configuration.vm_hash`: the VM item hash (drives the journal tags).
    pub vm_hash: String,
    pub settings: ControllerSettings,
    /// `Configuration.hypervisor`: the declared backend. The A1 dispatcher
    /// checks this FIRST (Python precedence), before the vm_configuration
    /// shape, so a QEMU-shaped payload labelled firecracker fails closed.
    pub hypervisor: HypervisorType,
    pub vm_configuration: VmConfiguration,
}

#[derive(Debug, Deserialize)]
struct RawConfiguration {
    vm_id: i64,
    vm_hash: String,
    settings: ControllerSettings,
    vm_configuration: serde_json::Value,
    #[serde(default = "default_hypervisor")]
    hypervisor: String,
}

fn default_hypervisor() -> String {
    "firecracker".to_string()
}

impl Configuration {
    /// Read and parse `{vm_hash}-controller.json` from disk.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let contents = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::from_json(&contents)
    }

    /// Parse one controller configuration file's JSON contents.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let raw: RawConfiguration =
            serde_json::from_str(json).map_err(|source| ConfigError::InvalidJson { source })?;
        // The hypervisor field is validated like the pydantic HypervisorType
        // enum. It does not pick the union member (the shape does), but the
        // dispatcher checks it first (Python's firecracker-first precedence),
        // so it is carried through, not just validated.
        let hypervisor = match raw.hypervisor.as_str() {
            "qemu" => HypervisorType::Qemu,
            "firecracker" => HypervisorType::Firecracker,
            other => {
                return Err(ConfigError::UnknownHypervisor {
                    value: other.to_string(),
                });
            }
        };
        let vm_configuration =
            match serde_json::from_value::<QemuConfig>(raw.vm_configuration.clone()) {
                Ok(config) => VmConfiguration::Qemu(Box::new(config)),
                Err(qemu_error) => {
                    match serde_json::from_value::<FirecrackerShape>(raw.vm_configuration) {
                        Ok(_) => VmConfiguration::Firecracker,
                        Err(firecracker_error) => {
                            return Err(ConfigError::NoUnionMember {
                                qemu_error,
                                firecracker_error,
                            });
                        }
                    }
                }
            };
        Ok(Self {
            vm_id: raw.vm_id,
            vm_hash: raw.vm_hash,
            settings: raw.settings,
            hypervisor,
            vm_configuration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config_with_mem(raw: &str) -> String {
        format!(
            r#"{{"qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
                "qmp_socket_path":"p","vcpu_count":1,"mem_size_mb":{raw},
                "host_volumes":[],"gpus":[]}}"#
        )
    }

    #[test]
    fn mem_size_reads_a_bare_integer() {
        // The only shape a real config carries: pydantic MiB is an int
        // subclass and the daemon writer holds a u64, so both serialize a
        // bare integer.
        let config = QemuConfig::from_json(&config_with_mem("2048")).unwrap();
        assert_eq!(config.mem_size_mb, MiB::from(2048));
    }

    #[test]
    fn a_non_integer_mem_size_is_a_parse_error() {
        // Strict by construction (MiB is a u64 newtype): a float would need
        // `-m 2048.7`-style truncation, a negative would wrap through a
        // C cast to `-m 0`, a string was never written by any producer.
        // All must fail the parse rather than be coerced.
        for raw in ["2048.7", "-2048", "\"2048\"", "null"] {
            assert!(
                QemuConfig::from_json(&config_with_mem(raw)).is_err(),
                "{raw} must be rejected"
            );
        }
    }

    #[test]
    fn confidential_resolves_only_when_all_four_fields_are_present() {
        let base = r#""qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
            "qmp_socket_path":"p","vcpu_count":1,"mem_size_mb":2048,
            "host_volumes":[],"gpus":[]"#;
        let plain = format!("{{{base}}}");
        assert!(!QemuConfig::from_json(&plain).unwrap().is_confidential());
        let confidential = format!(
            r#"{{{base},"ovmf_path":"o","sev_session_file":"s",
                "sev_dh_cert_file":"d","sev_policy":5}}"#
        );
        assert!(
            QemuConfig::from_json(&confidential)
                .unwrap()
                .is_confidential()
        );
    }

    #[test]
    fn snp_resolves_only_when_the_marker_and_all_measured_fields_are_present() {
        let base = r#""qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
            "qmp_socket_path":"p","vcpu_count":2,"mem_size_mb":2048,
            "host_volumes":[],"gpus":[]"#;
        // The complete SNP payload: marker plus all five measured fields.
        let complete = format!(
            r#"{{{base},"sev_snp":true,"ovmf_path":"/OVMF.fd","sev_policy":196608,
                "kernel_path":"/bzImage","initrd_path":"/initrd",
                "kernel_cmdline":"console=ttyS0 roothash=abc"}}"#
        );
        let config = QemuConfig::from_json(&complete).unwrap();
        assert!(config.is_snp(), "a complete SNP config resolves as SNP");
        assert!(config.is_snp_marked());

        // Each of the five measured fields dropped in turn: the marker stays set
        // (is_snp_marked), but is_snp is false, so the dispatcher never routes
        // it into build_snp_argv (whose .expect()s would panic).
        for missing in [
            "ovmf_path",
            "sev_policy",
            "kernel_path",
            "initrd_path",
            "kernel_cmdline",
        ] {
            let mut value: serde_json::Value = serde_json::from_str(&complete).unwrap();
            value.as_object_mut().unwrap().remove(missing);
            let partial = serde_json::to_string(&value).unwrap();
            let config = QemuConfig::from_json(&partial).unwrap();
            assert!(
                !config.is_snp(),
                "an SNP config missing {missing} must NOT resolve as SNP"
            );
            assert!(
                config.is_snp_marked(),
                "the marker is still set with {missing} missing"
            );
        }
    }

    #[test]
    fn rootfs_override_defaults_to_none_and_resolves_to_default() {
        // A config without the override keys (any non-luks SNP/plain config)
        // parses both as None and the pair resolves to Default, keeping
        // build_snp_argv's byte-identical token.
        let base = r#""qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
            "qmp_socket_path":"p","vcpu_count":1,"mem_size_mb":2048,
            "host_volumes":[],"gpus":[]"#;
        let config = QemuConfig::from_json(&format!("{{{base}}}")).unwrap();
        assert_eq!(config.image_format, None);
        assert_eq!(config.image_readonly, None);
        assert_eq!(config.rootfs_override(), RootfsOverride::Default);
    }

    #[test]
    fn rootfs_override_resolves_writable_when_both_keys_are_present() {
        // The luks config (the opaque-cmdline SEV-SNP arm): both keys set
        // together.
        let base = r#""qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
            "qmp_socket_path":"p","vcpu_count":1,"mem_size_mb":2048,
            "host_volumes":[],"gpus":[]"#;
        let json = format!(r#"{{{base},"image_format":"qcow2","image_readonly":false}}"#);
        let config = QemuConfig::from_json(&json).unwrap();
        assert_eq!(config.image_format.as_deref(), Some("qcow2"));
        assert_eq!(config.image_readonly, Some(false));
        assert_eq!(
            config.rootfs_override(),
            RootfsOverride::Writable("qcow2".to_string(), false)
        );
    }

    #[test]
    fn rootfs_override_is_malformed_when_only_one_key_is_present() {
        // The writer always sets image_format and image_readonly together;
        // a config with only one is corrupt/hand-edited and must fail
        // closed, not guess.
        let base = r#""qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
            "qmp_socket_path":"p","vcpu_count":1,"mem_size_mb":2048,
            "host_volumes":[],"gpus":[]"#;
        for json in [
            format!(r#"{{{base},"image_format":"qcow2"}}"#),
            format!(r#"{{{base},"image_readonly":false}}"#),
        ] {
            let config = QemuConfig::from_json(&json).unwrap();
            assert_eq!(
                config.rootfs_override(),
                RootfsOverride::Malformed,
                "half-populated config must resolve as Malformed: {json}"
            );
        }
    }

    #[test]
    fn a_firecracker_payload_resolves_to_the_unsupported_variant() {
        let json = r#"{
            "vm_id": 7, "vm_hash": "deadbeef", "settings": {},
            "vm_configuration": {
                "use_jailer": true,
                "firecracker_bin_path": "/opt/firecracker/firecracker",
                "jailer_bin_path": "/opt/firecracker/jailer",
                "config_file_path": "/var/lib/aleph/vm/deadbeef.json",
                "init_timeout": 5.0
            },
            "hypervisor": "firecracker"
        }"#;
        let config = Configuration::from_json(json).unwrap();
        assert!(matches!(
            config.vm_configuration,
            VmConfiguration::Firecracker
        ));
    }

    #[test]
    fn settings_defaults_fall_back_and_print_json_is_indented() {
        let config = Configuration::from_json(
            r#"{"vm_id":3,"vm_hash":"abc","settings":{"NETWORK_INTERFACE":"eth0"},
                "vm_configuration":{"qemu_bin_path":"q","image_path":"i",
                "monitor_socket_path":"m","qmp_socket_path":"p","vcpu_count":1,
                "mem_size_mb":2048,"host_volumes":[],"gpus":[]},"hypervisor":"qemu"}"#,
        )
        .unwrap();
        assert_eq!(config.settings.ipv4_address_pool, "172.16.0.0/12");
        assert_eq!(config.settings.network_interface.as_deref(), Some("eth0"));
        let printed = config.settings.to_print_json();
        assert!(printed.starts_with("{\n    \"JAILER_BASE_DIR\": null,"));
        assert!(printed.contains("\"IPV6_ALLOCATION_POLICY\": \"static\""));
    }
}
