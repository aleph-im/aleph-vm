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
//! Field names, defaults and the lax `mem_size_mb` coercion match the
//! pydantic models so a config written by the Python supervisor (or the Rust
//! daemon writer) parses unchanged.

use serde::{Deserialize, Deserializer, Serialize};

/// A failure to read or parse a controller config file.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct ConfigError(pub String);

/// The `IPv6AllocationPolicy` str-enum, validated like pydantic (an unknown
/// value is an error, not a fallback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum AllocationPolicy {
    #[serde(rename = "static")]
    Static,
    #[serde(rename = "dynamic")]
    Dynamic,
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
    #[serde(deserialize_with = "deserialize_mem_size_mib")]
    pub mem_size_mb: u64,
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
}

impl QemuConfig {
    /// Parse the `vm_configuration` object of a controller config.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        serde_json::from_str(json)
            .map_err(|error| ConfigError(format!("invalid QemuVMConfiguration JSON: {error}")))
    }

    /// True when this is a `QemuConfidentialVMConfiguration` (all four
    /// confidential fields present). The A1 dispatcher rejects these.
    pub fn is_confidential(&self) -> bool {
        self.ovmf_path.is_some()
            && self.sev_session_file.is_some()
            && self.sev_dh_cert_file.is_some()
            && self.sev_policy.is_some()
    }
}

/// `MemSizeMib` reads with the coercion of the Python `_coerce_mib`
/// (`MiB(int(value))`): an integer, a float JSON number (Python's `int()`
/// truncates) or an INTEGER string. A float STRING like "2048.5" raises in
/// `int(value)` and makes the whole config unparseable; it is rejected here
/// too.
fn deserialize_mem_size_mib<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = serde_json::Value::deserialize(deserializer)?;
    let parsed = match &value {
        serde_json::Value::Number(number) => number
            .as_u64()
            .or_else(|| number.as_f64().map(|float| float as u64)),
        serde_json::Value::String(text) => text.trim().parse::<u64>().ok(),
        _ => None,
    };
    parsed.ok_or_else(|| serde::de::Error::custom(format!("cannot coerce {value} to MiB")))
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
        let contents = std::fs::read_to_string(path)
            .map_err(|error| ConfigError(format!("cannot read {}: {error}", path.display())))?;
        Self::from_json(&contents)
    }

    /// Parse one controller configuration file's JSON contents.
    pub fn from_json(json: &str) -> Result<Self, ConfigError> {
        let raw: RawConfiguration = serde_json::from_str(json)
            .map_err(|error| ConfigError(format!("invalid Configuration JSON: {error}")))?;
        // The hypervisor field is validated like the pydantic HypervisorType
        // enum, but it does not pick the union member: the shape does.
        if raw.hypervisor != "qemu" && raw.hypervisor != "firecracker" {
            return Err(ConfigError(format!(
                "unknown hypervisor {:?}",
                raw.hypervisor
            )));
        }
        let vm_configuration =
            match serde_json::from_value::<QemuConfig>(raw.vm_configuration.clone()) {
                Ok(config) => VmConfiguration::Qemu(Box::new(config)),
                Err(qemu_error) => {
                    match serde_json::from_value::<FirecrackerShape>(raw.vm_configuration) {
                        Ok(_) => VmConfiguration::Firecracker,
                        Err(firecracker_error) => {
                            return Err(ConfigError(format!(
                                "vm_configuration fits no union member: \
                                 not QEMU ({qemu_error}); not Firecracker ({firecracker_error})"
                            )));
                        }
                    }
                }
            };
        Ok(Self {
            vm_id: raw.vm_id,
            vm_hash: raw.vm_hash,
            settings: raw.settings,
            vm_configuration,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mem_size_accepts_the_pydantic_lax_forms() {
        for (raw, expected) in [
            ("2048", 2048u64),
            ("2048.0", 2048),
            // Python int() truncates a float JSON number.
            ("2048.7", 2048),
            ("\"2048\"", 2048),
        ] {
            let json = format!(
                r#"{{"qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
                    "qmp_socket_path":"p","vcpu_count":1,"mem_size_mb":{raw},
                    "host_volumes":[],"gpus":[]}}"#
            );
            let config = QemuConfig::from_json(&json).unwrap();
            assert_eq!(config.mem_size_mb, expected);
        }
    }

    #[test]
    fn a_float_string_mem_size_is_rejected() {
        let json = r#"{"qemu_bin_path":"q","image_path":"i","monitor_socket_path":"m",
            "qmp_socket_path":"p","vcpu_count":1,"mem_size_mb":"2048.5",
            "host_volumes":[],"gpus":[]}"#;
        assert!(QemuConfig::from_json(json).is_err());
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
