use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TeeType {
    SevSnp,
    Tdx,
    NvidiaCc,
    None,
}

/// An attestation report as transported between the in-guest agent and the
/// verifying client.
///
/// # Trust model: `data` is the ONLY source of truth
///
/// `data` is the raw AMD-signed report blob (1184 bytes for SEV-SNP). It is the
/// ONLY field AMD's signature covers, and it internally carries its own
/// `report_data` (the 64 free bytes the guest chose) and `measurement` (the
/// launch digest). Verifiers MUST derive those values by PARSING `data` (see
/// `aleph_tee::sev_snp::report::{extract_report_data, extract_measurement}`)
/// and MUST run the full AMD certificate chain over `data` before trusting any
/// of it.
///
/// This type deliberately does NOT carry standalone `report_data` /
/// `measurement` copies. Earlier revisions (and the aleph-cvm donor) serialized
/// those alongside `data`, but they are unsigned: an attacker can replay any
/// genuine AMD-signed blob as `data` and set the JSON copies to whatever passes
/// a check. Removing them makes it structurally impossible to gate trust on the
/// unsigned copies. This is a deliberate divergence from the donor; see the
/// rust-port-divergences ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    pub tee_type: TeeType,
    /// The raw AMD-signed report blob. Single source of truth for
    /// `report_data` and `measurement`; both are derived by parsing this.
    #[serde(with = "hex_serde")]
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    pub valid: bool,
    pub tee_type: TeeType,
    pub summary: String,
    /// Launch measurement, derived from the AMD-verified blob (NOT a
    /// caller-supplied copy).
    #[serde(with = "hex_serde")]
    pub measurement: Vec<u8>,
    /// The 64-byte `report_data`, derived from the AMD-verified blob (NOT a
    /// caller-supplied copy). Callers bind key/nonce commitments against THIS
    /// value, never against any unsigned copy.
    #[serde(with = "hex_serde_array")]
    pub report_data: [u8; 64],
    pub details: serde_json::Value,
}

/// Configuration for a disk attached to a VM.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskConfig {
    pub path: std::path::PathBuf,
    #[serde(default = "default_true")]
    pub readonly: bool,
    #[serde(default = "default_raw")]
    pub format: String,
}

fn default_true() -> bool {
    true
}

fn default_raw() -> String {
    "raw".to_string()
}

/// Hugepage size used for the VM's memory backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HugePageSize {
    /// 2 MiB hugepages (default, always available).
    #[serde(rename = "2m")]
    Size2M,
    /// 1 GiB hugepages (requires boot-time reservation).
    #[serde(rename = "1g")]
    Size1G,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    pub vm_id: String,
    #[serde(default)]
    pub kernel: Option<std::path::PathBuf>,
    #[serde(default)]
    pub initrd: Option<std::path::PathBuf>,
    #[serde(default)]
    pub disks: Vec<DiskConfig>,
    pub vcpus: u32,
    pub memory_mb: u32,
    pub tee: TeeConfig,
    /// LUKS encrypted rootfs mode (skip dm-verity, user injects key via attest-agent).
    #[serde(default)]
    pub encrypted: bool,
    /// NUMA node this VM is pinned to (set by the allocator, not the user).
    #[serde(default)]
    pub numa_node: Option<u32>,
    /// Hugepage size for this VM's memory backend (set by the allocator, not the user).
    #[serde(default)]
    pub hugepage_size: Option<HugePageSize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeConfig {
    pub backend: TeeType,
    pub policy: Option<String>,
    /// QEMU CPU model for a measured SEV-SNP launch. A measurement input (it
    /// selects the per-vCPU VMSA contents), so it is carried, never inferred
    /// from the host. `None` = [`crate::sev_snp::qemu::DEFAULT_CPU_MODEL`].
    #[serde(default)]
    pub cpu_model: Option<String>,
}

/// Serde helper for hex-encoding `Vec<u8>` fields.
mod hex_serde {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for hex-encoding `[u8; 64]` fields.
mod hex_serde_array {
    use serde::{self, Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let array: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected exactly 64 bytes"))?;
        Ok(array)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tee_type_serialization() {
        // Serialize SevSnp to JSON
        let json = serde_json::to_string(&TeeType::SevSnp).unwrap();
        assert_eq!(json, "\"sev-snp\"");

        // Verify other variants too
        assert_eq!(serde_json::to_string(&TeeType::Tdx).unwrap(), "\"tdx\"");
        assert_eq!(
            serde_json::to_string(&TeeType::NvidiaCc).unwrap(),
            "\"nvidia-cc\""
        );

        // Deserialize back
        let deserialized: TeeType = serde_json::from_str("\"sev-snp\"").unwrap();
        assert_eq!(deserialized, TeeType::SevSnp);
    }

    #[test]
    fn test_attestation_report_roundtrip() {
        let report = AttestationReport {
            tee_type: TeeType::SevSnp,
            data: vec![0xde, 0xad, 0xbe, 0xef],
        };

        let json = serde_json::to_string(&report).unwrap();
        let deserialized: AttestationReport = serde_json::from_str(&json).unwrap();

        assert_eq!(deserialized.tee_type, report.tee_type);
        assert_eq!(deserialized.data, report.data);

        // Verify hex encoding is present in the JSON.
        assert!(json.contains("deadbeef"));
        // The unsigned copies are gone: only `data` (and tee_type) are carried.
        assert!(!json.contains("report_data"));
        assert!(!json.contains("measurement"));
    }

    #[test]
    fn test_vm_config_deserialization() {
        let json = r#"{
            "vm_id": "test-vm-001",
            "kernel": "/boot/vmlinuz",
            "initrd": "/boot/initrd.img",
            "disks": [
                {"path": "/images/rootfs.ext4", "readonly": true, "format": "raw"},
                {"path": "/data/volume.qcow2", "readonly": false, "format": "qcow2"}
            ],
            "vcpus": 4,
            "memory_mb": 2048,
            "tee": {
                "backend": "sev-snp",
                "policy": "0x30000"
            }
        }"#;

        let config: VmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.vm_id, "test-vm-001");
        assert_eq!(
            config.kernel,
            Some(std::path::PathBuf::from("/boot/vmlinuz"))
        );
        assert_eq!(
            config.initrd,
            Some(std::path::PathBuf::from("/boot/initrd.img"))
        );
        assert_eq!(config.disks.len(), 2);
        assert_eq!(
            config.disks[0].path,
            std::path::PathBuf::from("/images/rootfs.ext4")
        );
        assert!(config.disks[0].readonly);
        assert_eq!(config.disks[0].format, "raw");
        assert_eq!(
            config.disks[1].path,
            std::path::PathBuf::from("/data/volume.qcow2")
        );
        assert!(!config.disks[1].readonly);
        assert_eq!(config.disks[1].format, "qcow2");
        assert_eq!(config.vcpus, 4);
        assert_eq!(config.memory_mb, 2048);
        assert_eq!(config.tee.backend, TeeType::SevSnp);
        assert_eq!(config.tee.policy, Some("0x30000".to_string()));
    }

    #[test]
    fn test_vm_config_no_disks() {
        let json = r#"{
            "vm_id": "test-vm-002",
            "kernel": "/boot/vmlinuz",
            "initrd": "/boot/initrd.img",
            "vcpus": 2,
            "memory_mb": 1024,
            "tee": {
                "backend": "tdx",
                "policy": null
            }
        }"#;

        let config: VmConfig = serde_json::from_str(json).unwrap();
        assert!(config.disks.is_empty());
        assert_eq!(config.tee.backend, TeeType::Tdx);
        assert!(config.tee.policy.is_none());
    }

    #[test]
    fn test_disk_config_defaults() {
        let json = r#"{"path": "/images/rootfs.ext4"}"#;
        let disk: DiskConfig = serde_json::from_str(json).unwrap();
        assert!(disk.readonly); // default true
        assert_eq!(disk.format, "raw"); // default raw
    }

    #[test]
    fn test_tee_type_none_serialization() {
        let json = serde_json::to_string(&TeeType::None).unwrap();
        assert_eq!(json, "\"none\"");
        let deserialized: TeeType = serde_json::from_str("\"none\"").unwrap();
        assert_eq!(deserialized, TeeType::None);
    }

    #[test]
    fn test_vm_config_optional_kernel() {
        let json = r#"{
            "vm_id": "test-vm",
            "disks": [{"path": "/images/ubuntu.qcow2", "readonly": false, "format": "qcow2"}],
            "vcpus": 2,
            "memory_mb": 2048,
            "tee": {"backend": "none"}
        }"#;
        let config: VmConfig = serde_json::from_str(json).unwrap();
        assert!(config.kernel.is_none());
        assert!(config.initrd.is_none());
        assert_eq!(config.tee.backend, TeeType::None);
    }

    #[test]
    fn test_vm_config_backward_compat_with_kernel() {
        let json = r#"{
            "vm_id": "test-vm",
            "kernel": "/boot/vmlinuz",
            "initrd": "/boot/initrd.img",
            "vcpus": 2,
            "memory_mb": 2048,
            "tee": {"backend": "sev-snp", "policy": "0x30000"}
        }"#;
        let config: VmConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            config.kernel.unwrap(),
            std::path::PathBuf::from("/boot/vmlinuz")
        );
        assert_eq!(
            config.initrd.unwrap(),
            std::path::PathBuf::from("/boot/initrd.img")
        );
    }
}
