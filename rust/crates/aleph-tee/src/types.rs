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

/// The measurement registers SEV-SNP pins: one launch digest.
///
/// Mirrors `LaunchMeasurement.registers` on the message side (aleph-message
/// 1.3.0). A concrete struct rather than a per-platform enum because only
/// SEV-SNP is defined today; a second platform turns it into an enum
/// discriminated on TEE type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SevSnpRegisters {
    /// 48-byte launch digest, from the signed report.
    #[serde(with = "hex_serde")]
    pub launch: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "VerificationResultWire", into = "VerificationResultWire")]
pub struct VerificationResult {
    pub valid: bool,
    pub tee_type: TeeType,
    pub summary: String,
    /// Launch measurement registers, derived from the AMD-verified blob (NOT
    /// a caller-supplied copy). Object rather than scalar because a TEE's
    /// launch identity is not always one value; SEV-SNP pins `launch` only.
    pub registers: SevSnpRegisters,
    /// The 64-byte `report_data`, derived from the AMD-verified blob (NOT a
    /// caller-supplied copy). Callers bind key/nonce commitments against THIS
    /// value, never against any unsigned copy.
    #[serde(with = "hex_serde_array")]
    pub report_data: [u8; 64],
    pub details: serde_json::Value,
}

/// Wire form of [`VerificationResult`], carrying both register formats.
///
/// aleph-vm 2.0 serialized a scalar hex `measurement`; 2.1 carries
/// `registers`. Emitting both and accepting either keeps mixed-version
/// peers interoperating across the change. The scalar is a deprecated
/// duplicate of `registers.launch`; drop it after one release cycle.
#[derive(Serialize, Deserialize)]
struct VerificationResultWire {
    valid: bool,
    tee_type: TeeType,
    summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    registers: Option<SevSnpRegisters>,
    /// Deprecated scalar duplicate of `registers.launch`, hex-encoded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    measurement: Option<String>,
    #[serde(with = "hex_serde_array")]
    report_data: [u8; 64],
    details: serde_json::Value,
}

impl From<VerificationResult> for VerificationResultWire {
    fn from(result: VerificationResult) -> Self {
        VerificationResultWire {
            valid: result.valid,
            tee_type: result.tee_type,
            summary: result.summary,
            measurement: Some(hex::encode(&result.registers.launch)),
            registers: Some(result.registers),
            report_data: result.report_data,
            details: result.details,
        }
    }
}

impl TryFrom<VerificationResultWire> for VerificationResult {
    type Error = anyhow::Error;

    fn try_from(wire: VerificationResultWire) -> Result<Self, Self::Error> {
        let registers = match (wire.registers, wire.measurement) {
            (Some(registers), Some(measurement)) => {
                // Both formats present: they must agree, or one of them is
                // lying about the launch digest. Fail closed.
                let scalar = hex::decode(&measurement)
                    .map_err(|e| anyhow::anyhow!("legacy measurement is not hex: {e}"))?;
                anyhow::ensure!(
                    scalar == registers.launch,
                    "legacy measurement does not match registers.launch"
                );
                registers
            }
            (Some(registers), None) => registers,
            (None, Some(measurement)) => SevSnpRegisters {
                launch: hex::decode(&measurement)
                    .map_err(|e| anyhow::anyhow!("legacy measurement is not hex: {e}"))?,
            },
            (None, None) => anyhow::bail!(
                "verification result carries neither registers nor the legacy measurement"
            ),
        };
        Ok(VerificationResult {
            valid: wire.valid,
            tee_type: wire.tee_type,
            summary: wire.summary,
            registers,
            report_data: wire.report_data,
            details: wire.details,
        })
    }
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
    fn verification_result_speaks_both_register_formats() {
        let launch = vec![0xAB; 48];
        let result = VerificationResult {
            valid: true,
            tee_type: TeeType::SevSnp,
            summary: String::new(),
            registers: SevSnpRegisters {
                launch: launch.clone(),
            },
            report_data: [0u8; 64],
            details: serde_json::Value::Null,
        };
        let json = serde_json::to_value(&result).unwrap();
        // New format plus the deprecated scalar duplicate, so peers on
        // either side of the aleph-vm 2.0 -> 2.1 change keep parsing.
        assert_eq!(
            json["registers"]["launch"],
            serde_json::json!("ab".repeat(48))
        );
        assert_eq!(json["measurement"], json["registers"]["launch"]);

        let back: VerificationResult = serde_json::from_value(json.clone()).unwrap();
        assert_eq!(back.registers.launch, launch);

        // A 2.0 peer's payload (scalar only) still deserializes.
        let mut legacy = json.clone();
        legacy.as_object_mut().unwrap().remove("registers");
        let back: VerificationResult = serde_json::from_value(legacy).unwrap();
        assert_eq!(back.registers.launch, launch);

        // Registers-only (a future emitter that dropped the alias) works too.
        let mut modern = json.clone();
        modern.as_object_mut().unwrap().remove("measurement");
        let back: VerificationResult = serde_json::from_value(modern).unwrap();
        assert_eq!(back.registers.launch, launch);

        // Disagreeing formats fail closed rather than silently pick one.
        let mut lying = json;
        lying["measurement"] = serde_json::json!("cd".repeat(48));
        assert!(serde_json::from_value::<VerificationResult>(lying).is_err());
    }

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
