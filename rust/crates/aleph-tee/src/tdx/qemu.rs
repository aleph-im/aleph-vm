use base64::Engine;
use serde::Serialize;

use crate::types::VmConfig;

/// Default TDVF firmware path (edk2 IntelTdx variant, built by nix/tdvf.nix).
pub const DEFAULT_TDVF_PATH: &str = "/usr/local/share/tdvf/TDVF.fd";

/// Default Intel Quote Generation Service unix socket, as the DCAP `tdx-qgs`
/// package installs it.
pub const DEFAULT_QGS_SOCKET: &str = "/var/run/tdx-qgs/qgs.socket";

/// Size of the TD's MRCONFIGID register.
pub const MRCONFIGID_LEN: usize = 48;

/// The `tdx-guest` QOM object. QEMU accepts the nested `quote-generation-socket`
/// only in JSON `-object` form, so the whole object is one JSON argv element.
/// Field order is the emitted key order.
#[derive(Serialize)]
struct TdxGuestObject<'a> {
    #[serde(rename = "qom-type")]
    qom_type: &'static str,
    id: &'static str,
    mrconfigid: String,
    #[serde(rename = "quote-generation-socket")]
    quote_generation_socket: SocketAddress<'a>,
}

#[derive(Serialize)]
struct SocketAddress<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    path: &'a str,
}

/// Render the `tdx-guest` object as compact JSON, `mrconfigid` base64 (standard
/// alphabet, padded) as QEMU expects it.
pub fn tdx_guest_object(mrconfigid: &[u8; MRCONFIGID_LEN], qgs_socket: &str) -> String {
    let object = TdxGuestObject {
        qom_type: "tdx-guest",
        id: "tdx0",
        mrconfigid: base64::engine::general_purpose::STANDARD.encode(mrconfigid),
        quote_generation_socket: SocketAddress {
            kind: "unix",
            path: qgs_socket,
        },
    };
    serde_json::to_string(&object).expect("tdx-guest object always serializes")
}

/// Generate QEMU command-line arguments for launching a TDX confidential VM.
///
/// Produces, in order:
/// - `-cpu host` (TDX has no per-vCPU VMSA measurement, so no model pin)
/// - `-machine q35,kernel-irqchip=split,confidential-guest-support=tdx0,hpet=off,vmport=off,memory-backend=ram1`
/// - `-object memory-backend-memfd,id=ram1,size={memory_mb}M,share=true[,hugetlb..][,host-nodes..]`
///   (the SEV-SNP object unchanged: NUMA placement transfers as is)
/// - `-object {"qom-type":"tdx-guest","id":"tdx0","mrconfigid":"<b64>","quote-generation-socket":{"type":"unix","path":"<qgs>"}}`
/// - `-nodefaults`
/// - `-bios <tdvf_path>`
/// - `-kernel`, `-initrd`, `-append` (direct boot; TDVF measures the blobs
///   into RTMR1/RTMR2 itself, there is no `kernel-hashes` equivalent)
///
/// `mrconfigid` is the deployment binding (SHA-384 of the per-deployment
/// cmdline suffix); it lands in the TDREPORT byte-exact. There is no launch
/// policy: TD attributes come from the module defaults.
#[allow(clippy::too_many_arguments)]
pub fn tdx_qemu_args(
    config: &VmConfig,
    tdvf_path: &str,
    kernel: &str,
    initrd: &str,
    cmdline: &str,
    mrconfigid: &[u8; MRCONFIGID_LEN],
    qgs_socket: &str,
) -> Vec<String> {
    let hugetlb_opts = match config.hugepage_size {
        Some(crate::types::HugePageSize::Size1G) => ",hugetlb=on,hugetlbsize=1G",
        Some(crate::types::HugePageSize::Size2M) => ",hugetlb=on,hugetlbsize=2M",
        None => "",
    };

    let numa_opts = if let Some(node) = config.numa_node {
        format!(",host-nodes={node},policy=bind")
    } else {
        String::new()
    };

    let memfd_opts = format!(
        "memory-backend-memfd,id=ram1,size={}M,share=true{hugetlb_opts}{numa_opts}",
        config.memory_mb
    );

    vec![
        "-cpu".to_string(),
        "host".to_string(),
        "-machine".to_string(),
        "q35,kernel-irqchip=split,confidential-guest-support=tdx0,hpet=off,vmport=off,memory-backend=ram1"
            .to_string(),
        "-object".to_string(),
        memfd_opts,
        "-object".to_string(),
        tdx_guest_object(mrconfigid, qgs_socket),
        // Strip QEMU's default devices, like the SNP launch: less for TDVF
        // to enumerate.
        "-nodefaults".to_string(),
        "-bios".to_string(),
        tdvf_path.to_string(),
        "-kernel".to_string(),
        kernel.to_string(),
        "-initrd".to_string(),
        initrd.to_string(),
        "-append".to_string(),
        cmdline.to_string(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{HugePageSize, TeeConfig, TeeType, VmConfig};

    const MRCONFIGID: [u8; MRCONFIGID_LEN] = [0xA5; MRCONFIGID_LEN];

    fn make_config(memory_mb: u32) -> VmConfig {
        VmConfig {
            vm_id: "test-vm".to_string(),
            kernel: None,
            initrd: None,
            disks: vec![],
            vcpus: 2,
            memory_mb,
            tee: TeeConfig {
                backend: TeeType::Tdx,
                policy: None,
                cpu_model: None,
            },
            encrypted: false,
            numa_node: None,
            hugepage_size: None,
        }
    }

    fn args_for(config: &VmConfig) -> Vec<String> {
        tdx_qemu_args(
            config,
            DEFAULT_TDVF_PATH,
            "/boot/vmlinuz",
            "/boot/initrd.img",
            "console=ttyS0 aleph_tdx_descriptor=1",
            &MRCONFIGID,
            DEFAULT_QGS_SOCKET,
        )
    }

    #[test]
    fn argv_shape_is_fixed() {
        let args = args_for(&make_config(2048));
        assert_eq!(
            args,
            [
                "-cpu",
                "host",
                "-machine",
                "q35,kernel-irqchip=split,confidential-guest-support=tdx0,hpet=off,vmport=off,memory-backend=ram1",
                "-object",
                "memory-backend-memfd,id=ram1,size=2048M,share=true",
                "-object",
                r#"{"qom-type":"tdx-guest","id":"tdx0","mrconfigid":"paWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWlpaWl","quote-generation-socket":{"type":"unix","path":"/var/run/tdx-qgs/qgs.socket"}}"#,
                "-nodefaults",
                "-bios",
                DEFAULT_TDVF_PATH,
                "-kernel",
                "/boot/vmlinuz",
                "-initrd",
                "/boot/initrd.img",
                "-append",
                "console=ttyS0 aleph_tdx_descriptor=1",
            ]
        );
    }

    #[test]
    fn tdx_guest_object_is_compact_json_with_fixed_key_order() {
        let object = tdx_guest_object(&[0u8; MRCONFIGID_LEN], "/tmp/qgs.sock");
        assert_eq!(
            object,
            r#"{"qom-type":"tdx-guest","id":"tdx0","mrconfigid":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","quote-generation-socket":{"type":"unix","path":"/tmp/qgs.sock"}}"#
        );
        assert!(!object.contains(' '), "no whitespace: {object}");
        // 48 bytes always pad to a 64-char base64 string.
        let parsed: serde_json::Value = serde_json::from_str(&object).unwrap();
        assert_eq!(parsed["mrconfigid"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn socket_path_is_json_escaped_not_spliced() {
        // A path with a quote cannot break out of the object: serde escapes it.
        let object = tdx_guest_object(&MRCONFIGID, "/run/q\"gs.sock");
        let parsed: serde_json::Value = serde_json::from_str(&object).unwrap();
        assert_eq!(
            parsed["quote-generation-socket"]["path"].as_str().unwrap(),
            "/run/q\"gs.sock"
        );
    }

    #[test]
    fn memory_backend_matches_snp_shape_with_numa_and_hugepages() {
        let mut config = make_config(4096);
        config.numa_node = Some(1);
        config.hugepage_size = Some(HugePageSize::Size1G);
        let args = args_for(&config);
        assert_eq!(
            args[5],
            "memory-backend-memfd,id=ram1,size=4096M,share=true,hugetlb=on,hugetlbsize=1G,host-nodes=1,policy=bind"
        );
        // Same object the SEV-SNP generator renders for the same placement.
        let mut snp = config.clone();
        snp.tee.backend = TeeType::SevSnp;
        let snp_args = crate::sev_snp::qemu::sev_snp_qemu_args(&snp, "/OVMF.fd", 51, 1);
        assert_eq!(snp_args[5], args[5]);
    }

    #[test]
    fn no_policy_no_kernel_hashes_no_cpu_pin() {
        let joined = args_for(&make_config(2048)).join(" ");
        assert!(!joined.contains("kernel-hashes"));
        assert!(!joined.contains("policy=0x"));
        assert!(!joined.contains("EPYC"));
    }
}
