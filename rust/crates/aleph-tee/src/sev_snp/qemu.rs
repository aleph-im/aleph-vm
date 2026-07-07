use crate::types::VmConfig;

/// Default SEV-SNP guest policy value.
///
/// 0x30000 enables SEV-SNP with SMT allowed and debug disabled.
const DEFAULT_POLICY: &str = "0x30000";

/// Default OVMF firmware path (AMD SEV-SNP variant, built by nix/ovmf.nix).
pub const DEFAULT_OVMF_PATH: &str = "/usr/local/share/ovmf-snp/OVMF.fd";

/// Generate QEMU command-line arguments for launching an SEV-SNP confidential VM.
///
/// Produces the following arguments:
/// - `-machine q35,confidential-guest-support=sev0,memory-backend=ram1`
/// - `-object memory-backend-memfd,id=ram1,size={memory_mb}M,share=true`
/// - `-object sev-snp-guest,id=sev0,cbitpos={cbitpos},reduced-phys-bits={reduced_phys_bits},kernel-hashes=on,policy={policy}`
/// - `-bios <ovmf_path>` (SEV-SNP requires OVMF firmware)
///
/// `cbitpos` (the memory-encryption C-bit position) and `reduced_phys_bits`
/// (the guest physical-address-space reduction) are HOST hardware properties
/// read from CPUID leaf `0x8000001F`; they are NOT measurement inputs (they
/// configure memory encryption, not the launch digest). The caller injects them
/// so this generator stays architecture-agnostic, never baking in a specific
/// EPYC generation's values. On the current EPYC target CPUID reports
/// `cbitpos=51, reduced_phys_bits=1`.
///
/// `kernel-hashes=on` tells QEMU to populate the OVMF kernel hashing area with
/// SHA-256 hashes of the kernel, initrd, and cmdline. The AmdSev OVMF variant's
/// QemuKernelLoaderFsDxe uses BlobVerifierLibSevHashes to verify these hashes
/// before loading the kernel: without this flag, the blob verifier fails and
/// OVMF falls back to the embedded GRUB bootloader.
pub fn sev_snp_qemu_args(
    config: &VmConfig,
    ovmf_path: &str,
    cbitpos: u32,
    reduced_phys_bits: u32,
) -> Vec<String> {
    let policy = canonical_policy(config.tee.policy.as_deref().unwrap_or(DEFAULT_POLICY));

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
        "EPYC-v4".to_string(),
        "-machine".to_string(),
        "q35,confidential-guest-support=sev0,memory-backend=ram1,vmport=off".to_string(),
        "-object".to_string(),
        memfd_opts,
        "-object".to_string(),
        format!(
            "sev-snp-guest,id=sev0,cbitpos={cbitpos},reduced-phys-bits={reduced_phys_bits},kernel-hashes=on,policy={policy}"
        ),
        // Strip QEMU's default devices (USB, floppy, etc.) to reduce
        // OVMF PCI enumeration time.
        "-nodefaults".to_string(),
        "-bios".to_string(),
        ovmf_path.to_string(),
    ]
}

/// Canonicalize the guest policy into a bare `0x…` hex literal.
///
/// `config.tee.policy` is deserialized from (potentially untrusted) JSON, so it
/// must never reach the `sev-snp-guest` object verbatim: because that object is
/// a single comma-separated argv element, a value like `"0x30000,inject=on"`
/// would smuggle extra properties into it. We parse the policy as a base-0
/// unsigned integer (the same contract the daemon's `parse_sev_policy`
/// enforces) and re-emit it as `0x{:x}`, so the emitted text is always nothing
/// but hex digits. An unparseable policy falls back to the restrictive
/// [`DEFAULT_POLICY`] (debug disabled) rather than launching attacker-shaped
/// text; the fallback is logged so a mistyped policy is observable.
fn canonical_policy(policy: &str) -> String {
    match parse_policy_u32(policy) {
        Some(value) => format!("0x{value:x}"),
        None => {
            tracing::warn!(policy, "malformed SEV-SNP guest policy; using default");
            DEFAULT_POLICY.to_string()
        }
    }
}

/// Parse a base-0 unsigned policy value (`0x`/`0o`/`0b` prefix, else decimal)
/// that fits in a `u32`. Returns `None` for anything else, which notably
/// rejects embedded commas, whitespace, and signs.
fn parse_policy_u32(policy: &str) -> Option<u32> {
    let trimmed = policy.trim();
    let (radix, digits) = if let Some(rest) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        (16, rest)
    } else if let Some(rest) = trimmed
        .strip_prefix("0o")
        .or_else(|| trimmed.strip_prefix("0O"))
    {
        (8, rest)
    } else if let Some(rest) = trimmed
        .strip_prefix("0b")
        .or_else(|| trimmed.strip_prefix("0B"))
    {
        (2, rest)
    } else {
        (10, trimmed)
    };
    if digits.is_empty() {
        return None;
    }
    u32::from_str_radix(digits, radix).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{TeeConfig, TeeType, VmConfig};
    use std::path::PathBuf;

    fn make_config(memory_mb: u32, policy: Option<&str>) -> VmConfig {
        VmConfig {
            vm_id: "test-vm".to_string(),
            kernel: Some(PathBuf::from("/boot/vmlinuz")),
            initrd: Some(PathBuf::from("/boot/initrd.img")),
            disks: vec![],
            vcpus: 2,
            memory_mb,
            tee: TeeConfig {
                backend: TeeType::SevSnp,
                policy: policy.map(|s| s.to_string()),
            },
            encrypted: false,
            numa_node: None,
            hugepage_size: None,
        }
    }

    #[test]
    fn test_sev_snp_args_with_policy() {
        let config = make_config(2048, Some("0x50000"));
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        // Find the sev-snp-guest object arg
        let sev_arg = args
            .iter()
            .find(|a| a.contains("sev-snp-guest"))
            .expect("should have sev-snp-guest arg");

        assert!(
            sev_arg.contains("policy=0x50000"),
            "policy should be 0x50000 but got: {sev_arg}"
        );
        assert!(
            sev_arg.contains("kernel-hashes=on"),
            "kernel-hashes should be on but got: {sev_arg}"
        );
    }

    #[test]
    fn test_policy_injection_is_rejected() {
        // A policy carrying extra QEMU object properties must not survive: it
        // falls back to the default and the smuggled property is gone.
        let config = make_config(2048, Some("0x30000,inject=on"));
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH);

        let sev_arg = args
            .iter()
            .find(|a| a.contains("sev-snp-guest"))
            .expect("should have sev-snp-guest arg");

        assert!(
            !sev_arg.contains("inject=on"),
            "smuggled property must not survive but got: {sev_arg}"
        );
        assert!(
            sev_arg.contains("policy=0x30000"),
            "should fall back to default policy but got: {sev_arg}"
        );
    }

    #[test]
    fn test_policy_is_canonicalized() {
        // Uppercase-prefix hex and bare decimal both render as canonical
        // lowercase 0x hex (196608 == 0x30000).
        for input in ["0X30000", "196608"] {
            let config = make_config(2048, Some(input));
            let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH);
            let sev_arg = args
                .iter()
                .find(|a| a.contains("sev-snp-guest"))
                .expect("should have sev-snp-guest arg");
            assert!(
                sev_arg.contains("policy=0x30000"),
                "input {input:?} should canonicalize to 0x30000 but got: {sev_arg}"
            );
        }
    }

    #[test]
    fn test_sev_snp_args_default_policy() {
        let config = make_config(2048, None);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        let sev_arg = args
            .iter()
            .find(|a| a.contains("sev-snp-guest"))
            .expect("should have sev-snp-guest arg");

        assert!(
            sev_arg.contains("policy=0x30000"),
            "default policy should be 0x30000 but got: {sev_arg}"
        );
        assert!(
            sev_arg.contains("kernel-hashes=on"),
            "kernel-hashes should be on but got: {sev_arg}"
        );
    }

    #[test]
    fn test_sev_snp_confidential_guest_parameters_reflect_injected_values() {
        // cbitpos and reduced-phys-bits are HOST hardware properties injected by
        // the caller (read from CPUID leaf 0x8000001F), NOT hardcoded. Assert the
        // emitted object reflects whatever pair the caller passed, and that the
        // machine binds confidential-guest-support=sev0. The current EPYC target
        // reports cbitpos=51, reduced_phys_bits=1, so that pair is used here.
        let config = make_config(2048, None);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        let sev_arg = args
            .iter()
            .find(|a| a.contains("sev-snp-guest"))
            .expect("should have sev-snp-guest arg");
        assert!(
            sev_arg.contains("cbitpos=51"),
            "cbitpos must reflect the injected 51 but got: {sev_arg}"
        );
        assert!(
            sev_arg.contains("reduced-phys-bits=1"),
            "reduced-phys-bits must reflect the injected 1 but got: {sev_arg}"
        );
        assert!(
            sev_arg.contains("id=sev0"),
            "sev object id must be sev0 but got: {sev_arg}"
        );

        let machine_arg = args
            .iter()
            .find(|a| a.contains("confidential-guest-support"))
            .expect("should have machine arg");
        assert!(
            machine_arg.contains("confidential-guest-support=sev0"),
            "machine must bind sev0 but got: {machine_arg}"
        );
    }

    #[test]
    fn test_sev_snp_cbit_params_are_parameterized_not_hardcoded() {
        // Inject a DIFFERENT (cbitpos, reduced_phys_bits) pair than the EPYC
        // 51/1 default, proving the generator emits the caller-supplied host
        // values rather than baking in a specific CPU generation.
        let config = make_config(2048, None);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 47, 2);

        let sev_arg = args
            .iter()
            .find(|a| a.contains("sev-snp-guest"))
            .expect("should have sev-snp-guest arg");
        assert!(
            sev_arg.contains("cbitpos=47"),
            "cbitpos must reflect the injected 47 but got: {sev_arg}"
        );
        assert!(
            sev_arg.contains("reduced-phys-bits=2"),
            "reduced-phys-bits must reflect the injected 2 but got: {sev_arg}"
        );
        // The literal EPYC defaults must NOT leak through when a different pair
        // is injected.
        assert!(
            !sev_arg.contains("cbitpos=51"),
            "cbitpos=51 must not be hardcoded: {sev_arg}"
        );
        assert!(
            !sev_arg.contains("reduced-phys-bits=1"),
            "reduced-phys-bits=1 must not be hardcoded: {sev_arg}"
        );
    }

    #[test]
    fn test_memory_backend_matches_config() {
        let config = make_config(4096, None);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        let mem_arg = args
            .iter()
            .find(|a| a.contains("memory-backend-memfd"))
            .expect("should have memory-backend-memfd arg");

        assert!(
            mem_arg.contains("size=4096M"),
            "memory size should be 4096M but got: {mem_arg}"
        );
    }

    #[test]
    fn test_machine_arg_present() {
        let config = make_config(1024, None);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        // -cpu <val>, -machine <val>, -object <val>, -object <val>, -nodefaults, -bios <val>
        assert_eq!(args.len(), 11, "expected 11 args, got {}", args.len());
        assert_eq!(args[0], "-cpu");
        assert_eq!(args[1], "EPYC-v4");
        assert_eq!(args[2], "-machine");
        assert!(args[3].contains("q35"));
        assert!(args[3].contains("confidential-guest-support=sev0"));
        assert!(args[3].contains("memory-backend=ram1"));
    }

    #[test]
    fn test_memory_backend_numa_binding() {
        let mut config = make_config(2048, None);
        config.numa_node = Some(1);
        config.hugepage_size = Some(crate::types::HugePageSize::Size2M);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        let mem_arg = args
            .iter()
            .find(|a| a.contains("memory-backend-memfd"))
            .expect("should have memory-backend-memfd arg");

        assert!(
            mem_arg.contains("host-nodes=1"),
            "should bind to NUMA node 1 but got: {mem_arg}"
        );
        assert!(
            mem_arg.contains("policy=bind"),
            "should have policy=bind but got: {mem_arg}"
        );
    }

    #[test]
    fn test_memory_backend_no_numa() {
        let mut config = make_config(2048, None);
        config.hugepage_size = Some(crate::types::HugePageSize::Size2M);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        let mem_arg = args
            .iter()
            .find(|a| a.contains("memory-backend-memfd"))
            .expect("should have memory-backend-memfd arg");

        assert!(
            !mem_arg.contains("host-nodes"),
            "should NOT have host-nodes when numa_node is None: {mem_arg}"
        );
    }

    #[test]
    fn test_custom_ovmf_path() {
        let config = make_config(1024, None);
        let custom_path = "/opt/custom/OVMF.fd";
        let args = sev_snp_qemu_args(&config, custom_path, 51, 1);

        let bios_idx = args
            .iter()
            .position(|a| a == "-bios")
            .expect("-bios flag missing");
        assert_eq!(args[bios_idx + 1], custom_path);
    }

    #[test]
    fn test_memory_backend_1g_hugepages() {
        let mut config = make_config(4096, None);
        config.numa_node = Some(0);
        config.hugepage_size = Some(crate::types::HugePageSize::Size1G);
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        let mem_arg = args
            .iter()
            .find(|a| a.contains("memory-backend-memfd"))
            .expect("should have memory-backend-memfd arg");

        assert!(
            mem_arg.contains("hugetlbsize=1G"),
            "should use 1G hugepages but got: {mem_arg}"
        );
    }

    #[test]
    fn test_memory_backend_no_hugepages() {
        let mut config = make_config(1024, None);
        config.hugepage_size = None;
        let args = sev_snp_qemu_args(&config, DEFAULT_OVMF_PATH, 51, 1);

        let mem_arg = args
            .iter()
            .find(|a| a.contains("memory-backend-memfd"))
            .expect("should have memory-backend-memfd arg");

        assert!(
            !mem_arg.contains("hugetlb"),
            "should NOT have hugetlb when hugepage_size is None: {mem_arg}"
        );
    }
}
