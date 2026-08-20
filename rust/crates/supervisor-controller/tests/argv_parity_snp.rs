//! Conformance for the SEV-SNP measured-boot launch (increment B1).
//!
//! SNP has NO Python oracle (the Python controller never emitted SNP), so this
//! battery pins the launch two ways:
//!
//! 1. The TEE machine/object fragment (`qemu::snp_tee_fragment`) is asserted
//!    byte-for-byte against the `aleph-tee` generator (`sev_snp_qemu_args`),
//!    which is the shared reference the B2a Nix measurement was designed
//!    around. `aleph-tee` is a DEV dependency here only; the controller's
//!    runtime fragment is self-contained.
//! 2. The full `build_snp_argv` output is pinned against committed fixtures
//!    under `tests/conformance/controller_argv_snp/`.
//!
//! The fixtures also encode the load-bearing measurement inputs: `-cpu EPYC-v4`,
//! `-smp 2`, the exact `-bios`/`-kernel`/`-initrd`/`-append`, and `-S` absence
//! (SNP boots directly).

use std::path::Path;

use serde::Deserialize;
use supervisor_controller::config::QemuConfig;
use supervisor_controller::cpuid::SevHostInfo;
use supervisor_controller::qemu::{build_snp_argv, snp_tee_fragment};

/// The EPYC target's host CPUID values. The committed fixtures were captured
/// with these, so the fixture harness injects them; the runtime path reads them
/// from `SevHostInfo::read()`.
const EPYC_SEV_HOST_INFO: SevHostInfo = SevHostInfo {
    cbitpos: 51,
    reduced_phys_bits: 1,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    config_json: serde_json::Value,
    expected_argv: Vec<String>,
}

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/controller_argv_snp")
}

fn load(name: &str) -> Fixture {
    let path = fixture_dir().join(format!("{name}.json"));
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("cannot read fixture {}: {error}", path.display()));
    serde_json::from_str(&contents)
        .unwrap_or_else(|error| panic!("cannot parse fixture {}: {error}", path.display()))
}

fn assert_parity(name: &str) {
    let fixture = load(name);
    let config = QemuConfig::from_json(&fixture.config_json.to_string())
        .unwrap_or_else(|error| panic!("fixture {name} config did not parse: {error}"));
    assert!(config.is_snp(), "fixture {name} is not an SNP config");
    // The fixtures encode the EPYC host CPUID values (cbitpos=51,
    // reduced-phys-bits=1); inject them so the expected bytes hold.
    let argv = build_snp_argv(&config, EPYC_SEV_HOST_INFO);
    assert_eq!(argv, fixture.expected_argv, "SNP argv mismatch for {name}");
}

macro_rules! parity_case {
    ($test_name:ident, $fixture:literal) => {
        #[test]
        fn $test_name() {
            assert_parity($fixture);
        }
    };
}

parity_case!(minimal, "minimal");
parity_case!(with_nic, "with_nic");
parity_case!(host_volume, "host_volume");
parity_case!(custom_policy, "custom_policy");
// The luks arm: image_format="qcow2"/image_readonly=false, opaque
// (non-verity) cmdline, no host volumes (the daemon inserts no hash-tree
// volume for a writable rootfs, so no /dev/vdb drive appears).
parity_case!(luks, "luks");

/// Every fixture in the directory is covered by a named case above.
#[test]
fn every_snp_fixture_has_a_case() {
    let declared = [
        "minimal",
        "with_nic",
        "host_volume",
        "custom_policy",
        "luks",
    ];
    let mut on_disk: Vec<String> = std::fs::read_dir(fixture_dir())
        .unwrap()
        .filter_map(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            name.strip_suffix(".json").map(str::to_string)
        })
        .collect();
    on_disk.sort();
    let mut declared: Vec<String> = declared.iter().map(|name| name.to_string()).collect();
    declared.sort();
    assert_eq!(on_disk, declared, "fixture set and declared cases diverged");
}

/// The controller's runtime SNP TEE fragment MUST equal the `aleph-tee`
/// generator byte-for-byte (the byte-parity oracle). A drift here would mean
/// the launched measurement no longer matches the B2a precomputed value.
#[test]
fn snp_tee_fragment_matches_the_aleph_tee_generator() {
    use aleph_tee::types::{HugePageSize, TeeConfig, TeeType, VmConfig};

    // Exercise a spread of (memory, policy, ovmf) crossed with the C2 NUMA /
    // hugepage combinations so the whole rendered fragment is compared,
    // including the host-nodes / hugetlb suffix ordering, not just the head.
    // `hugepage_qemu` is the "1G"/"2M" string the controller carries; the
    // matching aleph-tee `HugePageSize` drives the generator.
    let numa_hugepage_cases: [(Option<u32>, Option<&str>, Option<HugePageSize>); 4] = [
        (None, None, None),
        (Some(1), None, None),
        (Some(0), Some("1G"), Some(HugePageSize::Size1G)),
        (Some(1), Some("2M"), Some(HugePageSize::Size2M)),
    ];
    // Cross at least two host CPUID (cbitpos, reduced-phys-bits) pairs: the EPYC
    // target's 51/1 AND a non-51 pair (47/2). Injecting the SAME pair into both
    // the controller fragment and the aleph-tee generator proves the two
    // implementations agree on the host-derived value, and that neither
    // hardcodes 51.
    let cbit_cases: [(u32, u32); 2] = [(51, 1), (47, 2)];
    // The CPU model is a measurement input, so both implementations must agree
    // on it, including on the shared "absent means EPYC-v4" default.
    let cpu_model_cases: [Option<&str>; 3] = [None, Some("EPYC-v4"), Some("EPYC-Genoa-v2")];
    for (mem, policy, ovmf) in [
        (2048u64, 0x30000u32, "/var/lib/aleph/vm/ovmf/OVMF.fd"),
        (4096, 0x30000, "/opt/ovmf/OVMF.fd"),
        (1024, 0x50000, "/OVMF.fd"),
    ] {
        for (numa_node, hugepage_qemu, hugepage_size) in numa_hugepage_cases {
            for (cbitpos, reduced_phys_bits) in cbit_cases {
                for cpu_model in cpu_model_cases {
                    let generator_config = VmConfig {
                        vm_id: "oracle".to_string(),
                        kernel: None,
                        initrd: None,
                        disks: vec![],
                        vcpus: 2,
                        memory_mb: mem as u32,
                        tee: TeeConfig {
                            backend: TeeType::SevSnp,
                            // The daemon carries the policy as a u32 and the
                            // controller renders it hex()-style; feed the generator
                            // the identical rendering so the two are comparable.
                            policy: Some(format!("0x{policy:x}")),
                            cpu_model: cpu_model.map(str::to_string),
                        },
                        encrypted: false,
                        numa_node,
                        hugepage_size,
                    };
                    let generator = aleph_tee::sev_snp::qemu::sev_snp_qemu_args(
                        &generator_config,
                        ovmf,
                        cbitpos,
                        reduced_phys_bits,
                    );
                    let controller = snp_tee_fragment(
                        mem,
                        policy,
                        ovmf,
                        numa_node,
                        hugepage_qemu,
                        cbitpos,
                        reduced_phys_bits,
                        cpu_model,
                    );
                    assert_eq!(
                        controller, generator,
                        "controller SNP fragment diverged from the aleph-tee generator \
                         (mem={mem}, policy={policy:#x}, numa={numa_node:?}, \
                         hugepage={hugepage_qemu:?}, cbitpos={cbitpos}, \
                         reduced_phys_bits={reduced_phys_bits}, cpu_model={cpu_model:?})"
                    );
                    assert_eq!(controller[0], "-cpu");
                    assert_eq!(controller[1], cpu_model.unwrap_or("EPYC-v4"));
                    // The injected non-51 pair must actually appear (guards against a
                    // regression to a hardcoded 51/1 that would still make the two
                    // sides equal to each other).
                    let sev_obj = controller
                        .iter()
                        .find(|a| a.contains("sev-snp-guest"))
                        .expect("fragment has a sev-snp-guest object");
                    assert!(
                        sev_obj.contains(&format!("cbitpos={cbitpos}"))
                            && sev_obj.contains(&format!("reduced-phys-bits={reduced_phys_bits}")),
                        "fragment did not reflect the injected host values: {sev_obj}"
                    );
                }
            }
        }
    }
}
