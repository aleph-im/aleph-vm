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
use supervisor_controller::qemu::{build_snp_argv, snp_tee_fragment};

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
    let argv = build_snp_argv(&config);
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

/// Every fixture in the directory is covered by a named case above.
#[test]
fn every_snp_fixture_has_a_case() {
    let declared = ["minimal", "with_nic", "host_volume", "custom_policy"];
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
    use aleph_tee::types::{TeeConfig, TeeType, VmConfig};

    // Exercise a spread of (memory, policy, ovmf) so the whole rendered
    // fragment is compared, not just its constant head.
    for (mem, policy, ovmf) in [
        (2048u64, 0x30000u32, "/var/lib/aleph/vm/ovmf/OVMF.fd"),
        (4096, 0x30000, "/opt/ovmf/OVMF.fd"),
        (1024, 0x50000, "/OVMF.fd"),
    ] {
        let generator_config = VmConfig {
            vm_id: "oracle".to_string(),
            kernel: None,
            initrd: None,
            disks: vec![],
            vcpus: 2,
            memory_mb: mem as u32,
            tee: TeeConfig {
                backend: TeeType::SevSnp,
                // The daemon carries the policy as a u32 and the controller
                // renders it hex()-style; feed the generator the identical
                // rendering so the two are comparable.
                policy: Some(format!("0x{policy:x}")),
            },
            encrypted: false,
            numa_node: None,
            hugepage_size: None,
        };
        let generator = aleph_tee::sev_snp::qemu::sev_snp_qemu_args(&generator_config, ovmf);
        let controller = snp_tee_fragment(mem, policy, ovmf);
        assert_eq!(
            controller, generator,
            "controller SNP fragment diverged from the aleph-tee generator \
             (mem={mem}, policy={policy:#x})"
        );
    }
}
