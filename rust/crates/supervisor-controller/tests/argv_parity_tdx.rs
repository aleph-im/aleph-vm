//! Conformance for the Intel TDX measured-boot launch.
//!
//! Like SNP, TDX has no Python oracle, so the launch is pinned two ways:
//!
//! 1. The TEE fragment (`qemu::tdx_tee_fragment`) is asserted byte-for-byte
//!    against the `aleph-tee` generator (`tdx_qemu_args`). `aleph-tee` is a
//!    DEV dependency here only, built with no features (the generator must
//!    not need `verify`).
//! 2. The full `build_tdx_argv` output is pinned against committed fixtures
//!    under `tests/conformance/controller_argv_tdx/`. `bad_mrconfigid` pins
//!    the refusal instead of an argv.

use std::path::Path;

use serde::Deserialize;
use supervisor_controller::config::QemuConfig;
use supervisor_controller::qemu::{
    DEFAULT_QGS_SOCKET, MRCONFIGID_LEN, build_tdx_argv, tdx_prelaunch_check, tdx_tee_fragment,
};

#[derive(Debug, Deserialize)]
struct Fixture {
    config_json: serde_json::Value,
    #[serde(default)]
    expected_argv: Option<Vec<String>>,
    #[serde(default)]
    expected_error: Option<String>,
}

fn fixture_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/conformance/controller_argv_tdx")
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
    assert!(config.is_tdx(), "fixture {name} is not a TDX config");
    let mrconfigid = tdx_prelaunch_check(&config)
        .unwrap_or_else(|error| panic!("fixture {name} failed the pre-launch check: {error}"));
    let argv = build_tdx_argv(&config, &mrconfigid);
    let expected = fixture
        .expected_argv
        .unwrap_or_else(|| panic!("fixture {name} carries no expected_argv"));
    assert_eq!(argv, expected, "TDX argv mismatch for {name}");
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
// NUMA placement + 1G hugepages on the ram1 memfd, plus a non-default QGS
// socket on the tdx-guest object.
parity_case!(numa_hugepages, "numa_hugepages");

/// A base64-valid `mrconfigid` of the wrong length (a SHA-256, 32 bytes) is
/// a complete TDX config (`is_tdx()` holds) that the pre-launch check must
/// refuse: no fallback, no truncation, no padding.
#[test]
fn bad_mrconfigid() {
    let fixture = load("bad_mrconfigid");
    let config = QemuConfig::from_json(&fixture.config_json.to_string()).unwrap();
    assert!(config.is_tdx(), "the marker and every field are present");
    let error = tdx_prelaunch_check(&config).expect_err("a 32-byte mrconfigid must be refused");
    assert_eq!(error.to_string(), fixture.expected_error.unwrap());
}

/// Every fixture in the directory is covered by a named case above.
#[test]
fn every_tdx_fixture_has_a_case() {
    let declared = [
        "minimal",
        "with_nic",
        "host_volume",
        "numa_hugepages",
        "bad_mrconfigid",
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

/// The controller's runtime TDX TEE fragment MUST equal the `aleph-tee`
/// generator byte-for-byte, including the JSON `tdx-guest` object's key order
/// and the memfd NUMA / hugetlb suffix.
#[test]
fn tdx_tee_fragment_matches_the_aleph_tee_generator() {
    use aleph_tee::types::{HugePageSize, TeeConfig, TeeType, VmConfig};

    assert_eq!(DEFAULT_QGS_SOCKET, aleph_tee::tdx::qemu::DEFAULT_QGS_SOCKET);
    assert_eq!(MRCONFIGID_LEN, aleph_tee::tdx::qemu::MRCONFIGID_LEN);

    let numa_hugepage_cases: [(Option<u32>, Option<&str>, Option<HugePageSize>); 4] = [
        (None, None, None),
        (Some(1), None, None),
        (Some(0), Some("1G"), Some(HugePageSize::Size1G)),
        (Some(1), Some("2M"), Some(HugePageSize::Size2M)),
    ];
    // Distinct byte patterns so a swapped or truncated register would show.
    let mrconfigid_cases: [[u8; MRCONFIGID_LEN]; 3] = [
        [0u8; MRCONFIGID_LEN],
        [0xFF; MRCONFIGID_LEN],
        std::array::from_fn(|i| i as u8),
    ];
    let qgs_cases = [DEFAULT_QGS_SOCKET, "/run/aleph/qgs.socket"];
    let boot = (
        "/image/bzImage",
        "/image/initrd",
        "console=ttyS0 aleph_tdx_descriptor=1",
    );
    for (mem, tdvf) in [
        (2048u64, "/var/lib/aleph/vm/tdvf/TDVF.fd"),
        (4096, "/opt/tdvf/TDVF.fd"),
    ] {
        for (numa_node, hugepage_qemu, hugepage_size) in numa_hugepage_cases {
            for mrconfigid in &mrconfigid_cases {
                for qgs in qgs_cases {
                    let generator_config = VmConfig {
                        vm_id: "oracle".to_string(),
                        kernel: None,
                        initrd: None,
                        disks: vec![],
                        vcpus: 2,
                        memory_mb: mem as u32,
                        tee: TeeConfig {
                            backend: TeeType::Tdx,
                            policy: None,
                            cpu_model: None,
                        },
                        encrypted: false,
                        numa_node,
                        hugepage_size,
                    };
                    let generator = aleph_tee::tdx::qemu::tdx_qemu_args(
                        &generator_config,
                        tdvf,
                        boot.0,
                        boot.1,
                        boot.2,
                        mrconfigid,
                        qgs,
                    );
                    let controller = tdx_tee_fragment(
                        mem,
                        tdvf,
                        numa_node,
                        hugepage_qemu,
                        mrconfigid,
                        qgs,
                        boot.0,
                        boot.1,
                        boot.2,
                    );
                    assert_eq!(
                        controller, generator,
                        "controller TDX fragment diverged from the aleph-tee generator \
                         (mem={mem}, numa={numa_node:?}, hugepage={hugepage_qemu:?}, \
                         mrconfigid[0]={:#x}, qgs={qgs})",
                        mrconfigid[0]
                    );
                    assert_eq!(&controller[..2], ["-cpu", "host"]);
                    let object = controller
                        .iter()
                        .find(|a| a.starts_with('{'))
                        .expect("fragment has one JSON tdx-guest object");
                    let parsed: serde_json::Value = serde_json::from_str(object).unwrap();
                    assert_eq!(parsed["quote-generation-socket"]["path"], qgs);
                }
            }
        }
    }
}
