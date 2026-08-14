//! Startup preconditions, the daemon slice of the Python `settings.check()`
//! (src/aleph/vm/conf.py), run once before serving like `daemon.py main()`.
//! A failed check aborts startup with the same message as the Python
//! assert.
//!
//! Deliberately NOT ported (ledgered): with host networking disabled
//! (ALLOW_VM_NETWORKING=false) the NETWORK_INTERFACE and ndppd checks are
//! skipped, where Python asserts them unconditionally; a daemon that
//! cannot create taps has no use for either, and requiring them would
//! break the container/CI boots that increment 2 deliberately supports.
//! Agent-side settings the daemon does not model (CONNECTOR_URL, the
//! FAKE_DATA_* fixtures) are out of scope. The confidential-computing gates
//! (SEV_CTL_PATH, the SEV/SEV-ES kernel modules) are ported, gated on
//! ENABLE_CONFIDENTIAL_COMPUTING (increment 6).

use std::path::{Path, PathBuf};

use crate::config::Settings;

/// Startup precondition failures from [`check`]. Display strings are
/// identical to the pre-typed messages they replace (pinned by the Python
/// `settings.check()` assert text and by tests below).
#[derive(Debug, thiserror::Error)]
pub enum ChecksError {
    #[error("KVM not found on `/dev/kvm`.")]
    KvmMissing,

    #[error(
        "EXECUTION_ROOT '{}' is too long for QEMU control sockets (UNIX socket paths are limited to 108 bytes)",
        root.display()
    )]
    ExecutionRootTooLong { root: PathBuf },

    #[error("File not found {}", path.display())]
    FileNotFound { path: PathBuf },

    #[error("Network interface is not specified")]
    NoNetworkInterface,

    #[error("Network interface {interface} does not exist")]
    InterfaceMissing { interface: String },

    #[error("invalid IPv4 pool {pool:?}")]
    InvalidIpv4Pool { pool: String },

    #[error("The IPv4 address pool prefix must be shorter than an individual VM network prefix")]
    PoolPrefixTooLong,

    #[error("The IPv6 subnet prefix cannot be larger than /124.")]
    Ipv6PrefixTooLarge,

    #[error("Command `{command}` not found, run `apt install {package}`")]
    CommandMissing {
        command: &'static str,
        package: &'static str,
    },

    #[error("SEV feature isn't enabled, enable it in BIOS")]
    SevDisabled,

    #[error("SEV-ES feature isn't enabled, enable it in BIOS")]
    SevEsDisabled,

    #[error("Qemu Support is needed for confidential computing and it's disabled, ")]
    QemuDisabledConfidential,

    #[error("Qemu Support is needed for GPU support and it's disabled, ")]
    QemuDisabledGpu,
}

/// `shutil.which` semantics over PATH: the first executable match.
pub fn which(command: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(command);
        let executable = candidate.is_file() && {
            use std::os::unix::fs::PermissionsExt;
            candidate
                .metadata()
                .map(|meta| meta.permissions().mode() & 0o111 != 0)
                .unwrap_or(false)
        };
        executable.then_some(candidate)
    })
}

/// Python `is_command_available`.
fn is_command_available(command: &str) -> bool {
    which(command).is_some()
}

/// The `settings.check()` slice, in the Python assertion order. The
/// resolved interface is the one HostState detected (None when host
/// networking is off).
pub fn check(settings: &Settings, resolved_interface: Option<&str>) -> Result<(), ChecksError> {
    if !Path::new("/dev/kvm").exists() {
        return Err(ChecksError::KvmMissing);
    }

    // QEMU control sockets live at EXECUTION_ROOT/<vm-hash>-monitor.socket
    // and sun_path caps UNIX socket paths at 108 bytes (see the conf.py
    // comment for the full derivation).
    let longest_socket_path =
        settings.execution_root.as_os_str().len() + 1 + 64 + "-monitor.socket".len();
    if longest_socket_path > 108 {
        return Err(ChecksError::ExecutionRootTooLong {
            root: settings.execution_root.clone(),
        });
    }

    for path in [
        &settings.firecracker_path,
        &settings.jailer_path,
        &settings.linux_path,
    ] {
        if !path.is_file() {
            return Err(ChecksError::FileNotFound { path: path.clone() });
        }
    }

    if settings.allow_vm_networking {
        let Some(interface) = resolved_interface else {
            return Err(ChecksError::NoNetworkInterface);
        };
        if !Path::new("/sys/class/net").join(interface).exists() {
            return Err(ChecksError::InterfaceMissing {
                interface: interface.to_string(),
            });
        }
        let pool_length: u8 = settings
            .ipv4_address_pool
            .split_once('/')
            .and_then(|(_, length)| length.parse().ok())
            .ok_or_else(|| ChecksError::InvalidIpv4Pool {
                pool: settings.ipv4_address_pool.clone(),
            })?;
        if pool_length > settings.ipv4_network_prefix_length {
            return Err(ChecksError::PoolPrefixTooLong);
        }
        // StaticIPv6Allocator.__init__ (hostnetwork.py): an IPV6_SUBNET_PREFIX
        // below 124 aborts the Python daemon at Network construction (the
        // static scheme reserves exactly the last 4 bits for the guest; the
        // allocated networks are always /124 regardless of the setting).
        if settings.ipv6_allocation_policy == crate::config::Ipv6AllocationPolicy::Static
            && settings.ipv6_subnet_prefix < 124
        {
            return Err(ChecksError::Ipv6PrefixTooLarge);
        }
    }

    if !is_command_available("setfacl") {
        return Err(ChecksError::CommandMissing {
            command: "setfacl",
            package: "acl",
        });
    }
    if settings.allow_vm_networking && settings.use_ndp_proxy && !is_command_available("ndppd") {
        return Err(ChecksError::CommandMissing {
            command: "ndppd",
            package: "ndppd",
        });
    }

    // Necessary for cloud-init customisation of instances.
    if !is_command_available("cloud-localds") {
        return Err(ChecksError::CommandMissing {
            command: "cloud-localds",
            package: "cloud-image-utils",
        });
    }

    if settings.enable_qemu_support {
        if !is_command_available("qemu-img") {
            return Err(ChecksError::CommandMissing {
                command: "qemu-img",
                package: "qemu-utils",
            });
        }
        if !is_command_available("qemu-system-x86_64") {
            return Err(ChecksError::CommandMissing {
                command: "qemu-system-x86_64",
                package: "qemu-system-x86",
            });
        }
    }

    // Confidential computing (increment 6): the sevctl tool plus the SEV /
    // SEV-ES kernel-module gates, only when the feature is enabled. Ported
    // from conf.py check(); SEV-SNP is intentionally left commented out
    // there, so it is not checked here either.
    if settings.enable_confidential_computing {
        if !settings.sev_ctl_path.is_file() {
            return Err(ChecksError::FileNotFound {
                path: settings.sev_ctl_path.clone(),
            });
        }
        if !check_amd_sev_supported() {
            return Err(ChecksError::SevDisabled);
        }
        if !check_amd_sev_es_supported() {
            return Err(ChecksError::SevEsDisabled);
        }
        if !settings.enable_qemu_support {
            return Err(ChecksError::QemuDisabledConfidential);
        }
    }

    if settings.enable_gpu_support && !settings.enable_qemu_support {
        return Err(ChecksError::QemuDisabledGpu);
    }

    Ok(())
}

/// Python `check_system_module`: the value of a `/sys/module/<path>`
/// parameter, or None when absent.
fn check_system_module(module_path: &str) -> Option<String> {
    std::fs::read_to_string(Path::new("/sys/module").join(module_path))
        .ok()
        .map(|value| value.trim().to_string())
}

/// Python `check_amd_sev_supported`: the SEV module parameter is "Y" and
/// /dev/sev exists.
fn check_amd_sev_supported() -> bool {
    check_system_module("kvm_amd/parameters/sev").as_deref() == Some("Y")
        && Path::new("/dev/sev").exists()
}

/// Python `check_amd_sev_es_supported`: the SEV-ES module parameter is "Y"
/// and /dev/sev exists.
fn check_amd_sev_es_supported() -> bool {
    check_system_module("kvm_amd/parameters/sev_es").as_deref() == Some("Y")
        && Path::new("/dev/sev").exists()
}

/// Python `check_amd_sev_snp_supported`: the SEV-SNP module parameter is "Y".
/// Note the Python does NOT also require `/dev/sev` here (unlike SEV / SEV-ES);
/// this mirrors it exactly. Feeds `HostInfo.sev_snp_supported`.
pub(crate) fn check_amd_sev_snp_supported() -> bool {
    check_system_module("kvm_amd/parameters/sev_snp").as_deref() == Some("Y")
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn settings_with_stub_hypervisors(root: &Path) -> Settings {
        for name in ["firecracker", "jailer", "vmlinux.bin"] {
            std::fs::write(root.join(name), b"stub").unwrap();
        }
        Settings::from_vars(
            [
                ("ALEPH_VM_EXECUTION_ROOT", root.to_str().unwrap()),
                (
                    "ALEPH_VM_FIRECRACKER_PATH",
                    root.join("firecracker").to_str().unwrap(),
                ),
                (
                    "ALEPH_VM_JAILER_PATH",
                    root.join("jailer").to_str().unwrap(),
                ),
                (
                    "ALEPH_VM_LINUX_PATH",
                    root.join("vmlinux.bin").to_str().unwrap(),
                ),
                ("ALEPH_VM_ALLOW_VM_NETWORKING", "false"),
            ]
            .into_iter()
            .map(|(key, value)| (key.to_string(), value.to_string())),
        )
        .unwrap()
    }

    #[test]
    fn missing_hypervisor_files_fail_with_the_python_message() {
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = settings_with_stub_hypervisors(tmp.path());
        settings.firecracker_path = tmp.path().join("absent");
        let error = check(&settings, None).unwrap_err();
        assert!(matches!(
            &error,
            ChecksError::FileNotFound { path } if *path == tmp.path().join("absent")
        ));
        assert_eq!(
            error.to_string(),
            format!("File not found {}", tmp.path().join("absent").display())
        );
    }

    #[test]
    fn an_over_long_execution_root_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = settings_with_stub_hypervisors(tmp.path());
        settings.execution_root = PathBuf::from(format!("/{}", "x".repeat(100)));
        let error = check(&settings, None).unwrap_err();
        assert!(
            matches!(&error, ChecksError::ExecutionRootTooLong { root } if *root == settings.execution_root)
        );
        assert!(
            error
                .to_string()
                .contains("too long for QEMU control sockets")
        );
    }

    #[test]
    fn networking_requires_an_interface_and_a_sane_pool() {
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = settings_with_stub_hypervisors(tmp.path());
        settings.allow_vm_networking = true;
        let error = check(&settings, None).unwrap_err();
        assert!(matches!(&error, ChecksError::NoNetworkInterface));
        assert_eq!(error.to_string(), "Network interface is not specified");

        let error = check(&settings, Some("definitely-not-an-iface0")).unwrap_err();
        assert!(matches!(
            &error,
            ChecksError::InterfaceMissing { interface } if interface == "definitely-not-an-iface0"
        ));
        assert!(error.to_string().contains("does not exist"));

        settings.ipv4_address_pool = "172.16.0.0/26".to_string();
        // /26 pool cannot be split into /24 VM networks; `lo` always exists.
        let error = check(&settings, Some("lo")).unwrap_err();
        assert!(matches!(&error, ChecksError::PoolPrefixTooLong));
        assert!(error.to_string().contains("IPv4 address pool prefix"));
    }

    #[test]
    fn the_static_policy_rejects_a_subnet_prefix_below_124() {
        // StaticIPv6Allocator.__init__: subnet_prefix < 124 aborts the
        // Python daemon; message identical.
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = settings_with_stub_hypervisors(tmp.path());
        settings.allow_vm_networking = true;
        settings.ipv6_subnet_prefix = 120;
        if !Path::new("/dev/kvm").exists() {
            // The KVM precondition fires first on kvm-less machines, like
            // the Python assert order.
            return;
        }
        let error = check(&settings, Some("lo")).unwrap_err();
        assert!(matches!(&error, ChecksError::Ipv6PrefixTooLarge));
        assert_eq!(
            error.to_string(),
            "The IPv6 subnet prefix cannot be larger than /124."
        );

        // The dynamic policy accepts it (Python builds a DynamicIPv6Allocator
        // without the check); /124 and above pass under static.
        settings.ipv6_allocation_policy = crate::config::Ipv6AllocationPolicy::Dynamic;
        assert!(!matches!(
            check(&settings, Some("lo")),
            Err(ChecksError::Ipv6PrefixTooLarge)
        ));
        settings.ipv6_allocation_policy = crate::config::Ipv6AllocationPolicy::Static;
        settings.ipv6_subnet_prefix = 124;
        assert!(!matches!(
            check(&settings, Some("lo")),
            Err(ChecksError::Ipv6PrefixTooLarge)
        ));
    }

    #[test]
    fn the_local_toolchain_passes_when_gated_paths_exist() {
        // The dev/CI environment carries the commands the gates require
        // (test-rust.yml installs them); with stub hypervisor files and
        // networking off, check() must pass.
        let tmp = tempfile::tempdir().unwrap();
        let settings = settings_with_stub_hypervisors(tmp.path());
        if !Path::new("/dev/kvm").exists() {
            // Containers without KVM: the first check fails, which is the
            // Python behavior too.
            let error = check(&settings, None).unwrap_err();
            assert!(matches!(&error, ChecksError::KvmMissing));
            assert_eq!(error.to_string(), "KVM not found on `/dev/kvm`.");
            return;
        }
        check(&settings, None).expect("check must pass on a provisioned host");
    }
}
