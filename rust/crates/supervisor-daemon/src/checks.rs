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
//! FAKE_DATA_* fixtures) and the confidential-computing checks (increment
//! 6) are out of scope.

use std::path::Path;

use crate::config::Settings;

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
pub fn check(settings: &Settings, resolved_interface: Option<&str>) -> Result<(), String> {
    if !Path::new("/dev/kvm").exists() {
        return Err("KVM not found on `/dev/kvm`.".to_string());
    }

    // QEMU control sockets live at EXECUTION_ROOT/<vm-hash>-monitor.socket
    // and sun_path caps UNIX socket paths at 108 bytes (see the conf.py
    // comment for the full derivation).
    let longest_socket_path =
        settings.execution_root.as_os_str().len() + 1 + 64 + "-monitor.socket".len();
    if longest_socket_path > 108 {
        return Err(format!(
            "EXECUTION_ROOT '{}' is too long for QEMU control sockets \
             (UNIX socket paths are limited to 108 bytes)",
            settings.execution_root.display()
        ));
    }

    for path in [
        &settings.firecracker_path,
        &settings.jailer_path,
        &settings.linux_path,
    ] {
        if !path.is_file() {
            return Err(format!("File not found {}", path.display()));
        }
    }

    if settings.allow_vm_networking {
        let Some(interface) = resolved_interface else {
            return Err("Network interface is not specified".to_string());
        };
        if !Path::new("/sys/class/net").join(interface).exists() {
            return Err(format!("Network interface {interface} does not exist"));
        }
        let pool_length: u8 = settings
            .ipv4_address_pool
            .split_once('/')
            .and_then(|(_, length)| length.parse().ok())
            .ok_or_else(|| format!("invalid IPv4 pool {:?}", settings.ipv4_address_pool))?;
        if pool_length > settings.ipv4_network_prefix_length {
            return Err(
                "The IPv4 address pool prefix must be shorter than an individual VM network prefix"
                    .to_string(),
            );
        }
    }

    if !is_command_available("setfacl") {
        return Err("Command `setfacl` not found, run `apt install acl`".to_string());
    }
    if settings.allow_vm_networking && settings.use_ndp_proxy && !is_command_available("ndppd") {
        return Err("Command `ndppd` not found, run `apt install ndppd`".to_string());
    }

    // Necessary for cloud-init customisation of instances.
    if !is_command_available("cloud-localds") {
        return Err(
            "Command `cloud-localds` not found, run `apt install cloud-image-utils`".to_string(),
        );
    }

    if settings.enable_qemu_support {
        if !is_command_available("qemu-img") {
            return Err("Command `qemu-img` not found, run `apt install qemu-utils`".to_string());
        }
        if !is_command_available("qemu-system-x86_64") {
            return Err(
                "Command `qemu-system-x86_64` not found, run `apt install qemu-system-x86`"
                    .to_string(),
            );
        }
    }

    if settings.enable_gpu_support && !settings.enable_qemu_support {
        return Err("Qemu Support is needed for GPU support and it's disabled, ".to_string());
    }

    Ok(())
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
        assert_eq!(
            error,
            format!("File not found {}", tmp.path().join("absent").display())
        );
    }

    #[test]
    fn an_over_long_execution_root_is_rejected() {
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = settings_with_stub_hypervisors(tmp.path());
        settings.execution_root = PathBuf::from(format!("/{}", "x".repeat(100)));
        let error = check(&settings, None).unwrap_err();
        assert!(error.contains("too long for QEMU control sockets"));
    }

    #[test]
    fn networking_requires_an_interface_and_a_sane_pool() {
        let tmp = tempfile::tempdir().unwrap();
        let mut settings = settings_with_stub_hypervisors(tmp.path());
        settings.allow_vm_networking = true;
        assert_eq!(
            check(&settings, None).unwrap_err(),
            "Network interface is not specified"
        );
        assert!(
            check(&settings, Some("definitely-not-an-iface0"))
                .unwrap_err()
                .contains("does not exist")
        );
        settings.ipv4_address_pool = "172.16.0.0/26".to_string();
        // /26 pool cannot be split into /24 VM networks; `lo` always exists.
        let error = check(&settings, Some("lo")).unwrap_err();
        assert!(error.contains("IPv4 address pool prefix"));
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
            assert_eq!(
                check(&settings, None).unwrap_err(),
                "KVM not found on `/dev/kvm`."
            );
            return;
        }
        check(&settings, None).expect("check must pass on a provisioned host");
    }
}
