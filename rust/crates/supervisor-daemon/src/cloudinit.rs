//! Cloud-init NoCloud seed generation, ported from
//! src/aleph/vm/supervisor/controllers/qemu/cloudinit.py and the
//! `build_cloud_init_drive` half of src/aleph/vm/supervisor/qemu_build.py.
//!
//! The Python builder emits YAML (yaml.safe_dump); this port emits the
//! `#cloud-config` header plus a JSON body. JSON is a YAML subset, so
//! cloud-init parses both into the same structure; the parity target is
//! the parsed mapping, asserted by the conformance suite against the
//! actual Python functions (ledgered divergence: representation only).
//! Increment 6 adds the confidential create path: the LUKS growpart
//! bootcmds and the install_guest_agent=false branch
//! (build_qemu_confidential_configuration).

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::tap::TapAssignment;

/// Failures creating cloud-init seed images.
#[derive(Debug, thiserror::Error)]
pub enum CloudInitError {
    #[error("cannot create a temp file: {source}")]
    TempCreate { source: std::io::Error },
    #[error("cannot write a temp file: {source}")]
    TempWrite { source: std::io::Error },
    #[error("cannot flush a temp file: {source}")]
    TempFlush { source: std::io::Error },
    #[error("cannot run cloud-localds: {source}")]
    Run { source: std::io::Error },
    #[error("cloud-localds failed ({status}): {stderr}")]
    Failed {
        status: std::process::ExitStatus,
        stderr: String,
    },
}

/// The qemu_build.py key merge: the spec's keys plus, when
/// USE_DEVELOPER_SSH_KEYS is truthy, settings.DEVELOPER_SSH_KEYS.
pub fn merged_ssh_keys(
    spec_keys: &[String],
    use_developer_ssh_keys: bool,
    developer_ssh_keys: &[String],
) -> Vec<String> {
    let mut keys = spec_keys.to_vec();
    if use_developer_ssh_keys {
        keys.extend(developer_ssh_keys.iter().cloned());
    }
    keys
}

/// The Python `vm_hash[:63]` hostname fallback: a CHARACTER slice
/// (hostnames are capped at 63 characters per label). Byte slicing would
/// panic on a vm_id whose 63rd boundary splits a multibyte character.
pub fn fallback_hostname(vm_hash: &str) -> &str {
    match vm_hash.char_indices().nth(63) {
        Some((offset, _)) => &vm_hash[..offset],
        None => vm_hash,
    }
}

/// Python `encode_user_data`. The plain-instance create path uses
/// is_confidential=False, install_guest_agent=True; the confidential create
/// path (increment 6) uses is_confidential=True, install_guest_agent=False
/// (the LUKS growpart bootcmds, no guest agent), mirroring
/// build_qemu_confidential_configuration.
pub fn user_data(
    hostname: &str,
    ssh_authorized_keys: &[String],
    has_gpu: bool,
    is_confidential: bool,
    install_guest_agent: bool,
) -> String {
    let mut config = serde_json::Map::new();
    config.insert("hostname".into(), json!(hostname));
    config.insert("disable_root".into(), json!(false));
    config.insert("ssh_pwauth".into(), json!(false));
    config.insert("ssh_authorized_keys".into(), json!(ssh_authorized_keys));
    config.insert("resize_rootfs".into(), json!(true));
    config.insert("package_update".into(), json!(true));
    let mut bootcmd: Vec<Value> = Vec::new();
    if is_confidential {
        // Confidential instances use LUKS: cloud-init's growpart cannot
        // resize the container, so do growpart + cryptsetup resize + resize2fs
        // in bootcmd (before cc_growpart/cc_resizefs).
        bootcmd.push(json!(["sh", "-c", "growpart /dev/vda 2 || true"]));
        bootcmd.push(json!(["sh", "-c", "cryptsetup resize cr_root || true"]));
        bootcmd.push(json!(["sh", "-c", "resize2fs /dev/mapper/cr_root || true"]));
    }
    if has_gpu {
        // PCI enumeration speed-up for large GPU BARs; the exact commands
        // of the Python builder.
        bootcmd.push(json!([
            "sed",
            "-i",
            "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 pci=realloc=off pci=noaer\"/",
            "/etc/default/grub"
        ]));
        bootcmd.push(json!([
            "sh",
            "-c",
            "command -v update-grub >/dev/null 2>&1 && update-grub || true"
        ]));
        bootcmd.push(json!([
            "sh",
            "-c",
            "command -v grub2-mkconfig >/dev/null 2>&1 && grub2-mkconfig -o /boot/grub2/grub.cfg || true"
        ]));
    }
    if !bootcmd.is_empty() {
        config.insert("bootcmd".into(), Value::Array(bootcmd));
    }
    if install_guest_agent {
        config.insert("packages".into(), json!(["qemu-guest-agent"]));
        config.insert(
            "runcmd".into(),
            json!(["systemctl start qemu-guest-agent.service"]),
        );
    }
    format!("#cloud-config\n{}", Value::Object(config))
}

/// Python `create_metadata_file`, byte-identical (json.dumps with default
/// separators).
pub fn metadata(hostname: &str, vm_index: i64) -> String {
    format!(
        "{{\"instance-id\": \"iid-instance-{vm_index}\", \"local-hostname\": {}}}",
        serde_json::to_string(hostname).expect("strings always serialize")
    )
}

/// Python `create_network_file`: the netplan v2 mapping (JSON body, parsed
/// identically). `nameservers` None renders null, like the Python
/// yaml-dump of DNS_NAMESERVERS=None.
pub fn network_config(
    ip: &str,
    ipv6: &str,
    ipv6_gateway: &str,
    nameservers: Option<&[String]>,
    route: &str,
) -> String {
    json!({
        "ethernets": {
            "eth0": {
                // Match on the virtio driver: the interface name is not
                // constant across distros.
                "match": {"driver": "virtio_net"},
                "addresses": [ip, ipv6],
                "gateway4": route,
                "gateway6": ipv6_gateway,
                "nameservers": {"addresses": nameservers},
            },
        },
        "version": 2,
    })
    .to_string()
}

/// The network parameters `build_cloud_init_drive` derives from the tap
/// (guest addresses with prefix, bare host route addresses), empty without
/// one.
fn network_parameters(tap: Option<&TapAssignment>) -> (String, String, String, String) {
    match tap {
        Some(tap) => (
            tap.guest_ipv4_cidr(),
            // Python: str(tap.host_ip).split("/", 1)[0].
            tap.ipv4.gateway.clone(),
            tap.guest_ipv6_cidr(),
            tap.ipv6.gateway.clone(),
        ),
        None => Default::default(),
    }
}

pub struct CloudInitDrive<'a> {
    pub execution_root: &'a Path,
    pub vm_hash: &'a str,
    pub vm_index: i64,
    pub tap: Option<&'a TapAssignment>,
    pub ssh_authorized_keys: &'a [String],
    /// Client hostname; empty falls back to the truncated vm_hash.
    pub hostname: &'a str,
    pub has_gpu: bool,
    pub dns_nameservers: Option<&'a [String]>,
    /// A confidential VM (increment 6): the LUKS growpart bootcmds and no
    /// guest agent, like build_qemu_confidential_configuration's
    /// is_confidential=True / install_guest_agent=False.
    pub confidential: bool,
}

impl CloudInitDrive<'_> {
    /// `EXECUTION_ROOT/cloud-init-{vm_hash}.img`.
    pub fn image_path(&self) -> PathBuf {
        self.execution_root
            .join(format!("cloud-init-{}.img", self.vm_hash))
    }

    /// Python `build_cloud_init_drive`: write the three seed files and run
    /// cloud-localds. Blocking (subprocess + temp files).
    pub fn create_image(&self) -> Result<PathBuf, CloudInitError> {
        // Hostnames are capped at 63 characters per label; the 64-hex-char
        // vm_hash is truncated to fit (by characters, like Python's
        // vm_hash[:63]; see fallback_hostname).
        let hostname = if self.hostname.is_empty() {
            fallback_hostname(self.vm_hash)
        } else {
            self.hostname
        };
        let (ip, route, ipv6, ipv6_gateway) = network_parameters(self.tap);

        let write_temp = |contents: &str| -> Result<tempfile::NamedTempFile, CloudInitError> {
            use std::io::Write;
            let mut file = tempfile::NamedTempFile::new()
                .map_err(|source| CloudInitError::TempCreate { source })?;
            file.write_all(contents.as_bytes())
                .map_err(|source| CloudInitError::TempWrite { source })?;
            file.flush()
                .map_err(|source| CloudInitError::TempFlush { source })?;
            Ok(file)
        };
        let user_data_file = write_temp(&user_data(
            hostname,
            self.ssh_authorized_keys,
            self.has_gpu,
            self.confidential,
            // Confidential VMs install no guest agent.
            !self.confidential,
        ))?;
        let network_file = write_temp(&network_config(
            &ip,
            &ipv6,
            &ipv6_gateway,
            self.dns_nameservers,
            &route,
        ))?;
        let metadata_file = write_temp(&metadata(hostname, self.vm_index))?;

        let image = self.image_path();
        let output = std::process::Command::new("cloud-localds")
            .arg(format!(
                "--network-config={}",
                network_file.path().display()
            ))
            .arg(&image)
            .arg(user_data_file.path())
            .arg(metadata_file.path())
            .output()
            .map_err(|source| CloudInitError::Run { source })?;
        if !output.status.success() {
            return Err(CloudInitError::Failed {
                status: output.status,
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
            });
        }
        Ok(image)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world::IpPair;

    /// The committed parity fixtures under tests/fixtures/cloudinit/; the
    /// conformance suite parses the same files and compares them with the
    /// parsed output of the actual Python builders. Regenerate with
    /// UPDATE_CLOUDINIT_FIXTURES=1 cargo test -p supervisor-daemon cloudinit.
    fn assert_matches_fixture(name: &str, produced: &str) {
        let path = crate::test_fixtures::fixtures_dir()
            .join("cloudinit")
            .join(name);
        if std::env::var_os("UPDATE_CLOUDINIT_FIXTURES").is_some() {
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, produced).unwrap();
            return;
        }
        let expected = std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("cannot read fixture {}: {error}", path.display()));
        assert_eq!(produced, expected, "fixture {name} diverged");
    }

    fn tap() -> TapAssignment {
        TapAssignment::new(
            4,
            IpPair {
                address: "172.16.4.2".into(),
                network_cidr: "172.16.4.0/24".into(),
                gateway: "172.16.4.1".into(),
            },
            IpPair {
                address: "fc00:1:2:3:3:aaaa:bbbb:cc01".into(),
                network_cidr: "fc00:1:2:3:3:aaaa:bbbb:cc00/124".into(),
                gateway: "fc00:1:2:3:3:aaaa:bbbb:cc00".into(),
            },
        )
    }

    #[test]
    fn user_data_is_pinned() {
        assert_matches_fixture(
            "user-data.json",
            &user_data(
                "my-host",
                &["ssh-ed25519 AAAA test@host".to_string()],
                false,
                false,
                true,
            ),
        );
        assert_matches_fixture(
            "user-data-gpu.json",
            &user_data("my-host", &[], true, false, true),
        );
        assert_matches_fixture(
            "user-data-confidential.json",
            &user_data(
                "my-host",
                &["ssh-ed25519 AAAA test@host".to_string()],
                false,
                true,
                false,
            ),
        );
    }

    #[test]
    fn network_config_is_pinned() {
        let tap = tap();
        let nameservers = vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()];
        assert_matches_fixture(
            "network-config.json",
            &network_config(
                &tap.guest_ipv4_cidr(),
                &tap.guest_ipv6_cidr(),
                &tap.ipv6.gateway,
                Some(&nameservers),
                &tap.ipv4.gateway,
            ),
        );
        assert_matches_fixture(
            "network-config-no-dns.json",
            &network_config("", "", "", None, ""),
        );
    }

    #[test]
    fn metadata_matches_python_json_dumps() {
        assert_eq!(
            metadata("my-host", 4),
            "{\"instance-id\": \"iid-instance-4\", \"local-hostname\": \"my-host\"}"
        );
    }

    #[test]
    fn an_empty_hostname_falls_back_to_the_truncated_hash() {
        let drive = CloudInitDrive {
            execution_root: Path::new("/var/lib/aleph/vm"),
            vm_hash: crate::test_fixtures::QEMU_HASH,
            vm_index: 3,
            tap: None,
            ssh_authorized_keys: &[],
            hostname: "",
            has_gpu: false,
            dns_nameservers: None,
            confidential: false,
        };
        assert_eq!(
            drive.image_path(),
            PathBuf::from(format!(
                "/var/lib/aleph/vm/cloud-init-{}.img",
                crate::test_fixtures::QEMU_HASH
            ))
        );
        // The 63-character cap itself is exercised through the fixture
        // parity test in tests/conformance (hostname derivation is inside
        // create_image, which needs cloud-localds).
    }

    #[test]
    fn the_hostname_fallback_slices_characters_not_bytes() {
        // Python vm_hash[:63] slices characters. A vm_id whose byte 63 sits
        // inside a multibyte character must not panic: U+00E9 ("é") is two
        // bytes, so 62 ASCII chars + "é" spans bytes 62..64.
        let ascii = "a".repeat(64);
        assert_eq!(fallback_hostname(&ascii), "a".repeat(63));
        let short = "abc";
        assert_eq!(fallback_hostname(short), "abc");
        let multibyte = format!("{}\u{00e9}x", "a".repeat(62)); // 64 chars, 65 bytes
        assert_eq!(
            fallback_hostname(&multibyte),
            format!("{}\u{00e9}", "a".repeat(62))
        );
        let boundary = format!("{}\u{00e9}", "a".repeat(63)); // char 63 is multibyte
        assert_eq!(fallback_hostname(&boundary), "a".repeat(63));
    }

    #[test]
    fn developer_keys_are_appended_only_when_enabled() {
        // qemu_build.py:83-85: keys += settings.DEVELOPER_SSH_KEYS when
        // settings.USE_DEVELOPER_SSH_KEYS is truthy.
        let spec_keys = vec!["ssh-ed25519 AAAA user@host".to_string()];
        let developer = vec!["ssh-ed25519 BBBB dev@host".to_string()];
        assert_eq!(merged_ssh_keys(&spec_keys, false, &developer), spec_keys);
        assert_eq!(
            merged_ssh_keys(&spec_keys, true, &developer),
            vec![
                "ssh-ed25519 AAAA user@host".to_string(),
                "ssh-ed25519 BBBB dev@host".to_string(),
            ]
        );
    }

    #[test]
    fn cloud_init_error_messages_are_correct() {
        use std::io;
        use std::os::unix::process::ExitStatusExt;

        let temp_create = CloudInitError::TempCreate {
            source: io::Error::new(io::ErrorKind::PermissionDenied, "no perms"),
        };
        assert_eq!(
            temp_create.to_string(),
            "cannot create a temp file: no perms"
        );

        let failed = CloudInitError::Failed {
            status: std::process::ExitStatus::from_raw(1 << 8),
            stderr: "boom".to_string(),
        };
        assert_eq!(
            failed.to_string(),
            "cloud-localds failed (exit status: 1): boom"
        );
    }
}
