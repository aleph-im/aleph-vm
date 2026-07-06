//! Cloud-init NoCloud seed generation, ported from
//! src/aleph/vm/supervisor/controllers/qemu/cloudinit.py and the
//! `build_cloud_init_drive` half of src/aleph/vm/supervisor/qemu_build.py.
//!
//! The Python builder emits YAML (yaml.safe_dump); this port emits the
//! `#cloud-config` header plus a JSON body. JSON is a YAML subset, so
//! cloud-init parses both into the same structure; the parity target is
//! the parsed mapping, asserted by the conformance suite against the
//! actual Python functions (ledgered divergence: representation only).
//! Increment 3 creates plain QEMU instances only, so the confidential
//! bootcmds and the install_guest_agent=false branch stay unported until
//! increment 6.

use std::path::{Path, PathBuf};

use serde_json::{Value, json};

use crate::tap::TapAssignment;

/// Python `encode_user_data` (is_confidential=False,
/// install_guest_agent=True: the plain-instance create path).
pub fn user_data(hostname: &str, ssh_authorized_keys: &[String], has_gpu: bool) -> String {
    let mut config = serde_json::Map::new();
    config.insert("hostname".into(), json!(hostname));
    config.insert("disable_root".into(), json!(false));
    config.insert("ssh_pwauth".into(), json!(false));
    config.insert("ssh_authorized_keys".into(), json!(ssh_authorized_keys));
    config.insert("resize_rootfs".into(), json!(true));
    config.insert("package_update".into(), json!(true));
    if has_gpu {
        // PCI enumeration speed-up for large GPU BARs; the exact commands
        // of the Python builder.
        config.insert(
            "bootcmd".into(),
            json!([
                [
                    "sed",
                    "-i",
                    "s/^GRUB_CMDLINE_LINUX_DEFAULT=\"\\(.*\\)\"/GRUB_CMDLINE_LINUX_DEFAULT=\"\\1 pci=realloc=off pci=noaer\"/",
                    "/etc/default/grub"
                ],
                ["sh", "-c", "command -v update-grub >/dev/null 2>&1 && update-grub || true"],
                [
                    "sh",
                    "-c",
                    "command -v grub2-mkconfig >/dev/null 2>&1 && grub2-mkconfig -o /boot/grub2/grub.cfg || true"
                ],
            ]),
        );
    }
    config.insert("packages".into(), json!(["qemu-guest-agent"]));
    config.insert(
        "runcmd".into(),
        json!(["systemctl start qemu-guest-agent.service"]),
    );
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
}

impl CloudInitDrive<'_> {
    /// `EXECUTION_ROOT/cloud-init-{vm_hash}.img`.
    pub fn image_path(&self) -> PathBuf {
        self.execution_root
            .join(format!("cloud-init-{}.img", self.vm_hash))
    }

    /// Python `build_cloud_init_drive`: write the three seed files and run
    /// cloud-localds. Blocking (subprocess + temp files).
    pub fn create_image(&self) -> Result<PathBuf, String> {
        // Hostnames are capped at 63 characters per label; the 64-hex-char
        // vm_hash is truncated to fit.
        let hostname = if self.hostname.is_empty() {
            &self.vm_hash[..self.vm_hash.len().min(63)]
        } else {
            self.hostname
        };
        let (ip, route, ipv6, ipv6_gateway) = network_parameters(self.tap);

        let write_temp = |contents: &str| -> Result<tempfile::NamedTempFile, String> {
            use std::io::Write;
            let mut file = tempfile::NamedTempFile::new()
                .map_err(|error| format!("cannot create a temp file: {error}"))?;
            file.write_all(contents.as_bytes())
                .map_err(|error| format!("cannot write a temp file: {error}"))?;
            file.flush()
                .map_err(|error| format!("cannot flush a temp file: {error}"))?;
            Ok(file)
        };
        let user_data_file =
            write_temp(&user_data(hostname, self.ssh_authorized_keys, self.has_gpu))?;
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
            .map_err(|error| format!("cannot run cloud-localds: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "cloud-localds failed ({}): {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
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
            ),
        );
        assert_matches_fixture("user-data-gpu.json", &user_data("my-host", &[], true));
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
}
