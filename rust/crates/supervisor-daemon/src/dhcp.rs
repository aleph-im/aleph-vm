//! Per-tap DHCP for SEV-SNP measured VMs.
//!
//! aleph-vm normally assigns a VM its IPv4 STATICALLY: the QEMU controller
//! seeds cloud-init with the guest address, gateway and mask
//! (src/aleph/vm/supervisor/controllers/qemu/cloudinit.py
//! `create_network_file`). The SEV-SNP measured image (nix/) deliberately
//! omits `ip=` from its kernel cmdline so the launch measurement is
//! host-independent, and its guest init (nix/init.sh) therefore falls back to
//! `udhcpc`. With no DHCP server on the tap the SNP guest never gets its
//! allocated address, so it is unreachable at `VmInfo.ipv4.address` and
//! attestation cannot connect.
//!
//! This module stands up a minimal, per-tap DHCP server (dnsmasq) that hands
//! the guest EXACTLY its allocated IPv4, with the host tap address as the
//! gateway (DHCP option 3), the tap netmask and the daemon's nameservers
//! (option 6). The aleph-cvm donor
//! (aleph-compute-node/src/network/tap.rs) reserves the IP by MAC through a
//! shared dnsmasq's `--dhcp-hostsdir`; the SNP NIC here has no fixed MAC
//! (ledger entry 70), so a SINGLE-address `--dhcp-range` is how the guest
//! deterministically gets the right address instead. Only the SNP path uses
//! this; plain and SEV/SEV-ES VMs keep the cloud-init static config,
//! untouched (ledger entry 77).
//!
//! The kernel/systemd edge lives behind the [`DhcpBackend`] seam, mirroring
//! [`crate::tap::TapBackend`], so cargo tests assert the derived dnsmasq
//! invocation and the teardown without running dnsmasq. The production
//! backend spawns dnsmasq as a transient systemd unit
//! (`aleph-vm-dhcp-{vm_hash}.service`) via `systemd-run`, keyed by vm_hash so
//! it survives a daemon restart and is torn down by unit name.

use std::num::ParseIntError;
use std::path::PathBuf;
use std::process::Command;

use crate::tap::TapAssignment;

/// The transient-unit name prefix for a VM's per-tap dnsmasq.
pub const DHCP_UNIT_PREFIX: &str = "aleph-vm-dhcp-";

/// The transient systemd unit name for a VM hash.
pub fn dhcp_unit_name(vm_hash: &str) -> String {
    format!("{DHCP_UNIT_PREFIX}{vm_hash}.service")
}

/// The per-VM dnsmasq lease file under `lease_dir`, named by the VM hash. The
/// single source of truth shared by [`DhcpConfig::for_snp`] (which passes it to
/// dnsmasq) and the teardown (which removes it), so start and stop never
/// disagree on the path.
pub fn lease_file_path(lease_dir: &std::path::Path, vm_hash: &str) -> std::path::PathBuf {
    lease_dir.join(format!("{vm_hash}.leases"))
}

/// One SNP VM's DHCP server configuration: hand the guest EXACTLY its
/// allocated IPv4, with the correct gateway, netmask and nameservers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpConfig {
    /// The VM hash, keys the transient unit for start and teardown.
    pub vm_hash: String,
    /// `vmtap{vm_index}`, the interface dnsmasq binds to.
    pub device_name: String,
    /// The single address the guest may lease (`VmInfo.ipv4.address`).
    pub guest_ip: String,
    /// The host tap address, DHCP option 3 (router / default gateway).
    pub gateway: String,
    /// The tap netmask, e.g. "255.255.255.0", the `--dhcp-range` mask.
    pub netmask: String,
    /// The single IPv6 address the guest may lease (`VmInfo.ipv6.address`).
    /// Always populated: `derive_tap_assignment` computes an IPv6 pair for
    /// every VM (static or dynamic policy), like cloud-init always writes
    /// static v6 config for non-SNP instances.
    pub guest_ipv6: String,
    /// The tap IPv6 prefix length (from the /124-per-VM scheme), the
    /// DHCPv6 `--dhcp-range` prefix and the RA on-link prefix.
    pub ipv6_prefix_len: u8,
    /// The daemon's resolved IPv4 nameservers, emitted in DHCPv4 option 6.
    /// An empty list omits the option.
    pub nameservers: Vec<String>,
    /// The `--dhcp-range` lease-time literal (e.g. "1h").
    pub lease: String,
    /// The per-VM dnsmasq lease file. A dedicated file per instance so two
    /// concurrent per-tap servers never clobber a shared lease database.
    pub lease_file: String,
}

/// The default lease time. A short, renewable lease is plenty: the address is
/// fixed for the VM's life and udhcpc renews.
pub const DEFAULT_LEASE: &str = "1h";

impl DhcpConfig {
    /// Build the config from a VM hash, its tap assignment and the daemon's
    /// nameservers. The netmask is derived from the tap's IPv4 prefix. The
    /// lease file lives under `lease_dir` (created by the backend), named by
    /// the VM hash.
    ///
    /// Only IPv4 nameservers are forwarded in DHCPv4 option 6. Valid IPv6
    /// nameservers are omitted; an IPv6-only list therefore emits no option 6.
    ///
    /// Fails (fail-closed) if the tap's IPv4 network CIDR carries no parseable
    /// prefix length or if a nameserver is not a valid IP address: silently
    /// falling back to `/32` would hand the guest an unroutable single-host
    /// netmask, while silently dropping malformed DNS configuration would boot
    /// a guest with no working resolver.
    pub fn for_snp(
        vm_hash: &str,
        tap: &TapAssignment,
        nameservers: &[String],
        lease_dir: &std::path::Path,
    ) -> Result<Self, DhcpError> {
        let prefix = cidr_prefix_len(&tap.ipv4.network_cidr, "IPv4")?;
        let ipv6_prefix_len = cidr_prefix_len(&tap.ipv6.network_cidr, "IPv6")?;
        let mut ipv4_nameservers = Vec::new();
        for server in nameservers {
            match server.parse::<std::net::IpAddr>() {
                Ok(std::net::IpAddr::V4(_)) => ipv4_nameservers.push(server.clone()),
                Ok(std::net::IpAddr::V6(_)) => {}
                Err(source) => {
                    return Err(DhcpError::InvalidNameserver {
                        nameserver: server.clone(),
                        source,
                    });
                }
            }
        }
        Ok(Self {
            vm_hash: vm_hash.to_string(),
            device_name: tap.device_name.clone(),
            guest_ip: tap.ipv4.address.clone(),
            gateway: tap.ipv4.gateway.clone(),
            netmask: netmask_for_prefix(prefix),
            guest_ipv6: tap.ipv6.address.clone(),
            ipv6_prefix_len,
            nameservers: ipv4_nameservers,
            lease: DEFAULT_LEASE.to_string(),
            lease_file: lease_file_path(lease_dir, vm_hash)
                .to_string_lossy()
                .into_owned(),
        })
    }

    /// The transient unit name, `aleph-vm-dhcp-{vm_hash}.service`.
    pub fn unit_name(&self) -> String {
        dhcp_unit_name(&self.vm_hash)
    }

    /// The dnsmasq argument vector: DHCP only (`--port=0` disables the DNS
    /// server so nothing binds port 53 and per-tap servers never collide),
    /// bound to the tap alone (`--bind-interfaces` + `--except-interface=lo`),
    /// authoritative, with a SINGLE-address range so the guest can only ever
    /// lease its allocated IP. `--keep-in-foreground` keeps dnsmasq as the
    /// unit's main process under `systemd-run` (Type=exec). `--user=root`
    /// suppresses the default setuid to the `dnsmasq`/`nobody` user, which need
    /// not exist on the host: the transient unit already runs as root under
    /// systemd-run, so this removes a missing-user failure mode.
    pub fn dnsmasq_args(&self) -> Vec<String> {
        let mut args = vec![
            "--keep-in-foreground".to_string(),
            // Stay as root; do not setuid to a possibly-absent dnsmasq user.
            "--user=root".to_string(),
            // DHCP only: no DNS server, so nothing binds :53 and multiple
            // per-tap dnsmasq instances never collide on the DNS port.
            "--port=0".to_string(),
            format!("--interface={}", self.device_name),
            "--bind-interfaces".to_string(),
            "--except-interface=lo".to_string(),
            "--no-resolv".to_string(),
            "--no-hosts".to_string(),
            "--dhcp-authoritative".to_string(),
            format!("--dhcp-leasefile={}", self.lease_file),
            // Single-address range: the guest can only get its allocated IP.
            format!(
                "--dhcp-range={},{},{},{}",
                self.guest_ip, self.guest_ip, self.netmask, self.lease
            ),
            // Option 3: router / default gateway = the host tap address.
            format!("--dhcp-option=3,{}", self.gateway),
            // The v6 twin of the single-address range above: stateful DHCPv6
            // (dnsmasq detects the family from the address syntax) handing the
            // guest EXACTLY its allocated /124-scheme address. --enable-ra
            // makes dnsmasq advertise on the tap; for a stateful (non-slaac)
            // range the RA carries M=1/A=0, so the guest takes its default
            // route from the RA (DHCPv6 cannot convey routes) and never
            // autoconfigures a second address. No radvd needed.
            format!(
                "--dhcp-range={},{},{},{}",
                self.guest_ipv6, self.guest_ipv6, self.ipv6_prefix_len, self.lease
            ),
            "--enable-ra".to_string(),
        ];
        // `for_snp` mirrors conf.py's DNS_NAMESERVERS_IPV4 split so DHCPv4
        // option 6 never receives an IPv6 address.
        if !self.nameservers.is_empty() {
            args.push(format!("--dhcp-option=6,{}", self.nameservers.join(",")));
        }
        args
    }

    /// The full `systemd-run` invocation that launches the transient unit:
    /// `systemd-run --unit=... --collect -p Type=exec -- dnsmasq <args>`.
    /// `--collect` garbage-collects the unit when it exits or fails, so a later
    /// restart of the same VM never trips over a lingering failed unit.
    ///
    /// `-p Type=exec` is load-bearing: with the default `Type=simple`,
    /// `systemd-run` returns success the instant the unit forks, so a missing
    /// or unrunnable dnsmasq (bad binary, failed bind) would still report a
    /// started job and the daemon would boot the VM with no DHCP (the guest
    /// never leases its IP, attestation is unreachable) while claiming success.
    /// `Type=exec` holds the start job until dnsmasq has successfully
    /// `execve`d, so an exec failure fails the job and propagates as `Err`.
    pub fn systemd_run_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("--unit={}", self.unit_name()),
            "--collect".to_string(),
            // Fail the start job if dnsmasq cannot exec (see doc above).
            "--property=Type=exec".to_string(),
            "--".to_string(),
            "dnsmasq".to_string(),
        ];
        args.extend(self.dnsmasq_args());
        args
    }
}

/// The prefix length of a CIDR string, fail-closed: a malformed prefix must
/// surface at config-build time rather than as a dnsmasq startup failure
/// (v4) or an unroutable netmask (see `for_snp`).
fn cidr_prefix_len(network_cidr: &str, family: &'static str) -> Result<u8, DhcpError> {
    let (_, prefix_str) = network_cidr
        .split_once('/')
        .ok_or_else(|| DhcpError::CidrNoPrefix {
            family,
            cidr: network_cidr.to_string(),
        })?;
    prefix_str
        .parse::<u8>()
        .map_err(|source| DhcpError::CidrBadPrefix {
            family,
            cidr: network_cidr.to_string(),
            source,
        })
}

/// The dotted netmask for an IPv4 prefix length (`/24` -> "255.255.255.0").
fn netmask_for_prefix(prefix: u8) -> String {
    let bits = if prefix >= 32 {
        u32::MAX
    } else if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    std::net::Ipv4Addr::from(bits).to_string()
}

/// The DHCP edge: start/stop a per-tap dnsmasq. Blocking; callers hop to the
/// blocking pool. Both operations are idempotent, like [`crate::tap`].
pub trait DhcpBackend: Send + Sync {
    /// Stand up the per-tap DHCP server for `config`. A pre-existing unit for
    /// the same VM is replaced (start after a best-effort stop), so a restart
    /// never fails on a leftover.
    fn start(&self, config: &DhcpConfig) -> Result<(), DhcpError>;

    /// Tear down the per-tap DHCP server for a VM hash and remove its lease
    /// file. A missing unit is a success (idempotent teardown, like the tap
    /// delete). `lease_file` is the per-VM dnsmasq lease database
    /// ([`lease_file_path`]); removing it stops the file leaking on persistent
    /// storage across the VM's lifetime.
    fn stop(&self, vm_hash: &str, lease_file: &std::path::Path) -> Result<(), DhcpError>;
}

/// Failures deriving a [`DhcpConfig`] or driving the per-tap DHCP server.
#[derive(Debug, thiserror::Error)]
pub enum DhcpError {
    #[error("tap {family} network CIDR {cidr:?} has no prefix length")]
    CidrNoPrefix { family: &'static str, cidr: String },

    #[error("tap {family} network CIDR {cidr:?} has an invalid prefix length: {source}")]
    CidrBadPrefix {
        family: &'static str,
        cidr: String,
        source: ParseIntError,
    },

    #[error("DNS nameserver {nameserver:?} is not a valid IP address: {source}")]
    InvalidNameserver {
        nameserver: String,
        source: std::net::AddrParseError,
    },

    #[error("cannot run {program}: {source}")]
    Run {
        program: String,
        source: std::io::Error,
    },

    #[error("cannot create the DHCP lease directory {path}: {source}")]
    LeaseDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error("systemd-run for {unit} failed: {stderr}")]
    StartFailed { unit: String, stderr: String },

    #[error("systemctl stop {unit} failed: {stderr}")]
    StopFailed { unit: String, stderr: String },
}

/// Whether a `systemctl stop` stderr describes a unit systemd never knew (it
/// was already gone), which a teardown treats as success, mirroring the
/// tap-delete tolerance of a missing device.
fn is_absent_unit_error(stderr: &str) -> bool {
    stderr.contains("not loaded") || stderr.contains("not-found")
}

/// Production backend: dnsmasq as a transient systemd unit via `systemd-run`,
/// torn down with `systemctl stop`.
pub struct SystemdRunDhcp;

impl SystemdRunDhcp {
    fn run(program: &str, args: &[String]) -> Result<std::process::Output, DhcpError> {
        Command::new(program)
            .args(args)
            .output()
            .map_err(|source| DhcpError::Run {
                program: program.to_string(),
                source,
            })
    }
}

impl DhcpBackend for SystemdRunDhcp {
    fn start(&self, config: &DhcpConfig) -> Result<(), DhcpError> {
        // Ensure the lease directory exists (dnsmasq will not create it).
        if let Some(parent) = std::path::Path::new(&config.lease_file).parent()
            && let Err(source) = std::fs::create_dir_all(parent)
        {
            return Err(DhcpError::LeaseDir {
                path: parent.to_path_buf(),
                source,
            });
        }
        // Replace any leftover unit from a previous life of this VM: stop is
        // best-effort (a missing unit is fine), reset-failed clears a failed
        // one so systemd-run does not refuse the name.
        let unit = config.unit_name();
        let _ = Self::run("systemctl", &["stop".to_string(), unit.clone()]);
        let _ = Self::run("systemctl", &["reset-failed".to_string(), unit.clone()]);
        let output = Self::run("systemd-run", &config.systemd_run_args())?;
        if output.status.success() {
            tracing::info!(
                unit,
                device = config.device_name,
                guest_ip = config.guest_ip,
                "started per-tap DHCP server for SNP VM"
            );
            return Ok(());
        }
        Err(DhcpError::StartFailed {
            unit,
            stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        })
    }

    fn stop(&self, vm_hash: &str, lease_file: &std::path::Path) -> Result<(), DhcpError> {
        let unit = dhcp_unit_name(vm_hash);
        let result = Self::run("systemctl", &["stop".to_string(), unit.clone()]);
        // Best-effort lease-file cleanup, regardless of the stop outcome: the
        // per-VM lease database lives on persistent storage and must not
        // accumulate across VM lifetimes. Idempotent (a missing file is fine).
        if let Err(error) = std::fs::remove_file(lease_file)
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(
                lease_file = %lease_file.display(),
                error = %error,
                "could not remove the DHCP lease file"
            );
        }
        let output = result?;
        if output.status.success() {
            tracing::info!(unit, "stopped per-tap DHCP server");
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        if is_absent_unit_error(&stderr) {
            tracing::warn!(unit, "DHCP unit already gone, treating stop as done");
            return Ok(());
        }
        Err(DhcpError::StopFailed {
            unit,
            stderr: stderr.trim().to_string(),
        })
    }
}

/// Test backend: records every started [`DhcpConfig`] and stopped hash, with
/// an optional shared [`crate::test_fixtures::EventLog`] to interleave with
/// the tap/nft fakes for ordering checks. Failures are injectable.
#[derive(Default)]
pub struct FakeDhcpBackend {
    inner: std::sync::Mutex<FakeDhcpState>,
    event_log: std::sync::OnceLock<crate::test_fixtures::EventLog>,
}

/// A builder rather than a stored `DhcpError`: `DhcpError` deliberately has
/// no `Clone` impl (its `io::Error` sources must stay real, non-reconstructed
/// errors everywhere outside this test-only injection path), so repeated
/// failures are produced by calling the closure again instead of cloning a
/// stored value.
type DhcpErrorFn = Box<dyn Fn() -> DhcpError + Send + Sync>;

#[derive(Default)]
struct FakeDhcpState {
    started: Vec<DhcpConfig>,
    stopped: Vec<String>,
    running: std::collections::HashSet<String>,
    fail_start: Option<DhcpErrorFn>,
    fail_stop: Option<DhcpErrorFn>,
}

impl FakeDhcpBackend {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeDhcpState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The configs passed to `start`, in call order.
    pub fn started(&self) -> Vec<DhcpConfig> {
        self.lock().started.clone()
    }

    /// The vm_hashes passed to `stop`, in call order.
    pub fn stopped(&self) -> Vec<String> {
        self.lock().stopped.clone()
    }

    /// Whether a DHCP server is currently up for this VM hash.
    pub fn is_running(&self, vm_hash: &str) -> bool {
        self.lock().running.contains(vm_hash)
    }

    /// Every `start` fails with the error `make` builds, until cleared. A
    /// builder (not a stored error) so each call gets its own real
    /// `DhcpError`, e.g. `backend.fail_start(|| DhcpError::StartFailed { .. })`.
    pub fn fail_start(&self, make: impl Fn() -> DhcpError + Send + Sync + 'static) {
        self.lock().fail_start = Some(Box::new(make));
    }

    /// Every `stop` fails with the error `make` builds, until cleared.
    pub fn fail_stop(&self, make: impl Fn() -> DhcpError + Send + Sync + 'static) {
        self.lock().fail_stop = Some(Box::new(make));
    }

    /// Attach a shared chronological event log.
    pub fn set_event_log(&self, log: crate::test_fixtures::EventLog) {
        let _ = self.event_log.set(log);
    }

    fn record(&self, event: String) {
        if let Some(log) = self.event_log.get() {
            log.record(&event);
        }
    }
}

impl DhcpBackend for FakeDhcpBackend {
    fn start(&self, config: &DhcpConfig) -> Result<(), DhcpError> {
        let mut inner = self.lock();
        if let Some(make) = &inner.fail_start {
            return Err(make());
        }
        inner.started.push(config.clone());
        inner.running.insert(config.vm_hash.clone());
        drop(inner);
        self.record(format!("dhcp: start {}", config.device_name));
        Ok(())
    }

    fn stop(&self, vm_hash: &str, _lease_file: &std::path::Path) -> Result<(), DhcpError> {
        let mut inner = self.lock();
        if let Some(make) = &inner.fail_stop {
            return Err(make());
        }
        inner.stopped.push(vm_hash.to_string());
        inner.running.remove(vm_hash);
        drop(inner);
        self.record(format!("dhcp: stop {vm_hash}"));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::world::IpPair;

    fn snp_tap() -> TapAssignment {
        TapAssignment::new(
            4,
            IpPair {
                address: "172.16.4.2".into(),
                network_cidr: "172.16.4.0/24".into(),
                gateway: "172.16.4.1".into(),
            },
            IpPair {
                address: "fc00:1:2:3::11".into(),
                network_cidr: "fc00:1:2:3::10/124".into(),
                gateway: "fc00:1:2:3::10".into(),
            },
        )
    }

    #[test]
    fn netmask_derivation_matches_the_prefix() {
        assert_eq!(netmask_for_prefix(24), "255.255.255.0");
        assert_eq!(netmask_for_prefix(16), "255.255.0.0");
        assert_eq!(netmask_for_prefix(32), "255.255.255.255");
        assert_eq!(netmask_for_prefix(0), "0.0.0.0");
        assert_eq!(netmask_for_prefix(25), "255.255.255.128");
    }

    #[test]
    fn config_derives_the_single_address_range_from_the_tap() {
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["1.1.1.1".to_string(), "9.9.9.9".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        assert_eq!(config.device_name, "vmtap4");
        assert_eq!(config.guest_ip, "172.16.4.2");
        assert_eq!(config.gateway, "172.16.4.1");
        assert_eq!(config.netmask, "255.255.255.0");
        assert_eq!(
            config.lease_file,
            format!("/run/aleph/dhcp/{}.leases", "e".repeat(64))
        );
        assert_eq!(
            config.unit_name(),
            format!("aleph-vm-dhcp-{}.service", "e".repeat(64))
        );
    }

    #[test]
    fn dnsmasq_args_hand_the_guest_exactly_its_allocated_ip() {
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["1.1.1.1".to_string(), "9.9.9.9".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        let args = config.dnsmasq_args();
        // DHCP only, bound to the tap alone, authoritative.
        assert!(args.contains(&"--port=0".to_string()));
        // Stay as root; do not setuid to a possibly-absent dnsmasq user.
        assert!(args.contains(&"--user=root".to_string()));
        assert!(args.contains(&"--interface=vmtap4".to_string()));
        assert!(args.contains(&"--bind-interfaces".to_string()));
        assert!(args.contains(&"--except-interface=lo".to_string()));
        assert!(args.contains(&"--dhcp-authoritative".to_string()));
        // The SINGLE-address range: low == high == the allocated guest IP.
        assert!(
            args.contains(&"--dhcp-range=172.16.4.2,172.16.4.2,255.255.255.0,1h".to_string()),
            "the guest can only lease its allocated IP, got {args:?}"
        );
        // Gateway (option 3) and DNS (option 6).
        assert!(args.contains(&"--dhcp-option=3,172.16.4.1".to_string()));
        assert!(args.contains(&"--dhcp-option=6,1.1.1.1,9.9.9.9".to_string()));
        assert!(args.contains(&format!(
            "--dhcp-leasefile=/run/aleph/dhcp/{}.leases",
            "e".repeat(64)
        )));
    }

    #[test]
    fn dnsmasq_args_omit_option_6_without_nameservers() {
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &[],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        let args = config.dnsmasq_args();
        assert!(
            !args.iter().any(|arg| arg.starts_with("--dhcp-option=6")),
            "no DNS option when the daemon resolved no nameservers, got {args:?}"
        );
        // The gateway option is still handed out.
        assert!(args.contains(&"--dhcp-option=3,172.16.4.1".to_string()));
    }

    #[test]
    fn dnsmasq_args_filter_ipv6_nameservers_from_option_6() {
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &[
                "192.0.2.53".to_string(),
                "2001:db8::53".to_string(),
                "192.0.2.54".to_string(),
                "2001:db8::54".to_string(),
            ],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        let args = config.dnsmasq_args();
        let option_6 = args
            .iter()
            .filter(|arg| arg.starts_with("--dhcp-option=6"))
            .collect::<Vec<_>>();
        assert_eq!(option_6.len(), 1);
        assert_eq!(option_6[0], "--dhcp-option=6,192.0.2.53,192.0.2.54");
    }

    #[test]
    fn dnsmasq_args_omit_option_6_with_only_ipv6_nameservers() {
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["2001:db8::53".to_string(), "2001:db8::54".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        let args = config.dnsmasq_args();
        assert!(
            !args.iter().any(|arg| arg.starts_with("--dhcp-option=6")),
            "DHCPv4 option 6 must not contain IPv6 nameservers, got {args:?}"
        );
    }

    #[test]
    fn for_snp_rejects_a_malformed_nameserver() {
        let result = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["192.0.2.53".to_string(), "1.1.1".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        );
        assert!(matches!(
            result,
            Err(DhcpError::InvalidNameserver { nameserver, .. }) if nameserver == "1.1.1"
        ));
    }

    #[test]
    fn systemd_run_wraps_dnsmasq_in_a_keyed_transient_unit() {
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["1.1.1.1".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        let args = config.systemd_run_args();
        assert_eq!(
            args[0],
            format!("--unit=aleph-vm-dhcp-{}.service", "e".repeat(64))
        );
        assert!(args.contains(&"--collect".to_string()));
        // Type=exec so a dnsmasq that cannot exec fails the start job (and the
        // daemon's `start` returns Err) instead of a silent no-DHCP boot.
        assert!(args.contains(&"--property=Type=exec".to_string()));
        // The separator then the program, so the dnsmasq flags are the unit's
        // command and not consumed by systemd-run.
        let sep = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[sep + 1], "dnsmasq");
        assert!(args[sep + 2..].contains(&"--keep-in-foreground".to_string()));
        // The Type=exec property is a systemd-run flag, before the separator.
        assert!(args[..sep].contains(&"--property=Type=exec".to_string()));
    }

    #[test]
    fn the_fake_backend_records_start_and_stop() {
        let backend = FakeDhcpBackend::new();
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["1.1.1.1".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        let lease = std::path::Path::new(&config.lease_file);
        assert!(!backend.is_running(&"e".repeat(64)));
        backend.start(&config).unwrap();
        assert!(backend.is_running(&"e".repeat(64)));
        assert_eq!(backend.started(), vec![config.clone()]);

        backend.stop(&"e".repeat(64), lease).unwrap();
        assert!(!backend.is_running(&"e".repeat(64)));
        assert_eq!(backend.stopped(), vec!["e".repeat(64)]);
    }

    #[test]
    fn the_fake_backend_can_inject_failures() {
        let backend = FakeDhcpBackend::new();
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &[],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        let lease = std::path::Path::new(&config.lease_file);
        let unit = config.unit_name();
        backend.fail_start(move || DhcpError::StartFailed {
            unit: unit.clone(),
            stderr: "boom".to_string(),
        });
        assert!(matches!(
            backend.start(&config),
            Err(DhcpError::StartFailed { stderr, .. }) if stderr == "boom"
        ));
        let unit = config.unit_name();
        backend.fail_stop(move || DhcpError::StopFailed {
            unit: unit.clone(),
            stderr: "nope".to_string(),
        });
        assert!(matches!(
            backend.stop(&"e".repeat(64), lease),
            Err(DhcpError::StopFailed { stderr, .. }) if stderr == "nope"
        ));
    }

    #[test]
    fn dnsmasq_args_hand_the_guest_exactly_its_allocated_ipv6() {
        // The v6 twin of the IPv4 single-address range: a stateful DHCPv6
        // range with low == high == the allocated address, plus --enable-ra.
        // dnsmasq's RA for a stateful (non-slaac) range carries M=1/A=0, so
        // the guest gets its default route from the RA (DHCPv6 cannot convey
        // routes) and never SLAACs a second address.
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["1.1.1.1".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        )
        .unwrap();
        assert_eq!(config.guest_ipv6, "fc00:1:2:3::11");
        assert_eq!(config.ipv6_prefix_len, 124);
        let args = config.dnsmasq_args();
        assert!(args.contains(&"--enable-ra".to_string()));
        assert!(
            args.contains(&"--dhcp-range=fc00:1:2:3::11,fc00:1:2:3::11,124,1h".to_string()),
            "the guest can only lease its allocated IPv6, got {args:?}"
        );
    }

    #[test]
    fn for_snp_rejects_an_ipv6_cidr_without_a_prefix() {
        // Same fail-closed rule as the v4 CIDR: a malformed prefix must error
        // rather than silently produce a dnsmasq range dnsmasq would reject at
        // startup (an Err here surfaces at create; a bad range would instead
        // fail the transient unit and leave the guest v4-only with no trace in
        // the create response).
        let mut tap = snp_tap();
        tap.ipv6.network_cidr = "fc00:1:2:3::10".into(); // no prefix length
        assert!(
            DhcpConfig::for_snp(
                &"e".repeat(64),
                &tap,
                &[],
                std::path::Path::new("/run/aleph/dhcp"),
            )
            .is_err(),
            "an IPv6 CIDR with no prefix must be rejected"
        );
    }

    #[test]
    fn for_snp_rejects_a_cidr_without_a_prefix() {
        // A `/`-less (or non-numeric-prefix) network CIDR must fail rather than
        // silently yield an unroutable /32 (255.255.255.255) that leaves the
        // guest unable to reach its gateway.
        let mut tap = snp_tap();
        tap.ipv4.network_cidr = "172.16.4.0".into(); // no prefix length
        let result = DhcpConfig::for_snp(
            &"e".repeat(64),
            &tap,
            &[],
            std::path::Path::new("/run/aleph/dhcp"),
        );
        assert!(result.is_err(), "a CIDR with no prefix must be rejected");

        let mut tap = snp_tap();
        tap.ipv4.network_cidr = "172.16.4.0/xx".into(); // non-numeric prefix
        assert!(
            DhcpConfig::for_snp(
                &"e".repeat(64),
                &tap,
                &[],
                std::path::Path::new("/run/aleph/dhcp"),
            )
            .is_err(),
            "a non-numeric prefix must be rejected"
        );
    }

    #[test]
    fn is_absent_unit_error_matches_systemd_not_found_messages() {
        assert!(is_absent_unit_error(
            "Failed to stop aleph-vm-dhcp-x.service: Unit aleph-vm-dhcp-x.service not loaded."
        ));
        assert!(is_absent_unit_error(
            "Unit aleph-vm-dhcp-x.service not-found."
        ));
        assert!(!is_absent_unit_error(
            "Failed to stop unit: Connection timed out"
        ));
        assert!(!is_absent_unit_error(""));
    }

    #[test]
    fn systemd_stop_removes_the_lease_file() {
        // The per-VM lease database must be cleaned up on teardown so it does
        // not accumulate on persistent storage. Removal is best-effort and
        // happens regardless of the (here irrelevant) systemctl outcome, so
        // the test does not depend on systemd being present.
        let dir = tempfile::tempdir().unwrap();
        let lease = dir.path().join(format!("{}.leases", "a".repeat(64)));
        std::fs::write(&lease, b"1 aa:bb 172.16.4.2 host *\n").unwrap();
        assert!(lease.exists());
        let _ = SystemdRunDhcp.stop(&"a".repeat(64), &lease);
        assert!(!lease.exists(), "the lease file is removed on stop");
    }

    #[test]
    fn systemd_stop_tolerates_a_missing_lease_file() {
        // A second teardown (or one where dnsmasq never wrote a lease) must not
        // error on the absent file.
        let dir = tempfile::tempdir().unwrap();
        let lease = dir.path().join("gone.leases");
        assert!(!lease.exists());
        // Does not panic; the missing file is silently tolerated.
        let _ = SystemdRunDhcp.stop(&"b".repeat(64), &lease);
    }
}
