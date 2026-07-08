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

use std::process::Command;

use crate::tap::TapAssignment;

/// The transient-unit name prefix for a VM's per-tap dnsmasq.
pub const DHCP_UNIT_PREFIX: &str = "aleph-vm-dhcp-";

/// The transient systemd unit name for a VM hash.
pub fn dhcp_unit_name(vm_hash: &str) -> String {
    format!("{DHCP_UNIT_PREFIX}{vm_hash}.service")
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
    /// The daemon's resolved nameservers, DHCP option 6. Empty omits the
    /// option (the guest gets no DNS, the same as a nameserver-less host).
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
    pub fn for_snp(
        vm_hash: &str,
        tap: &TapAssignment,
        nameservers: &[String],
        lease_dir: &std::path::Path,
    ) -> Self {
        let prefix = tap
            .ipv4
            .network_cidr
            .split_once('/')
            .and_then(|(_, prefix)| prefix.parse::<u8>().ok())
            .unwrap_or(32);
        Self {
            vm_hash: vm_hash.to_string(),
            device_name: tap.device_name.clone(),
            guest_ip: tap.ipv4.address.clone(),
            gateway: tap.ipv4.gateway.clone(),
            netmask: netmask_for_prefix(prefix),
            nameservers: nameservers.to_vec(),
            lease: DEFAULT_LEASE.to_string(),
            lease_file: lease_dir
                .join(format!("{vm_hash}.leases"))
                .to_string_lossy()
                .into_owned(),
        }
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
    /// unit's main process under `systemd-run` (Type=simple).
    pub fn dnsmasq_args(&self) -> Vec<String> {
        let mut args = vec![
            "--keep-in-foreground".to_string(),
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
        ];
        // Option 6: DNS servers, only when the daemon resolved some.
        if !self.nameservers.is_empty() {
            args.push(format!("--dhcp-option=6,{}", self.nameservers.join(",")));
        }
        args
    }

    /// The full `systemd-run` invocation that launches the transient unit:
    /// `systemd-run --unit=... --collect -- dnsmasq <args>`. `--collect`
    /// garbage-collects the unit when it exits or fails, so a later restart
    /// of the same VM never trips over a lingering failed unit.
    pub fn systemd_run_args(&self) -> Vec<String> {
        let mut args = vec![
            format!("--unit={}", self.unit_name()),
            "--collect".to_string(),
            "--".to_string(),
            "dnsmasq".to_string(),
        ];
        args.extend(self.dnsmasq_args());
        args
    }
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
    fn start(&self, config: &DhcpConfig) -> Result<(), String>;

    /// Tear down the per-tap DHCP server for a VM hash. A missing unit is a
    /// success (idempotent teardown, like the tap delete).
    fn stop(&self, vm_hash: &str) -> Result<(), String>;
}

/// Production backend: dnsmasq as a transient systemd unit via `systemd-run`,
/// torn down with `systemctl stop`.
pub struct SystemdRunDhcp;

impl SystemdRunDhcp {
    fn run(program: &str, args: &[String]) -> Result<std::process::Output, String> {
        Command::new(program)
            .args(args)
            .output()
            .map_err(|error| format!("cannot run {program}: {error}"))
    }
}

impl DhcpBackend for SystemdRunDhcp {
    fn start(&self, config: &DhcpConfig) -> Result<(), String> {
        // Ensure the lease directory exists (dnsmasq will not create it).
        if let Some(parent) = std::path::Path::new(&config.lease_file).parent()
            && let Err(error) = std::fs::create_dir_all(parent)
        {
            return Err(format!(
                "cannot create the DHCP lease directory {}: {error}",
                parent.display()
            ));
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
        Err(format!(
            "systemd-run for {unit} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    fn stop(&self, vm_hash: &str) -> Result<(), String> {
        let unit = dhcp_unit_name(vm_hash);
        let output = Self::run("systemctl", &["stop".to_string(), unit.clone()])?;
        if output.status.success() {
            tracing::info!(unit, "stopped per-tap DHCP server");
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        // A unit systemd never knew (already gone) is a successful teardown,
        // mirroring the tap-delete tolerance of a missing device.
        if stderr.contains("not loaded") || stderr.contains("not-found") {
            tracing::warn!(unit, "DHCP unit already gone, treating stop as done");
            return Ok(());
        }
        Err(format!("systemctl stop {unit} failed: {}", stderr.trim()))
    }
}

/// Test backend: records every started [`DhcpConfig`] and stopped hash, with
/// an optional shared [`crate::test_fixtures::EventLog`] to interleave with
/// the tap/nft fakes for ordering checks. Failures are injectable.
#[derive(Debug, Default)]
pub struct FakeDhcpBackend {
    inner: std::sync::Mutex<FakeDhcpState>,
    event_log: std::sync::OnceLock<crate::test_fixtures::EventLog>,
}

#[derive(Debug, Default)]
struct FakeDhcpState {
    started: Vec<DhcpConfig>,
    stopped: Vec<String>,
    running: std::collections::HashSet<String>,
    fail_start: Option<String>,
    fail_stop: Option<String>,
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

    /// Every `start` fails with this message until cleared.
    pub fn fail_start(&self, message: &str) {
        self.lock().fail_start = Some(message.to_string());
    }

    /// Every `stop` fails with this message until cleared.
    pub fn fail_stop(&self, message: &str) {
        self.lock().fail_stop = Some(message.to_string());
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
    fn start(&self, config: &DhcpConfig) -> Result<(), String> {
        let mut inner = self.lock();
        if let Some(message) = &inner.fail_start {
            return Err(message.clone());
        }
        inner.started.push(config.clone());
        inner.running.insert(config.vm_hash.clone());
        drop(inner);
        self.record(format!("dhcp: start {}", config.device_name));
        Ok(())
    }

    fn stop(&self, vm_hash: &str) -> Result<(), String> {
        let mut inner = self.lock();
        if let Some(message) = &inner.fail_stop {
            return Err(message.clone());
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
        );
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
        );
        let args = config.dnsmasq_args();
        // DHCP only, bound to the tap alone, authoritative.
        assert!(args.contains(&"--port=0".to_string()));
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
        );
        let args = config.dnsmasq_args();
        assert!(
            !args.iter().any(|arg| arg.starts_with("--dhcp-option=6")),
            "no DNS option when the daemon resolved no nameservers, got {args:?}"
        );
        // The gateway option is still handed out.
        assert!(args.contains(&"--dhcp-option=3,172.16.4.1".to_string()));
    }

    #[test]
    fn systemd_run_wraps_dnsmasq_in_a_keyed_transient_unit() {
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["1.1.1.1".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        );
        let args = config.systemd_run_args();
        assert_eq!(
            args[0],
            format!("--unit=aleph-vm-dhcp-{}.service", "e".repeat(64))
        );
        assert!(args.contains(&"--collect".to_string()));
        // The separator then the program, so the dnsmasq flags are the unit's
        // command and not consumed by systemd-run.
        let sep = args.iter().position(|arg| arg == "--").unwrap();
        assert_eq!(args[sep + 1], "dnsmasq");
        assert!(args[sep + 2..].contains(&"--keep-in-foreground".to_string()));
    }

    #[test]
    fn the_fake_backend_records_start_and_stop() {
        let backend = FakeDhcpBackend::new();
        let config = DhcpConfig::for_snp(
            &"e".repeat(64),
            &snp_tap(),
            &["1.1.1.1".to_string()],
            std::path::Path::new("/run/aleph/dhcp"),
        );
        assert!(!backend.is_running(&"e".repeat(64)));
        backend.start(&config).unwrap();
        assert!(backend.is_running(&"e".repeat(64)));
        assert_eq!(backend.started(), vec![config.clone()]);

        backend.stop(&"e".repeat(64)).unwrap();
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
        );
        backend.fail_start("boom");
        assert_eq!(backend.start(&config), Err("boom".to_string()));
        backend.fail_stop("nope");
        assert_eq!(backend.stop(&"e".repeat(64)), Err("nope".to_string()));
    }
}
