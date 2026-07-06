//! TAP device management, ported from the Python `TapInterface`
//! (src/aleph/vm/network/interfaces.py) and `Network.prepare_tap`
//! (src/aleph/vm/network/hostnetwork.py).
//!
//! The address math (the vm_index-th IPv4 subnet, the static/dynamic IPv6
//! allocation) lives in src/world.rs; this module owns the derived
//! [`TapAssignment`] and the kernel edge behind the [`TapBackend`] seam.
//! The production backend shells out to `ip(8)` where Python drives
//! netlink through pyroute2: same kernel operations, same tolerance for
//! already-existing devices and addresses (ledgered divergence in
//! representation only).

use std::process::Command;

use crate::world::IpPair;

/// One VM's tap networking, the Python `TapInterface` fields the supervisor
/// reads: device name plus the guest/host addresses of both families.
#[derive(Debug, Clone)]
pub struct TapAssignment {
    pub vm_index: i64,
    /// `vmtap{vm_index}`.
    pub device_name: String,
    /// guest = network+2, gateway (host) = network+1.
    pub ipv4: IpPair,
    /// guest = network+1, gateway (host) = the network address.
    pub ipv6: IpPair,
}

impl TapAssignment {
    pub fn new(vm_index: i64, ipv4: IpPair, ipv6: IpPair) -> Self {
        Self {
            vm_index,
            device_name: format!("vmtap{vm_index}"),
            ipv4,
            ipv6,
        }
    }

    fn prefix_of(pair: &IpPair) -> &str {
        pair.network_cidr
            .split_once('/')
            .map(|(_, prefix)| prefix)
            .unwrap_or("32")
    }

    /// Host-side IPv4 in CIDR form, `TapInterface.host_ip` (e.g.
    /// "172.16.3.1/24").
    pub fn host_ipv4_cidr(&self) -> String {
        format!("{}/{}", self.ipv4.gateway, Self::prefix_of(&self.ipv4))
    }

    /// Host-side IPv6 in CIDR form, `TapInterface.host_ipv6`.
    pub fn host_ipv6_cidr(&self) -> String {
        format!("{}/{}", self.ipv6.gateway, Self::prefix_of(&self.ipv6))
    }

    /// Guest IPv4 in CIDR form, `guest_ip.with_prefixlen` (cloud-init).
    pub fn guest_ipv4_cidr(&self) -> String {
        format!("{}/{}", self.ipv4.address, Self::prefix_of(&self.ipv4))
    }

    /// Guest IPv6 in CIDR form, `guest_ipv6.with_prefixlen` (cloud-init).
    pub fn guest_ipv6_cidr(&self) -> String {
        format!("{}/{}", self.ipv6.address, Self::prefix_of(&self.ipv6))
    }
}

/// The kernel edge: create/delete tap devices, check their existence.
/// Blocking; callers hop to the blocking pool.
pub trait TapBackend: Send + Sync {
    /// Python `Network.interface_exists` (NDB lookup; here /sys/class/net).
    fn interface_exists(&self, device_name: &str) -> bool;

    /// Python `TapInterface.create` minus the NDP range (the caller owns
    /// ndppd): create the tap, add both host addresses, set the link up.
    /// An already-existing device or address is tolerated with a warning,
    /// like the pyroute2 EEXIST handling.
    fn create_tap(&self, tap: &TapAssignment) -> Result<(), String>;

    /// Python `TapInterface.delete` minus the NDP range: remove the
    /// addresses and the device. A missing device is a warning, not an
    /// error.
    fn delete_tap(&self, tap: &TapAssignment) -> Result<(), String>;
}

/// Production backend over `ip(8)`.
pub struct IpCommand;

fn run_ip(args: &[&str]) -> Result<(), String> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|error| format!("cannot run ip: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    // pyroute2 parity: EEXIST (device or address already there) is a
    // warning, never a failure; the create path is idempotent.
    if stderr.contains("File exists") || stderr.contains("already exists") {
        tracing::warn!(?args, stderr, "ip reported the object already exists");
        return Ok(());
    }
    Err(format!("ip {} failed: {stderr}", args.join(" ")))
}

impl TapBackend for IpCommand {
    fn interface_exists(&self, device_name: &str) -> bool {
        std::path::Path::new("/sys/class/net")
            .join(device_name)
            .exists()
    }

    fn create_tap(&self, tap: &TapAssignment) -> Result<(), String> {
        run_ip(&["tuntap", "add", "name", &tap.device_name, "mode", "tap"])?;
        // Address failures are logged and tolerated in Python
        // (add_ip_address catches every NetlinkError); mirror that.
        for address in [tap.host_ipv4_cidr(), tap.host_ipv6_cidr()] {
            if let Err(error) = run_ip(&["addr", "add", &address, "dev", &tap.device_name]) {
                tracing::error!(
                    device = tap.device_name,
                    address,
                    error,
                    "cannot add address to tap interface"
                );
            }
        }
        run_ip(&["link", "set", &tap.device_name, "up"])?;
        Ok(())
    }

    fn delete_tap(&self, tap: &TapAssignment) -> Result<(), String> {
        if !self.interface_exists(&tap.device_name) {
            tracing::warn!(
                device = tap.device_name,
                "interface already removed, skipping delete"
            );
            return Ok(());
        }
        // `ip link del` removes the device with its addresses; Python
        // deletes the addresses one by one first, a netlink detail with no
        // observable difference.
        run_ip(&["link", "del", &tap.device_name])
    }
}

/// Test backend: an in-memory device set, every call recorded.
#[derive(Debug, Default)]
pub struct FakeTapBackend {
    inner: std::sync::Mutex<FakeTapState>,
}

#[derive(Debug, Default)]
struct FakeTapState {
    devices: std::collections::HashSet<String>,
    pub actions: Vec<String>,
}

impl FakeTapBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_devices(devices: &[&str]) -> Self {
        let fake = Self::new();
        fake.lock().devices = devices.iter().map(|name| name.to_string()).collect();
        fake
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeTapState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn actions(&self) -> Vec<String> {
        self.lock().actions.clone()
    }

    pub fn devices(&self) -> std::collections::HashSet<String> {
        self.lock().devices.clone()
    }
}

impl TapBackend for FakeTapBackend {
    fn interface_exists(&self, device_name: &str) -> bool {
        self.lock().devices.contains(device_name)
    }

    fn create_tap(&self, tap: &TapAssignment) -> Result<(), String> {
        let mut inner = self.lock();
        inner.actions.push(format!(
            "create {} {} {}",
            tap.device_name,
            tap.host_ipv4_cidr(),
            tap.host_ipv6_cidr()
        ));
        inner.devices.insert(tap.device_name.clone());
        Ok(())
    }

    fn delete_tap(&self, tap: &TapAssignment) -> Result<(), String> {
        let mut inner = self.lock();
        inner.actions.push(format!("delete {}", tap.device_name));
        inner.devices.remove(&tap.device_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assignment() -> TapAssignment {
        TapAssignment::new(
            3,
            IpPair {
                address: "172.16.3.2".into(),
                network_cidr: "172.16.3.0/24".into(),
                gateway: "172.16.3.1".into(),
            },
            IpPair {
                address: "fc00:1:2:3::11".into(),
                network_cidr: "fc00:1:2:3::10/124".into(),
                gateway: "fc00:1:2:3::10".into(),
            },
        )
    }

    #[test]
    fn cidr_forms_match_the_python_tap_interface_properties() {
        let tap = assignment();
        assert_eq!(tap.device_name, "vmtap3");
        assert_eq!(tap.host_ipv4_cidr(), "172.16.3.1/24");
        assert_eq!(tap.guest_ipv4_cidr(), "172.16.3.2/24");
        assert_eq!(tap.host_ipv6_cidr(), "fc00:1:2:3::10/124");
        assert_eq!(tap.guest_ipv6_cidr(), "fc00:1:2:3::11/124");
    }

    #[test]
    fn the_fake_backend_tracks_devices() {
        let backend = FakeTapBackend::new();
        let tap = assignment();
        assert!(!backend.interface_exists("vmtap3"));
        backend.create_tap(&tap).unwrap();
        assert!(backend.interface_exists("vmtap3"));
        backend.delete_tap(&tap).unwrap();
        assert!(!backend.interface_exists("vmtap3"));
    }
}
