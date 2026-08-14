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
    fn create_tap(&self, tap: &TapAssignment) -> Result<(), TapError>;

    /// Python `TapInterface.delete` minus the NDP range: remove the
    /// addresses and the device. A missing device is a warning, not an
    /// error.
    fn delete_tap(&self, tap: &TapAssignment) -> Result<(), TapError>;
}

/// Failures creating or deleting a tap device via `ip(8)`.
#[derive(Debug, thiserror::Error)]
pub enum TapError {
    #[error("cannot run ip: {source}")]
    Run { source: std::io::Error },

    #[error("ip {argv} failed: {stderr}")]
    Command { argv: String, stderr: String },
}

/// Production backend over `ip(8)`.
pub struct IpCommand;

/// The tolerance classes of the Python interfaces.py error handling.
#[derive(Debug, PartialEq, Eq)]
enum IpFailure {
    /// EEXIST: pyroute2's NetlinkError code 17 is a warning in both
    /// create_tap_interface and add_ip_address; the create is idempotent.
    AlreadyExists,
    /// EBUSY on tap creation: NetlinkError 16 / OSError EBUSY is a warning
    /// in create_tap_interface ("is there another process using it?").
    Busy,
    /// Everything else propagates from the tap creation (and only there).
    Other,
}

/// Classify one failed `ip(8)` stderr like the pyroute2 error codes.
fn classify_ip_failure(stderr: &str) -> IpFailure {
    if stderr.contains("File exists") || stderr.contains("already exists") {
        IpFailure::AlreadyExists
    } else if stderr.contains("Device or resource busy") || stderr.contains("busy") {
        IpFailure::Busy
    } else {
        IpFailure::Other
    }
}

fn run_ip(args: &[&str]) -> Result<(), TapError> {
    let output = Command::new("ip")
        .args(args)
        .output()
        .map_err(|source| TapError::Run { source })?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    // Python create_tap_interface tolerance: EEXIST and EBUSY are
    // warnings, never failures.
    match classify_ip_failure(&stderr) {
        IpFailure::AlreadyExists => {
            tracing::warn!(?args, stderr, "ip reported the object already exists");
            Ok(())
        }
        IpFailure::Busy => {
            tracing::warn!(
                ?args,
                stderr,
                "ip reported the object busy; is another process using it?"
            );
            Ok(())
        }
        IpFailure::Other => Err(TapError::Command {
            argv: args.join(" "),
            stderr,
        }),
    }
}

impl TapBackend for IpCommand {
    fn interface_exists(&self, device_name: &str) -> bool {
        std::path::Path::new("/sys/class/net")
            .join(device_name)
            .exists()
    }

    fn create_tap(&self, tap: &TapAssignment) -> Result<(), TapError> {
        run_ip(&["tuntap", "add", "name", &tap.device_name, "mode", "tap"])?;
        // Address failures are logged and tolerated in Python
        // (add_ip_address catches every NetlinkError); mirror that.
        for address in [tap.host_ipv4_cidr(), tap.host_ipv6_cidr()] {
            if let Err(error) = run_ip(&["addr", "add", &address, "dev", &tap.device_name]) {
                tracing::error!(
                    device = tap.device_name,
                    address,
                    %error,
                    "cannot add address to tap interface"
                );
            }
        }
        // Python set_link_up logs NetlinkError/OSError and proceeds
        // (interfaces.py:84-89); a link that stays down is a warning, not
        // a failed create.
        if let Err(error) = run_ip(&["link", "set", &tap.device_name, "up"]) {
            tracing::error!(
                device = tap.device_name,
                %error,
                "cannot set the tap interface up"
            );
        }
        Ok(())
    }

    fn delete_tap(&self, tap: &TapAssignment) -> Result<(), TapError> {
        if !self.interface_exists(&tap.device_name) {
            tracing::warn!(
                device = tap.device_name,
                "interface already removed, skipping delete"
            );
            return Ok(());
        }
        // `ip link del` removes the device with its addresses; Python
        // deletes the addresses one by one first, a netlink detail with no
        // observable difference. Python's TapInterface.delete swallows
        // every deletion failure with a warning (interfaces.py:214-217).
        if let Err(error) = run_ip(&["link", "del", &tap.device_name]) {
            tracing::warn!(
                device = tap.device_name,
                %error,
                "interface cannot be deleted"
            );
        }
        Ok(())
    }
}

/// Test backend: an in-memory device set, every call recorded. Failures
/// are injectable per operation, and an optional shared [`EventLog`]
/// interleaves the tap calls with the other fakes' for ordering checks.
#[derive(Default)]
pub struct FakeTapBackend {
    inner: std::sync::Mutex<FakeTapState>,
    event_log: std::sync::OnceLock<crate::test_fixtures::EventLog>,
}

/// A builder rather than a stored `TapError`: `TapError` deliberately has no
/// `Clone` impl (its `io::Error` source must stay a real, non-reconstructed
/// error everywhere outside this test-only injection path), so repeated
/// failures are produced by calling the closure again instead of cloning a
/// stored value.
type TapErrorFn = Box<dyn Fn() -> TapError + Send + Sync>;

#[derive(Default)]
struct FakeTapState {
    devices: std::collections::HashSet<String>,
    pub actions: Vec<String>,
    fail_create: Option<TapErrorFn>,
    fail_delete: Option<TapErrorFn>,
    panic_on_create: bool,
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

    /// Every create_tap fails with the error `make` builds, until cleared.
    /// A builder (not a stored error) so each call gets its own real
    /// `TapError`, e.g. `backend.fail_create(|| TapError::Command { .. })`.
    pub fn fail_create(&self, make: impl Fn() -> TapError + Send + Sync + 'static) {
        self.lock().fail_create = Some(Box::new(make));
    }

    /// Every delete_tap fails with the error `make` builds, until cleared.
    pub fn fail_delete(&self, make: impl Fn() -> TapError + Send + Sync + 'static) {
        self.lock().fail_delete = Some(Box::new(make));
    }

    /// The next create_tap panics (for unwind-safety tests).
    pub fn panic_on_create(&self) {
        self.lock().panic_on_create = true;
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

impl TapBackend for FakeTapBackend {
    fn interface_exists(&self, device_name: &str) -> bool {
        self.lock().devices.contains(device_name)
    }

    fn create_tap(&self, tap: &TapAssignment) -> Result<(), TapError> {
        let mut inner = self.lock();
        if inner.panic_on_create {
            inner.panic_on_create = false;
            drop(inner);
            panic!("injected tap creation panic");
        }
        if let Some(make) = &inner.fail_create {
            return Err(make());
        }
        inner.actions.push(format!(
            "create {} {} {}",
            tap.device_name,
            tap.host_ipv4_cidr(),
            tap.host_ipv6_cidr()
        ));
        inner.devices.insert(tap.device_name.clone());
        drop(inner);
        self.record(format!("tap: create {}", tap.device_name));
        Ok(())
    }

    fn delete_tap(&self, tap: &TapAssignment) -> Result<(), TapError> {
        let mut inner = self.lock();
        if let Some(make) = &inner.fail_delete {
            return Err(make());
        }
        inner.actions.push(format!("delete {}", tap.device_name));
        inner.devices.remove(&tap.device_name);
        drop(inner);
        self.record(format!("tap: delete {}", tap.device_name));
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

    #[test]
    fn fail_create_injects_a_typed_error() {
        let backend = FakeTapBackend::new();
        let tap = assignment();
        backend.fail_create(|| TapError::Command {
            argv: "tuntap add name vmtap3 mode tap".to_string(),
            stderr: "Operation not permitted".to_string(),
        });
        let error = backend.create_tap(&tap).unwrap_err();
        assert!(matches!(error, TapError::Command { .. }));
        assert_eq!(
            error.to_string(),
            "ip tuntap add name vmtap3 mode tap failed: Operation not permitted"
        );
    }

    #[test]
    fn ip_failures_classify_like_the_pyroute2_error_codes() {
        // interfaces.py tolerance: EEXIST (NetlinkError 17) and EBUSY
        // (NetlinkError 16 / OSError EBUSY) are warnings on tap creation;
        // everything else propagates.
        assert_eq!(
            classify_ip_failure("RTNETLINK answers: File exists"),
            IpFailure::AlreadyExists
        );
        assert_eq!(
            classify_ip_failure("ioctl(TUNSETIFF): Device or resource busy"),
            IpFailure::Busy
        );
        assert_eq!(
            classify_ip_failure("RTNETLINK answers: Operation not permitted"),
            IpFailure::Other
        );
    }
}
