//! NDP proxy handling, ported from the Python `NdpProxy`
//! (src/aleph/vm/network/ndp_proxy.py).
//!
//! The proxy state is an in-memory interface-to-range map (insertion
//! ordered, like the Python dict); every update rewrites /etc/ndppd.conf
//! from it and schedules a debounced `systemctl restart ndppd`. At adoption
//! the map is primed WITHOUT touching the file or the service
//! (`add_range(update_service=False)`), exactly like the Python reattach:
//! the on-disk config already covers running VMs, and a boot-time restart
//! would drop NDP answers for no reason.
//!
//! The file/systemctl edge sits behind [`NdppdEdge`] so cargo tests replay
//! the config generation hermetically.

use std::process::Command;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

/// Python `_RESTART_DEBOUNCE_SECONDS`: bursts of add/delete (one per VM at
/// startup or teardown) coalesce into a single ndppd restart.
const RESTART_DEBOUNCE: Duration = Duration::from_millis(500);

/// Error type for NDP proxy operations.
#[derive(Debug, thiserror::Error)]
pub enum NdppdError {
    #[error("cannot write /etc/ndppd.conf: {source}")]
    WriteConf { source: std::io::Error },
}

/// Where the config lands and how the service restarts.
pub trait NdppdEdge: Send + Sync {
    fn write_conf(&self, contents: &str) -> Result<(), NdppdError>;
    fn restart_service(&self);
}

/// Production edge: /etc/ndppd.conf plus `systemctl restart ndppd` (the
/// Python code shells out to systemctl here too, not D-Bus).
pub struct SystemNdppd;

impl NdppdEdge for SystemNdppd {
    fn write_conf(&self, contents: &str) -> Result<(), NdppdError> {
        std::fs::write("/etc/ndppd.conf", contents)
            .map_err(|source| NdppdError::WriteConf { source })
    }

    fn restart_service(&self) {
        match Command::new("systemctl")
            .args(["restart", "ndppd"])
            .output()
        {
            Ok(output) if !output.status.success() => {
                tracing::error!(
                    stderr = %String::from_utf8_lossy(&output.stderr).trim(),
                    "failed to restart ndppd"
                );
            }
            Ok(_) => {}
            Err(error) => tracing::error!(%error, "failed to run systemctl restart ndppd"),
        }
    }
}

/// Test edge: recorded writes, counted restarts.
#[derive(Default)]
pub struct FakeNdppd {
    pub writes: Mutex<Vec<String>>,
    pub restarts: std::sync::atomic::AtomicUsize,
}

impl FakeNdppd {
    pub fn written(&self) -> Vec<String> {
        self.writes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    pub fn restart_count(&self) -> usize {
        self.restarts.load(std::sync::atomic::Ordering::SeqCst)
    }
}

impl NdppdEdge for FakeNdppd {
    fn write_conf(&self, contents: &str) -> Result<(), NdppdError> {
        self.writes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(contents.to_string());
        Ok(())
    }

    fn restart_service(&self) {
        self.restarts
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Default)]
struct NdpState {
    /// interface -> proxied IPv6 range, insertion ordered like the Python
    /// dict (an update in place keeps the position).
    ranges: Vec<(String, String)>,
    restart_pending: bool,
}

/// The NDP proxy bookkeeping plus its edge.
pub struct NdpProxy {
    host_network_interface: String,
    edge: Arc<dyn NdppdEdge>,
    state: Arc<Mutex<NdpState>>,
}

impl NdpProxy {
    pub fn new(host_network_interface: String, edge: Arc<dyn NdppdEdge>) -> Self {
        Self {
            host_network_interface,
            edge,
            state: Arc::new(Mutex::new(NdpState::default())),
        }
    }

    fn lock(&self) -> MutexGuard<'_, NdpState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The exact `_update_ndppd_conf` config text.
    fn render(&self, ranges: &[(String, String)]) -> String {
        let mut config = format!("proxy {} {{\n", self.host_network_interface);
        for (interface, range) in ranges {
            config.push_str(&format!("  rule {range} {{\n    iface {interface}\n  }}\n"));
        }
        config.push_str("}\n");
        config
    }

    fn update_conf(&self, state: &mut NdpState) -> Result<(), NdppdError> {
        let contents = self.render(&state.ranges);
        // A failed config write propagates and fails the calling RPC,
        // exactly like the Python `Path.write_text` in _update_ndppd_conf.
        self.edge.write_conf(&contents)?;
        if state.restart_pending {
            // A restart is already scheduled; it will pick the new config
            // up (Python `_schedule_restart` early return).
            return Ok(());
        }
        state.restart_pending = true;
        let edge = self.edge.clone();
        let shared = self.state.clone();
        tokio::spawn(async move {
            tokio::time::sleep(RESTART_DEBOUNCE).await;
            shared
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .restart_pending = false;
            edge.restart_service();
        });
        Ok(())
    }

    /// Python `add_range`. `update_service=false` at adoption only.
    pub fn add_range(
        &self,
        interface: &str,
        address_range: &str,
        update_service: bool,
    ) -> Result<(), NdppdError> {
        let mut state = self.lock();
        tracing::debug!(interface, address_range, "proxying range");
        match state
            .ranges
            .iter_mut()
            .find(|(existing, _)| existing == interface)
        {
            Some(entry) => entry.1 = address_range.to_string(),
            None => state
                .ranges
                .push((interface.to_string(), address_range.to_string())),
        }
        if update_service {
            self.update_conf(&mut state)?;
        }
        Ok(())
    }

    /// Python `delete_range`: absent interfaces are a silent no-op.
    pub fn delete_range(&self, interface: &str, update_service: bool) -> Result<(), NdppdError> {
        let mut state = self.lock();
        let Some(position) = state
            .ranges
            .iter()
            .position(|(existing, _)| existing == interface)
        else {
            return Ok(());
        };
        state.ranges.remove(position);
        if update_service {
            self.update_conf(&mut state)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> (NdpProxy, Arc<FakeNdppd>) {
        let edge = Arc::new(FakeNdppd::default());
        (NdpProxy::new("eth0".to_string(), edge.clone()), edge)
    }

    #[tokio::test]
    async fn the_config_matches_the_python_update_ndppd_conf() {
        let (proxy, edge) = proxy();
        proxy
            .add_range("vmtap3", "fc00:1:2:3::10/124", true)
            .unwrap();
        proxy
            .add_range("vmtap4", "fc00:1:2:3::20/124", true)
            .unwrap();
        let writes = edge.written();
        assert_eq!(
            writes.last().unwrap(),
            "proxy eth0 {\n\
             \x20 rule fc00:1:2:3::10/124 {\n\
             \x20   iface vmtap3\n\
             \x20 }\n\
             \x20 rule fc00:1:2:3::20/124 {\n\
             \x20   iface vmtap4\n\
             \x20 }\n\
             }\n"
        );

        proxy.delete_range("vmtap3", true).unwrap();
        assert!(edge.written().last().unwrap().contains("vmtap4"));
        assert!(!edge.written().last().unwrap().contains("vmtap3"));

        // Bursts coalesce into one restart.
        tokio::time::sleep(RESTART_DEBOUNCE * 3).await;
        assert_eq!(edge.restart_count(), 1);
    }

    #[tokio::test]
    async fn priming_at_adoption_never_touches_the_file_or_service() {
        let (proxy, edge) = proxy();
        proxy
            .add_range("vmtap3", "fc00:1:2:3::10/124", false)
            .unwrap();
        assert!(edge.written().is_empty());
        tokio::time::sleep(RESTART_DEBOUNCE * 2).await;
        assert_eq!(edge.restart_count(), 0);

        // The primed range survives into the next real update.
        proxy
            .add_range("vmtap4", "fc00:1:2:3::20/124", true)
            .unwrap();
        assert!(edge.written().last().unwrap().contains("vmtap3"));
    }

    #[tokio::test]
    async fn deleting_an_unknown_interface_is_a_no_op() {
        let (proxy, edge) = proxy();
        proxy.delete_range("vmtap9", true).unwrap();
        assert!(edge.written().is_empty());
    }

    /// A config write failure fails the call, like the Python
    /// `Path("/etc/ndppd.conf").write_text` propagating out of add_range.
    struct FailingEdge;

    impl NdppdEdge for FailingEdge {
        fn write_conf(&self, _contents: &str) -> Result<(), NdppdError> {
            Err(NdppdError::WriteConf {
                source: std::io::Error::other("read-only /etc"),
            })
        }
        fn restart_service(&self) {}
    }

    #[tokio::test]
    async fn a_conf_write_failure_propagates_like_python() {
        let proxy = NdpProxy::new("eth0".to_string(), Arc::new(FailingEdge));
        let error = proxy
            .add_range("vmtap3", "fc00:1:2:3::10/124", true)
            .unwrap_err();
        assert!(error.to_string().contains("read-only /etc"));
        // Priming (update_service=false) never writes, so it cannot fail.
        proxy.add_range("vmtap4", "fc00::20/124", false).unwrap();
        let error = proxy.delete_range("vmtap4", true).unwrap_err();
        assert!(error.to_string().contains("read-only /etc"));
    }
}
