//! systemd unit states, the daemon's view of which controllers are alive.
//!
//! Mirrors the Python `SystemDManager.get_services_active_states`
//! (src/aleph/vm/systemd.py): one batched `ListUnits()` D-Bus call, units
//! absent from the reply count as inactive. Unlike the Python method, a bus
//! failure surfaces as an error instead of degrading to "everything
//! inactive" inside this module: callers need the distinction between "the
//! bus answered and the unit is inactive" and "the bus did not answer"
//! (adoption must not stamp a VM stopped on a transient bus outage). The
//! per-RPC handlers still degrade to all-inactive on error, the Python
//! parity behavior (ledger entry 13). The seam is a trait so cargo tests
//! stay hermetic: the production implementation talks to the system bus
//! over zbus, tests use [`StaticUnitStates`] and [`UnreachableBus`].
//!
//! Graceful no-bus degradation is deliberate (and ledgered in
//! docs/plans/rust-port-divergences.md): the Python daemon cannot construct
//! its `SystemDManager` without a bus and dies at startup, while this daemon
//! must still boot in a container.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use zbus::zvariant::OwnedObjectPath;

/// Unit name prefix of the per-VM controller template instances.
pub const CONTROLLER_UNIT_PREFIX: &str = "aleph-vm-controller@";

/// How long one D-Bus method call may take before it fails. The zbus
/// builder default is no timeout at all, so a wedged bus (dbus-broker hung,
/// systemd not answering) would stall boot or an RPC forever; 5 seconds is
/// orders of magnitude above any healthy ListUnits round trip.
const DBUS_METHOD_TIMEOUT: Duration = Duration::from_secs(5);

/// The controller unit for a VM hash, `aleph-vm-controller@{hash}.service`.
pub fn controller_unit_name(vm_hash: &str) -> String {
    format!("{CONTROLLER_UNIT_PREFIX}{vm_hash}.service")
}

/// Where the daemon learns systemd unit states from.
///
/// Both methods are blocking (one D-Bus round trip); RPC handlers call them
/// through `spawn_blocking`, the same way the Python daemon pushes its
/// batched ListUnits call off the event loop (`asyncio.to_thread` in
/// `LocalSupervisor.list_vms`).
pub trait UnitStateSource: Send + Sync {
    /// Active flag per requested unit name, one batched query. Units not
    /// loaded in systemd report `false`. `Err` means the bus did not answer
    /// (unreachable, timed out, malformed reply): the caller cannot tell
    /// running from stopped and must not pretend it can.
    fn active_states(&self, units: &[String]) -> Result<HashMap<String, bool>, String>;

    /// Every loaded `aleph-vm-controller@*.service` unit with its active
    /// flag, for the boot-time "unit without a config file" sweep.
    fn controller_units(&self) -> Result<HashMap<String, bool>, String>;
}

/// The `ListUnits()` reply row: (name, description, load_state,
/// active_state, sub_state, following, unit_path, job_id, job_type,
/// job_path). Only name and active_state are read, like the Python side.
type ListedUnit = (
    String,
    String,
    String,
    String,
    String,
    String,
    OwnedObjectPath,
    u32,
    String,
    OwnedObjectPath,
);

/// System-bus implementation over zbus. The connection is cached and
/// re-established once per failing call, mirroring the Python
/// `SystemDManager._ensure_connection` reconnect behavior.
///
/// The Mutex serializes callers on the shared connection; with the 5 second
/// method timeout on every call, one slow call delays the others by at most
/// that cap (and two retry passes bound a single `list_units` at ~10s),
/// never forever.
pub struct ZbusUnitStates {
    connection: Mutex<Option<zbus::blocking::Connection>>,
}

impl ZbusUnitStates {
    pub fn new() -> Self {
        Self {
            connection: Mutex::new(None),
        }
    }

    fn list_units(&self) -> Result<Vec<(String, String)>, zbus::Error> {
        let mut guard = self
            .connection
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for attempt in 0..2 {
            if guard.is_none() {
                *guard = Some(
                    zbus::blocking::connection::Builder::system()?
                        // A wedged bus must fail calls within seconds, both
                        // at boot and per RPC; the builder default is no
                        // method timeout at all.
                        .method_timeout(DBUS_METHOD_TIMEOUT)
                        .build()?,
                );
            }
            let connection = guard.as_ref().expect("connection was just established");
            let reply = connection.call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.systemd1.Manager"),
                "ListUnits",
                &(),
            );
            match reply {
                Ok(message) => {
                    let units: Vec<ListedUnit> = message.body().deserialize()?;
                    return Ok(units.into_iter().map(|unit| (unit.0, unit.3)).collect());
                }
                Err(error) => {
                    // Drop the cached connection and retry once on a fresh
                    // one (the bus may have restarted under us).
                    *guard = None;
                    if attempt == 1 {
                        return Err(error);
                    }
                    tracing::debug!(%error, "ListUnits failed, reconnecting to the system bus");
                }
            }
        }
        // `attempt` only takes 0 and 1, and the attempt == 1 arm above
        // returns unconditionally, so the loop cannot fall through.
        unreachable!("the retry loop returns on its second pass");
    }
}

impl Default for ZbusUnitStates {
    fn default() -> Self {
        Self::new()
    }
}

impl UnitStateSource for ZbusUnitStates {
    fn active_states(&self, units: &[String]) -> Result<HashMap<String, bool>, String> {
        if units.is_empty() {
            return Ok(HashMap::new());
        }
        let listed = self.list_units().map_err(|error| error.to_string())?;
        let by_name: HashMap<&str, &str> = listed
            .iter()
            .map(|(name, state)| (name.as_str(), state.as_str()))
            .collect();
        Ok(units
            .iter()
            .map(|unit| {
                let active = by_name.get(unit.as_str()) == Some(&"active");
                (unit.clone(), active)
            })
            .collect())
    }

    fn controller_units(&self) -> Result<HashMap<String, bool>, String> {
        let listed = self.list_units().map_err(|error| error.to_string())?;
        Ok(listed
            .into_iter()
            .filter(|(name, _)| {
                name.starts_with(CONTROLLER_UNIT_PREFIX) && name.ends_with(".service")
            })
            .map(|(name, state)| (name, state == "active"))
            .collect())
    }
}

/// In-memory fake for tests: a fixed unit-name to active-flag map.
#[derive(Debug, Default, Clone)]
pub struct StaticUnitStates {
    states: HashMap<String, bool>,
}

impl StaticUnitStates {
    pub fn new(states: HashMap<String, bool>) -> Self {
        Self { states }
    }

    /// Convenience: mark these VM hashes' controller units active.
    pub fn with_active_vms(vm_hashes: &[&str]) -> Self {
        Self::new(
            vm_hashes
                .iter()
                .map(|hash| (controller_unit_name(hash), true))
                .collect(),
        )
    }
}

impl UnitStateSource for StaticUnitStates {
    fn active_states(&self, units: &[String]) -> Result<HashMap<String, bool>, String> {
        Ok(units
            .iter()
            .map(|unit| {
                (
                    unit.clone(),
                    self.states.get(unit).copied().unwrap_or(false),
                )
            })
            .collect())
    }

    fn controller_units(&self) -> Result<HashMap<String, bool>, String> {
        Ok(self
            .states
            .iter()
            .filter(|(name, _)| name.starts_with(CONTROLLER_UNIT_PREFIX))
            .map(|(name, active)| (name.clone(), *active))
            .collect())
    }
}

/// In-memory fake of a bus that never answers: every call errors, the way
/// `ZbusUnitStates` fails when the system bus is unreachable or wedged.
#[derive(Debug, Default, Clone)]
pub struct UnreachableBus;

impl UnitStateSource for UnreachableBus {
    fn active_states(&self, _units: &[String]) -> Result<HashMap<String, bool>, String> {
        Err("test bus is unreachable".to_string())
    }

    fn controller_units(&self) -> Result<HashMap<String, bool>, String> {
        Err("test bus is unreachable".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_states_answer_requested_units_and_default_to_inactive() {
        let source = StaticUnitStates::with_active_vms(&["aa"]);
        let states = source
            .active_states(&[controller_unit_name("aa"), controller_unit_name("bb")])
            .unwrap();
        assert!(states[&controller_unit_name("aa")]);
        assert!(!states[&controller_unit_name("bb")]);
        assert_eq!(source.controller_units().unwrap().len(), 1);
    }

    #[test]
    fn the_unreachable_bus_errors_instead_of_reporting_inactive() {
        let source = UnreachableBus;
        assert!(source.active_states(&[controller_unit_name("aa")]).is_err());
        assert!(source.controller_units().is_err());
    }
}
