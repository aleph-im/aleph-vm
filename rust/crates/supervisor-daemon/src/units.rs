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

    // ── Mutations (increment 3), mirroring the Python SystemDManager ──

    /// The unit's ActiveState string, plus the two synthetic values the
    /// Python `get_service_active_state` adds: "not-loaded" when systemd
    /// does not know the unit (GetUnit raises NoSuchUnit) and "unknown" on
    /// any other bus error. Callers retry on "unknown"; "not-loaded" means
    /// positively not running.
    fn get_active_state(&self, unit: &str) -> String;

    /// `StartUnit(unit, "replace")`.
    fn start(&self, unit: &str) -> Result<(), String>;

    /// `StopUnit(unit, "replace")`.
    fn stop(&self, unit: &str) -> Result<(), String>;

    /// `RestartUnit(unit, "replace")`.
    fn restart(&self, unit: &str) -> Result<(), String>;

    /// `EnableUnitFiles([unit], runtime=false, force=true)`.
    fn enable(&self, unit: &str) -> Result<(), String>;

    /// `DisableUnitFiles([unit], runtime=false)`.
    fn disable(&self, unit: &str) -> Result<(), String>;

    /// Python `is_service_enabled`: `GetUnitFileState(unit) == "enabled"`,
    /// false on any bus error.
    fn is_enabled(&self, unit: &str) -> bool;

    /// `Reload()`: reread unit files and drop-ins, so a freshly written
    /// per-instance `.service.d` drop-in (the NUMA `AllowedCPUs=` pin) is
    /// picked up even when systemd already had the unit loaded. NUMA-only;
    /// the default is a no-op for the in-memory test fakes, which have no
    /// on-disk unit files to reread.
    fn reload(&self) -> Result<(), String> {
        Ok(())
    }
}

/// Python `SystemDManager.stop_and_disable`: stop gated on the actual
/// ActiveState (never on enablement), then disable when enabled.
pub fn stop_and_disable(units: &dyn UnitStateSource, unit: &str) -> Result<(), String> {
    if !matches!(
        units.get_active_state(unit).as_str(),
        "inactive" | "failed" | "not-loaded"
    ) {
        units.stop(unit)?;
    }
    if units.is_enabled(unit) {
        units.disable(unit)?;
    }
    Ok(())
}

/// Python `SystemDManager.enable_and_start`. The active probe mirrors
/// `is_service_active`, which (wart) checks enablement first; here the unit
/// was just enabled, so the ActiveState alone decides.
pub fn enable_and_start(units: &dyn UnitStateSource, unit: &str) -> Result<(), String> {
    if !units.is_enabled(unit) {
        units.enable(unit)?;
    }
    if units.get_active_state(unit) != "active" {
        units.start(unit)?;
    }
    Ok(())
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

    /// Run one bus interaction with the cached connection, reconnecting
    /// once on failure (the bus may have restarted under us), mirroring
    /// the Python `_ensure_connection` reconnect behavior.
    fn with_connection<T>(
        &self,
        call: impl Fn(&zbus::blocking::Connection) -> Result<T, zbus::Error>,
    ) -> Result<T, zbus::Error> {
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
            match call(connection) {
                Ok(value) => return Ok(value),
                Err(error) => {
                    // Drop the cached connection and retry once on a fresh
                    // one.
                    *guard = None;
                    if attempt == 1 {
                        return Err(error);
                    }
                    tracing::debug!(%error, "D-Bus call failed, reconnecting to the system bus");
                }
            }
        }
        // `attempt` only takes 0 and 1, and the attempt == 1 arm above
        // returns unconditionally, so the loop cannot fall through.
        unreachable!("the retry loop returns on its second pass");
    }

    fn list_units(&self) -> Result<Vec<(String, String)>, zbus::Error> {
        self.with_connection(|connection| {
            let reply = connection.call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.systemd1.Manager"),
                "ListUnits",
                &(),
            )?;
            let units: Vec<ListedUnit> = reply.body().deserialize()?;
            Ok(units.into_iter().map(|unit| (unit.0, unit.3)).collect())
        })
    }

    /// One Manager method taking the unit name plus the "replace" job mode
    /// (StartUnit/StopUnit/RestartUnit).
    fn unit_job(&self, method: &str, unit: &str) -> Result<(), String> {
        self.with_connection(|connection| {
            connection
                .call_method(
                    Some("org.freedesktop.systemd1"),
                    "/org/freedesktop/systemd1",
                    Some("org.freedesktop.systemd1.Manager"),
                    method,
                    &(unit, "replace"),
                )
                .map(|_| ())
        })
        .map_err(|error| format!("{method}({unit}) failed: {error}"))
    }
}

/// The D-Bus error systemd raises for a unit it does not know.
const NO_SUCH_UNIT: &str = "org.freedesktop.systemd1.NoSuchUnit";

fn is_no_such_unit(error: &zbus::Error) -> bool {
    matches!(error, zbus::Error::MethodError(name, _, _) if name.as_str() == NO_SUCH_UNIT)
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

    fn get_active_state(&self, unit: &str) -> String {
        // GetUnit + Properties.Get(ActiveState), like the Python method.
        // NoSuchUnit is a routine outcome (never started, or garbage
        // collected after a clean stop); other errors are "unknown".
        let result = self.with_connection(|connection| {
            let reply = connection.call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.systemd1.Manager"),
                "GetUnit",
                &(unit,),
            )?;
            let unit_path: OwnedObjectPath = reply.body().deserialize()?;
            let reply = connection.call_method(
                Some("org.freedesktop.systemd1"),
                &unit_path,
                Some("org.freedesktop.DBus.Properties"),
                "Get",
                &("org.freedesktop.systemd1.Unit", "ActiveState"),
            )?;
            let state: zbus::zvariant::OwnedValue = reply.body().deserialize()?;
            Ok(String::try_from(state).unwrap_or_default())
        });
        match result {
            Ok(state) => state,
            Err(error) if is_no_such_unit(&error) => {
                tracing::debug!(unit, "unit not loaded");
                "not-loaded".to_string()
            }
            Err(error) => {
                tracing::error!(unit, %error, "D-Bus lookup failed");
                "unknown".to_string()
            }
        }
    }

    fn start(&self, unit: &str) -> Result<(), String> {
        self.unit_job("StartUnit", unit)
    }

    fn stop(&self, unit: &str) -> Result<(), String> {
        self.unit_job("StopUnit", unit)
    }

    fn restart(&self, unit: &str) -> Result<(), String> {
        self.unit_job("RestartUnit", unit)
    }

    fn enable(&self, unit: &str) -> Result<(), String> {
        // EnableUnitFiles(files, runtime=false, force=true), the Python
        // manager.EnableUnitFiles([service], False, True).
        self.with_connection(|connection| {
            connection
                .call_method(
                    Some("org.freedesktop.systemd1"),
                    "/org/freedesktop/systemd1",
                    Some("org.freedesktop.systemd1.Manager"),
                    "EnableUnitFiles",
                    &(vec![unit], false, true),
                )
                .map(|_| ())
        })
        .map_err(|error| format!("EnableUnitFiles({unit}) failed: {error}"))
    }

    fn disable(&self, unit: &str) -> Result<(), String> {
        self.with_connection(|connection| {
            connection
                .call_method(
                    Some("org.freedesktop.systemd1"),
                    "/org/freedesktop/systemd1",
                    Some("org.freedesktop.systemd1.Manager"),
                    "DisableUnitFiles",
                    &(vec![unit], false),
                )
                .map(|_| ())
        })
        .map_err(|error| format!("DisableUnitFiles({unit}) failed: {error}"))
    }

    fn reload(&self) -> Result<(), String> {
        // Manager.Reload(): reread unit files + drop-ins. Applied after a
        // NUMA AllowedCPUs drop-in is written so an already-loaded unit
        // picks it up before start.
        self.with_connection(|connection| {
            connection
                .call_method(
                    Some("org.freedesktop.systemd1"),
                    "/org/freedesktop/systemd1",
                    Some("org.freedesktop.systemd1.Manager"),
                    "Reload",
                    &(),
                )
                .map(|_| ())
        })
        .map_err(|error| format!("Reload() failed: {error}"))
    }

    fn is_enabled(&self, unit: &str) -> bool {
        // GetUnitFileState == "enabled"; any error reads as disabled, like
        // the Python is_service_enabled.
        self.with_connection(|connection| {
            let reply = connection.call_method(
                Some("org.freedesktop.systemd1"),
                "/org/freedesktop/systemd1",
                Some("org.freedesktop.systemd1.Manager"),
                "GetUnitFileState",
                &(unit,),
            )?;
            let state: String = reply.body().deserialize()?;
            Ok(state == "enabled")
        })
        .unwrap_or_else(|error| {
            tracing::error!(unit, %error, "GetUnitFileState failed");
            false
        })
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

    fn get_active_state(&self, unit: &str) -> String {
        match self.states.get(unit) {
            Some(true) => "active".to_string(),
            Some(false) => "inactive".to_string(),
            None => "not-loaded".to_string(),
        }
    }

    fn start(&self, unit: &str) -> Result<(), String> {
        Err(format!("StaticUnitStates cannot start {unit}"))
    }

    fn stop(&self, unit: &str) -> Result<(), String> {
        Err(format!("StaticUnitStates cannot stop {unit}"))
    }

    fn restart(&self, unit: &str) -> Result<(), String> {
        Err(format!("StaticUnitStates cannot restart {unit}"))
    }

    fn enable(&self, unit: &str) -> Result<(), String> {
        Err(format!("StaticUnitStates cannot enable {unit}"))
    }

    fn disable(&self, unit: &str) -> Result<(), String> {
        Err(format!("StaticUnitStates cannot disable {unit}"))
    }

    fn is_enabled(&self, _unit: &str) -> bool {
        false
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

    fn get_active_state(&self, _unit: &str) -> String {
        // Ledger entry 13's taxonomy: a dead bus is "unknown", never a
        // definitive inactive.
        "unknown".to_string()
    }

    fn start(&self, _unit: &str) -> Result<(), String> {
        Err("test bus is unreachable".to_string())
    }

    fn stop(&self, _unit: &str) -> Result<(), String> {
        Err("test bus is unreachable".to_string())
    }

    fn restart(&self, _unit: &str) -> Result<(), String> {
        Err("test bus is unreachable".to_string())
    }

    fn enable(&self, _unit: &str) -> Result<(), String> {
        Err("test bus is unreachable".to_string())
    }

    fn disable(&self, _unit: &str) -> Result<(), String> {
        Err("test bus is unreachable".to_string())
    }

    fn is_enabled(&self, _unit: &str) -> bool {
        false
    }
}

/// Mutable in-memory systemd for lifecycle tests: unit states flip on
/// start/stop/restart, every mutation is recorded in call order (and in
/// the optional shared [`crate::test_fixtures::EventLog`], interleaved
/// with the other fakes' events for cross-seam ordering assertions).
#[derive(Debug, Default)]
pub struct FakeSystemd {
    inner: Mutex<FakeSystemdState>,
    event_log: std::sync::OnceLock<crate::test_fixtures::EventLog>,
}

#[derive(Debug, Default)]
struct FakeSystemdState {
    /// ActiveState per unit; absent units are "not-loaded".
    states: HashMap<String, String>,
    enabled: std::collections::HashSet<String>,
    actions: Vec<String>,
}

impl FakeSystemd {
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark these VM hashes' controller units active (and enabled).
    pub fn with_active_vms(vm_hashes: &[&str]) -> Self {
        let fake = Self::new();
        {
            let mut inner = fake.lock();
            for hash in vm_hashes {
                let unit = controller_unit_name(hash);
                inner.states.insert(unit.clone(), "active".to_string());
                inner.enabled.insert(unit);
            }
        }
        fake
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, FakeSystemdState> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn set_state(&self, unit: &str, state: &str) {
        self.lock().states.insert(unit.into(), state.into());
    }

    /// Every mutation performed so far, e.g. `"start aleph-vm-...service"`.
    pub fn actions(&self) -> Vec<String> {
        self.lock().actions.clone()
    }

    /// Attach a shared chronological event log.
    pub fn set_event_log(&self, log: crate::test_fixtures::EventLog) {
        let _ = self.event_log.set(log);
    }

    fn record_action(&self, action: String) {
        if let Some(log) = self.event_log.get() {
            log.record(&format!("systemd: {action}"));
        }
        self.lock().actions.push(action);
    }
}

impl UnitStateSource for FakeSystemd {
    fn active_states(&self, units: &[String]) -> Result<HashMap<String, bool>, String> {
        let inner = self.lock();
        Ok(units
            .iter()
            .map(|unit| {
                let active = inner.states.get(unit).map(String::as_str) == Some("active");
                (unit.clone(), active)
            })
            .collect())
    }

    fn controller_units(&self) -> Result<HashMap<String, bool>, String> {
        let inner = self.lock();
        Ok(inner
            .states
            .iter()
            .filter(|(name, _)| name.starts_with(CONTROLLER_UNIT_PREFIX))
            .map(|(name, state)| (name.clone(), state == "active"))
            .collect())
    }

    fn get_active_state(&self, unit: &str) -> String {
        self.lock()
            .states
            .get(unit)
            .cloned()
            .unwrap_or_else(|| "not-loaded".to_string())
    }

    fn start(&self, unit: &str) -> Result<(), String> {
        self.record_action(format!("start {unit}"));
        self.lock().states.insert(unit.into(), "active".to_string());
        Ok(())
    }

    fn stop(&self, unit: &str) -> Result<(), String> {
        self.record_action(format!("stop {unit}"));
        self.lock()
            .states
            .insert(unit.into(), "inactive".to_string());
        Ok(())
    }

    fn restart(&self, unit: &str) -> Result<(), String> {
        self.record_action(format!("restart {unit}"));
        self.lock().states.insert(unit.into(), "active".to_string());
        Ok(())
    }

    fn enable(&self, unit: &str) -> Result<(), String> {
        self.record_action(format!("enable {unit}"));
        self.lock().enabled.insert(unit.into());
        Ok(())
    }

    fn disable(&self, unit: &str) -> Result<(), String> {
        self.record_action(format!("disable {unit}"));
        self.lock().enabled.remove(unit);
        Ok(())
    }

    fn is_enabled(&self, unit: &str) -> bool {
        self.lock().enabled.contains(unit)
    }

    fn reload(&self) -> Result<(), String> {
        self.record_action("daemon-reload".to_string());
        Ok(())
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
        assert_eq!(
            source.get_active_state(&controller_unit_name("aa")),
            "unknown"
        );
    }

    #[test]
    fn stop_and_disable_gates_on_active_state_then_enablement() {
        // Python parity: the stop is gated on the unit's ActiveState (a
        // unit can be active without being enabled), the disable on its
        // enablement.
        let fake = FakeSystemd::with_active_vms(&["aa"]);
        let unit = controller_unit_name("aa");
        stop_and_disable(&fake, &unit).unwrap();
        assert_eq!(
            fake.actions(),
            vec![format!("stop {unit}"), format!("disable {unit}")]
        );
        assert_eq!(fake.get_active_state(&unit), "inactive");

        // Already inactive and disabled: nothing happens.
        stop_and_disable(&fake, &unit).unwrap();
        assert_eq!(fake.actions().len(), 2);
    }

    #[test]
    fn enable_and_start_skips_what_is_already_done() {
        let fake = FakeSystemd::new();
        let unit = controller_unit_name("bb");
        enable_and_start(&fake, &unit).unwrap();
        assert_eq!(
            fake.actions(),
            vec![format!("enable {unit}"), format!("start {unit}")]
        );
        assert_eq!(fake.get_active_state(&unit), "active");

        enable_and_start(&fake, &unit).unwrap();
        assert_eq!(fake.actions().len(), 2, "second call is a no-op");
    }
}
