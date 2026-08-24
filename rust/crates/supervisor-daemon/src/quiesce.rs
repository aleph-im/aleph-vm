//! Guest quiescence (FreezeGuest / ThawGuest), the supervisor's only part in
//! a backup, a port of `LocalSupervisor.freeze_guest` / `thaw_guest`
//! (src/aleph/vm/supervisor/local.py).
//!
//! The agent owns the archives: it created the disks, so it copies, stores,
//! expires and restores them. What it cannot do from outside the VM is
//! quiesce the guest, so it asks the daemon to freeze the guest filesystems
//! through the QEMU guest agent around its copy and to thaw them afterwards.
//! Best effort: a guest without an agent (or a stopped VM) answers "not
//! frozen" and the copy proceeds crash-consistent. A freeze is auto-thawed
//! after `GUEST_FREEZE_TIMEOUT` (the service spawns the timer) so an agent
//! that dies mid-copy cannot leave a guest with its filesystems frozen.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::lifecycle::RpcError;
use crate::service::DaemonState;

/// The guests frozen through [`freeze_guest`], each with the QGA socket that
/// froze it and the generation its auto-thaw timer was armed with.
#[derive(Default)]
pub struct FrozenGuests {
    inner: Mutex<HashMap<String, FrozenGuest>>,
    next_generation: Mutex<u64>,
}

struct FrozenGuest {
    qga_socket: PathBuf,
    generation: u64,
}

impl FrozenGuests {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, FrozenGuest>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn next_generation(&self) -> u64 {
        let mut next = self
            .next_generation
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *next += 1;
        *next
    }

    /// True while the guest is frozen (a test seam).
    pub fn is_frozen(&self, vm_id: &str) -> bool {
        self.lock().contains_key(vm_id)
    }

    /// Drop the record of a VM that is gone (DeleteVm): there is no guest
    /// left to thaw, and a stale entry must not shadow a future freeze of a
    /// recreated VM with the same hash.
    pub fn forget(&self, vm_id: &str) {
        self.lock().remove(vm_id);
    }
}

/// What a FreezeGuest call did; the service arms the auto-thaw timer only
/// for a freeze it performed (an idempotent repeat keeps the first timer).
#[derive(Debug, PartialEq, Eq)]
pub enum FreezeOutcome {
    /// No guest agent, or the VM is not running: nothing is frozen.
    NotFrozen,
    /// A freeze was already in place; its timer stands.
    AlreadyFrozen,
    /// This call froze the guest; the value is the generation to arm the
    /// auto-thaw timer with.
    Frozen(u64),
}

impl FreezeOutcome {
    pub fn frozen(&self) -> bool {
        !matches!(self, FreezeOutcome::NotFrozen)
    }
}

/// `LocalSupervisor.freeze_guest`: freeze the guest filesystems through the
/// QEMU guest agent. Best effort: `NotFrozen` when the guest agent is
/// unavailable or the VM is not running. Idempotent while frozen.
pub fn freeze_guest(state: &DaemonState, vm_id: &str) -> Result<FreezeOutcome, RpcError> {
    let entry = crate::lifecycle::entry_snapshot(state, vm_id)
        .ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    if state.frozen_guests.is_frozen(vm_id) {
        return Ok(FreezeOutcome::AlreadyFrozen);
    }
    if !crate::lifecycle::entry_running(state, &entry) {
        tracing::info!(vm_id, "Not freezing: not running");
        return Ok(FreezeOutcome::NotFrozen);
    }
    let Some(qga_socket) = entry.config.qga_socket_path.as_deref().map(PathBuf::from) else {
        tracing::warn!(vm_id, "fsfreeze unavailable, no guest agent socket");
        return Ok(FreezeOutcome::NotFrozen);
    };
    match crate::qmp::qga_fsfreeze_freeze(&qga_socket) {
        Ok(count) => {
            tracing::info!(vm_id, frozen = count, "Froze filesystem(s)");
        }
        Err(error) => {
            tracing::warn!(vm_id, %error, "fsfreeze unavailable, proceeding without");
            return Ok(FreezeOutcome::NotFrozen);
        }
    }
    let generation = state.frozen_guests.next_generation();
    state.frozen_guests.lock().insert(
        vm_id.to_string(),
        FrozenGuest {
            qga_socket,
            generation,
        },
    );
    Ok(FreezeOutcome::Frozen(generation))
}

/// `LocalSupervisor.thaw_guest`: thaw a guest frozen by [`freeze_guest`]; a
/// no-op when nothing is frozen (including after the auto-thaw fired).
pub fn thaw_guest(state: &DaemonState, vm_id: &str) -> Result<(), RpcError> {
    crate::lifecycle::entry_snapshot(state, vm_id)
        .ok_or_else(|| RpcError::NotFound(vm_id.into()))?;
    let frozen = state.frozen_guests.lock().remove(vm_id);
    if let Some(frozen) = frozen {
        try_fsthaw(&frozen.qga_socket, vm_id);
    }
    Ok(())
}

/// The freeze deadline: thaw the guest if the freeze of `generation` is still
/// in place (a later freeze, or a thaw already done, leaves it alone).
pub fn auto_thaw(state: &DaemonState, vm_id: &str, generation: u64, timeout_secs: f64) {
    let frozen = {
        let mut guests = state.frozen_guests.lock();
        match guests.get(vm_id) {
            Some(frozen) if frozen.generation == generation => guests.remove(vm_id),
            _ => None,
        }
    };
    if let Some(frozen) = frozen {
        tracing::warn!(
            vm_id,
            timeout_secs,
            "Guest was still frozen after the timeout without a ThawGuest; thawing it"
        );
        try_fsthaw(&frozen.qga_socket, vm_id);
    }
}

/// `_try_fsthaw`: best-effort thaw; a failure is logged, never fatal.
fn try_fsthaw(qga_socket: &std::path::Path, vm_id: &str) {
    if let Err(error) = crate::qmp::qga_fsfreeze_thaw(qga_socket) {
        tracing::error!(vm_id, %error, "Failed to thaw filesystems");
    }
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use std::thread;

    use serde_json::Value;

    use super::*;
    use crate::service::HostState;
    use crate::units::StaticUnitStates;
    use crate::world::{VmEntry, WorldView};

    const VM: &str = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";

    type RecordedRequests = Arc<Mutex<Vec<Value>>>;

    /// A fake QGA server answering every request with `{"return": 1}` and
    /// recording the commands, for as many connections as the test opens.
    fn fake_qga_server(dir: &Path) -> (PathBuf, RecordedRequests) {
        let socket_path = dir.join("qga.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let requests: RecordedRequests = Arc::new(Mutex::new(Vec::new()));
        let recorder = requests.clone();
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_err() || line.is_empty() {
                    continue;
                }
                let request: Value = serde_json::from_str(line.trim()).unwrap();
                recorder.lock().unwrap().push(request);
                let _ = writer.write_all(b"{\"return\": 1}\n");
            }
        });
        (socket_path, requests)
    }

    fn commands(requests: &RecordedRequests) -> Vec<String> {
        requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request["execute"].as_str().unwrap().to_string())
            .collect()
    }

    fn state_with(entry: VmEntry, running: bool) -> DaemonState {
        let tmp = tempfile::tempdir().unwrap();
        let settings = crate::config::Settings::from_vars(
            [(
                "ALEPH_VM_EXECUTION_ROOT".to_string(),
                tmp.path().to_string_lossy().into_owned(),
            )]
            .into_iter(),
        )
        .unwrap();
        let host = HostState {
            settings,
            host_ipv4: String::new(),
            network_interface: None,
            gpus: Vec::new(),
            dns_nameservers: None,
        };
        let units = if running {
            StaticUnitStates::with_active_vms(&[VM])
        } else {
            StaticUnitStates::default()
        };
        let mut world = WorldView::default();
        world.insert_entry(entry);
        // The tempdir must outlive the state: leak it for the test's
        // lifetime (the process exits right after).
        std::mem::forget(tmp);
        DaemonState::hermetic(
            host,
            world,
            Arc::new(units),
            Arc::new(crate::logs::StaticLogSource::default()),
        )
    }

    fn entry_with_qga(qga_socket: Option<&Path>) -> VmEntry {
        let mut entry = VmEntry::test_qemu(VM, "/tmp/rootfs.qcow2");
        entry.config.qga_socket_path = qga_socket.map(|path| path.to_string_lossy().into_owned());
        entry
    }

    #[test]
    fn unknown_vm_is_not_found() {
        let state = state_with(entry_with_qga(None), true);
        assert!(matches!(
            freeze_guest(&state, "missing"),
            Err(RpcError::NotFound(_))
        ));
        assert!(matches!(
            thaw_guest(&state, "missing"),
            Err(RpcError::NotFound(_))
        ));
    }

    #[test]
    fn freeze_then_thaw_drives_the_guest_agent() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qga_server(dir.path());
        let state = state_with(entry_with_qga(Some(&socket)), true);

        let outcome = freeze_guest(&state, VM).unwrap();
        assert!(matches!(outcome, FreezeOutcome::Frozen(_)));
        assert!(outcome.frozen());
        assert!(state.frozen_guests.is_frozen(VM));

        // Idempotent while frozen: no second QGA freeze, the timer stands.
        assert_eq!(
            freeze_guest(&state, VM).unwrap(),
            FreezeOutcome::AlreadyFrozen
        );

        thaw_guest(&state, VM).unwrap();
        assert!(!state.frozen_guests.is_frozen(VM));
        assert_eq!(
            commands(&requests),
            vec!["guest-fsfreeze-freeze", "guest-fsfreeze-thaw"]
        );

        // A thaw of an unfrozen guest is a no-op, not a second QGA thaw.
        thaw_guest(&state, VM).unwrap();
        assert_eq!(commands(&requests).len(), 2);
    }

    #[test]
    fn no_guest_agent_socket_is_not_frozen() {
        let state = state_with(entry_with_qga(None), true);
        assert_eq!(freeze_guest(&state, VM).unwrap(), FreezeOutcome::NotFrozen);
        assert!(!state.frozen_guests.is_frozen(VM));
    }

    #[test]
    fn unreachable_guest_agent_is_not_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let state = state_with(entry_with_qga(Some(&dir.path().join("absent.sock"))), true);
        assert_eq!(freeze_guest(&state, VM).unwrap(), FreezeOutcome::NotFrozen);
    }

    #[test]
    fn a_stopped_vm_is_not_frozen() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qga_server(dir.path());
        let state = state_with(entry_with_qga(Some(&socket)), false);
        assert_eq!(freeze_guest(&state, VM).unwrap(), FreezeOutcome::NotFrozen);
        assert!(commands(&requests).is_empty());
    }

    #[test]
    fn auto_thaw_releases_only_its_own_generation() {
        let dir = tempfile::tempdir().unwrap();
        let (socket, requests) = fake_qga_server(dir.path());
        let state = state_with(entry_with_qga(Some(&socket)), true);

        let FreezeOutcome::Frozen(first) = freeze_guest(&state, VM).unwrap() else {
            panic!("the first freeze must freeze");
        };
        // The agent thawed and froze again before the first timer fired.
        thaw_guest(&state, VM).unwrap();
        let FreezeOutcome::Frozen(second) = freeze_guest(&state, VM).unwrap() else {
            panic!("the second freeze must freeze");
        };
        assert_ne!(first, second);

        // The stale timer leaves the newer freeze alone.
        auto_thaw(&state, VM, first, 0.0);
        assert!(state.frozen_guests.is_frozen(VM));
        // The live timer thaws it.
        auto_thaw(&state, VM, second, 0.0);
        assert!(!state.frozen_guests.is_frozen(VM));
        assert_eq!(
            commands(&requests),
            vec![
                "guest-fsfreeze-freeze",
                "guest-fsfreeze-thaw",
                "guest-fsfreeze-freeze",
                "guest-fsfreeze-thaw"
            ]
        );
    }
}
