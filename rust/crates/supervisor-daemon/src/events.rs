//! Lifecycle event fan-out, the engine behind WatchEvents.
//!
//! Python parity (`LocalSupervisor._emit_event` / `watch_events`): every
//! lifecycle transition the daemon itself performs (create, stop, start,
//! reboot, delete) is fanned out to every live subscriber; there is no
//! replay (a subscriber joining mid-flight only sees later events; clients
//! snapshot with ListVms first, as the proto documents), and the
//! per-subscriber queue is unbounded,
//! exactly like the Python `asyncio.Queue()` the emitter `put_nowait`s
//! into. The one transition no RPC path can announce is spontaneous guest
//! death: nothing calls the daemon when a guest's QEMU exits on its own. The
//! daemon notices it when a status read finds the controller unit dead under
//! a VM it has seen alive, and [`EventHub::observe`] turns that observation
//! into the same event a deliberate stop emits, once per transition.
//!
//! The timestamp is `time.time_ns()` parity: full nanosecond wall-clock
//! precision, unlike the microsecond-truncated lifecycle stage stamps.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use supervisor_proto::pb;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct EventHub {
    subscribers: Mutex<Vec<mpsc::UnboundedSender<pb::VmEvent>>>,
    /// The last status this hub reported for each VM, whether a lifecycle
    /// path announced it or a status read observed it. It is what makes an
    /// observation fire once per transition instead of once per read.
    last_status: Mutex<HashMap<String, pb::VmStatus>>,
}

impl EventHub {
    /// Register a watcher; events emitted from now on arrive on the
    /// receiver. Dropping the receiver unsubscribes (the sender is pruned
    /// on the next emit), the Python `finally: discard(queue)`.
    pub fn subscribe(&self) -> mpsc::UnboundedReceiver<pb::VmEvent> {
        let (sender, receiver) = mpsc::unbounded_channel();
        self.lock().push(sender);
        receiver
    }

    /// Python `_emit_event`: fan one transition out to every watcher.
    pub fn emit(&self, vm_id: &str, old_status: pb::VmStatus, new_status: pb::VmStatus) {
        // Recorded even with nobody listening, and before the early return:
        // an observation must diff against what the lifecycle last did, or
        // the first read after a stop would announce that stop a second
        // time to whoever subscribed in between.
        self.record(vm_id, new_status);
        let mut subscribers = self.lock();
        if subscribers.is_empty() {
            return;
        }
        let event = pb::VmEvent {
            vm_id: vm_id.to_string(),
            old_status: old_status as i32,
            new_status: new_status as i32,
            timestamp_ns: wall_clock_ns(),
        };
        subscribers.retain(|sender| sender.send(event.clone()).is_ok());
    }

    /// Record the status a read just computed, and announce it when it is a
    /// guest that died since the last time this hub reported on the VM.
    ///
    /// Only death is announced. A status read is not an event source: every
    /// other transition either has an RPC path that already emits it, or is
    /// a poll finding what a poll is for. Death has neither, and the agent
    /// needs it to drop the VM's guest-side state and rebuild it rather than
    /// wait out its backstop interval.
    ///
    /// The first status seen for a VM only seeds the map: with no earlier
    /// report there is no transition, and an event would have to invent the
    /// status it came from. A VM already dead when the daemon adopts it is
    /// the agent's next ListVms to find, not an event's.
    pub fn observe(&self, vm_id: &str, status: pb::VmStatus) {
        let previous = self.record(vm_id, status);
        let Some(previous) = previous else {
            return;
        };
        if status == pb::VmStatus::Failed && previous != pb::VmStatus::Failed {
            self.emit(vm_id, previous, status);
        }
    }

    /// Drop a VM's recorded status, so a hash created again after a delete
    /// is not diffed against the life it had before.
    pub fn forget(&self, vm_id: &str) {
        self.last_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(vm_id);
    }

    /// Store `status` as this VM's last reported one, returning the status
    /// it replaces (`None` the first time the hub reports on the VM).
    fn record(&self, vm_id: &str, status: pb::VmStatus) -> Option<pb::VmStatus> {
        self.last_status
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(vm_id.to_string(), status)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<mpsc::UnboundedSender<pb::VmEvent>>> {
        self.subscribers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// `time.time_ns()`: unix nanoseconds, full precision.
fn wall_clock_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
}

#[cfg(test)]
mod tests {
    use pb::VmStatus::{Failed, Running};

    use super::*;

    #[test]
    fn events_fan_out_to_every_subscriber_without_replay() {
        let hub = EventHub::default();
        // Emitted before anyone subscribes: lost, never replayed.
        hub.emit("aa", pb::VmStatus::Defined, pb::VmStatus::Running);

        let mut first = hub.subscribe();
        hub.emit("bb", pb::VmStatus::Running, pb::VmStatus::Stopped);
        let mut second = hub.subscribe();
        hub.emit("cc", pb::VmStatus::Stopped, pb::VmStatus::Running);

        let event = first.try_recv().unwrap();
        assert_eq!(event.vm_id, "bb");
        assert_eq!(event.old_status, pb::VmStatus::Running as i32);
        assert_eq!(event.new_status, pb::VmStatus::Stopped as i32);
        assert_ne!(event.timestamp_ns, 0);
        assert_eq!(first.try_recv().unwrap().vm_id, "cc");
        assert!(first.try_recv().is_err(), "no more events");

        // The late subscriber only sees what came after it joined.
        assert_eq!(second.try_recv().unwrap().vm_id, "cc");
        assert!(second.try_recv().is_err());
    }

    #[test]
    fn an_observed_death_is_announced_exactly_once() {
        // Nothing calls the daemon when a guest's QEMU exits on its own, so
        // the status reads are where the death is noticed. It has to reach
        // the agent as one event, not one per read: the reads are a poll.
        let hub = EventHub::default();
        let mut watcher = hub.subscribe();
        hub.emit("aa", pb::VmStatus::Defined, pb::VmStatus::Running);
        assert_eq!(watcher.try_recv().unwrap().new_status, Running as i32);

        for _ in 0..3 {
            hub.observe("aa", pb::VmStatus::Failed);
        }
        let event = watcher.try_recv().unwrap();
        assert_eq!(event.vm_id, "aa");
        assert_eq!(event.old_status, Running as i32);
        assert_eq!(event.new_status, Failed as i32);
        assert!(watcher.try_recv().is_err(), "one event per transition");

        // It fires again once the VM has been through another life.
        hub.emit("aa", pb::VmStatus::Defined, pb::VmStatus::Running);
        assert_eq!(watcher.try_recv().unwrap().new_status, Running as i32);
        hub.observe("aa", pb::VmStatus::Failed);
        assert_eq!(watcher.try_recv().unwrap().new_status, Failed as i32);
        assert!(watcher.try_recv().is_err());
    }

    #[test]
    fn a_read_is_not_an_event_source() {
        // Only death is announced from a read. Every other transition has an
        // RPC path that emits it, and the first status seen for a VM is a
        // seed: with nothing reported before it, there is no transition and
        // no old status to name.
        let hub = EventHub::default();
        let mut watcher = hub.subscribe();
        hub.observe("aa", pb::VmStatus::Failed);
        assert!(watcher.try_recv().is_err(), "the first read only seeds");

        hub.observe("bb", pb::VmStatus::Booting);
        hub.observe("bb", pb::VmStatus::Running);
        hub.observe("bb", pb::VmStatus::Stopped);
        assert!(
            watcher.try_recv().is_err(),
            "a poll found what a poll is for"
        );

        // A deliberate stop is announced by the path that performed it, and
        // the read that follows must not announce it a second time.
        hub.emit("cc", pb::VmStatus::Running, pb::VmStatus::Stopped);
        assert_eq!(watcher.try_recv().unwrap().vm_id, "cc");
        hub.observe("cc", pb::VmStatus::Stopped);
        assert!(watcher.try_recv().is_err());

        // And a hash created again after a delete is not diffed against the
        // life it had before.
        hub.forget("aa");
        hub.observe("aa", pb::VmStatus::Failed);
        assert!(watcher.try_recv().is_err());
    }

    #[test]
    fn a_dropped_subscriber_is_pruned() {
        let hub = EventHub::default();
        let receiver = hub.subscribe();
        drop(receiver);
        hub.emit("aa", pb::VmStatus::Defined, pb::VmStatus::Running);
        assert!(hub.lock().is_empty(), "the dead sender was pruned");
    }
}
