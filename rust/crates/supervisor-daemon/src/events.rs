//! Lifecycle event fan-out, the engine behind WatchEvents.
//!
//! Python parity (`LocalSupervisor._emit_event` / `watch_events`,
//! src/aleph/vm/supervisor/local.py): every lifecycle transition the daemon
//! itself performs (create/stop/start/reboot/reinstall/delete) is fanned
//! out to every live subscriber; there is no replay (a subscriber joining
//! mid-flight only sees later events; clients snapshot with ListVms first,
//! as the proto documents), and the per-subscriber queue is unbounded,
//! exactly like the Python `asyncio.Queue()` the emitter `put_nowait`s
//! into. Spontaneous guest death is not detected by either daemon today
//! (the proto's documented WatchEvents gap).
//!
//! The timestamp is `time.time_ns()` parity: full nanosecond wall-clock
//! precision, unlike the microsecond-truncated lifecycle stage stamps.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use supervisor_proto::pb;
use tokio::sync::mpsc;

#[derive(Debug, Default)]
pub struct EventHub {
    subscribers: Mutex<Vec<mpsc::UnboundedSender<pb::VmEvent>>>,
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
    fn a_dropped_subscriber_is_pruned() {
        let hub = EventHub::default();
        let receiver = hub.subscribe();
        drop(receiver);
        hub.emit("aa", pb::VmStatus::Defined, pb::VmStatus::Running);
        assert!(hub.lock().is_empty(), "the dead sender was pruned");
    }
}
