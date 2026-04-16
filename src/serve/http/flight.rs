use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::Notify;

pub(crate) struct FlightGuard {
    key: String,
    notify: Arc<Notify>,
    inflight: Arc<DashMap<String, Arc<Notify>>>,
}

impl Drop for FlightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

pub(crate) enum Flight {
    Leader(FlightGuard),
    Follower(std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>>),
}

const FLIGHT_WAIT_WARN_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);
const FLIGHT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub(crate) async fn await_flight(
    kind: &str,
    key: &str,
    notified: std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>>,
) -> bool {
    let started = std::time::Instant::now();
    match tokio::time::timeout(FLIGHT_WAIT_TIMEOUT, notified).await {
        Ok(()) => {
            let elapsed = started.elapsed();
            if elapsed >= FLIGHT_WAIT_WARN_THRESHOLD {
                log::warn!(
                    "flight follower waited {}ms: kind={} key={}",
                    elapsed.as_millis(),
                    kind,
                    &key[..key.len().min(24)],
                );
            }
            true
        }
        Err(_) => {
            log::warn!(
                "flight follower timed out after {}ms: kind={} key={}",
                started.elapsed().as_millis(),
                kind,
                &key[..key.len().min(24)],
            );
            false
        }
    }
}

pub(crate) fn begin_flight(inflight: &Arc<DashMap<String, Arc<Notify>>>, key: String) -> Flight {
    match inflight.entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(existing) => {
            let mut notified = Box::pin(existing.get().clone().notified_owned());
            notified.as_mut().enable();
            Flight::Follower(notified)
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            let notify = Arc::new(Notify::new());
            entry.insert(notify.clone());
            Flight::Leader(FlightGuard {
                key,
                notify,
                inflight: inflight.clone(),
            })
        }
    }
}

pub(crate) fn clear_flight_entry(inflight: &Arc<DashMap<String, Arc<Notify>>>, key: &str) {
    inflight.remove(key);
}
