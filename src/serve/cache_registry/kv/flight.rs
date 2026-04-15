use super::*;

pub(crate) fn lookup_flight_key_for_sizes(scoped_keys: &[String]) -> String {
    let mut sorted = scoped_keys.to_vec();
    sorted.sort();
    let digest = crate::cas_file::sha256_hex(sorted.join("\0").as_bytes());
    format!("sizes:{digest}")
}

pub(crate) struct LookupFlightGuard {
    key: String,
    notify: Arc<tokio::sync::Notify>,
    inflight: Arc<dashmap::DashMap<String, Arc<tokio::sync::Notify>>>,
}

impl Drop for LookupFlightGuard {
    fn drop(&mut self) {
        self.inflight.remove(&self.key);
        self.notify.notify_waiters();
    }
}

pub(crate) enum LookupFlight {
    Leader(LookupFlightGuard),
    Follower(std::pin::Pin<Box<tokio::sync::futures::OwnedNotified>>),
}

const FLIGHT_WAIT_WARN_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(1);
const FLIGHT_WAIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

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

pub(crate) fn begin_lookup_flight(state: &AppState, key: String) -> LookupFlight {
    match state.kv_lookup_inflight.entry(key.clone()) {
        dashmap::mapref::entry::Entry::Occupied(existing) => {
            let mut notified = Box::pin(existing.get().clone().notified_owned());
            notified.as_mut().enable();
            LookupFlight::Follower(notified)
        }
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            let notify = Arc::new(tokio::sync::Notify::new());
            entry.insert(notify.clone());
            LookupFlight::Leader(LookupFlightGuard {
                key,
                notify,
                inflight: state.kv_lookup_inflight.clone(),
            })
        }
    }
}

pub(crate) fn clear_lookup_flight_entry(state: &AppState, key: &str) {
    state.kv_lookup_inflight.remove(key);
}
