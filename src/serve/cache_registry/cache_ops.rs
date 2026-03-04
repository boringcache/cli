use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::OnceLock;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::kv::KvNamespace;

const BUCKET_SECONDS: u64 = 10;
const DEFAULT_CACHE_OPS_QUEUE_CAPACITY: usize = 32_768;
const MIN_CACHE_OPS_QUEUE_CAPACITY: usize = 1_024;
const MAX_CACHE_OPS_QUEUE_CAPACITY: usize = 262_144;
const CACHE_OPS_BARRIER_TIMEOUT: Duration = Duration::from_millis(200);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Tool {
    Runtime,
    Turborepo,
    Nx,
    Bazel,
    Gradle,
    Maven,
    Sccache,
    GoCache,
    Oci,
}

impl Tool {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Turborepo => "turborepo",
            Self::Nx => "nx",
            Self::Bazel => "bazel",
            Self::Gradle => "gradle",
            Self::Maven => "maven",
            Self::Sccache => "sccache",
            Self::GoCache => "gocache",
            Self::Oci => "oci",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "runtime" => Some(Self::Runtime),
            "turborepo" => Some(Self::Turborepo),
            "nx" => Some(Self::Nx),
            "bazel" => Some(Self::Bazel),
            "gradle" => Some(Self::Gradle),
            "maven" => Some(Self::Maven),
            "sccache" => Some(Self::Sccache),
            "gocache" => Some(Self::GoCache),
            "oci" => Some(Self::Oci),
            _ => None,
        }
    }
}

impl From<KvNamespace> for Tool {
    fn from(ns: KvNamespace) -> Self {
        match ns {
            KvNamespace::Turborepo => Self::Turborepo,
            KvNamespace::Nx | KvNamespace::NxTerminalOutput => Self::Nx,
            KvNamespace::BazelAc | KvNamespace::BazelCas => Self::Bazel,
            KvNamespace::Gradle => Self::Gradle,
            KvNamespace::Maven => Self::Maven,
            KvNamespace::Sccache => Self::Sccache,
            KvNamespace::GoCache => Self::GoCache,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Op {
    Get,
    Put,
    Query,
}

impl Op {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Put => "put",
            Self::Query => "query",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "get" => Some(Self::Get),
            "put" => Some(Self::Put),
            "query" => Some(Self::Query),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum OpResult {
    Hit,
    Miss,
    Error,
}

impl OpResult {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::Miss => "miss",
            Self::Error => "error",
        }
    }

    pub(crate) fn from_str(value: &str) -> Option<Self> {
        match value {
            "hit" => Some(Self::Hit),
            "miss" => Some(Self::Miss),
            "error" => Some(Self::Error),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct BucketKey {
    epoch_secs: u64,
    tool: Tool,
    op: Op,
    result: OpResult,
    degraded: bool,
}

#[derive(Debug, Default)]
struct BucketCounters {
    event_count: u64,
    bytes_total: u64,
    latency_sum_ms: u64,
    latency_count: u64,
}

fn bucket_epoch(now_secs: u64) -> u64 {
    now_secs - (now_secs % BUCKET_SECONDS)
}

fn now_epoch_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[derive(Debug)]
struct MissEntry {
    key_hash: String,
    count: u64,
    sampled_prefix: Option<String>,
}

#[derive(Default)]
struct AggregateState {
    buckets: HashMap<BucketKey, BucketCounters>,
    missed_keys: HashMap<(String, Tool), MissEntry>,
}

enum CacheOpEvent {
    Record {
        epoch_secs: u64,
        tool: Tool,
        op: Op,
        result: OpResult,
        degraded: bool,
        bytes: u64,
        latency_ms: u64,
    },
    Miss {
        tool: Tool,
        raw_key: String,
    },
    Barrier {
        ack: mpsc::Sender<()>,
    },
}

#[derive(Clone)]
pub struct Aggregator {
    state: Arc<Mutex<AggregateState>>,
    queue_tx: Option<Arc<SyncSender<CacheOpEvent>>>,
    queued_events: Arc<AtomicU64>,
    dropped_events: Arc<AtomicU64>,
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl Aggregator {
    pub fn new() -> Self {
        let state = Arc::new(Mutex::new(AggregateState::default()));
        let queued_events = Arc::new(AtomicU64::new(0));
        let dropped_events = Arc::new(AtomicU64::new(0));

        let queue_tx = {
            let (tx, rx) = mpsc::sync_channel(cache_ops_queue_capacity());
            let worker_state = state.clone();
            let worker_queued_events = queued_events.clone();
            match std::thread::Builder::new()
                .name("cache-ops-worker".to_string())
                .spawn(move || {
                    Self::run_worker(rx, worker_state, worker_queued_events);
                }) {
                Ok(_) => Some(Arc::new(tx)),
                Err(error) => {
                    log::warn!("Cache ops worker spawn failed ({error}); using direct mode");
                    None
                }
            }
        };

        Self {
            state,
            queue_tx,
            queued_events,
            dropped_events,
        }
    }

    fn lock_state(&self) -> MutexGuard<'_, AggregateState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_state_arc(state: &Arc<Mutex<AggregateState>>) -> MutexGuard<'_, AggregateState> {
        state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn run_worker(
        rx: mpsc::Receiver<CacheOpEvent>,
        state: Arc<Mutex<AggregateState>>,
        queued_events: Arc<AtomicU64>,
    ) {
        while let Ok(event) = rx.recv() {
            match event {
                CacheOpEvent::Record {
                    epoch_secs,
                    tool,
                    op,
                    result,
                    degraded,
                    bytes,
                    latency_ms,
                } => {
                    let mut guard = Self::lock_state_arc(&state);
                    Self::apply_record_to_state(
                        &mut guard,
                        BucketKey {
                            epoch_secs,
                            tool,
                            op,
                            result,
                            degraded,
                        },
                        bytes,
                        latency_ms,
                    );
                    queued_events.fetch_sub(1, Ordering::AcqRel);
                }
                CacheOpEvent::Miss { tool, raw_key } => {
                    let mut guard = Self::lock_state_arc(&state);
                    Self::apply_miss_to_state(&mut guard, tool, &raw_key);
                    queued_events.fetch_sub(1, Ordering::AcqRel);
                }
                CacheOpEvent::Barrier { ack } => {
                    let _ = ack.send(());
                }
            }
        }
    }

    fn enqueue_event(&self, event: CacheOpEvent) -> Option<CacheOpEvent> {
        let Some(queue_tx) = &self.queue_tx else {
            return Some(event);
        };

        match queue_tx.try_send(event) {
            Ok(()) => {
                self.queued_events.fetch_add(1, Ordering::AcqRel);
                None
            }
            Err(TrySendError::Full(_)) => {
                self.note_dropped_event();
                None
            }
            Err(TrySendError::Disconnected(event)) => Some(event),
        }
    }

    fn note_dropped_event(&self) {
        let dropped = self.dropped_events.fetch_add(1, Ordering::AcqRel) + 1;
        if dropped == 1 || dropped.is_multiple_of(1_000) {
            log::warn!("Cache ops queue saturated; dropped {dropped} analytics events");
        }
    }

    fn flush_async_events(&self) {
        if self.queued_events.load(Ordering::Acquire) == 0 {
            return;
        }
        let Some(queue_tx) = &self.queue_tx else {
            return;
        };

        let deadline = std::time::Instant::now() + CACHE_OPS_BARRIER_TIMEOUT;
        loop {
            let (ack_tx, ack_rx) = mpsc::channel();
            match queue_tx.try_send(CacheOpEvent::Barrier { ack: ack_tx }) {
                Ok(()) => {
                    let _ = ack_rx.recv_timeout(CACHE_OPS_BARRIER_TIMEOUT);
                    return;
                }
                Err(TrySendError::Full(_)) => {
                    if std::time::Instant::now() >= deadline {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(TrySendError::Disconnected(_)) => return,
            }
        }
    }

    fn apply_event_direct(&self, event: CacheOpEvent) {
        let mut guard = self.lock_state();
        match event {
            CacheOpEvent::Record {
                epoch_secs,
                tool,
                op,
                result,
                degraded,
                bytes,
                latency_ms,
            } => {
                Self::apply_record_to_state(
                    &mut guard,
                    BucketKey {
                        epoch_secs,
                        tool,
                        op,
                        result,
                        degraded,
                    },
                    bytes,
                    latency_ms,
                );
            }
            CacheOpEvent::Miss { tool, raw_key } => {
                Self::apply_miss_to_state(&mut guard, tool, &raw_key);
            }
            CacheOpEvent::Barrier { .. } => {}
        }
    }

    fn apply_record_to_state(
        state: &mut AggregateState,
        key: BucketKey,
        bytes: u64,
        latency_ms: u64,
    ) {
        let counters = state.buckets.entry(key).or_default();

        counters.event_count = counters.event_count.saturating_add(1);
        counters.bytes_total = counters.bytes_total.saturating_add(bytes);
        if latency_ms > 0 {
            counters.latency_sum_ms = counters.latency_sum_ms.saturating_add(latency_ms);
            counters.latency_count = counters.latency_count.saturating_add(1);
        }
    }

    fn apply_miss_to_state(state: &mut AggregateState, tool: Tool, raw_key: &str) {
        let key_hash = crate::cas_oci::sha256_hex(raw_key.as_bytes());
        let map_key = (key_hash.clone(), tool);
        let prefix = raw_key.get(..32).unwrap_or(raw_key).to_string();

        state
            .missed_keys
            .entry(map_key)
            .and_modify(|entry| {
                entry.count = entry.count.saturating_add(1);
            })
            .or_insert(MissEntry {
                key_hash,
                count: 1,
                sampled_prefix: Some(prefix),
            });
    }

    pub(crate) fn record(
        &self,
        tool: Tool,
        op: Op,
        result: OpResult,
        degraded: bool,
        bytes: u64,
        latency_ms: u64,
    ) {
        let event = CacheOpEvent::Record {
            epoch_secs: bucket_epoch(now_epoch_secs()),
            tool,
            op,
            result,
            degraded,
            bytes,
            latency_ms,
        };
        if let Some(event) = self.enqueue_event(event) {
            self.apply_event_direct(event);
        }
    }

    pub(crate) fn restore(&self, rollups: Vec<RollupRecord>, missed_keys: Vec<MissedKeyRecord>) {
        self.flush_async_events();
        let mut state = self.lock_state();

        for rollup in rollups {
            let Some(tool) = Tool::from_str(&rollup.tool) else {
                continue;
            };
            let Some(op) = Op::from_str(&rollup.operation) else {
                continue;
            };
            let Some(result) = OpResult::from_str(&rollup.result) else {
                continue;
            };

            let key = BucketKey {
                epoch_secs: rollup.bucket_epoch_secs,
                tool,
                op,
                result,
                degraded: rollup.degraded,
            };

            let counters = state.buckets.entry(key).or_default();
            counters.event_count = counters.event_count.saturating_add(rollup.event_count);
            counters.bytes_total = counters.bytes_total.saturating_add(rollup.bytes_total);
            counters.latency_sum_ms = counters
                .latency_sum_ms
                .saturating_add(rollup.latency_sum_ms);
            counters.latency_count = counters.latency_count.saturating_add(rollup.latency_count);
        }

        for miss in missed_keys {
            let Some(tool) = Tool::from_str(&miss.tool) else {
                continue;
            };

            state
                .missed_keys
                .entry((miss.key_hash.clone(), tool))
                .and_modify(|entry| {
                    entry.count = entry.count.saturating_add(miss.miss_count);
                    if entry.sampled_prefix.is_none() {
                        entry.sampled_prefix = miss.sampled_key_prefix.clone();
                    }
                })
                .or_insert(MissEntry {
                    key_hash: miss.key_hash,
                    count: miss.miss_count,
                    sampled_prefix: miss.sampled_key_prefix,
                });
        }
    }

    pub(crate) fn record_miss(&self, tool: Tool, raw_key: &str) {
        if tool == Tool::Sccache && !track_sccache_miss_keys_enabled() {
            return;
        }
        let event = CacheOpEvent::Miss {
            tool,
            raw_key: raw_key.to_string(),
        };
        if let Some(event) = self.enqueue_event(event) {
            self.apply_event_direct(event);
        }
    }

    pub(crate) fn drain(&self) -> (Vec<RollupRecord>, Vec<MissedKeyRecord>) {
        self.flush_async_events();
        let mut state = self.lock_state();

        let drained_buckets = std::mem::take(&mut state.buckets);
        let mut rollups = Vec::with_capacity(drained_buckets.len());
        for (key, counters) in drained_buckets {
            if counters.event_count == 0 {
                continue;
            }
            rollups.push(RollupRecord {
                bucket_epoch_secs: key.epoch_secs,
                tool: key.tool.as_str().to_string(),
                operation: key.op.as_str().to_string(),
                result: key.result.as_str().to_string(),
                degraded: key.degraded,
                event_count: counters.event_count,
                bytes_total: counters.bytes_total,
                latency_sum_ms: counters.latency_sum_ms,
                latency_count: counters.latency_count,
            });
        }

        let drained_missed_keys = std::mem::take(&mut state.missed_keys);
        let mut missed = Vec::with_capacity(drained_missed_keys.len());
        for ((_, tool), entry) in drained_missed_keys {
            missed.push(MissedKeyRecord {
                key_hash: entry.key_hash,
                tool: tool.as_str().to_string(),
                miss_count: entry.count,
                sampled_key_prefix: entry.sampled_prefix,
            });
        }

        (rollups, missed)
    }

    pub(crate) fn is_empty(&self) -> bool {
        if self.queued_events.load(Ordering::Acquire) > 0 {
            return false;
        }
        let state = self.lock_state();
        state.buckets.is_empty() && state.missed_keys.is_empty()
    }

    pub(crate) fn queue_depth(&self) -> u64 {
        self.queued_events.load(Ordering::Acquire)
    }

    pub(crate) fn dropped_events_total(&self) -> u64 {
        self.dropped_events.load(Ordering::Acquire)
    }
}

fn cache_ops_queue_capacity() -> usize {
    std::env::var("BORINGCACHE_CACHE_OPS_QUEUE_CAPACITY")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .map(|value| value.clamp(MIN_CACHE_OPS_QUEUE_CAPACITY, MAX_CACHE_OPS_QUEUE_CAPACITY))
        .unwrap_or(DEFAULT_CACHE_OPS_QUEUE_CAPACITY)
}

fn track_sccache_miss_keys_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("BORINGCACHE_CACHE_OPS_TRACK_SCCACHE_MISSES")
            .ok()
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    })
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct RollupRecord {
    pub bucket_epoch_secs: u64,
    pub tool: String,
    pub operation: String,
    pub result: String,
    pub degraded: bool,
    pub event_count: u64,
    pub bytes_total: u64,
    pub latency_sum_ms: u64,
    pub latency_count: u64,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct MissedKeyRecord {
    pub key_hash: String,
    pub tool: String,
    pub miss_count: u64,
    pub sampled_key_prefix: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_epoch_aligns_to_10_seconds() {
        assert_eq!(bucket_epoch(0), 0);
        assert_eq!(bucket_epoch(9), 0);
        assert_eq!(bucket_epoch(10), 10);
        assert_eq!(bucket_epoch(19), 10);
        assert_eq!(bucket_epoch(100), 100);
        assert_eq!(bucket_epoch(107), 100);
    }

    #[test]
    fn record_and_drain() {
        let agg = Aggregator::new();
        agg.record(Tool::Turborepo, Op::Get, OpResult::Hit, false, 1024, 5);
        agg.record(Tool::Turborepo, Op::Get, OpResult::Hit, false, 2048, 10);
        agg.record(Tool::Nx, Op::Put, OpResult::Hit, false, 512, 3);

        assert!(!agg.is_empty());

        let (rollups, missed) = agg.drain();
        assert!(agg.is_empty());
        assert!(missed.is_empty());
        assert!(!rollups.is_empty());

        let turbo = rollups
            .iter()
            .find(|r| r.tool == "turborepo")
            .expect("turborepo rollup");
        assert_eq!(turbo.event_count, 2);
        assert_eq!(turbo.bytes_total, 3072);
        assert_eq!(turbo.latency_sum_ms, 15);
        assert_eq!(turbo.latency_count, 2);
        assert_eq!(turbo.operation, "get");
        assert_eq!(turbo.result, "hit");
        assert!(!turbo.degraded);

        let nx = rollups.iter().find(|r| r.tool == "nx").expect("nx rollup");
        assert_eq!(nx.event_count, 1);
    }

    #[test]
    fn runtime_tool_round_trip() {
        assert_eq!(Tool::Runtime.as_str(), "runtime");
        assert_eq!(Tool::from_str("runtime"), Some(Tool::Runtime));
    }

    #[test]
    fn record_miss_deduplicates_by_key_hash() {
        let agg = Aggregator::new();
        agg.record_miss(Tool::Turborepo, "some-cache-key");
        agg.record_miss(Tool::Turborepo, "some-cache-key");
        agg.record_miss(Tool::Turborepo, "other-key");

        let (_, missed) = agg.drain();
        assert_eq!(missed.len(), 2);

        let some_key = missed
            .iter()
            .find(|m| m.miss_count == 2)
            .expect("deduplicated miss");
        assert_eq!(some_key.tool, "turborepo");
        assert!(some_key.sampled_key_prefix.is_some());
    }

    #[test]
    fn drain_clears_state() {
        let agg = Aggregator::new();
        agg.record(Tool::Bazel, Op::Get, OpResult::Miss, false, 0, 1);
        agg.record_miss(Tool::Bazel, "key");

        let (rollups, missed) = agg.drain();
        assert_eq!(rollups.len(), 1);
        assert_eq!(missed.len(), 1);
        assert!(agg.is_empty());

        let (rollups2, missed2) = agg.drain();
        assert!(rollups2.is_empty());
        assert!(missed2.is_empty());
    }

    #[test]
    fn degraded_events_separate_from_normal() {
        let agg = Aggregator::new();
        agg.record(Tool::Turborepo, Op::Get, OpResult::Hit, false, 100, 5);
        agg.record(Tool::Turborepo, Op::Get, OpResult::Hit, true, 100, 5);

        let (rollups, _) = agg.drain();
        assert_eq!(rollups.len(), 2);

        let normal = rollups.iter().find(|r| !r.degraded).unwrap();
        let degraded = rollups.iter().find(|r| r.degraded).unwrap();
        assert_eq!(normal.event_count, 1);
        assert_eq!(degraded.event_count, 1);
    }

    #[test]
    fn namespace_to_tool_mapping() {
        assert_eq!(Tool::from(KvNamespace::Turborepo), Tool::Turborepo);
        assert_eq!(Tool::from(KvNamespace::Nx), Tool::Nx);
        assert_eq!(Tool::from(KvNamespace::NxTerminalOutput), Tool::Nx);
        assert_eq!(Tool::from(KvNamespace::BazelAc), Tool::Bazel);
        assert_eq!(Tool::from(KvNamespace::BazelCas), Tool::Bazel);
        assert_eq!(Tool::from(KvNamespace::Gradle), Tool::Gradle);
        assert_eq!(Tool::from(KvNamespace::Maven), Tool::Maven);
        assert_eq!(Tool::from(KvNamespace::Sccache), Tool::Sccache);
        assert_eq!(Tool::from(KvNamespace::GoCache), Tool::GoCache);
        assert_eq!(Tool::from_str("oci"), Some(Tool::Oci));
    }

    #[test]
    fn restore_replays_drained_records() {
        let agg = Aggregator::new();
        agg.record(Tool::Turborepo, Op::Get, OpResult::Hit, false, 100, 5);
        agg.record_miss(Tool::Turborepo, "cache-key");
        let (rollups, missed) = agg.drain();

        assert!(agg.is_empty());
        agg.restore(rollups.clone(), missed.clone());
        assert!(!agg.is_empty());

        let (restored_rollups, restored_missed) = agg.drain();
        assert_eq!(restored_rollups.len(), rollups.len());
        assert_eq!(restored_missed.len(), missed.len());

        let restored_turbo = restored_rollups
            .iter()
            .find(|r| r.tool == "turborepo")
            .expect("restored turborepo rollup");
        assert_eq!(restored_turbo.event_count, 1);
        assert_eq!(restored_turbo.bytes_total, 100);
        assert_eq!(restored_turbo.latency_sum_ms, 5);

        let restored_miss = restored_missed
            .iter()
            .find(|r| r.tool == "turborepo")
            .expect("restored miss");
        assert_eq!(restored_miss.miss_count, 1);
    }
}
