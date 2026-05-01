use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use super::kv::KvNamespace;
use crate::observability;

const BUCKET_SECONDS: u64 = 10;
const SESSION_IDLE_SECS: u64 = 10;
const SESSION_TOP_MISSED_KEYS: usize = 5;
const SCCACHE_MISS_SAMPLE_MASK: u64 = 0x0F;
const SCCACHE_MISSED_KEY_CAP: usize = 2_048;
const SCCACHE_SESSION_MISSED_KEY_CAP: usize = 256;
const DEFAULT_CACHE_OPS_QUEUE_CAPACITY: usize = 32_768;
const MIN_CACHE_OPS_QUEUE_CAPACITY: usize = 1_024;
const MAX_CACHE_OPS_QUEUE_CAPACITY: usize = 262_144;
const CACHE_OPS_BARRIER_TIMEOUT: Duration = Duration::from_millis(200);
const CACHE_OPS_OBSERVABILITY_ENV: &str = "BORINGCACHE_OBSERVABILITY_INCLUDE_CACHE_OPS";
const CACHE_OPS_OBSERVABILITY_SOURCE: &str = "serve";
const CACHE_OPS_OBSERVABILITY_PATH: &str = "/serve/cache_registry/cache-ops";
const CACHE_OPS_OBSERVABILITY_RECORD_OP: &str = "cache_ops_record";
const CACHE_OPS_OBSERVABILITY_MISS_OP: &str = "cache_ops_miss";
const CACHE_OPS_OBSERVABILITY_CONNECT_OP: &str = "cache_ops_session_connect";

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
            KvNamespace::Turborepo | KvNamespace::TurborepoMeta => Self::Turborepo,
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BucketKey {
    epoch_secs: u64,
    session_id: String,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OperationTotalKey {
    tool: Tool,
    op: Op,
    result: OpResult,
    degraded: bool,
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

#[derive(Debug)]
struct SessionMissEntry {
    key_hash: String,
    count: u64,
    sampled_prefix: Option<String>,
}

#[derive(Debug)]
struct SessionState {
    id: String,
    tool: Tool,
    started_at_secs: u64,
    last_event_secs: u64,
    hit_count: u64,
    miss_count: u64,
    error_count: u64,
    bytes_read: u64,
    bytes_written: u64,
    metadata_hints: BTreeMap<String, String>,
    missed_keys: HashMap<String, SessionMissEntry>,
}

#[derive(Default)]
struct AggregateState {
    buckets: HashMap<BucketKey, BucketCounters>,
    operation_totals: HashMap<OperationTotalKey, BucketCounters>,
    missed_keys: HashMap<(String, Tool), MissEntry>,
    missed_key_cardinality: HashMap<Tool, usize>,
    active_sessions: HashMap<Tool, SessionState>,
    completed_sessions: Vec<SessionRecord>,
    next_session_seq: HashMap<Tool, u64>,
    session_metadata_hints: BTreeMap<String, String>,
}

impl SessionState {
    fn new(
        id: String,
        tool: Tool,
        started_at_secs: u64,
        metadata_hints: BTreeMap<String, String>,
    ) -> Self {
        Self {
            id,
            tool,
            started_at_secs,
            last_event_secs: started_at_secs,
            hit_count: 0,
            miss_count: 0,
            error_count: 0,
            bytes_read: 0,
            bytes_written: 0,
            metadata_hints,
            missed_keys: HashMap::new(),
        }
    }

    fn record_event(&mut self, op: Op, result: OpResult, degraded: bool, bytes: u64) {
        match (op, result, degraded) {
            (Op::Get, OpResult::Hit, _) => self.hit_count = self.hit_count.saturating_add(1),
            (Op::Get, OpResult::Miss, _) => self.miss_count = self.miss_count.saturating_add(1),
            (Op::Get, OpResult::Error, true) => self.miss_count = self.miss_count.saturating_add(1),
            (_, OpResult::Error, _) => self.error_count = self.error_count.saturating_add(1),
            _ => {}
        }

        if result == OpResult::Hit {
            match op {
                Op::Get => self.bytes_read = self.bytes_read.saturating_add(bytes),
                Op::Put => self.bytes_written = self.bytes_written.saturating_add(bytes),
                Op::Query => {}
            }
        }
    }

    fn into_record(mut self, ended_at_secs: u64) -> SessionRecord {
        let ended_at = ended_at_secs.max(self.last_event_secs);
        self.last_event_secs = ended_at;
        let session_duration_ms = ended_at
            .saturating_sub(self.started_at_secs)
            .saturating_mul(1000);

        let mut top_missed_keys: Vec<SessionMissedKeyRecord> = self
            .missed_keys
            .drain()
            .map(|(_, entry)| SessionMissedKeyRecord {
                key_hash: entry.key_hash,
                miss_count: entry.count,
                sampled_key_prefix: entry.sampled_prefix,
            })
            .collect();
        top_missed_keys.sort_by(|left, right| {
            right
                .miss_count
                .cmp(&left.miss_count)
                .then_with(|| left.key_hash.cmp(&right.key_hash))
        });
        top_missed_keys.truncate(SESSION_TOP_MISSED_KEYS);

        SessionRecord {
            session_id: self.id,
            tool: self.tool.as_str().to_string(),
            session_duration_ms,
            hit_count: self.hit_count,
            miss_count: self.miss_count,
            error_count: self.error_count,
            bytes_read: self.bytes_read,
            bytes_written: self.bytes_written,
            metadata_hints: self.metadata_hints,
            top_missed_keys,
        }
    }
}

enum CacheOpEvent {
    Record(RecordEvent),
    Miss {
        event_epoch_secs: u64,
        tool: Tool,
        raw_key: String,
    },
    SessionConnect {
        event_epoch_secs: u64,
        tool: Tool,
    },
    Barrier {
        ack: mpsc::Sender<()>,
    },
}

#[derive(Debug, Clone, Copy)]
struct RecordEvent {
    event_epoch_secs: u64,
    tool: Tool,
    op: Op,
    result: OpResult,
    degraded: bool,
    bytes: u64,
    latency_ms: u64,
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
        Self::new_with_metadata_hints(BTreeMap::new())
    }

    pub fn new_with_metadata_hints(metadata_hints: BTreeMap<String, String>) -> Self {
        let state = Arc::new(Mutex::new(AggregateState {
            session_metadata_hints: metadata_hints,
            ..AggregateState::default()
        }));
        let queued_events = Arc::new(AtomicU64::new(0));
        let dropped_events = Arc::new(AtomicU64::new(0));

        let queue_tx = {
            let (tx, rx) = mpsc::sync_channel(cache_ops_queue_capacity());
            let worker_state = state.clone();
            let worker_queued_events = queued_events.clone();
            let spawn_result = std::thread::Builder::new()
                .name("cache-ops-worker".to_string())
                .spawn(move || {
                    Self::run_worker(rx, worker_state, worker_queued_events);
                });
            match spawn_result {
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

    pub fn merge_session_metadata_hints(&self, metadata_hints: BTreeMap<String, String>) {
        if metadata_hints.is_empty() {
            return;
        }
        self.flush_async_events();
        let mut state = self.lock_state();
        for (key, value) in metadata_hints {
            state
                .session_metadata_hints
                .insert(key.clone(), value.clone());
            for session in state.active_sessions.values_mut() {
                session.metadata_hints.insert(key.clone(), value.clone());
            }
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
        loop {
            let next_event = rx.recv();
            let Ok(event) = next_event else {
                break;
            };
            match event {
                CacheOpEvent::Record(record) => {
                    let mut guard = Self::lock_state_arc(&state);
                    Self::apply_record_event(&mut guard, record);
                    queued_events.fetch_sub(1, Ordering::AcqRel);
                }
                CacheOpEvent::Miss {
                    event_epoch_secs,
                    tool,
                    raw_key,
                } => {
                    let mut guard = Self::lock_state_arc(&state);
                    Self::apply_miss_event(&mut guard, event_epoch_secs, tool, &raw_key);
                    queued_events.fetch_sub(1, Ordering::AcqRel);
                }
                CacheOpEvent::SessionConnect {
                    event_epoch_secs,
                    tool,
                } => {
                    let mut guard = Self::lock_state_arc(&state);
                    Self::apply_session_connect_event(&mut guard, event_epoch_secs, tool);
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
            let send_result = queue_tx.try_send(CacheOpEvent::Barrier { ack: ack_tx });
            match send_result {
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
            CacheOpEvent::Record(record) => Self::apply_record_event(&mut guard, record),
            CacheOpEvent::Miss {
                event_epoch_secs,
                tool,
                raw_key,
            } => {
                Self::apply_miss_event(&mut guard, event_epoch_secs, tool, &raw_key);
            }
            CacheOpEvent::SessionConnect {
                event_epoch_secs,
                tool,
            } => Self::apply_session_connect_event(&mut guard, event_epoch_secs, tool),
            CacheOpEvent::Barrier { .. } => {}
        }
    }

    fn apply_record_event(state: &mut AggregateState, event: RecordEvent) {
        Self::close_idle_sessions_for_tool(state, event.tool, event.event_epoch_secs);
        let session_id = Self::ensure_active_session(state, event.tool, event.event_epoch_secs);
        if let Some(session) = state.active_sessions.get_mut(&event.tool) {
            session.last_event_secs = event.event_epoch_secs;
            session.record_event(event.op, event.result, event.degraded, event.bytes);
        }

        let key = BucketKey {
            epoch_secs: bucket_epoch(event.event_epoch_secs),
            session_id,
            tool: event.tool,
            op: event.op,
            result: event.result,
            degraded: event.degraded,
        };

        let counters = state.buckets.entry(key).or_default();

        counters.event_count = counters.event_count.saturating_add(1);
        counters.bytes_total = counters.bytes_total.saturating_add(event.bytes);
        if event.latency_ms > 0 {
            counters.latency_sum_ms = counters.latency_sum_ms.saturating_add(event.latency_ms);
            counters.latency_count = counters.latency_count.saturating_add(1);
        }

        let total_key = OperationTotalKey {
            tool: event.tool,
            op: event.op,
            result: event.result,
            degraded: event.degraded,
        };
        let operation_totals = state.operation_totals.entry(total_key).or_default();
        operation_totals.event_count = operation_totals.event_count.saturating_add(1);
        operation_totals.bytes_total = operation_totals.bytes_total.saturating_add(event.bytes);
        if event.latency_ms > 0 {
            operation_totals.latency_sum_ms = operation_totals
                .latency_sum_ms
                .saturating_add(event.latency_ms);
            operation_totals.latency_count = operation_totals.latency_count.saturating_add(1);
        }
    }

    fn apply_session_connect_event(state: &mut AggregateState, event_epoch_secs: u64, tool: Tool) {
        Self::close_idle_sessions_for_tool(state, tool, event_epoch_secs);
        let _ = Self::ensure_active_session(state, tool, event_epoch_secs);
    }

    fn apply_miss_event(
        state: &mut AggregateState,
        event_epoch_secs: u64,
        tool: Tool,
        raw_key: &str,
    ) {
        Self::close_idle_sessions_for_tool(state, tool, event_epoch_secs);
        let _ = Self::ensure_active_session(state, tool, event_epoch_secs);
        let key_hash = crate::cas_oci::sha256_hex(raw_key.as_bytes());
        let prefix = raw_key.get(..32).unwrap_or(raw_key).to_string();
        Self::record_global_miss_key(state, tool, &key_hash, &prefix);
        if let Some(session) = state.active_sessions.get_mut(&tool) {
            session.last_event_secs = event_epoch_secs;
            Self::record_session_miss_key(session, tool, &key_hash, &prefix);
        }
    }

    fn record_global_miss_key(
        state: &mut AggregateState,
        tool: Tool,
        key_hash: &str,
        prefix: &str,
    ) {
        let map_key = (key_hash.to_string(), tool);
        if let Some(entry) = state.missed_keys.get_mut(&map_key) {
            entry.count = entry.count.saturating_add(1);
            return;
        }

        if tool == Tool::Sccache {
            let current = state
                .missed_key_cardinality
                .get(&tool)
                .copied()
                .unwrap_or(0);
            if current >= SCCACHE_MISSED_KEY_CAP {
                return;
            }
        }

        state.missed_keys.insert(
            map_key,
            MissEntry {
                key_hash: key_hash.to_string(),
                count: 1,
                sampled_prefix: Some(prefix.to_string()),
            },
        );
        *state.missed_key_cardinality.entry(tool).or_default() += 1;
    }

    fn record_session_miss_key(
        session: &mut SessionState,
        tool: Tool,
        key_hash: &str,
        prefix: &str,
    ) {
        if let Some(entry) = session.missed_keys.get_mut(key_hash) {
            entry.count = entry.count.saturating_add(1);
            return;
        }

        if tool == Tool::Sccache && session.missed_keys.len() >= SCCACHE_SESSION_MISSED_KEY_CAP {
            return;
        }

        session.missed_keys.insert(
            key_hash.to_string(),
            SessionMissEntry {
                key_hash: key_hash.to_string(),
                count: 1,
                sampled_prefix: Some(prefix.to_string()),
            },
        );
    }

    fn ensure_active_session(
        state: &mut AggregateState,
        tool: Tool,
        event_epoch_secs: u64,
    ) -> String {
        if let Some(session) = state.active_sessions.get_mut(&tool) {
            session.last_event_secs = event_epoch_secs;
            return session.id.clone();
        }

        let seq = state.next_session_seq.entry(tool).or_insert(0);
        *seq = seq.saturating_add(1);
        let session_id = format!("{}-{}-{}", tool.as_str(), event_epoch_secs, *seq);
        state.active_sessions.insert(
            tool,
            SessionState::new(
                session_id.clone(),
                tool,
                event_epoch_secs,
                state.session_metadata_hints.clone(),
            ),
        );
        session_id
    }

    fn close_idle_sessions(state: &mut AggregateState, now_secs: u64) {
        let tools_to_close: Vec<(Tool, u64)> = state
            .active_sessions
            .iter()
            .filter_map(|(tool, session)| {
                if now_secs.saturating_sub(session.last_event_secs) >= SESSION_IDLE_SECS {
                    Some((
                        *tool,
                        session.last_event_secs.saturating_add(SESSION_IDLE_SECS),
                    ))
                } else {
                    None
                }
            })
            .collect();
        for (tool, ended_at_secs) in tools_to_close {
            Self::finalize_session(state, tool, ended_at_secs);
        }
    }

    fn close_idle_sessions_for_tool(state: &mut AggregateState, tool: Tool, now_secs: u64) {
        let ended_at_secs = state.active_sessions.get(&tool).and_then(|session| {
            if now_secs.saturating_sub(session.last_event_secs) >= SESSION_IDLE_SECS {
                Some(session.last_event_secs.saturating_add(SESSION_IDLE_SECS))
            } else {
                None
            }
        });
        if let Some(ended_at_secs) = ended_at_secs {
            Self::finalize_session(state, tool, ended_at_secs);
        }
    }

    fn close_all_sessions(state: &mut AggregateState, ended_at_secs: u64) {
        let tools_to_close: Vec<Tool> = state.active_sessions.keys().copied().collect();
        for tool in tools_to_close {
            Self::finalize_session(state, tool, ended_at_secs);
        }
    }

    fn finalize_session(state: &mut AggregateState, tool: Tool, ended_at_secs: u64) {
        let Some(session) = state.active_sessions.remove(&tool) else {
            return;
        };
        let record = session.into_record(ended_at_secs);
        if crate::serve::state::diagnostics_enabled() {
            Self::emit_session_summary(&record);
        }
        state.completed_sessions.push(record);
    }

    fn emit_session_summary(record: &SessionRecord) {
        let duration_secs = record.session_duration_ms / 1000;
        let miss_denom = record.hit_count.saturating_add(record.miss_count);
        let hit_rate = if miss_denom == 0 {
            100.0
        } else {
            (record.hit_count as f64 / miss_denom as f64) * 100.0
        };
        eprintln!(
            "SESSION tool={} session_id={} duration={}s hits={} misses={} errors={} hit_rate={:.1}% bytes_read={} bytes_written={}",
            record.tool,
            record.session_id,
            duration_secs,
            record.hit_count,
            record.miss_count,
            record.error_count,
            hit_rate,
            crate::progress::format_bytes(record.bytes_read),
            crate::progress::format_bytes(record.bytes_written),
        );
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
        let event_epoch_secs = now_epoch_secs();
        let event = CacheOpEvent::Record(RecordEvent {
            event_epoch_secs,
            tool,
            op,
            result,
            degraded,
            bytes,
            latency_ms,
        });
        if let Some(event) = self.enqueue_event(event) {
            self.apply_event_direct(event);
        }
        emit_cache_ops_record(tool, op, result, degraded, bytes, latency_ms);
    }

    pub(crate) fn record_session_connect(&self, tool: Tool) {
        let event = CacheOpEvent::SessionConnect {
            event_epoch_secs: now_epoch_secs(),
            tool,
        };
        if let Some(event) = self.enqueue_event(event) {
            self.apply_event_direct(event);
        }
        emit_cache_ops_session_connect(tool);
    }

    pub(crate) fn restore(
        &self,
        rollups: Vec<RollupRecord>,
        missed_keys: Vec<MissedKeyRecord>,
        sessions: Vec<SessionRecord>,
    ) {
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
                session_id: rollup.session_id.clone(),
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

            let map_key = (miss.key_hash.clone(), tool);
            if let Some(entry) = state.missed_keys.get_mut(&map_key) {
                entry.count = entry.count.saturating_add(miss.miss_count);
                if entry.sampled_prefix.is_none() {
                    entry.sampled_prefix = miss.sampled_key_prefix.clone();
                }
            } else {
                state.missed_keys.insert(
                    map_key,
                    MissEntry {
                        key_hash: miss.key_hash,
                        count: miss.miss_count,
                        sampled_prefix: miss.sampled_key_prefix,
                    },
                );
            }
        }
        Self::rebuild_missed_key_cardinality(&mut state);

        state.completed_sessions.extend(sessions);
    }

    pub(crate) fn record_miss(&self, tool: Tool, raw_key: &str) {
        if tool == Tool::Sccache && !should_track_sccache_miss_key(raw_key) {
            return;
        }
        let event = CacheOpEvent::Miss {
            event_epoch_secs: now_epoch_secs(),
            tool,
            raw_key: raw_key.to_string(),
        };
        if let Some(event) = self.enqueue_event(event) {
            self.apply_event_direct(event);
        }
        emit_cache_ops_miss(tool, raw_key);
    }

    pub(crate) fn tool_operation_summary(&self, tool_name: &str) -> ToolOperationSummary {
        let Some(tool) = Tool::from_str(tool_name) else {
            return ToolOperationSummary::default();
        };

        self.flush_async_events();
        let state = self.lock_state();
        let mut summary = ToolOperationSummary::default();
        for (key, counters) in &state.operation_totals {
            if key.tool != tool {
                continue;
            }

            summary.record(
                key.op,
                key.result,
                key.degraded,
                counters.event_count,
                counters.bytes_total,
            );
        }
        summary
    }

    pub(crate) fn drain(&self) -> (Vec<RollupRecord>, Vec<MissedKeyRecord>, Vec<SessionRecord>) {
        self.drain_inner(false)
    }

    pub(crate) fn drain_for_shutdown(
        &self,
    ) -> (Vec<RollupRecord>, Vec<MissedKeyRecord>, Vec<SessionRecord>) {
        self.drain_inner(true)
    }

    fn drain_inner(
        &self,
        close_active_sessions: bool,
    ) -> (Vec<RollupRecord>, Vec<MissedKeyRecord>, Vec<SessionRecord>) {
        self.flush_async_events();
        let mut state = self.lock_state();
        let now_secs = now_epoch_secs();
        Self::close_idle_sessions(&mut state, now_secs);
        if close_active_sessions {
            Self::close_all_sessions(&mut state, now_secs);
        }

        let drained_buckets = std::mem::take(&mut state.buckets);
        let mut rollups = Vec::with_capacity(drained_buckets.len());
        for (key, counters) in drained_buckets {
            if counters.event_count == 0 {
                continue;
            }
            rollups.push(RollupRecord {
                bucket_epoch_secs: key.epoch_secs,
                session_id: key.session_id,
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
        state.missed_key_cardinality.clear();
        let mut missed = Vec::with_capacity(drained_missed_keys.len());
        for ((_, tool), entry) in drained_missed_keys {
            missed.push(MissedKeyRecord {
                key_hash: entry.key_hash,
                tool: tool.as_str().to_string(),
                miss_count: entry.count,
                sampled_key_prefix: entry.sampled_prefix,
            });
        }

        let sessions = std::mem::take(&mut state.completed_sessions);

        (rollups, missed, sessions)
    }

    pub(crate) fn is_empty(&self) -> bool {
        if self.queued_events.load(Ordering::Acquire) > 0 {
            return false;
        }
        let now_secs = now_epoch_secs();
        let state = self.lock_state();
        let has_idle_session_to_close = state
            .active_sessions
            .values()
            .any(|session| now_secs.saturating_sub(session.last_event_secs) >= SESSION_IDLE_SECS);
        state.buckets.is_empty()
            && state.missed_keys.is_empty()
            && state.completed_sessions.is_empty()
            && !has_idle_session_to_close
    }

    pub(crate) fn queue_depth(&self) -> u64 {
        self.queued_events.load(Ordering::Acquire)
    }

    pub(crate) fn dropped_events_total(&self) -> u64 {
        self.dropped_events.load(Ordering::Acquire)
    }

    fn rebuild_missed_key_cardinality(state: &mut AggregateState) {
        state.missed_key_cardinality.clear();
        for (_, tool) in state.missed_keys.keys() {
            *state.missed_key_cardinality.entry(*tool).or_default() += 1;
        }
    }
}

fn cache_ops_queue_capacity() -> usize {
    let resources = crate::platform::resources::SystemResources::detect();
    let memory_target = match resources.memory_strategy {
        crate::platform::resources::MemoryStrategy::Balanced => DEFAULT_CACHE_OPS_QUEUE_CAPACITY,
        crate::platform::resources::MemoryStrategy::Aggressive => {
            DEFAULT_CACHE_OPS_QUEUE_CAPACITY.saturating_mul(2)
        }
        crate::platform::resources::MemoryStrategy::UltraAggressive => {
            DEFAULT_CACHE_OPS_QUEUE_CAPACITY.saturating_mul(4)
        }
    };
    let cpu_target = resources.cpu_cores.saturating_mul(8_192);
    memory_target
        .max(cpu_target)
        .clamp(MIN_CACHE_OPS_QUEUE_CAPACITY, MAX_CACHE_OPS_QUEUE_CAPACITY)
}

fn cache_ops_observability_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var(CACHE_OPS_OBSERVABILITY_ENV)
            .ok()
            .map(|raw| {
                let v = raw.trim();
                v == "1"
                    || v.eq_ignore_ascii_case("true")
                    || v.eq_ignore_ascii_case("yes")
                    || v.eq_ignore_ascii_case("on")
            })
            .unwrap_or(false)
    })
}

fn emit_cache_ops_record(
    tool: Tool,
    op: Op,
    result: OpResult,
    degraded: bool,
    bytes: u64,
    latency_ms: u64,
) {
    if !cache_ops_observability_enabled() {
        return;
    }

    let status = match result {
        OpResult::Hit => 200,
        OpResult::Miss => 404,
        OpResult::Error => 500,
    };
    observability::emit(
        observability::ObservabilityEvent::success(
            CACHE_OPS_OBSERVABILITY_SOURCE,
            CACHE_OPS_OBSERVABILITY_RECORD_OP,
            "EVENT",
            CACHE_OPS_OBSERVABILITY_PATH.to_string(),
            status,
            latency_ms,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .with_details(Some(format!(
            "tool={} op={} result={} degraded={} bytes={}",
            tool.as_str(),
            op.as_str(),
            result.as_str(),
            degraded,
            bytes
        ))),
    );
}

fn emit_cache_ops_miss(tool: Tool, raw_key: &str) {
    if !cache_ops_observability_enabled() {
        return;
    }
    let key_hash = crate::cas_oci::sha256_hex(raw_key.as_bytes());
    observability::emit(observability::ObservabilityEvent::event(
        CACHE_OPS_OBSERVABILITY_SOURCE,
        CACHE_OPS_OBSERVABILITY_MISS_OP,
        "EVENT",
        CACHE_OPS_OBSERVABILITY_PATH.to_string(),
        format!("tool={} key_hash={key_hash}", tool.as_str()),
    ));
}

fn emit_cache_ops_session_connect(tool: Tool) {
    if !cache_ops_observability_enabled() {
        return;
    }
    observability::emit(observability::ObservabilityEvent::event(
        CACHE_OPS_OBSERVABILITY_SOURCE,
        CACHE_OPS_OBSERVABILITY_CONNECT_OP,
        "EVENT",
        CACHE_OPS_OBSERVABILITY_PATH.to_string(),
        format!("tool={}", tool.as_str()),
    ));
}

fn should_track_sccache_miss_key(raw_key: &str) -> bool {
    fnv1a64(raw_key.as_bytes()) & SCCACHE_MISS_SAMPLE_MASK == 0
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    const OFFSET_BASIS: u64 = 0xcbf29ce484222325;
    const PRIME: u64 = 0x100000001b3;
    let mut hash = OFFSET_BASIS;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(PRIME);
    }
    hash
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct RollupRecord {
    pub bucket_epoch_secs: u64,
    pub session_id: String,
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

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct SessionMissedKeyRecord {
    pub key_hash: String,
    pub miss_count: u64,
    pub sampled_key_prefix: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub(crate) struct SessionRecord {
    pub session_id: String,
    pub tool: String,
    pub session_duration_ms: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub error_count: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub metadata_hints: BTreeMap<String, String>,
    pub top_missed_keys: Vec<SessionMissedKeyRecord>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct ToolOperationSummary {
    pub cache_read_hit_count: u64,
    pub cache_read_miss_count: u64,
    pub cache_read_error_count: u64,
    pub cache_read_bytes: u64,
    pub cache_write_count: u64,
    pub cache_write_error_count: u64,
    pub cache_write_bytes: u64,
}

impl ToolOperationSummary {
    fn record(
        &mut self,
        op: Op,
        result: OpResult,
        degraded: bool,
        event_count: u64,
        bytes_total: u64,
    ) {
        match (op, result, degraded) {
            (Op::Get, OpResult::Hit, _) => {
                self.cache_read_hit_count = self.cache_read_hit_count.saturating_add(event_count);
                self.cache_read_bytes = self.cache_read_bytes.saturating_add(bytes_total);
            }
            (Op::Get, OpResult::Miss, _) | (Op::Get, OpResult::Error, true) => {
                self.cache_read_miss_count = self.cache_read_miss_count.saturating_add(event_count);
            }
            (Op::Get, OpResult::Error, false) => {
                self.cache_read_error_count =
                    self.cache_read_error_count.saturating_add(event_count);
            }
            (Op::Put, OpResult::Hit, _) => {
                self.cache_write_count = self.cache_write_count.saturating_add(event_count);
                self.cache_write_bytes = self.cache_write_bytes.saturating_add(bytes_total);
            }
            (Op::Put, OpResult::Error, _) => {
                self.cache_write_error_count =
                    self.cache_write_error_count.saturating_add(event_count);
            }
            _ => {}
        }
    }
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

        let (rollups, missed, sessions) = agg.drain();
        assert!(agg.is_empty());
        assert!(missed.is_empty());
        assert!(sessions.is_empty());
        assert!(!rollups.is_empty());

        let turbo = rollups
            .iter()
            .find(|r| r.tool == "turborepo")
            .expect("turborepo rollup");
        assert!(!turbo.session_id.is_empty());
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

        let (_, missed, sessions) = agg.drain();
        assert!(sessions.is_empty());
        assert_eq!(missed.len(), 2);

        let some_key = missed
            .iter()
            .find(|m| m.miss_count == 2)
            .expect("deduplicated miss");
        assert_eq!(some_key.tool, "turborepo");
        assert!(some_key.sampled_key_prefix.is_some());
    }

    #[test]
    fn sccache_record_miss_uses_deterministic_sampling() {
        let agg = Aggregator::new();
        let mut expected = 0_u64;
        let keys: Vec<String> = (0..512)
            .map(|index| format!("sccache-key-{index}"))
            .collect();
        for key in &keys {
            if should_track_sccache_miss_key(key) {
                expected = expected.saturating_add(1);
            }
            agg.record_miss(Tool::Sccache, key);
        }

        let (_, missed, sessions) = agg.drain();
        assert!(sessions.is_empty());
        let observed = missed
            .iter()
            .filter(|entry| entry.tool == "sccache")
            .map(|entry| entry.miss_count)
            .sum::<u64>();
        assert_eq!(observed, expected);
        assert!(observed > 0);
        assert!(observed < keys.len() as u64);
    }

    #[test]
    fn sccache_miss_key_tracking_caps_unique_keys() {
        let mut state = AggregateState::default();
        Aggregator::apply_session_connect_event(&mut state, 100, Tool::Sccache);

        for index in 0..(SCCACHE_MISSED_KEY_CAP + 64) {
            let key = format!("sccache-cap-key-{index}");
            Aggregator::apply_miss_event(&mut state, 100, Tool::Sccache, &key);
        }

        let tracked_global = state
            .missed_keys
            .keys()
            .filter(|(_, tool)| *tool == Tool::Sccache)
            .count();
        assert_eq!(tracked_global, SCCACHE_MISSED_KEY_CAP);

        let session = state
            .active_sessions
            .get(&Tool::Sccache)
            .expect("active sccache session");
        assert_eq!(session.missed_keys.len(), SCCACHE_SESSION_MISSED_KEY_CAP);
    }

    #[test]
    fn drain_clears_state() {
        let agg = Aggregator::new();
        agg.record(Tool::Bazel, Op::Get, OpResult::Miss, false, 0, 1);
        agg.record_miss(Tool::Bazel, "key");

        let (rollups, missed, sessions) = agg.drain();
        assert_eq!(rollups.len(), 1);
        assert_eq!(missed.len(), 1);
        assert!(sessions.is_empty());
        assert!(agg.is_empty());

        let (rollups2, missed2, sessions2) = agg.drain();
        assert!(rollups2.is_empty());
        assert!(missed2.is_empty());
        assert!(sessions2.is_empty());
    }

    #[test]
    fn degraded_events_separate_from_normal() {
        let agg = Aggregator::new();
        agg.record(Tool::Turborepo, Op::Get, OpResult::Hit, false, 100, 5);
        agg.record(Tool::Turborepo, Op::Get, OpResult::Hit, true, 100, 5);

        let (rollups, _, sessions) = agg.drain();
        assert!(sessions.is_empty());
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
        let (rollups, missed, sessions) = agg.drain();

        assert!(agg.is_empty());
        agg.restore(rollups.clone(), missed.clone(), sessions.clone());
        assert!(!agg.is_empty());

        let (restored_rollups, restored_missed, restored_sessions) = agg.drain();
        assert_eq!(restored_rollups.len(), rollups.len());
        assert_eq!(restored_missed.len(), missed.len());
        assert_eq!(restored_sessions.len(), sessions.len());

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

    #[test]
    fn drain_for_shutdown_finalizes_active_sessions() {
        let agg = Aggregator::new_with_metadata_hints(BTreeMap::from([(
            "project".to_string(),
            "launch".to_string(),
        )]));
        agg.record_session_connect(Tool::Sccache);
        agg.record(Tool::Sccache, Op::Get, OpResult::Miss, false, 0, 3);

        let (_, _, sessions) = agg.drain_for_shutdown();

        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.tool, "sccache");
        assert_eq!(session.hit_count, 0);
        assert_eq!(session.miss_count, 1);
        assert_eq!(session.error_count, 0);
        assert_eq!(
            session.metadata_hints.get("project"),
            Some(&"launch".to_string())
        );
    }

    #[test]
    fn tool_operation_summary_tracks_read_counts_without_put_hits() {
        let agg = Aggregator::new();
        agg.record(Tool::Sccache, Op::Get, OpResult::Hit, false, 100, 5);
        agg.record(Tool::Sccache, Op::Get, OpResult::Miss, false, 0, 2);
        agg.record(Tool::Sccache, Op::Get, OpResult::Error, true, 0, 4);
        agg.record(Tool::Sccache, Op::Get, OpResult::Error, false, 0, 6);
        agg.record(Tool::Sccache, Op::Put, OpResult::Hit, false, 50, 3);

        let summary = agg.tool_operation_summary("sccache");

        assert_eq!(summary.cache_read_hit_count, 1);
        assert_eq!(summary.cache_read_miss_count, 2);
        assert_eq!(summary.cache_read_error_count, 1);
        assert_eq!(summary.cache_read_bytes, 100);
        assert_eq!(summary.cache_write_count, 1);
        assert_eq!(summary.cache_write_bytes, 50);

        let (_, _, sessions) = agg.drain_for_shutdown();
        assert_eq!(sessions.len(), 1);
        let session = &sessions[0];
        assert_eq!(session.hit_count, 1);
        assert_eq!(session.miss_count, 2);
        assert_eq!(session.error_count, 1);
        assert_eq!(session.bytes_read, 100);
        assert_eq!(session.bytes_written, 50);
    }

    #[test]
    fn session_rollup_contains_duration_and_top_missed_keys() {
        let mut state = AggregateState {
            session_metadata_hints: BTreeMap::from([
                ("project".to_string(), "zed".to_string()),
                ("phase".to_string(), "warm".to_string()),
            ]),
            ..AggregateState::default()
        };
        Aggregator::apply_session_connect_event(&mut state, 100, Tool::Sccache);
        Aggregator::apply_record_event(
            &mut state,
            RecordEvent {
                event_epoch_secs: 100,
                tool: Tool::Sccache,
                op: Op::Get,
                result: OpResult::Hit,
                degraded: false,
                bytes: 48 * 1024 * 1024,
                latency_ms: 5,
            },
        );
        Aggregator::apply_record_event(
            &mut state,
            RecordEvent {
                event_epoch_secs: 101,
                tool: Tool::Sccache,
                op: Op::Get,
                result: OpResult::Miss,
                degraded: false,
                bytes: 0,
                latency_ms: 2,
            },
        );
        Aggregator::apply_miss_event(&mut state, 101, Tool::Sccache, "missing-key-a");
        Aggregator::apply_miss_event(&mut state, 101, Tool::Sccache, "missing-key-a");
        Aggregator::apply_miss_event(&mut state, 101, Tool::Sccache, "missing-key-b");
        Aggregator::close_idle_sessions(&mut state, 112);

        assert!(state.active_sessions.is_empty());
        assert_eq!(state.completed_sessions.len(), 1);
        let session = &state.completed_sessions[0];
        assert_eq!(session.tool, "sccache");
        assert_eq!(session.hit_count, 1);
        assert_eq!(session.miss_count, 1);
        assert_eq!(session.error_count, 0);
        assert_eq!(session.bytes_read, 48 * 1024 * 1024);
        assert_eq!(session.bytes_written, 0);
        assert_eq!(session.session_duration_ms, 11_000);
        assert_eq!(
            session.metadata_hints.get("project"),
            Some(&"zed".to_string())
        );
        assert_eq!(
            session.metadata_hints.get("phase"),
            Some(&"warm".to_string())
        );
        assert_eq!(session.top_missed_keys.len(), 2);
        assert_eq!(session.top_missed_keys[0].miss_count, 2);
    }

    #[test]
    fn degraded_get_error_counts_as_miss_not_error_in_session() {
        let mut state = AggregateState::default();
        Aggregator::apply_session_connect_event(&mut state, 100, Tool::Sccache);
        Aggregator::apply_record_event(
            &mut state,
            RecordEvent {
                event_epoch_secs: 101,
                tool: Tool::Sccache,
                op: Op::Get,
                result: OpResult::Error,
                degraded: true,
                bytes: 0,
                latency_ms: 20,
            },
        );
        Aggregator::close_idle_sessions(&mut state, 112);

        assert_eq!(state.completed_sessions.len(), 1);
        let session = &state.completed_sessions[0];
        assert_eq!(session.hit_count, 0);
        assert_eq!(session.miss_count, 1);
        assert_eq!(session.error_count, 0);
    }

    #[test]
    fn degraded_put_error_still_counts_as_error_in_session() {
        let mut state = AggregateState::default();
        Aggregator::apply_session_connect_event(&mut state, 100, Tool::Sccache);
        Aggregator::apply_record_event(
            &mut state,
            RecordEvent {
                event_epoch_secs: 101,
                tool: Tool::Sccache,
                op: Op::Put,
                result: OpResult::Error,
                degraded: true,
                bytes: 0,
                latency_ms: 20,
            },
        );
        Aggregator::close_idle_sessions(&mut state, 112);

        assert_eq!(state.completed_sessions.len(), 1);
        let session = &state.completed_sessions[0];
        assert_eq!(session.hit_count, 0);
        assert_eq!(session.miss_count, 0);
        assert_eq!(session.error_count, 1);
    }
}
