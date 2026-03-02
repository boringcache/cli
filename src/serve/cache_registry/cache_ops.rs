use dashmap::DashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use super::kv::KvNamespace;

const BUCKET_SECONDS: u64 = 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Tool {
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
    event_count: AtomicU64,
    bytes_total: AtomicU64,
    latency_sum_ms: AtomicU64,
    latency_count: AtomicU64,
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

#[derive(Debug, Clone)]
pub struct Aggregator {
    buckets: Arc<DashMap<BucketKey, Arc<BucketCounters>>>,
    missed_keys: Arc<DashMap<(String, Tool), MissEntry>>,
}

#[derive(Debug, Clone)]
struct MissEntry {
    key_hash: String,
    count: u64,
    sampled_prefix: Option<String>,
}

impl Default for Aggregator {
    fn default() -> Self {
        Self::new()
    }
}

impl Aggregator {
    pub fn new() -> Self {
        Self {
            buckets: Arc::new(DashMap::new()),
            missed_keys: Arc::new(DashMap::new()),
        }
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
        let key = BucketKey {
            epoch_secs: bucket_epoch(now_epoch_secs()),
            tool,
            op,
            result,
            degraded,
        };

        let counters = self
            .buckets
            .entry(key)
            .or_insert_with(|| Arc::new(BucketCounters::default()))
            .clone();

        counters.event_count.fetch_add(1, Ordering::Relaxed);
        counters.bytes_total.fetch_add(bytes, Ordering::Relaxed);
        if latency_ms > 0 {
            counters
                .latency_sum_ms
                .fetch_add(latency_ms, Ordering::Relaxed);
            counters.latency_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn restore(&self, rollups: Vec<RollupRecord>, missed_keys: Vec<MissedKeyRecord>) {
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

            let counters = self
                .buckets
                .entry(key)
                .or_insert_with(|| Arc::new(BucketCounters::default()))
                .clone();
            counters
                .event_count
                .fetch_add(rollup.event_count, Ordering::Relaxed);
            counters
                .bytes_total
                .fetch_add(rollup.bytes_total, Ordering::Relaxed);
            counters
                .latency_sum_ms
                .fetch_add(rollup.latency_sum_ms, Ordering::Relaxed);
            counters
                .latency_count
                .fetch_add(rollup.latency_count, Ordering::Relaxed);
        }

        for miss in missed_keys {
            let Some(tool) = Tool::from_str(&miss.tool) else {
                continue;
            };

            self.missed_keys
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
        let key_hash = crate::cas_oci::sha256_hex(raw_key.as_bytes());
        let map_key = (key_hash.clone(), tool);
        let prefix = raw_key.get(..32).unwrap_or(raw_key).to_string();

        self.missed_keys
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

    pub(crate) fn drain(&self) -> (Vec<RollupRecord>, Vec<MissedKeyRecord>) {
        let bucket_keys: Vec<BucketKey> = self.buckets.iter().map(|entry| *entry.key()).collect();

        let mut rollups = Vec::with_capacity(bucket_keys.len());
        for key in bucket_keys {
            if let Some((_, counters)) = self.buckets.remove(&key) {
                let count = counters.event_count.load(Ordering::Relaxed);
                if count == 0 {
                    continue;
                }
                rollups.push(RollupRecord {
                    bucket_epoch_secs: key.epoch_secs,
                    tool: key.tool.as_str().to_string(),
                    operation: key.op.as_str().to_string(),
                    result: key.result.as_str().to_string(),
                    degraded: key.degraded,
                    event_count: count,
                    bytes_total: counters.bytes_total.load(Ordering::Relaxed),
                    latency_sum_ms: counters.latency_sum_ms.load(Ordering::Relaxed),
                    latency_count: counters.latency_count.load(Ordering::Relaxed),
                });
            }
        }

        let miss_keys: Vec<_> = self
            .missed_keys
            .iter()
            .map(|entry| entry.key().clone())
            .collect();

        let mut missed = Vec::with_capacity(miss_keys.len());
        for mk in miss_keys {
            if let Some((_, entry)) = self.missed_keys.remove(&mk) {
                missed.push(MissedKeyRecord {
                    key_hash: entry.key_hash,
                    tool: mk.1.as_str().to_string(),
                    miss_count: entry.count,
                    sampled_key_prefix: entry.sampled_prefix,
                });
            }
        }

        (rollups, missed)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buckets.is_empty() && self.missed_keys.is_empty()
    }
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
