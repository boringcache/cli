use super::*;
use std::collections::BTreeMap;

pub(crate) const CACHE_ROLLUP_MAX_ROLLUPS_PER_REQUEST: usize = 500;
pub(crate) const CACHE_ROLLUP_MAX_MISSED_KEYS_PER_REQUEST: usize = 500;
pub(crate) const CACHE_ROLLUP_MAX_SESSIONS_PER_REQUEST: usize = 80;
pub(crate) const CACHE_ROLLUP_MAX_RECORDS_PER_REQUEST: usize = 800;
pub(crate) const CACHE_ROLLUP_MAX_SERIALIZED_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct BatchParams {
    pub rollups: Vec<RollupParam>,
    pub missed_keys: Vec<MissedKeyParam>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<SessionParam>,
}

impl BatchParams {
    pub(crate) fn record_count(&self) -> usize {
        self.rollups.len() + self.missed_keys.len() + self.sessions.len()
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.record_count() == 0
    }

    pub(crate) fn split_for_ingest(self) -> Vec<Self> {
        let mut chunks = Vec::new();
        let mut current = Self::empty();

        for rollup in self.rollups {
            push_record(&mut chunks, &mut current, CacheRollupRecord::Rollup(rollup));
        }
        for missed_key in self.missed_keys {
            push_record(
                &mut chunks,
                &mut current,
                CacheRollupRecord::MissedKey(missed_key),
            );
        }
        for session in self.sessions {
            push_record(
                &mut chunks,
                &mut current,
                CacheRollupRecord::Session(Box::new(session)),
            );
        }

        push_chunk_if_present(&mut chunks, current);
        chunks
    }

    fn empty() -> Self {
        Self {
            rollups: Vec::new(),
            missed_keys: Vec::new(),
            sessions: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct RollupParam {
    pub bucket_at: String,
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

#[derive(Debug, Clone, Serialize)]
pub struct MissedKeyParam {
    pub key_hash: String,
    pub tool: String,
    pub miss_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled_key_prefix: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionParam {
    pub session_id: String,
    pub tool: String,
    pub session_duration_ms: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub error_count: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_run_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_attempt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_repository: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_ref_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_ref_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_change_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_commit_sha: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata_hints: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary_json: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_missed_keys: Vec<SessionMissedKeyParam>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SessionMissedKeyParam {
    pub key_hash: String,
    pub miss_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled_key_prefix: Option<String>,
}

enum CacheRollupRecord {
    Rollup(RollupParam),
    MissedKey(MissedKeyParam),
    Session(Box<SessionParam>),
}

fn push_record(
    chunks: &mut Vec<BatchParams>,
    current: &mut BatchParams,
    record: CacheRollupRecord,
) {
    if !record_fits(current, &record) {
        let flushed = std::mem::replace(current, BatchParams::empty());
        push_chunk_if_present(chunks, flushed);
    }

    append_record(current, record);
    if serialized_size(current) > CACHE_ROLLUP_MAX_SERIALIZED_BYTES && current.record_count() > 1 {
        let record = pop_last_record(current).expect("record was just appended");
        let flushed = std::mem::replace(current, BatchParams::empty());
        push_chunk_if_present(chunks, flushed);
        append_record(current, record);
    }
}

fn record_fits(batch: &BatchParams, record: &CacheRollupRecord) -> bool {
    if batch.record_count() >= CACHE_ROLLUP_MAX_RECORDS_PER_REQUEST {
        return false;
    }

    match record {
        CacheRollupRecord::Rollup(_) => batch.rollups.len() < CACHE_ROLLUP_MAX_ROLLUPS_PER_REQUEST,
        CacheRollupRecord::MissedKey(_) => {
            batch.missed_keys.len() < CACHE_ROLLUP_MAX_MISSED_KEYS_PER_REQUEST
        }
        CacheRollupRecord::Session(_) => {
            batch.sessions.len() < CACHE_ROLLUP_MAX_SESSIONS_PER_REQUEST
        }
    }
}

fn append_record(batch: &mut BatchParams, record: CacheRollupRecord) {
    match record {
        CacheRollupRecord::Rollup(record) => batch.rollups.push(record),
        CacheRollupRecord::MissedKey(record) => batch.missed_keys.push(record),
        CacheRollupRecord::Session(record) => batch.sessions.push(*record),
    }
}

fn pop_last_record(batch: &mut BatchParams) -> Option<CacheRollupRecord> {
    if let Some(record) = batch.sessions.pop() {
        return Some(CacheRollupRecord::Session(Box::new(record)));
    }
    if let Some(record) = batch.missed_keys.pop() {
        return Some(CacheRollupRecord::MissedKey(record));
    }
    batch.rollups.pop().map(CacheRollupRecord::Rollup)
}

fn push_chunk_if_present(chunks: &mut Vec<BatchParams>, batch: BatchParams) {
    if !batch.is_empty() {
        chunks.push(batch);
    }
}

fn serialized_size(batch: &BatchParams) -> usize {
    serde_json::to_vec(batch)
        .map(|bytes| bytes.len())
        .unwrap_or(usize::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rollup(index: usize) -> RollupParam {
        RollupParam {
            bucket_at: "2026-05-13T00:00:00Z".to_string(),
            session_id: format!("session-{index}"),
            tool: "turborepo".to_string(),
            operation: "get".to_string(),
            result: "hit".to_string(),
            degraded: false,
            event_count: 1,
            bytes_total: 10,
            latency_sum_ms: 2,
            latency_count: 1,
        }
    }

    fn session(index: usize, summary_size: usize) -> SessionParam {
        SessionParam {
            session_id: format!("summary-{index}"),
            tool: "oci".to_string(),
            session_duration_ms: 100,
            hit_count: 1,
            miss_count: 0,
            error_count: 0,
            bytes_read: 1,
            bytes_written: 0,
            run_uid: None,
            run_provider: None,
            provider_run_uid: None,
            run_attempt: None,
            run_repository: None,
            run_ref_type: None,
            run_ref_name: None,
            run_change_number: None,
            run_commit_sha: None,
            metadata_hints: BTreeMap::new(),
            summary_schema: Some("cache_session_summary.v2".to_string()),
            summary_json: Some(serde_json::json!({ "payload": "x".repeat(summary_size) })),
            top_missed_keys: Vec::new(),
        }
    }

    #[test]
    fn split_for_ingest_chunks_by_record_count() {
        let batch = BatchParams {
            rollups: (0..(CACHE_ROLLUP_MAX_ROLLUPS_PER_REQUEST + 1))
                .map(rollup)
                .collect(),
            missed_keys: Vec::new(),
            sessions: Vec::new(),
        };

        let chunks = batch.split_for_ingest();

        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0].rollups.len(),
            CACHE_ROLLUP_MAX_ROLLUPS_PER_REQUEST
        );
        assert_eq!(chunks[1].rollups.len(), 1);
    }

    #[test]
    fn split_for_ingest_chunks_by_serialized_bytes() {
        let batch = BatchParams {
            rollups: Vec::new(),
            missed_keys: Vec::new(),
            sessions: vec![
                session(1, CACHE_ROLLUP_MAX_SERIALIZED_BYTES / 2),
                session(2, CACHE_ROLLUP_MAX_SERIALIZED_BYTES / 2),
            ],
        };

        let chunks = batch.split_for_ingest();

        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].sessions.len(), 1);
        assert_eq!(chunks[1].sessions.len(), 1);
    }
}
