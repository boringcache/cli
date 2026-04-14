use super::*;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct BatchParams {
    pub rollups: Vec<RollupParam>,
    pub missed_keys: Vec<MissedKeyParam>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<SessionParam>,
}

#[derive(Debug, Serialize)]
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

#[derive(Debug, Serialize)]
pub struct MissedKeyParam {
    pub key_hash: String,
    pub tool: String,
    pub miss_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled_key_prefix: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SessionParam {
    pub session_id: String,
    pub tool: String,
    pub session_duration_ms: u64,
    pub hit_count: u64,
    pub miss_count: u64,
    pub error_count: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata_hints: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub top_missed_keys: Vec<SessionMissedKeyParam>,
}

#[derive(Debug, Serialize)]
pub struct SessionMissedKeyParam {
    pub key_hash: String,
    pub miss_count: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampled_key_prefix: Option<String>,
}
