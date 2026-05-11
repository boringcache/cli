use crate::api::ApiClient;
use serde_json::{Value, json};
use std::collections::BTreeMap;

use super::StorageMetrics;

const CACHE_SESSION_SUMMARY_SCHEMA: &str = "cache_session_summary.v2";

pub struct SaveMetrics {
    pub tool: String,
    pub tag: String,
    pub manifest_root_digest: String,
    pub total_duration_ms: u64,
    pub archive_duration_ms: u64,
    pub upload_duration_ms: u64,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub file_count: u32,
    pub part_count: Option<u32>,
    pub part_size_mb: Option<u32>,
    pub concurrency_level: Option<u32>,
    pub streaming_enabled: Option<bool>,
    pub storage_metrics: StorageMetrics,
}

pub struct RestoreMetrics {
    pub tool: String,
    pub tag: String,
    pub manifest_root_digest: Option<String>,
    pub total_duration_ms: u64,
    pub download_duration_ms: u64,
    pub extract_duration_ms: u64,
    pub compressed_size: u64,
    pub part_count: Option<u32>,
    pub part_size_mb: Option<u32>,
    pub concurrency_level: Option<u32>,
    pub streaming_enabled: Option<bool>,
    pub storage_metrics: StorageMetrics,
}

struct OperationMetrics {
    tool: String,
    operation_type: String,
    tag: String,
    manifest_root_digest: Option<String>,
    total_duration_ms: u64,
    archive_duration_ms: Option<u64>,
    upload_duration_ms: Option<u64>,
    download_duration_ms: Option<u64>,
    extract_duration_ms: Option<u64>,
    uncompressed_size: Option<u64>,
    compressed_size: Option<u64>,
    file_count: Option<u32>,
    part_count: Option<u32>,
    part_size_mb: Option<u32>,
    concurrency_level: Option<u32>,
    streaming_enabled: Option<bool>,
    storage_metrics: StorageMetrics,
}

impl From<SaveMetrics> for OperationMetrics {
    fn from(m: SaveMetrics) -> Self {
        Self {
            tool: m.tool,
            operation_type: "save".to_string(),
            tag: m.tag,
            manifest_root_digest: Some(m.manifest_root_digest),
            total_duration_ms: m.total_duration_ms,
            archive_duration_ms: Some(m.archive_duration_ms),
            upload_duration_ms: Some(m.upload_duration_ms),
            download_duration_ms: None,
            extract_duration_ms: None,
            uncompressed_size: Some(m.uncompressed_size),
            compressed_size: Some(m.compressed_size),
            file_count: Some(m.file_count),
            part_count: m.part_count,
            part_size_mb: m.part_size_mb,
            concurrency_level: m.concurrency_level,
            streaming_enabled: m.streaming_enabled,
            storage_metrics: m.storage_metrics,
        }
    }
}

impl From<RestoreMetrics> for OperationMetrics {
    fn from(m: RestoreMetrics) -> Self {
        Self {
            tool: m.tool,
            operation_type: "restore".to_string(),
            tag: m.tag,
            manifest_root_digest: m.manifest_root_digest,
            total_duration_ms: m.total_duration_ms,
            archive_duration_ms: None,
            upload_duration_ms: None,
            download_duration_ms: Some(m.download_duration_ms),
            extract_duration_ms: Some(m.extract_duration_ms),
            uncompressed_size: None,
            compressed_size: Some(m.compressed_size),
            file_count: None,
            part_count: m.part_count,
            part_size_mb: m.part_size_mb,
            concurrency_level: m.concurrency_level,
            streaming_enabled: m.streaming_enabled,
            storage_metrics: m.storage_metrics,
        }
    }
}

impl OperationMetrics {
    async fn send(self, api_client: &ApiClient, workspace: &str) {
        if std::env::var("BORINGCACHE_TELEMETRY_DISABLED").is_ok() {
            return;
        }

        let session_id = self.session_id();
        let bucket_at = chrono::Utc::now().to_rfc3339();
        let ci_context = crate::ci_detection::detect_ci_context();
        let run_identity = crate::serve::state::CacheSessionRunIdentity::detect(
            workspace,
            &session_id,
            ci_context.run_context(),
        );
        let batch = self.cache_rollups_batch(workspace, session_id, bucket_at, run_identity);
        let _ = api_client.send_cache_rollups(workspace, batch).await;
    }

    fn cache_rollups_batch(
        &self,
        workspace: &str,
        session_id: String,
        bucket_at: String,
        run_identity: crate::serve::state::CacheSessionRunIdentity,
    ) -> crate::api::models::cache_rollups::BatchParams {
        let operation = self.rollup_operation().to_string();
        let bytes_total = self.bytes_total();
        let metadata_hints = self.metadata_hints();
        let summary_json = self.summary_json(workspace, &run_identity, &session_id);

        crate::api::models::cache_rollups::BatchParams {
            rollups: vec![crate::api::models::cache_rollups::RollupParam {
                bucket_at,
                session_id: session_id.clone(),
                tool: self.tool.clone(),
                operation,
                result: "hit".to_string(),
                degraded: false,
                event_count: 1,
                bytes_total,
                latency_sum_ms: self.total_duration_ms,
                latency_count: 1,
            }],
            missed_keys: Vec::new(),
            sessions: vec![crate::api::models::cache_rollups::SessionParam {
                session_id,
                tool: self.tool.clone(),
                session_duration_ms: self.total_duration_ms,
                hit_count: u64::from(self.operation_type == "restore"),
                miss_count: 0,
                error_count: 0,
                bytes_read: if self.operation_type == "restore" {
                    bytes_total
                } else {
                    0
                },
                bytes_written: if self.operation_type == "save" {
                    bytes_total
                } else {
                    0
                },
                run_uid: run_identity.uid.clone(),
                run_provider: run_identity.provider.clone(),
                provider_run_uid: run_identity.provider_run_uid.clone(),
                run_attempt: run_identity.attempt.clone(),
                run_repository: run_identity.repository.clone(),
                run_ref_type: run_identity.source_ref_type.clone(),
                run_ref_name: run_identity.source_ref_name.clone(),
                run_change_number: run_identity.change_number.clone(),
                run_commit_sha: run_identity.commit_sha.clone(),
                metadata_hints,
                summary_schema: Some(CACHE_SESSION_SUMMARY_SCHEMA.to_string()),
                summary_json: Some(summary_json),
                top_missed_keys: Vec::new(),
            }],
        }
    }

    fn summary_json(
        &self,
        workspace: &str,
        run_identity: &crate::serve::state::CacheSessionRunIdentity,
        session_id: &str,
    ) -> Value {
        json!({
            "schema": "cache-session-v2",
            "mode": "direct",
            "adapter": self.tool.as_str(),
            "workspace": workspace,
            "duration_ms": self.total_duration_ms,
            "identity": run_identity.summary_json(session_id),
            "proxy": {
                "mode": "direct",
                "adapter": self.tool.as_str(),
                "duration_ms": self.total_duration_ms,
                "read_only": self.operation_type == "restore",
            },
            "backend_api": {},
            "rails": {},
            "storage": self.storage_summary(),
            "phases": self.phase_summary(),
            "archive": self.archive_summary(),
            "lifecycle": {
                "miss_reason_counts": {},
                "degradation_reason_counts": {},
                "product_behavior_reason_counts": {},
            },
            "oci": {},
            "startup_prefetch": {},
            "kv_upload": {},
            "singleflight": {},
            "local_cache": {},
            "buildkit": {
                "run_classification": "not_applicable",
            },
            "classification": {
                "issue_candidates": [],
            },
        })
    }

    fn phase_summary(&self) -> Value {
        json!({
            "total_duration_ms": self.total_duration_ms,
            "archive_duration_ms": self.archive_duration_ms,
            "upload_duration_ms": self.upload_duration_ms,
            "download_duration_ms": self.download_duration_ms,
            "extract_duration_ms": self.extract_duration_ms,
        })
    }

    fn archive_summary(&self) -> Value {
        json!({
            "uncompressed_size": self.uncompressed_size,
            "compressed_size": self.compressed_size,
            "file_count": self.file_count,
        })
    }

    fn storage_summary(&self) -> Value {
        let body_duration_ms = self.body_duration_ms();
        let mut object = serde_json::Map::new();
        object.insert(
            "direction".to_string(),
            Value::String(self.storage_direction().to_string()),
        );
        object.insert(
            "object_kind".to_string(),
            Value::String(self.storage_object_kind().to_string()),
        );
        object.insert(
            "request_count".to_string(),
            Value::from(self.part_count.unwrap_or(1).max(1)),
        );
        object.insert("bytes".to_string(), Value::from(self.bytes_total()));
        object.insert("retry_count".to_string(), Value::from(0));
        object.insert("error_count".to_string(), Value::from(0));

        if let Some(value) = body_duration_ms {
            object.insert("body_duration_ms".to_string(), Value::from(value));
            object.insert("body_duration_ms_sum".to_string(), Value::from(value));
            object.insert("body_duration_ms_p95".to_string(), Value::from(value));
        }
        if let Some(value) = self.throughput_mbps(body_duration_ms) {
            object.insert("throughput_mbps".to_string(), json!(value));
        }
        insert_optional_string(&mut object, "region", self.storage_metrics.region.as_ref());
        insert_optional_string(
            &mut object,
            "cache_status",
            self.storage_metrics.cache_status.as_ref(),
        );
        insert_optional_string(
            &mut object,
            "block_location",
            self.storage_metrics.block_location.as_ref(),
        );
        insert_optional_string(
            &mut object,
            "server_timing",
            self.storage_metrics.timing_header.as_ref(),
        );
        insert_optional_u32(&mut object, "part_count", self.part_count);
        insert_optional_u32(&mut object, "part_size_mb", self.part_size_mb);
        insert_optional_u32(&mut object, "concurrency_level", self.concurrency_level);
        if let Some(value) = self.streaming_enabled {
            object.insert("streaming_enabled".to_string(), Value::from(value));
        }

        Value::Object(object)
    }

    fn metadata_hints(&self) -> BTreeMap<String, String> {
        let mut hints = BTreeMap::new();
        hints.insert("source".to_string(), "cli".to_string());
        hints.insert("operation".to_string(), self.operation_type.clone());
        hints.insert("tool".to_string(), self.tool.clone());
        hints.insert("adapter".to_string(), self.tool.clone());
        hints.insert("cache_tag".to_string(), self.tag.clone());
        if let Some(digest) = self.manifest_root_digest.as_ref()
            && !digest.trim().is_empty()
        {
            hints.insert("manifest_root_digest".to_string(), digest.clone());
        }
        hints
    }

    fn session_id(&self) -> String {
        format!(
            "cli-{}-{}-{}",
            self.tool,
            self.operation_type,
            uuid::Uuid::new_v4()
        )
    }

    fn rollup_operation(&self) -> &'static str {
        if self.operation_type == "save" {
            "put"
        } else {
            "get"
        }
    }

    fn storage_direction(&self) -> &'static str {
        if self.operation_type == "save" {
            "upload"
        } else {
            "download"
        }
    }

    fn storage_object_kind(&self) -> &'static str {
        match self.tool.as_str() {
            "archive" => "archive",
            "oci" => "oci_blob",
            "bazel" => "bazel_cas_blob",
            _ => "cas_blob",
        }
    }

    fn bytes_total(&self) -> u64 {
        self.compressed_size.unwrap_or(0)
    }

    fn body_duration_ms(&self) -> Option<u64> {
        match self.operation_type.as_str() {
            "save" => self.upload_duration_ms,
            "restore" => self.download_duration_ms,
            _ => None,
        }
    }

    fn throughput_mbps(&self, body_duration_ms: Option<u64>) -> Option<f64> {
        let duration_ms = body_duration_ms?;
        if duration_ms == 0 {
            return None;
        }

        Some(
            ((self.bytes_total() as f64 / 1_000_000.0) / (duration_ms as f64 / 1000.0)
                * 8.0
                * 1000.0)
                .round()
                / 1000.0,
        )
    }
}

pub(crate) fn canonical_tool_for_cas_layout(cas_layout: Option<&str>) -> &'static str {
    match cas_layout.unwrap_or_default() {
        layout if layout.starts_with("oci") => "oci",
        layout if layout.starts_with("bazel") => "bazel",
        _ => "archive",
    }
}

fn insert_optional_string(
    object: &mut serde_json::Map<String, Value>,
    key: &str,
    value: Option<&String>,
) {
    if let Some(value) = value
        && !value.trim().is_empty()
    {
        object.insert(key.to_string(), Value::String(value.clone()));
    }
}

fn insert_optional_u32(object: &mut serde_json::Map<String, Value>, key: &str, value: Option<u32>) {
    if let Some(value) = value
        && value > 0
    {
        object.insert(key.to_string(), Value::from(value));
    }
}

impl SaveMetrics {
    pub async fn send(self, api_client: &ApiClient, workspace: &str) {
        OperationMetrics::from(self)
            .send(api_client, workspace)
            .await;
    }
}

impl RestoreMetrics {
    pub async fn send(self, api_client: &ApiClient, workspace: &str) {
        OperationMetrics::from(self)
            .send(api_client, workspace)
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_archive_metrics_build_cache_rollup_session_summary() {
        let metrics = OperationMetrics::from(SaveMetrics {
            tool: "archive".to_string(),
            tag: "deps".to_string(),
            manifest_root_digest: "sha256:abc".to_string(),
            total_duration_ms: 1_500,
            archive_duration_ms: 400,
            upload_duration_ms: 1_000,
            uncompressed_size: 20_000_000,
            compressed_size: 10_000_000,
            file_count: 42,
            part_count: Some(4),
            part_size_mb: Some(64),
            concurrency_level: Some(8),
            streaming_enabled: Some(false),
            storage_metrics: StorageMetrics {
                region: Some("iad".to_string()),
                cache_status: Some("hit".to_string()),
                block_location: Some("remote".to_string()),
                timing_header: Some("total;dur=1000".to_string()),
            },
        });
        let identity = crate::serve::state::CacheSessionRunIdentity {
            kind: Some("ci".to_string()),
            uid: Some("github-actions:demo/repo:123".to_string()),
            provider: Some("github-actions".to_string()),
            provider_run_uid: Some("123".to_string()),
            attempt: Some("1".to_string()),
            repository: Some("demo/repo".to_string()),
            source_ref_type: Some("branch".to_string()),
            source_ref_name: Some("main".to_string()),
            commit_sha: Some("abc123".to_string()),
            ..crate::serve::state::CacheSessionRunIdentity::default()
        };

        let batch = metrics.cache_rollups_batch(
            "demo/workspace",
            "session-1".to_string(),
            "2026-05-11T12:00:00Z".to_string(),
            identity,
        );

        assert_eq!(batch.rollups.len(), 1);
        assert_eq!(batch.rollups[0].tool, "archive");
        assert_eq!(batch.rollups[0].operation, "put");
        assert_eq!(batch.rollups[0].bytes_total, 10_000_000);
        assert_eq!(batch.sessions.len(), 1);
        let session = &batch.sessions[0];
        assert_eq!(
            session.summary_schema.as_deref(),
            Some(CACHE_SESSION_SUMMARY_SCHEMA)
        );
        assert_eq!(session.bytes_written, 10_000_000);
        assert_eq!(
            session.metadata_hints.get("cache_tag").map(String::as_str),
            Some("deps")
        );
        let summary = session.summary_json.as_ref().expect("summary json");
        assert_eq!(summary["mode"], "direct");
        assert_eq!(summary["adapter"], "archive");
        assert_eq!(summary["storage"]["object_kind"], "archive");
        assert_eq!(summary["storage"]["part_count"], 4);
        assert_eq!(summary["storage"]["part_size_mb"], 64);
        assert_eq!(summary["storage"]["concurrency_level"], 8);
        assert_eq!(summary["storage"]["streaming_enabled"], false);
        assert_eq!(summary["storage"]["throughput_mbps"], 80.0);
    }

    #[test]
    fn cas_layout_maps_to_canonical_reporting_tool() {
        assert_eq!(canonical_tool_for_cas_layout(Some("bazel-v2")), "bazel");
        assert_eq!(canonical_tool_for_cas_layout(Some("oci-v1")), "oci");
        assert_eq!(canonical_tool_for_cas_layout(Some("file-v1")), "archive");
        assert_eq!(canonical_tool_for_cas_layout(None), "archive");
    }
}
