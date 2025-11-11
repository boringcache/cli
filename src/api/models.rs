use serde::{Deserialize, Serialize};

/// Cache operation models
pub mod cache {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Serialize, Clone)]
    pub struct SaveRequest {
        pub tag: String,
        pub manifest_root_digest: String,
        pub compression_algorithm: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_format_version: Option<u32>,
        pub total_size_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        pub chunk_digests: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub chunk_metadata: Option<Vec<SaveChunkMetadata>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expected_manifest_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expected_manifest_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub force: Option<bool>,
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct SaveChunkMetadata {
        pub digest: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub offset: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    pub struct SaveResponse {
        pub tag: String,
        pub cache_entry_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_root_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_upload_url: Option<String>,
        #[serde(default)]
        pub missing_chunk_digests: Vec<String>,
        #[serde(default)]
        pub chunk_upload_urls: HashMap<String, String>,
        #[serde(default)]
        pub exists: bool,
        #[serde(default)]
        pub status: Option<String>,
        #[serde(default)]
        pub error: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct CacheEntriesListResponse {
        pub entries: Vec<CacheEntry>,
        pub total: u32,
        pub page: u32,
        pub limit: u32,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct CacheEntry {
        pub id: String,
        pub manifest_root_digest: String,
        #[serde(default)]
        pub tag: Option<String>,
        pub total_size_bytes: u64,
        #[serde(default)]
        pub uncompressed_size: Option<u64>,
        #[serde(default)]
        pub compressed_size: Option<u64>,
        #[serde(default)]
        pub file_count: Option<u32>,
        pub compression_algorithm: String,
        #[serde(default)]
        pub chunk_count: Option<u32>,
        pub created_at: String,
        #[serde(default)]
        pub uploaded_at: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct ConfirmRequest {
        pub chunk_count: u32,
        pub size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_etag: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct RestoreChunk {
        pub digest: String,
        pub url: String,
        pub sequence_index: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
    }

    #[derive(Debug, Deserialize, Serialize, Clone, Default)]
    pub struct RestoreMetadata {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_root_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub total_size_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct RestoreResult {
        pub tag: String,
        pub status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_entry_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_root_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub chunk_count: Option<u32>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        pub chunks: Vec<RestoreChunk>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub metadata: Option<RestoreMetadata>,
    }

    pub type RestoreResponse = Vec<RestoreResult>;

    #[derive(Debug, Deserialize, Clone)]
    pub struct TagResponse {
        pub id: String,
        pub name: String,
        pub key_hash: String,
        pub cache_entry_id: String,
        pub action: String,
        pub created_at: String,
        pub updated_at: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct CacheConfirmResponse {
        pub status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tag: Option<TagResponse>,
    }

    #[derive(Debug, Deserialize)]
    pub struct TagDeleteResponse {
        pub tag: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_entry_id: Option<String>,
        pub status: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct ManifestCheckRequest {
        pub tag: String,
        pub manifest_root_digest: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub chunk_digests: Option<Vec<String>>,
    }

    #[derive(Debug, Serialize)]
    pub struct ManifestCheckBatchRequest {
        pub manifest_checks: Vec<ManifestCheckRequest>,
    }

    #[derive(Debug, Deserialize)]
    pub struct ManifestCheckResult {
        pub tag: String,
        pub exists: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_root_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_entry_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_url: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub chunk_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub chunk_urls: Option<Vec<RestoreChunk>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uploaded_at: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub missing_chunk_digests: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct ManifestCheckResponse {
        pub results: Vec<ManifestCheckResult>,
    }

    #[derive(Debug, Clone)]
    pub struct CacheResolutionEntry {
        pub tag: String,
        pub status: String,
        pub cache_entry_id: Option<String>,
        pub manifest_url: Option<String>,
        pub manifest_root_digest: Option<String>,
        pub manifest_digest: Option<String>,
        pub compression_algorithm: Option<String>,
        pub chunk_count: Option<u32>,
        pub chunks: Vec<RestoreChunk>,
        pub chunk_digests: Vec<String>,
        pub size: Option<u64>,
        pub uncompressed_size: Option<u64>,
        pub compressed_size: Option<u64>,
        pub uploaded_at: Option<String>,
        pub content_hash: Option<String>,
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct PartInfo {
        pub part_number: u32,
        pub etag: String,
    }
}

/// Workspace and user models
pub mod workspace {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct Workspace {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub id: Option<String>,
        pub slug: String,
        pub name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
        #[serde(default)]
        pub cache_entries_count: u32,
        #[serde(default)]
        pub total_cache_size: u64,
        pub created_at: String,
        pub updated_at: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct SessionInfo {
        #[allow(dead_code)]
        pub valid: bool,
        #[allow(dead_code)]
        pub user: UserInfo,
        #[allow(dead_code)]
        pub organization: Option<OrganizationInfo>,
        #[allow(dead_code)]
        pub workspace: Option<WorkspaceInfo>,
        #[allow(dead_code)]
        pub token: TokenInfo,
    }

    #[derive(Debug, Deserialize)]
    pub struct UserInfo {
        #[allow(dead_code)]
        pub id: String,
        #[allow(dead_code)]
        pub email: String,
        #[allow(dead_code)]
        pub name: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct OrganizationInfo {
        #[allow(dead_code)]
        pub id: String,
        #[allow(dead_code)]
        pub name: String,
        #[allow(dead_code)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub slug: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct WorkspaceInfo {
        #[allow(dead_code)]
        pub id: String,
        #[allow(dead_code)]
        pub name: String,
        #[allow(dead_code)]
        #[serde(skip_serializing_if = "Option::is_none")]
        pub slug: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct TokenInfo {
        pub id: String,
        pub name: String,
        pub scope_type: String,
        #[serde(default)]
        pub scopes: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_at: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expires_in_days: Option<i32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub last_used_at: Option<String>,
    }
}

/// Metrics and telemetry models
pub mod metrics {
    use super::*;

    #[derive(Debug, Serialize)]
    pub struct MetricsParams {
        pub operation_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content_hash: Option<String>,
        pub total_duration: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub archive_duration: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub upload_duration: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub download_duration: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub extract_duration: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub confirm_duration: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_ratio: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub upload_speed_mbps: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub download_speed_mbps: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_age_hours: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error_message: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub benchmark_compression_ratio: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_duration: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub predicted_time_ms: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub prediction_accuracy: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tags: Option<Vec<String>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cpu_cores: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cpu_load_percent: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub total_memory_gb: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub available_memory_gb: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub memory_strategy: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub disk_type: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub disk_speed_estimate_mb_s: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub concurrent_operations: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub buffer_size_mb: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub chunk_size_mb: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub part_size_mb: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub concurrency_level: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub streaming_enabled: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub parallel_extraction: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_level: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_threads: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub benchmark_throughput_mb_s: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub bandwidth_probe_mb_s: Option<f64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub multipart_threshold_mb: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub part_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub retry_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub transfer_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_efficiency: Option<f64>,
    }
}

// Re-export commonly used types for ergonomic access
pub use cache::*;
pub use metrics::*;
pub use workspace::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_info_deserializes_without_scopes() {
        let json = r#"{
            "id": "token123",
            "name": "Test Token",
            "scope_type": "workspace",
            "expires_at": "2024-01-01T00:00:00Z"
        }"#;

        let token_info: workspace::TokenInfo =
            serde_json::from_str(json).expect("Should deserialize without scopes field");
        assert_eq!(token_info.id, "token123");
        assert_eq!(token_info.scopes, Vec::<String>::new());
    }

    #[test]
    fn test_workspace_info_deserializes_with_slug() {
        let json = r#"{
            "id": "ws123",
            "name": "Test Workspace",
            "slug": "test-workspace"
        }"#;

        let workspace_info: workspace::WorkspaceInfo =
            serde_json::from_str(json).expect("Should deserialize with slug");
        assert_eq!(workspace_info.id, "ws123");
        assert_eq!(workspace_info.name, "Test Workspace");
        assert_eq!(workspace_info.slug, Some("test-workspace".to_string()));
    }

    #[test]
    fn test_restore_result_deserializes_hit() {
        let json = r#"{
            "tag": "ruby-3.4.4-darwin-arm64",
            "status": "hit",
            "cache_entry_id": "11111111-2222-3333-4444-555555555555",
            "manifest_root_digest": "blake3:abc123",
            "manifest_url": "https://example.com/manifest",
            "chunks": [
                {
                    "digest": "chunk1",
                    "url": "https://example.com/chunk1",
                    "sequence_index": 0
                }
            ],
            "metadata": {
                "manifest_root_digest": "blake3:abc123",
                "total_size_bytes": 1024,
                "file_count": 3,
                "compression_algorithm": "zstd"
            }
        }"#;

        let result: cache::RestoreResult =
            serde_json::from_str(json).expect("Should deserialize cache restore hit");
        assert_eq!(result.status, "hit");
        assert_eq!(result.chunks.len(), 1);
    }
}
