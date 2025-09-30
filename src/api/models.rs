/// Data models for API communication
///
/// Contains all the request and response models used for API communication,
/// organized by functional area for better maintainability.
use serde::{Deserialize, Serialize};

/// Cache operation models
pub mod cache {
    use super::*;

    #[derive(Debug, Deserialize)]
    pub struct SaveCacheResponse {
        pub cache_entry_id: String,
        pub storage_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub upload_url: Option<String>,
        #[serde(default)]
        pub multipart: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub upload_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub part_urls: Option<Vec<PartUpload>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tag: Option<TagResponse>,
    }

    #[derive(Debug, Clone, Deserialize)]
    pub struct PartUpload {
        pub part_number: u32,
        pub upload_url: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct ListCachesResponse {
        pub entries: Vec<CacheEntry>,
        pub total: u32,
        pub page: u32,
        pub limit: u32,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct CacheEntry {
        pub id: String,
        pub cache_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tag: Option<String>,
        pub size: u64,
        pub created_at: String,
        pub compression_algorithm: String,
        pub file_count: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub description: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct ConfirmUploadParams {
        pub size: u64,
        pub content_hash: Option<String>,
        pub storage_key: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct CacheTag {
        pub id: String,
        pub name: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub path: Option<String>,
    }

    #[derive(Debug, Deserialize, Clone)]
    pub struct CacheResolutionEntry {
        pub identifier: Option<String>,
        pub tag: Option<String>,
        pub status: Option<String>,
        pub url: Option<String>,
        pub size: Option<u64>,
        pub content_hash: Option<String>,
        pub compression_algorithm: Option<String>,
        pub key: Option<String>,
        pub path: Option<String>,
        pub source: Option<String>,
        pub cache_tag: Option<CacheTag>,
    }

    #[derive(Debug, Deserialize)]
    pub struct CacheCheckHashResponse {
        pub exists: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content_fingerprint: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_entry_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<u64>,
    }

    #[derive(Debug, Deserialize)]
    pub struct BatchCacheCheckResponse {
        pub results: Vec<CacheCheckResult>,
    }

    #[derive(Debug, Deserialize)]
    pub struct CacheCheckResult {
        pub identifier: String,
        pub identifier_type: String, // "tag", "content_fingerprint", or "content_hash"
        pub exists: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_entry_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content_hash: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub content_fingerprint: Option<String>,
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct PartInfo {
        pub part_number: u32,
        pub etag: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct TagResponse {
        pub id: String,
        pub name: String,
        pub key_hash: String,
        pub cache_entry_id: String,
        pub action: String,
        pub created_at: String,
        pub updated_at: String,
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

// Re-export commonly used types for backward compatibility
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
        assert_eq!(token_info.scopes, Vec::<String>::new()); // Default empty vec
    }

    #[test]
    fn test_token_info_deserializes_with_scopes() {
        let json = r#"{
            "id": "token123",
            "name": "Test Token", 
            "scope_type": "workspace",
            "scopes": ["read", "write"],
            "expires_at": "2024-01-01T00:00:00Z"
        }"#;

        let token_info: workspace::TokenInfo =
            serde_json::from_str(json).expect("Should deserialize with scopes field");
        assert_eq!(token_info.scopes, vec!["read", "write"]);
    }

    #[test]
    fn test_workspace_info_deserializes_basic_fields() {
        let json = r#"{
            "id": "ws123",
            "name": "Test Workspace"
        }"#;

        let workspace_info: workspace::WorkspaceInfo =
            serde_json::from_str(json).expect("Should deserialize with basic fields");
        assert_eq!(workspace_info.id, "ws123");
        assert_eq!(workspace_info.name, "Test Workspace");
        assert_eq!(workspace_info.slug, None);
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
    fn test_organization_info_deserializes_without_slug() {
        let json = r#"{
            "id": "org123",
            "name": "Test Organization"
        }"#;

        let org_info: workspace::OrganizationInfo =
            serde_json::from_str(json).expect("Should deserialize without slug");
        assert_eq!(org_info.id, "org123");
        assert_eq!(org_info.name, "Test Organization");
        assert_eq!(org_info.slug, None);
    }

    #[test]
    fn test_organization_info_deserializes_with_slug() {
        let json = r#"{
            "id": "org123",
            "name": "Test Organization",
            "slug": "test-org"
        }"#;

        let org_info: workspace::OrganizationInfo =
            serde_json::from_str(json).expect("Should deserialize with slug");
        assert_eq!(org_info.id, "org123");
        assert_eq!(org_info.name, "Test Organization");
        assert_eq!(org_info.slug, Some("test-org".to_string()));
    }

    #[test]
    fn test_cache_resolution_entry_deserializes_hit() {
        let json = r#"{
            "status": "hit",
            "tag": "ruby-3.4.4-ubuntu-24-x86_64",
            "size": 53930000,
            "url": "https://example.com/download",
            "content_hash": "abc123",
            "compression_algorithm": "zstd"
        }"#;

        let entry: CacheResolutionEntry =
            serde_json::from_str(json).expect("Should deserialize cache hit");
        assert_eq!(entry.status, Some("hit".to_string()));
        assert_eq!(entry.size, Some(53930000));
    }

    #[test]
    fn test_cache_resolution_entry_deserializes_miss() {
        let json = r#"{
            "status": "miss",
            "identifier": "ruby-3.4.4"
        }"#;

        let entry: CacheResolutionEntry =
            serde_json::from_str(json).expect("Should deserialize cache miss");
        assert_eq!(entry.status, Some("miss".to_string()));
        assert_eq!(entry.size, None);
        assert_eq!(entry.url, None);
    }

    #[test]
    fn test_workspace_deserializes_with_slug() {
        let json = r#"{
            "id": "ws123",
            "slug": "my-workspace",
            "name": "My Workspace",
            "cache_entries_count": 5,
            "total_cache_size": 1024000,
            "created_at": "2024-01-01T00:00:00Z",
            "updated_at": "2024-01-02T00:00:00Z"
        }"#;

        let workspace: workspace::Workspace =
            serde_json::from_str(json).expect("Should deserialize workspace with slug");
        assert_eq!(workspace.slug, "my-workspace".to_string());
        assert_eq!(workspace.name, "My Workspace");
        assert_eq!(workspace.cache_entries_count, 5);
    }

    #[test]
    fn test_session_info_deserializes_with_workspace_containing_slug() {
        let json = r#"{
            "valid": true,
            "user": {
                "id": "user123",
                "email": "test@example.com",
                "name": "Test User"
            },
            "workspace": {
                "id": "ws123",
                "name": "My Workspace",
                "slug": "my-workspace"
            },
            "token": {
                "id": "token123",
                "name": "Test Token",
                "scope_type": "workspace"
            }
        }"#;

        let session: workspace::SessionInfo = serde_json::from_str(json)
            .expect("Should deserialize session info with workspace slug");
        assert_eq!(session.valid, true);
        if let Some(workspace) = &session.workspace {
            assert_eq!(workspace.id, "ws123");
            assert_eq!(workspace.name, "My Workspace");
        } else {
            panic!("Expected workspace to be present");
        }
    }
}
