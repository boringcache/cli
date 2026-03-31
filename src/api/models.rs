use serde::{Deserialize, Serialize};

pub mod cache {
    use super::*;

    #[derive(Debug, Serialize, Clone)]
    pub struct SaveRequest {
        pub tag: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub write_scope_tag: Option<String>,
        pub manifest_root_digest: String,
        pub compression_algorithm: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_mode: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_total_size_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cas_layout: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_format_version: Option<u32>,
        pub total_size_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expected_manifest_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expected_manifest_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub force: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub use_multipart: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ci_provider: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub encrypted: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub encryption_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub encryption_recipient_hint: Option<String>,
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct PreflightRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub write_scope_tag: Option<String>,
        pub manifest_root_digest: String,
        pub compression_algorithm: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_mode: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_total_size_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cas_layout: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_format_version: Option<u32>,
        pub total_size_bytes: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expected_manifest_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub expected_manifest_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub force: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub ci_provider: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub encrypted: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub encryption_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub encryption_recipient_hint: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct SaveResponse {
        pub tag: String,
        pub cache_entry_id: String,
        #[serde(default)]
        pub upload_session_id: Option<String>,
        #[serde(default)]
        pub upload_state: Option<String>,
        #[serde(default)]
        pub exists: bool,
        #[serde(default)]
        pub storage_mode: Option<String>,
        #[serde(default)]
        pub blob_count: Option<u64>,
        #[serde(default)]
        pub blob_total_size_bytes: Option<u64>,
        #[serde(default)]
        pub cas_layout: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_upload_url: Option<String>,
        #[serde(default)]
        pub archive_part_urls: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub upload_id: Option<String>,
        #[serde(default)]
        pub upload_headers: std::collections::HashMap<String, String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_root_digest: Option<String>,
        #[serde(default)]
        pub status: Option<String>,
        #[serde(default)]
        pub error: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        archive_upload_url: Option<String>,
        #[serde(default)]
        archive_urls: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        multipart_upload_id: Option<String>,
    }

    impl SaveResponse {
        pub fn get_archive_urls(&self) -> &[String] {
            if !self.archive_part_urls.is_empty() {
                &self.archive_part_urls
            } else if !self.archive_urls.is_empty() {
                &self.archive_urls
            } else if let Some(url) = &self.archive_upload_url {
                std::slice::from_ref(url)
            } else {
                &[]
            }
        }

        pub fn get_upload_id(&self) -> Option<&str> {
            self.upload_id
                .as_deref()
                .or(self.multipart_upload_id.as_deref())
        }
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
        pub created_at: String,
        #[serde(default)]
        pub uploaded_at: Option<String>,
        #[serde(default)]
        pub encrypted: bool,
    }

    #[derive(Debug, Serialize)]
    pub struct ConfirmRequest {
        pub manifest_digest: String,
        pub manifest_size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_etag: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub archive_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub archive_etag: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_total_size_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_mode: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        pub tag: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub write_scope_tag: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct CompleteMultipartRequest {
        pub upload_id: String,
        pub parts: Vec<MultipartPart>,
    }

    #[derive(Debug, Serialize)]
    pub struct MultipartPart {
        pub part_number: usize,
        pub etag: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct CompleteMultipartResponse {
        pub archive_etag: String,
    }

    #[derive(Debug, Deserialize, Serialize, Clone, Default)]
    pub struct RestoreMetadata {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_root_digest: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub total_size_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_mode: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_count: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub blob_total_size_bytes: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cas_layout: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub file_count: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compression_algorithm: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub signature_tag: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct RestoreResult {
        pub tag: String,
        #[serde(default)]
        pub primary_tag: Option<String>,
        #[serde(default)]
        pub signature_tag: Option<String>,
        pub status: String,
        #[serde(default)]
        pub cache_entry_id: Option<String>,
        #[serde(default)]
        pub manifest_root_digest: Option<String>,
        #[serde(default)]
        pub manifest_digest: Option<String>,
        #[serde(default)]
        pub manifest_url: Option<String>,
        #[serde(default)]
        pub compression_algorithm: Option<String>,
        #[serde(default)]
        pub storage_mode: Option<String>,
        #[serde(default)]
        pub blob_count: Option<u64>,
        #[serde(default)]
        pub blob_total_size_bytes: Option<u64>,
        #[serde(default)]
        pub cas_layout: Option<String>,
        #[serde(default)]
        pub archive_urls: Vec<String>,
        #[serde(default)]
        pub metadata: Option<RestoreMetadata>,
        #[serde(default)]
        pub error: Option<String>,

        #[serde(default)]
        pub pending: bool,

        #[serde(default)]
        pub workspace_signing_public_key: Option<String>,

        #[serde(default)]
        pub server_signature: Option<String>,

        #[serde(default)]
        pub server_signed_at: Option<String>,
        #[serde(default)]
        pub encrypted: bool,
    }

    pub type RestoreResponse = Vec<RestoreResult>;

    #[derive(Debug, Deserialize, Clone)]
    pub struct RestorePendingResponse {
        #[serde(default)]
        pub pending: bool,
        #[serde(default)]
        pub status: Option<String>,
        #[serde(default)]
        pub message: Option<String>,
    }

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
        pub cache_entry_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uploaded_at: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub tag: Option<TagResponse>,

        #[serde(skip_serializing_if = "Option::is_none")]
        pub tag_status: Option<String>,

        #[serde(default)]
        pub signature: Option<String>,

        #[serde(default)]
        pub signing_public_key: Option<String>,

        #[serde(default)]
        pub signed_at: Option<String>,
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

    impl TagDeleteResponse {
        pub fn is_deleted(&self) -> bool {
            self.status == "deleted"
        }
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct ManifestCheckRequest {
        pub tag: String,
        pub manifest_root_digest: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub lookup: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct ManifestCheckBatchRequest {
        pub manifest_checks: Vec<ManifestCheckRequest>,
    }

    #[derive(Debug, Deserialize)]
    pub struct ManifestCheckResult {
        pub tag: String,
        pub exists: bool,

        #[serde(default)]
        pub pending: bool,
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
        #[serde(default)]
        pub archive_urls: Vec<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uncompressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub compressed_size: Option<u64>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub uploaded_at: Option<String>,

        #[serde(default)]
        pub status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub error: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct ManifestCheckResponse {
        pub results: Vec<ManifestCheckResult>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct BlobDescriptor {
        pub digest: String,
        pub size_bytes: u64,
    }

    #[derive(Debug, Serialize)]
    pub struct BlobCheckRequest {
        pub blobs: Vec<BlobDescriptor>,
    }

    #[derive(Debug, Deserialize)]
    pub struct BlobCheckResult {
        pub digest: String,
        pub exists: bool,
    }

    #[derive(Debug, Deserialize)]
    pub struct BlobCheckResponse {
        pub results: Vec<BlobCheckResult>,
    }

    #[derive(Debug, Serialize)]
    pub struct BlobStageRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_entry_id: Option<String>,
        pub blobs: Vec<BlobDescriptor>,
    }

    #[derive(Debug, Serialize)]
    pub struct BlobUploadUrlsRequest {
        pub cache_entry_id: String,
        pub blobs: Vec<BlobDescriptor>,
    }

    #[derive(Debug, Deserialize)]
    pub struct BlobUploadUrl {
        pub digest: String,
        pub url: String,
        #[serde(default)]
        pub headers: std::collections::HashMap<String, String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct BlobUploadUrlsResponse {
        #[serde(default)]
        pub upload_urls: Vec<BlobUploadUrl>,
        #[serde(default)]
        pub already_present: Vec<String>,
        #[serde(default)]
        pub upload_session_id: Option<String>,
        #[serde(default)]
        pub upload_state: Option<String>,
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct BlobReceipt {
        pub digest: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub etag: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct BlobReceiptCommitRequest {
        pub receipts: Vec<BlobReceipt>,
    }

    #[derive(Debug, Serialize)]
    pub struct ManifestReceiptCommitRequest {
        pub manifest_digest: String,
        pub manifest_size: u64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_etag: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct BlobDownloadUrlsRequest {
        pub cache_entry_id: String,
        pub blobs: Vec<BlobDescriptor>,
    }

    #[derive(Debug, Deserialize)]
    pub struct BlobDownloadUrl {
        pub digest: String,
        pub url: String,
    }

    #[derive(Debug, Deserialize)]
    pub struct BlobDownloadUrlsResponse {
        #[serde(default)]
        pub download_urls: Vec<BlobDownloadUrl>,
        #[serde(default)]
        pub missing: Vec<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct TagPointerResponse {
        pub tag: String,
        pub cache_entry_id: Option<String>,
        pub manifest_root_digest: Option<String>,
        pub version: Option<String>,
    }

    #[derive(Debug, Deserialize)]
    pub struct UploadSessionStatusResponse {
        pub upload_session_id: String,
        pub cache_entry_id: String,
        #[serde(default)]
        pub tag: Option<String>,
        #[serde(default)]
        pub storage_mode: Option<String>,
        pub state: String,
        #[serde(default)]
        pub publish_attempt_id: Option<String>,
        #[serde(default)]
        pub publish_state: Option<String>,
        #[serde(default)]
        pub expected_blob_count: Option<u64>,
        #[serde(default)]
        pub attached_blob_count: Option<u64>,
        #[serde(default)]
        pub receipt_blob_count: Option<u64>,
        #[serde(default)]
        pub visible_blob_count: Option<u64>,
        #[serde(default)]
        pub manifest_receipt_received_at: Option<String>,
        #[serde(default)]
        pub pending_blob_count: Option<u64>,
        #[serde(default)]
        pub published_tag_version: Option<String>,
        #[serde(default)]
        pub error: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct CacheResolutionEntry {
        pub tag: String,
        pub primary_tag: Option<String>,
        pub signature_tag: Option<String>,
        pub status: String,
        pub cache_entry_id: Option<String>,
        pub manifest_url: Option<String>,
        pub manifest_root_digest: Option<String>,
        pub manifest_digest: Option<String>,
        pub compression_algorithm: Option<String>,
        pub storage_mode: Option<String>,
        pub blob_count: Option<u64>,
        pub blob_total_size_bytes: Option<u64>,
        pub cas_layout: Option<String>,
        pub archive_urls: Vec<String>,
        pub size: Option<u64>,
        pub uncompressed_size: Option<u64>,
        pub compressed_size: Option<u64>,
        pub uploaded_at: Option<String>,
        pub content_hash: Option<String>,

        pub pending: bool,

        pub error: Option<String>,

        pub workspace_signing_public_key: Option<String>,

        pub server_signature: Option<String>,

        pub server_signed_at: Option<String>,
        pub encrypted: bool,
    }

    #[derive(Debug, Serialize, Clone)]
    pub struct PartInfo {
        pub part_number: u32,
        pub etag: String,
    }
}

pub mod workspace {
    use super::*;
    use serde_json::Value;
    use std::collections::BTreeMap;

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

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusResponse {
        pub workspace: WorkspaceStatusWorkspace,
        pub period: WorkspaceStatusPeriod,
        pub generated_at: String,
        pub inventory: WorkspaceStatusInventory,
        pub operations: WorkspaceStatusOperations,
        pub savings: WorkspaceStatusSavings,
        pub tools: Vec<WorkspaceStatusTool>,
        pub sessions: Vec<WorkspaceStatusSession>,
        pub missed_keys: Vec<WorkspaceStatusMissedKey>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusWorkspace {
        pub id: Value,
        pub name: String,
        pub slug: String,
        #[serde(default)]
        pub description: Option<String>,
        pub provisioned: bool,
        pub created_at: String,
        pub updated_at: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusPeriod {
        pub key: String,
        pub started_at: String,
        pub ended_at: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusInventory {
        pub tagged_entries_count: u64,
        pub tagged_storage_bytes: u64,
        pub tagged_hits: u64,
        pub version_count: u64,
        pub orphaned_entries_count: u64,
        pub orphaned_storage_bytes: u64,
        pub dedup_unique_bytes: u64,
        pub dedup_logical_bytes: u64,
        pub dedup_savings_bytes: u64,
        pub dedup_ratio: f64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusOperations {
        pub cache: WorkspaceStatusCacheSummary,
        pub runtime: WorkspaceStatusRuntimeSummary,
        pub cache_health: WorkspaceStatusCacheHealth,
        pub session_health: WorkspaceStatusSessionHealth,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusCacheSummary {
        pub total_requests: u64,
        pub total_hits: u64,
        pub lookup_requests: u64,
        pub hit_rate: f64,
        pub bytes_total: u64,
        pub avg_latency_ms: f64,
        pub degraded_count: u64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusRuntimeSummary {
        pub total_queries: u64,
        pub error_count: u64,
        pub error_rate: f64,
        pub avg_latency_ms: f64,
        pub degraded_count: u64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusCacheHealth {
        pub warm_hit_rate: f64,
        pub cold_misses: u64,
        pub recurring_misses: u64,
        pub cold_pct: f64,
        pub recurring_pct: f64,
        pub session_miss_total: u64,
        pub normal_misses: u64,
        pub degraded_misses: u64,
        pub total_misses: u64,
        pub degraded_pct: f64,
        pub excluded_seed_misses: u64,
        pub excluded_seed_sessions: u64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusSessionHealth {
        pub total_sessions: u64,
        pub healthy_sessions: u64,
        pub error_sessions: u64,
        pub degraded_sessions: u64,
        pub avg_hit_rate: f64,
        pub avg_duration_ms: f64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusSavings {
        pub cache_hits: u64,
        pub bytes_served: u64,
        pub bytes_written: u64,
        pub cli_restores: u64,
        pub cli_restore_bytes: u64,
        pub cli_compression_saved: u64,
        pub cli_avg_restore_ms: f64,
        pub dedup_unique_bytes: u64,
        pub dedup_logical_bytes: u64,
        pub dedup_savings_bytes: u64,
        pub dedup_ratio: f64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusTool {
        pub tool: String,
        pub total: u64,
        pub hits: u64,
        pub misses: u64,
        pub lookup_total: u64,
        pub hit_rate: f64,
        pub warm_hit_rate: f64,
        pub recurring_misses: u64,
        pub new_key_misses: u64,
        pub bytes_total: u64,
        pub avg_latency_ms: f64,
        pub degraded: u64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusSession {
        pub session_id: String,
        pub tool: String,
        #[serde(default)]
        pub project_hint: Option<String>,
        #[serde(default)]
        pub phase_hint: Option<String>,
        #[serde(default)]
        pub metadata_hints: BTreeMap<String, String>,
        pub hit_rate: f64,
        pub hit_count: u64,
        pub miss_count: u64,
        pub error_count: u64,
        pub error_details: Vec<WorkspaceStatusSessionError>,
        #[serde(default)]
        pub duration_seconds: Option<f64>,
        pub bytes_read: u64,
        pub bytes_written: u64,
        pub created_at: String,
        pub missed_keys: Vec<WorkspaceStatusSessionMissedKey>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusSessionError {
        pub operation: String,
        pub count: u64,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusSessionMissedKey {
        pub key_hash: String,
        pub miss_count: u64,
        #[serde(default)]
        pub sampled_key_prefix: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct WorkspaceStatusMissedKey {
        pub key_hash: String,
        pub tool: String,
        pub miss_count: u64,
        #[serde(default)]
        pub last_seen_at: Option<String>,
        #[serde(default)]
        pub sampled_key_prefix: Option<String>,
        pub miss_state: String,
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

pub mod cache_rollups {
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
}

pub mod metrics {
    use super::*;

    #[derive(Debug, Serialize)]
    pub struct MetricsParams {
        pub operation_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub cache_path: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub manifest_root_digest: Option<String>,
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
        pub part_size_mb: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub concurrency_level: Option<u32>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub streaming_enabled: Option<bool>,
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

        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_region: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_cache_status: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_block_location: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub storage_timing: Option<String>,
    }
}

pub mod optimize {
    use super::*;

    #[derive(Debug, Serialize)]
    pub struct OptimizeFileRequest {
        pub path: String,
        pub content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub input_type: Option<String>,
    }

    #[derive(Debug, Serialize)]
    pub struct OptimizeRequest {
        pub files: Vec<OptimizeFileRequest>,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct OptimizeChange {
        pub description: String,
        #[serde(default)]
        pub before_snippet: Option<String>,
        #[serde(default)]
        pub after_snippet: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct OptimizeFileResult {
        pub path: String,
        pub status: String,
        #[serde(default)]
        pub detected_type: Option<String>,
        #[serde(default)]
        pub optimized_content: Option<String>,
        #[serde(default)]
        pub changes: Vec<OptimizeChange>,
        #[serde(default)]
        pub explanation: Option<String>,
        #[serde(default)]
        pub error: Option<String>,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct OptimizeResponse {
        pub results: Vec<OptimizeFileResult>,
    }
}

pub mod cli_connect {
    use super::*;

    #[derive(Debug, Deserialize, Serialize)]
    pub struct CliConnectSessionCreateResponse {
        pub session_id: String,
        pub poll_token: String,
        pub authorize_url: String,
        pub expires_at: String,
        pub poll_interval_seconds: u64,
    }

    #[derive(Debug, Deserialize, Serialize, Clone)]
    pub struct CliConnectWorkspace {
        pub name: String,
        pub slug: String,
    }

    #[derive(Debug, Deserialize, Serialize)]
    pub struct CliConnectSessionPollResponse {
        pub session_id: String,
        pub status: String,
        pub expires_at: String,
        #[serde(default)]
        pub token: Option<String>,
        #[serde(default)]
        pub workspace: Option<CliConnectWorkspace>,
    }
}

pub use cache::*;
pub use cli_connect::*;
pub use metrics::*;
pub use optimize::*;
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
    }
}
