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
    pub ci_run_uid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_run_attempt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_ref_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_ref_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_default_branch: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_pr_number: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_commit_sha: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ci_run_started_at: Option<String>,
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

    pub fn is_resumable_pending_cas(&self) -> bool {
        self.exists
            && self.status.as_deref() == Some("pending")
            && self.storage_mode.as_deref() == Some("cas")
            && self.upload_session_id.is_some()
            && self.manifest_upload_url.is_some()
    }

    pub fn is_resumable_pending_cas_for(&self, expected_manifest_root_digest: &str) -> bool {
        self.is_resumable_pending_cas()
            && self.manifest_root_digest.as_deref() == Some(expected_manifest_root_digest)
    }

    pub fn blocking_pending_cas_reason(
        &self,
        expected_manifest_root_digest: &str,
    ) -> Option<String> {
        if !self.exists
            || self.status.as_deref() != Some("pending")
            || self.storage_mode.as_deref() != Some("cas")
        {
            return None;
        }

        let server_manifest_root_digest =
            self.manifest_root_digest.as_deref().unwrap_or("<missing>");
        if server_manifest_root_digest != expected_manifest_root_digest {
            return Some(format!(
                "pending CAS entry manifest_root_digest={} does not match expected {}",
                server_manifest_root_digest, expected_manifest_root_digest
            ));
        }

        if self.upload_session_id.as_deref().is_none()
            || self.manifest_upload_url.as_ref().is_none()
        {
            return Some("pending CAS entry is missing resumable upload metadata".to_string());
        }

        None
    }

    pub fn should_skip_existing_uploads(&self) -> bool {
        self.exists && !self.is_resumable_pending_cas()
    }

    pub fn should_skip_existing_uploads_for(&self, expected_manifest_root_digest: &str) -> bool {
        self.exists
            && !self.is_resumable_pending_cas_for(expected_manifest_root_digest)
            && self
                .blocking_pending_cas_reason(expected_manifest_root_digest)
                .is_none()
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
    pub workspace_signing_key_fingerprint: Option<String>,

    #[serde(default)]
    pub server_signature: Option<String>,

    #[serde(default)]
    pub server_signature_payload: Option<String>,

    #[serde(default)]
    pub server_envelope_signature: Option<String>,

    #[serde(default)]
    pub server_signature_version: Option<u32>,

    #[serde(default)]
    pub server_signing_key_id: Option<String>,

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
    pub manifest_root_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uploaded_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<TagResponse>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag_status: Option<String>,

    #[serde(default)]
    pub promotion_status: Option<String>,

    #[serde(default)]
    pub promotion_reason: Option<String>,

    #[serde(default)]
    pub requested_cache_entry_id: Option<String>,

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_storage: Option<bool>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blob_digests: Option<Vec<String>>,
}

#[derive(Debug, Serialize)]
pub struct BlobDownloadUrlsRequest {
    pub cache_entry_id: String,
    pub blobs: Vec<BlobDescriptor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_storage: Option<bool>,
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

#[derive(Debug, Deserialize, Serialize)]
pub struct CacheInspectResponse {
    pub workspace: CacheInspectWorkspace,
    pub identifier: CacheInspectIdentifier,
    pub entry: CacheInspectEntry,
    #[serde(default)]
    pub tags: Vec<CacheInspectTag>,
    #[serde(default)]
    pub versions: Option<CacheInspectVersions>,
    #[serde(default)]
    pub performance: Option<CacheInspectPerformance>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CacheInspectWorkspace {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CacheInspectIdentifier {
    pub query: String,
    pub matched_by: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CacheInspectEntry {
    pub id: String,
    #[serde(default)]
    pub primary_tag: Option<String>,
    pub status: String,
    pub manifest_root_digest: String,
    #[serde(default)]
    pub manifest_digest: Option<String>,
    #[serde(default)]
    pub manifest_format_version: Option<u32>,
    pub storage_mode: String,
    pub stored_size_bytes: u64,
    #[serde(default)]
    pub uncompressed_size: Option<u64>,
    #[serde(default)]
    pub compressed_size: Option<u64>,
    #[serde(default)]
    pub archive_size: Option<u64>,
    #[serde(default)]
    pub file_count: Option<u32>,
    #[serde(default)]
    pub compression_algorithm: Option<String>,
    #[serde(default)]
    pub blob_count: Option<u64>,
    #[serde(default)]
    pub blob_total_size_bytes: Option<u64>,
    #[serde(default)]
    pub cas_layout: Option<String>,
    #[serde(default)]
    pub storage_verified: bool,
    pub hit_count: u64,
    pub created_at: String,
    #[serde(default)]
    pub uploaded_at: Option<String>,
    #[serde(default)]
    pub last_accessed_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub encrypted: bool,
    #[serde(default)]
    pub encryption_algorithm: Option<String>,
    #[serde(default)]
    pub encryption_recipient_hint: Option<String>,
    #[serde(default)]
    pub server_signed: bool,
    #[serde(default)]
    pub server_signed_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CacheInspectTag {
    pub name: String,
    pub primary: bool,
    pub system: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CacheInspectVersions {
    pub tag: String,
    pub version_count: u64,
    pub max_versions: u64,
    pub current: bool,
    pub total_storage_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CacheInspectPerformance {
    pub total_operations: u64,
    pub saves: u64,
    pub restores: u64,
    pub avg_restore_ms: f64,
    pub avg_save_ms: f64,
    pub errors: u64,
    pub avg_download_speed: f64,
    pub avg_upload_speed: f64,
    #[serde(default)]
    pub last_operation: Option<String>,
    pub error_rate: f64,
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

    pub workspace_signing_key_fingerprint: Option<String>,

    pub server_signature: Option<String>,

    pub server_signature_payload: Option<String>,

    pub server_envelope_signature: Option<String>,

    pub server_signature_version: Option<u32>,

    pub server_signing_key_id: Option<String>,

    pub server_signed_at: Option<String>,
    pub encrypted: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct PartInfo {
    pub part_number: u32,
    pub etag: String,
}
