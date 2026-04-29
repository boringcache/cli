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
pub struct WorkspacePagination {
    pub limit: u32,
    pub offset: u32,
    pub total: u32,
    pub returned: u32,
    pub has_more: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceSessionsResponse {
    pub workspace: WorkspaceStatusWorkspace,
    pub period: WorkspaceStatusPeriod,
    pub generated_at: String,
    pub session_health: WorkspaceStatusSessionHealth,
    pub pagination: WorkspacePagination,
    pub sessions: Vec<WorkspaceStatusSession>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceMissesResponse {
    pub workspace: WorkspaceStatusWorkspace,
    pub period: WorkspaceStatusPeriod,
    pub generated_at: String,
    pub cache_health: WorkspaceStatusCacheHealth,
    pub pagination: WorkspacePagination,
    pub missed_keys: Vec<WorkspaceStatusMissedKey>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceSummaryContext {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceTagsFilter {
    #[serde(default)]
    pub query: Option<String>,
    pub include_system: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceTagFeedItem {
    pub name: String,
    pub primary: bool,
    pub system: bool,
    pub primary_tag: String,
    pub cache_entry_id: String,
    pub manifest_root_digest: String,
    pub storage_mode: String,
    pub stored_size_bytes: u64,
    pub hit_count: u64,
    #[serde(default)]
    pub uploaded_at: Option<String>,
    #[serde(default)]
    pub last_accessed_at: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceTagsResponse {
    pub workspace: WorkspaceSummaryContext,
    pub filter: WorkspaceTagsFilter,
    pub pagination: WorkspacePagination,
    pub tags: Vec<WorkspaceTagFeedItem>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceTokensFilter {
    pub include_inactive: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceApiToken {
    pub id: String,
    pub name: String,
    pub access_level: String,
    pub scope_type: String,
    pub state: String,
    pub active: bool,
    pub created_at: String,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub expires_in_days: Option<i32>,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub write_tag_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceTokensResponse {
    pub workspace: WorkspaceSummaryContext,
    pub filter: WorkspaceTokensFilter,
    pub pagination: WorkspacePagination,
    pub tokens: Vec<WorkspaceApiToken>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceIssuedToken {
    pub token: WorkspaceApiToken,
    pub value: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceTokenResponse {
    pub workspace: WorkspaceSummaryContext,
    pub token: WorkspaceApiToken,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub rotated_from: Option<WorkspaceApiToken>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceTokenPairResponse {
    pub workspace: WorkspaceSummaryContext,
    pub restore: WorkspaceIssuedToken,
    pub save: WorkspaceIssuedToken,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceTokenCreateRequest {
    pub token: WorkspaceTokenCreateParams,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceTokenCreateParams {
    pub name: String,
    pub access_level: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub write_tag_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_preset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_expires_on: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceTokenRotateRequest {
    pub token: WorkspaceTokenRotateParams,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceTokenRotateParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_preset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_expires_on: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceTokenPairCreateRequest {
    pub token_pair: WorkspaceTokenPairCreateParams,
}

#[derive(Debug, Serialize)]
pub struct WorkspaceTokenPairCreateParams {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name_prefix: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub save_tag_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_preset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_expires_on: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub review: Option<WorkspaceStatusSessionReview>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceStatusSessionReview {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_bottleneck: Option<String>,
    pub state: String,
    pub summary: String,
    pub service_side_issue: bool,
    #[serde(default)]
    pub issue_candidates: Vec<WorkspaceStatusSessionIssueCandidate>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceStatusSessionIssueCandidate {
    pub owner: String,
    pub kind: String,
    pub surface: String,
    pub severity: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_action: Option<String>,
    #[serde(default)]
    pub evidence_refs: Vec<String>,
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

#[derive(Debug, Deserialize, Serialize)]
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

#[derive(Debug, Deserialize, Serialize)]
pub struct UserInfo {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub email: String,
    #[allow(dead_code)]
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct OrganizationInfo {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub name: String,
    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct WorkspaceInfo {
    #[allow(dead_code)]
    pub id: String,
    #[allow(dead_code)]
    pub name: String,
    #[allow(dead_code)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slug: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub scope_type: String,
    #[serde(default)]
    pub access_level: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub write_tag_prefixes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}
