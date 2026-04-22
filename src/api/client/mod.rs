//! API client namespace.
//! Future splits belong here: transport/http, cache, workspace, auth, and metrics.

mod auth;
mod cache;
mod http;
mod metrics;
mod workspace;

use crate::config::{AuthPurpose, Config};
use crate::error::{BoringCacheError, ConflictMetadata};
use crate::observability;
use crate::retry_resume::RetryConfig;
use crate::types::Result;
use anyhow::{Context, ensure};
use log::debug;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;

const BLOB_CHECK_BATCH_MAX: usize = 10_000;
const BLOB_URL_BATCH_MAX: usize = 2_000;
const BLOB_METRIC_ENDPOINT_OPERATION_CHECK: &str = "cache_blobs_check";
const BLOB_METRIC_ENDPOINT_OPERATION_UPLOAD_URLS: &str = "cache_blobs_upload_urls";
const BLOB_METRIC_ENDPOINT_OPERATION_DOWNLOAD_URLS: &str = "cache_blobs_download_urls";
const CACHE_METRIC_ENDPOINT_OPERATION_SAVE_ENTRY: &str = "cache_flush_upload";
const CACHE_METRIC_ENDPOINT_OPERATION_CONFIRM_PUBLISH: &str = "cache_finalize_publish";
const CACHE_METRIC_ENDPOINT_OPERATION_UPLOAD_SESSION_BLOB_RECEIPTS: &str =
    "upload_session_commit_blobs";
const CACHE_METRIC_ENDPOINT_OPERATION_UPLOAD_SESSION_MANIFEST_RECEIPT: &str =
    "upload_session_commit_manifest";
const REQUEST_METRIC_SOURCE_CLI: &str = "cli";
const API_VERSION_V1: &str = "v1";
const API_VERSION_V2: &str = "v2";
const FALLBACK_API_BASE_URL: &str = "https://api.boringcache.com";
const CONFIRM_PUBLISH_TIMEOUT_SECS_ENV: &str = "BORINGCACHE_CONFIRM_PUBLISH_TIMEOUT_SECS";
const DEFAULT_CONFIRM_PUBLISH_TIMEOUT_SECS: u64 = 10;
const TRANSFER_CONNECT_TIMEOUT_SECS_ENV: &str = "BORINGCACHE_TRANSFER_CONNECT_TIMEOUT_SECS";
const DEFAULT_TRANSFER_CONNECT_TIMEOUT_SECS: u64 = 10;
const BLOB_RECEIPT_COMMIT_BATCH_MAX: usize = 500;

#[derive(Debug, Clone, Default, Deserialize)]
struct CapabilityResponse {
    #[serde(default)]
    features: CapabilityFlags,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[allow(dead_code)]
struct CapabilityFlags {
    #[serde(default)]
    blob_stage_v2: bool,
    #[serde(default)]
    tag_publish_v2: bool,
    #[serde(default)]
    finalize_only_v2: bool,
    #[serde(default)]
    entry_create_v2: bool,
    #[serde(default)]
    upload_sessions_v2: bool,
    #[serde(default)]
    upload_receipts_v2: bool,
    #[serde(default)]
    cas_publish_bootstrap_if_match: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TagPointer {
    version: String,
    #[serde(default)]
    cache_entry_id: Option<String>,
    #[serde(default)]
    manifest_root_digest: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    uploaded_at: Option<String>,
    #[serde(default)]
    promotion_status: Option<String>,
    #[serde(default)]
    promotion_reason: Option<String>,
    #[serde(default)]
    requested_cache_entry_id: Option<String>,
}

#[derive(Debug)]
pub enum TagPointerPollResult {
    NotModified,
    NotFound,
    Changed {
        pointer: super::models::cache::TagPointerResponse,
        etag: Option<String>,
    },
}

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    transfer_client: Client,
    base_url: String,
    v1_base_url: String,
    v2_base_url: String,
    auth_token: Option<String>,
    capabilities: Arc<RwLock<Option<CapabilityFlags>>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedError {
    success: Option<bool>,
    code: Option<String>,
    message: String,
    details: Vec<String>,
}

fn determine_publish_mode(request: &crate::api::models::cache::ConfirmRequest) -> &'static str {
    match request.storage_mode.as_deref() {
        Some(mode) if mode.eq_ignore_ascii_case("cas") => "cas",
        Some(_) => "replace",
        None => {
            if request.blob_count.is_some() || request.blob_total_size_bytes.is_some() {
                "cas"
            } else {
                "replace"
            }
        }
    }
}

fn parse_error_payload(body: &str) -> Option<ParsedError> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;

    let message = value
        .get("error")
        .and_then(|v| v.as_str())
        .or_else(|| value.get("message").and_then(|v| v.as_str()))?;

    let success = value.get("success").and_then(|v| v.as_bool());
    let code = value
        .get("code")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let details = match value.get("details") {
        Some(serde_json::Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(|s| s.to_string()))
            .collect(),
        Some(serde_json::Value::String(detail)) => vec![detail.to_string()],
        _ => Vec::new(),
    };

    Some(ParsedError {
        success,
        code,
        message: message.to_string(),
        details,
    })
}

fn parse_restore_not_found_body(
    body: &str,
) -> Result<Option<crate::api::models::cache::RestoreResponse>> {
    use crate::api::models::cache::{RestorePendingResponse, RestoreResponse};

    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }

    if let Ok(restore_response) = serde_json::from_str::<RestoreResponse>(trimmed) {
        return Ok(Some(restore_response));
    }

    if let Ok(pending_response) = serde_json::from_str::<RestorePendingResponse>(trimmed)
        && (pending_response.pending || pending_response.status.as_deref() == Some("pending"))
    {
        return Err(BoringCacheError::cache_pending().into());
    }

    Ok(None)
}

fn is_rate_limit_error(error: &anyhow::Error) -> bool {
    let lower = format!("{error:#}").to_lowercase();
    lower.contains("429")
        || lower.contains("too many requests")
        || lower.contains("rate limit exceeded")
        || lower.contains("throttled")
}

fn confirm_publish_error_delay(error: &anyhow::Error, consecutive_errors: u32) -> Duration {
    let base = Duration::from_secs(1);
    if !is_rate_limit_error(error) {
        return base;
    }

    let throttled_base = Duration::from_secs(2);
    let multiplier = 1u32 << consecutive_errors.saturating_sub(1).min(4);
    throttled_base
        .checked_mul(multiplier)
        .unwrap_or(Duration::from_secs(10))
        .min(Duration::from_secs(10))
}

fn should_retry_confirm_publish_error(error: &anyhow::Error) -> bool {
    if crate::error::is_connection_error(error) {
        return true;
    }

    let lower = format!("{error:#}").to_lowercase();
    is_rate_limit_error(error)
        || lower.contains("500")
        || lower.contains("server error")
        || lower.contains("502")
        || lower.contains("bad gateway")
        || lower.contains("503")
        || lower.contains("service unavailable")
        || lower.contains("504")
        || lower.contains("gateway timeout")
        || lower.contains("request timeout")
        || lower.contains("timed out")
}

fn is_retryable_api_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::REQUEST_TIMEOUT
            | StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn cache_confirm_response_from_tag_pointer(
    response: TagPointer,
) -> super::models::cache::CacheConfirmResponse {
    super::models::cache::CacheConfirmResponse {
        status: response
            .status
            .clone()
            .unwrap_or_else(|| "ready".to_string()),
        cache_entry_id: response.cache_entry_id.clone(),
        manifest_root_digest: response.manifest_root_digest,
        uploaded_at: response.uploaded_at,
        tag: None,
        tag_status: response.status,
        promotion_status: response.promotion_status,
        promotion_reason: response.promotion_reason,
        requested_cache_entry_id: response.requested_cache_entry_id,
        signature: None,
        signing_public_key: None,
        signed_at: None,
    }
}

fn parse_conflict_metadata(body: &str) -> Option<ConflictMetadata> {
    fn object_field<'a>(
        value: &'a serde_json::Value,
        field: &str,
    ) -> Option<&'a serde_json::Value> {
        value.as_object()?.get(field)
    }

    fn string_at_path(value: &serde_json::Value, path: &[&str]) -> Option<String> {
        let mut current = value;
        for segment in path {
            current = object_field(current, segment)?;
        }
        current.as_str().map(|s| s.to_string())
    }

    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let current_version = string_at_path(&value, &["current_pointer", "version"])
        .or_else(|| string_at_path(&value, &["current", "version"]))
        .or_else(|| string_at_path(&value, &["conflict", "version"]))
        .or_else(|| string_at_path(&value, &["version"]))
        .or_else(|| string_at_path(&value, &["current_version"]));
    let current_cache_entry_id = string_at_path(&value, &["current_pointer", "cache_entry_id"])
        .or_else(|| string_at_path(&value, &["current", "cache_entry_id"]))
        .or_else(|| string_at_path(&value, &["conflict", "cache_entry_id"]))
        .or_else(|| string_at_path(&value, &["cache_entry_id"]))
        .or_else(|| string_at_path(&value, &["current_cache_entry_id"]));
    let current_tag = string_at_path(&value, &["current_pointer", "tag"])
        .or_else(|| string_at_path(&value, &["current", "tag"]))
        .or_else(|| string_at_path(&value, &["conflict", "tag"]))
        .or_else(|| string_at_path(&value, &["tag"]))
        .or_else(|| string_at_path(&value, &["current_tag"]));

    let metadata = ConflictMetadata {
        current_version,
        current_cache_entry_id,
        current_tag,
    };

    if metadata.current_version.is_none()
        && metadata.current_cache_entry_id.is_none()
        && metadata.current_tag.is_none()
    {
        return None;
    }

    Some(metadata)
}

fn format_error_message(
    status: StatusCode,
    url: &reqwest::Url,
    payload: Option<&ParsedError>,
    raw_body: &str,
) -> String {
    if let Some(parsed) = payload {
        let mut message = format!("Server returned {} for {}: {}", status, url, parsed.message);

        if let Some(code) = parsed.code.as_ref() {
            message.push_str(&format!(" ({code})"));
        }

        if !parsed.details.is_empty() {
            for detail in &parsed.details {
                message.push_str(&format!("\n  - {}", detail));
            }
        }

        return message;
    }

    if raw_body.trim().is_empty() {
        format!("HTTP {} from {}", status, url)
    } else {
        format!("HTTP {} from {}: {}", status, url, raw_body)
    }
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut deduped = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            deduped.push(value);
        }
    }
    deduped
}

fn confirm_publish_request_timeout() -> Duration {
    let seconds = std::env::var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CONFIRM_PUBLISH_TIMEOUT_SECS);
    Duration::from_secs(seconds)
}

fn transfer_connect_timeout() -> Duration {
    let seconds = std::env::var(TRANSFER_CONNECT_TIMEOUT_SECS_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_TRANSFER_CONNECT_TIMEOUT_SECS);
    Duration::from_secs(seconds)
}

fn blob_check_batch_max() -> usize {
    BLOB_CHECK_BATCH_MAX
}

pub(crate) fn blob_url_batch_max() -> usize {
    BLOB_URL_BATCH_MAX
}

fn blob_check_batch_concurrency(chunk_count: usize) -> usize {
    if chunk_count == 0 {
        return 1;
    }
    api_batch_concurrency(chunk_count).clamp(1, chunk_count)
}

fn blob_url_batch_concurrency(chunk_count: usize) -> usize {
    if chunk_count == 0 {
        return 1;
    }
    api_batch_concurrency(chunk_count).clamp(1, chunk_count)
}

fn normalize_optional_token(token: Option<String>) -> Option<String> {
    token.and_then(|value| {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn map_request_send_error(err: reqwest::Error) -> anyhow::Error {
    let boringcache_error: BoringCacheError = err.into();
    boringcache_error.into()
}

pub(crate) fn derive_api_base_urls(configured_base_url: &str) -> (String, String) {
    let configured = configured_base_url.trim().trim_end_matches('/');
    let default = crate::config::Config::default_api_url_value()
        .trim()
        .trim_end_matches('/');
    let base = if configured.is_empty() {
        if default.is_empty() {
            FALLBACK_API_BASE_URL
        } else {
            default
        }
    } else {
        configured
    };
    let trimmed = base.to_string();
    let lower = base.to_ascii_lowercase();
    let v1_suffix = format!("/{}", API_VERSION_V1);
    let v2_suffix = format!("/{}", API_VERSION_V2);

    if lower.ends_with(&v1_suffix) {
        let prefix = &trimmed[..trimmed.len() - v1_suffix.len()];
        return (trimmed.clone(), format!("{prefix}/{API_VERSION_V2}"));
    }

    if lower.ends_with(&v2_suffix) {
        let prefix = &trimmed[..trimmed.len() - v2_suffix.len()];
        return (format!("{prefix}/{API_VERSION_V1}"), trimmed);
    }

    (
        format!("{trimmed}/{API_VERSION_V1}"),
        format!("{trimmed}/{API_VERSION_V2}"),
    )
}

fn api_batch_concurrency(chunk_count: usize) -> usize {
    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let is_ci = std::env::var_os("CI").is_some();
    api_batch_concurrency_for_context(chunk_count, cpu_count, is_ci)
}

fn api_batch_concurrency_for_context(chunk_count: usize, cpu_count: usize, is_ci: bool) -> usize {
    if chunk_count == 0 {
        return 1;
    }

    let cpu_limited = if is_ci {
        cpu_count.saturating_mul(2)
    } else {
        cpu_count
    };
    let cap = 8;

    chunk_count.min(cap).min(cpu_limited.max(1)).max(1)
}

fn ensure_crypto_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn build_api_client_with_headers(headers: Option<reqwest::header::HeaderMap>) -> Result<Client> {
    ensure_crypto_provider();
    let is_test_mode = std::env::var("BORINGCACHE_TEST_MODE")
        .map(|value| value == "1")
        .unwrap_or(false);

    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(256)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .redirect(reqwest::redirect::Policy::limited(4))
        .tls_backend_rustls()
        .http2_adaptive_window(true);

    if is_test_mode {
        builder = builder
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_secs(2));
    } else {
        builder = builder
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(30));
    }

    if let Some(headers) = headers {
        builder = builder.default_headers(headers);
    }

    builder.build().context("Failed to build HTTP client")
}

fn build_transfer_client_with_headers(
    headers: Option<reqwest::header::HeaderMap>,
) -> Result<Client> {
    ensure_crypto_provider();

    let is_test_mode = std::env::var("BORINGCACHE_TEST_MODE")
        .map(|value| value == "1")
        .unwrap_or(false);
    let use_http2 = transfer_http2_enabled();

    let mut builder = reqwest::Client::builder()
        .pool_max_idle_per_host(256)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .tcp_nodelay(true)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::limited(4));
    if use_http2 {
        builder = builder.http2_adaptive_window(true);
    } else {
        builder = builder.http1_only();
    }

    if is_test_mode {
        builder = builder
            .connect_timeout(Duration::from_millis(200))
            .timeout(Duration::from_secs(10));
    } else {
        builder = builder
            .connect_timeout(transfer_connect_timeout())
            .timeout(Duration::from_secs(300));
    }

    if let Some(headers) = headers {
        builder = builder.default_headers(headers);
    }

    builder
        .build()
        .context("Failed to build transfer HTTP client")
}

fn transfer_http2_enabled() -> bool {
    let Ok(raw) = std::env::var("BORINGCACHE_TRANSFER_HTTP2") else {
        return true;
    };
    match raw.trim().to_ascii_lowercase().as_str() {
        "0" | "false" | "no" | "off" => false,
        "1" | "true" | "yes" | "on" => true,
        _ => true,
    }
}

#[cfg(test)]
mod tests;
