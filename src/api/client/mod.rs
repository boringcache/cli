//! API client namespace.
//! Future splits belong here: transport/http, cache, workspace, auth, and metrics.

mod auth;
mod cache;
mod http;
mod metrics;
mod workspace;

use crate::config::{AuthPurpose, Config};
use crate::error::{BoringCacheError, ConflictMetadata, PendingMetadata};
use crate::observability;
use crate::retry_resume::RetryConfig;
use crate::types::Result;
use anyhow::{Context, ensure};
use log::debug;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
const REQUEST_METRIC_SOURCE_CLI: &str = "cli";
const API_VERSION_V1: &str = "v1";
const API_VERSION_V2: &str = "v2";
const FALLBACK_API_BASE_URL: &str = "https://api.boringcache.com";
const CONFIRM_PUBLISH_TIMEOUT_SECS_ENV: &str = "BORINGCACHE_CONFIRM_PUBLISH_TIMEOUT_SECS";
const DEFAULT_CONFIRM_PUBLISH_TIMEOUT_SECS: u64 = 10;
const SHUTDOWN_PENDING_PUBLISH_GRACE_SECS_ENV: &str =
    "BORINGCACHE_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS";
const DEFAULT_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS: u64 = 10;
const TRANSFER_CONNECT_TIMEOUT_SECS_ENV: &str = "BORINGCACHE_TRANSFER_CONNECT_TIMEOUT_SECS";
const DEFAULT_TRANSFER_CONNECT_TIMEOUT_SECS: u64 = 10;
const PENDING_PUBLISH_POLL_TIMEOUT: Duration = Duration::from_secs(180);
const PENDING_PUBLISH_POLL_INTERVAL: Duration = Duration::from_millis(500);
const PENDING_PUBLISH_POLL_MAX_INTERVAL: Duration = Duration::from_secs(10);
const BLOB_RECEIPT_COMMIT_BATCH_MAX: usize = 500;

#[derive(Debug)]
pub enum ConfirmPublishResult {
    Published(Box<super::models::cache::CacheConfirmResponse>),
    Pending(PendingMetadata),
}

#[derive(Debug)]
enum PendingPublishPollOutcome {
    Published(TagPointer),
    Pending(PendingMetadata),
}

#[derive(Clone, Copy)]
struct PendingPublishPollContext<'a> {
    started_at: Instant,
    pending_started_at: Instant,
    shutdown_pending_policy: ShutdownPendingPublishPolicy<'a>,
    accept_server_owned_pending_after_timeout: bool,
}

#[derive(Clone, Copy)]
struct ShutdownPendingPublishPolicy<'a> {
    shutdown_requested: Option<&'a AtomicBool>,
    grace: Duration,
}

impl ShutdownPendingPublishPolicy<'_> {
    fn should_accept_server_owned_pending(
        self,
        metadata: &PendingMetadata,
        pending_started_at: Instant,
    ) -> bool {
        server_owned_pending_publish(metadata)
            && self
                .shutdown_requested
                .is_some_and(|flag| flag.load(Ordering::Acquire))
            && pending_started_at.elapsed() >= self.grace
    }
}

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
    pending_publish_status_v2: bool,
    #[serde(default)]
    cas_publish_bootstrap_if_match: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct TagPointer {
    version: String,
    #[serde(default)]
    cache_entry_id: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    uploaded_at: Option<String>,
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

fn parse_pending_metadata(
    body: &str,
    parsed_payload: Option<&ParsedError>,
) -> Option<PendingMetadata> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let details = value.get("details")?;

    let upload_session_id = details
        .get("upload_session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let publish_attempt_id = details
        .get("publish_attempt_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let poll_path = details
        .get("poll_path")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let retry_after_seconds = details
        .get("retry_after_seconds")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            details
                .get("retry_after_seconds")
                .and_then(|v| v.as_str())
                .and_then(|v| v.parse::<u64>().ok())
        });

    Some(PendingMetadata {
        code: parsed_payload.and_then(|p| p.code.clone()),
        upload_session_id,
        publish_attempt_id,
        poll_path,
        retry_after_seconds,
    })
}

fn pending_metadata_from_error(error: &anyhow::Error) -> Option<&PendingMetadata> {
    error.downcast_ref::<BoringCacheError>()?.pending_metadata()
}

fn server_owned_pending_publish(metadata: &PendingMetadata) -> bool {
    if metadata.code.as_deref() != Some("pending_publish") {
        return false;
    }

    metadata.poll_path.is_some() || metadata.upload_session_id.is_some()
}

fn should_accept_server_owned_pending_after_timeout(
    accept_server_owned_pending_after_timeout: bool,
    metadata: &PendingMetadata,
) -> bool {
    accept_server_owned_pending_after_timeout && server_owned_pending_publish(metadata)
}

fn pending_publish_poll_delay(retry_after_seconds: Option<u64>) -> Duration {
    Duration::from_secs(retry_after_seconds.unwrap_or(1).max(1))
        .max(PENDING_PUBLISH_POLL_INTERVAL)
        .min(PENDING_PUBLISH_POLL_MAX_INTERVAL)
}

fn is_rate_limit_error(error: &anyhow::Error) -> bool {
    let lower = format!("{error:#}").to_lowercase();
    lower.contains("429")
        || lower.contains("too many requests")
        || lower.contains("rate limit exceeded")
        || lower.contains("throttled")
}

fn pending_publish_poll_error_delay(
    retry_after_seconds: Option<u64>,
    error: &anyhow::Error,
    consecutive_errors: u32,
) -> Duration {
    let base = pending_publish_poll_delay(retry_after_seconds);
    if !is_rate_limit_error(error) {
        return base;
    }

    // Start a little slower on throttling to avoid hammering publish-status APIs.
    let throttled_base = base.max(Duration::from_secs(2));
    let multiplier = 1u32 << consecutive_errors.saturating_sub(1).min(4);
    throttled_base
        .checked_mul(multiplier)
        .unwrap_or(PENDING_PUBLISH_POLL_MAX_INTERVAL)
        .min(PENDING_PUBLISH_POLL_MAX_INTERVAL)
}

fn confirm_publish_error_delay(error: &anyhow::Error, consecutive_errors: u32) -> Duration {
    pending_publish_poll_error_delay(Some(1), error, consecutive_errors)
}

fn should_retry_pending_publish_poll_error(error: &anyhow::Error) -> bool {
    if crate::error::is_connection_error(error) {
        return true;
    }

    let lower = format!("{error:#}").to_lowercase();
    is_rate_limit_error(error)
        || lower.contains("503")
        || lower.contains("service unavailable")
        || lower.contains("504")
        || lower.contains("gateway timeout")
        || lower.contains("request timeout")
        || lower.contains("timed out")
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
        uploaded_at: response.uploaded_at,
        tag: None,
        tag_status: response.status,
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

fn shutdown_pending_publish_grace() -> Duration {
    let seconds = std::env::var(SHUTDOWN_PENDING_PUBLISH_GRACE_SECS_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .unwrap_or(DEFAULT_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS);
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
mod tests {
    use super::*;
    use crate::api::cache;
    use crate::test_env;
    use mockito::Matcher;
    use serde_json::json;
    use std::net::TcpListener;

    fn networking_available() -> bool {
        match TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                drop(listener);
                true
            }
            Err(_) => false,
        }
    }

    fn digest_for(index: usize) -> String {
        format!("sha256:{index:064x}")
    }

    #[test]
    fn test_url_building() {
        super::ensure_crypto_provider();
        let client = ApiClient {
            client: Client::new(),
            transfer_client: Client::new(),
            base_url: "https://api.example.com".to_string(),
            v1_base_url: "https://api.example.com/v1".to_string(),
            v2_base_url: "https://api.example.com/v2".to_string(),
            auth_token: None,
            capabilities: Arc::new(RwLock::new(None)),
        };

        assert_eq!(
            client.build_url("test/endpoint"),
            "https://api.example.com/test/endpoint"
        );

        assert_eq!(
            client.build_url("/test/endpoint"),
            "https://api.example.com/test/endpoint"
        );
    }

    #[test]
    fn test_api_batch_concurrency_is_bounded() {
        assert_eq!(api_batch_concurrency_for_context(1, 4, false), 1);
        assert_eq!(api_batch_concurrency_for_context(4, 4, false), 4);
        assert_eq!(api_batch_concurrency_for_context(32, 4, false), 4);
        assert_eq!(api_batch_concurrency_for_context(32, 4, true), 8);
        assert_eq!(api_batch_concurrency_for_context(32, 2, true), 4);
    }

    #[test]
    fn test_blob_batch_maxes_use_fixed_defaults() {
        assert_eq!(blob_check_batch_max(), BLOB_CHECK_BATCH_MAX);
        assert_eq!(blob_url_batch_max(), BLOB_URL_BATCH_MAX);
    }

    #[test]
    fn test_blob_batch_concurrency_uses_machine_governor() {
        assert_eq!(blob_check_batch_concurrency(0), 1);
        assert_eq!(blob_url_batch_concurrency(0), 1);
        assert_eq!(blob_check_batch_concurrency(1), 1);
        assert_eq!(
            blob_check_batch_concurrency(10),
            api_batch_concurrency(10).clamp(1, 10)
        );
        assert_eq!(
            blob_url_batch_concurrency(10),
            api_batch_concurrency(10).clamp(1, 10)
        );
    }

    #[test]
    fn test_transfer_http2_enabled_defaults_true() {
        let _guard = test_env::lock();

        test_env::remove_var("BORINGCACHE_TRANSFER_HTTP2");
        assert!(transfer_http2_enabled());
    }

    #[test]
    fn test_transfer_http2_enabled_respects_false_values() {
        let _guard = test_env::lock();

        for value in ["0", "false", "FALSE", "no", "off"] {
            test_env::set_var("BORINGCACHE_TRANSFER_HTTP2", value);
            assert!(!transfer_http2_enabled(), "value {value} should disable h2");
        }
        test_env::remove_var("BORINGCACHE_TRANSFER_HTTP2");
    }

    #[test]
    fn test_transfer_http2_enabled_respects_true_and_unknown_values() {
        let _guard = test_env::lock();

        for value in ["1", "true", "TRUE", "yes", "on", "unexpected"] {
            test_env::set_var("BORINGCACHE_TRANSFER_HTTP2", value);
            assert!(transfer_http2_enabled(), "value {value} should enable h2");
        }
        test_env::remove_var("BORINGCACHE_TRANSFER_HTTP2");
    }

    #[test]
    fn test_derive_api_base_urls_from_v1() {
        let (v1, v2) = derive_api_base_urls("https://api.example.com/v1");
        assert_eq!(v1, "https://api.example.com/v1");
        assert_eq!(v2, "https://api.example.com/v2");
    }

    #[test]
    fn test_derive_api_base_urls_from_v2() {
        let (v1, v2) = derive_api_base_urls("https://api.example.com/v2");
        assert_eq!(v1, "https://api.example.com/v1");
        assert_eq!(v2, "https://api.example.com/v2");
    }

    #[test]
    fn test_derive_api_base_urls_from_unversioned_remote() {
        let (v1, v2) = derive_api_base_urls("https://api.example.com");
        assert_eq!(v1, "https://api.example.com/v1");
        assert_eq!(v2, "https://api.example.com/v2");
    }

    #[test]
    fn test_derive_api_base_urls_from_unversioned_localhost() {
        let (v1, v2) = derive_api_base_urls("http://127.0.0.1:1234");
        assert_eq!(v1, "http://127.0.0.1:1234/v1");
        assert_eq!(v2, "http://127.0.0.1:1234/v2");
    }

    #[test]
    fn test_derive_api_base_urls_from_empty_input_uses_default_base() {
        let (v1, v2) = derive_api_base_urls("   ");
        assert_eq!(v1, "https://api.boringcache.com/v1");
        assert_eq!(v2, "https://api.boringcache.com/v2");
    }

    #[test]
    fn test_default_base_url_matches_config() {
        let _guard = test_env::lock();

        // Isolate from user config by using a temp HOME directory
        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());
        test_env::remove_var("BORINGCACHE_API_URL");

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize without BORINGCACHE_API_URL or config file");

        // Restore original HOME
        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }

        let (_v1, expected_v2) =
            derive_api_base_urls(crate::config::Config::default_api_url_value());
        assert_eq!(client.base_url(), expected_v2);
    }

    #[tokio::test]
    async fn test_reqwest_rejects_newline_authorization_header_as_builder_error() {
        super::ensure_crypto_provider();
        let request = Client::new()
            .get("https://example.com")
            .header("Authorization", "Bearer test-token\n");
        let error = request
            .send()
            .await
            .expect_err("newline header should fail before send");

        assert!(error.is_builder(), "expected builder error, got: {error}");
    }

    #[test]
    fn test_new_with_token_override_trims_whitespace() {
        let _guard = test_env::lock();

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());
        test_env::remove_var("BORINGCACHE_API_TOKEN");

        let client = ApiClient::new_with_token_override(Some("  test-token\n".to_string()))
            .expect("client should initialize");
        assert_eq!(client.get_token().unwrap(), "test-token");

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
    }

    #[tokio::test]
    async fn test_authenticated_builder_errors_do_not_retry() {
        super::ensure_crypto_provider();
        let client = ApiClient {
            client: Client::new(),
            transfer_client: Client::new(),
            base_url: "https://api.example.com/v2".to_string(),
            v1_base_url: "https://api.example.com/v1".to_string(),
            v2_base_url: "https://api.example.com/v2".to_string(),
            auth_token: Some("test-token\n".to_string()),
            capabilities: Arc::new(RwLock::new(None)),
        };

        let (result, retry_count) = client
            .send_authenticated_request_with_retry_count(
                client.get_client().get("https://example.com"),
            )
            .await;

        let error = result.expect_err("invalid token header should fail");
        let message = error.to_string();
        assert_eq!(retry_count, 0);
        assert!(
            message.contains("Invalid API request before send"),
            "unexpected error message: {message}"
        );
        assert!(!message.contains("after 3 attempts"));
    }

    #[tokio::test]
    async fn test_public_builder_errors_do_not_retry() {
        super::ensure_crypto_provider();
        let client = ApiClient {
            client: Client::new(),
            transfer_client: Client::new(),
            base_url: "https://api.example.com/v2".to_string(),
            v1_base_url: "https://api.example.com/v1".to_string(),
            v2_base_url: "https://api.example.com/v2".to_string(),
            auth_token: None,
            capabilities: Arc::new(RwLock::new(None)),
        };

        let error = client
            .send_public_request(
                client
                    .get_client()
                    .get("https://example.com")
                    .header("Authorization", "Bearer test-token\n"),
            )
            .await
            .expect_err("invalid header should fail");
        let message = error.to_string();
        assert!(
            message.contains("Invalid API request before send"),
            "unexpected error message: {message}"
        );
        assert!(!message.contains("after 3 attempts"));
    }

    #[test]
    fn test_parse_error_payload_with_details() {
        let body = r#"{
            "success": false,
            "error": "Validation failed",
            "details": ["Tag is invalid", "Path is missing"],
            "code": "invalid_tag"
        }"#;

        let parsed = parse_error_payload(body).expect("payload should parse");
        assert_eq!(parsed.message, "Validation failed");
        assert_eq!(parsed.success, Some(false));
        assert_eq!(parsed.code.as_deref(), Some("invalid_tag"));
        assert_eq!(parsed.details.len(), 2);
        assert_eq!(parsed.details[0], "Tag is invalid");
    }

    #[test]
    fn test_format_error_message_includes_details() {
        let body = r#"{
            "success": false,
            "error": "Validation failed",
            "details": ["Tag is invalid"],
            "code": "invalid_tag"
        }"#;

        let payload = parse_error_payload(body).expect("payload should parse");
        let url = reqwest::Url::parse("https://api.boringcache.com/v1/test").unwrap();
        let message =
            format_error_message(StatusCode::UNPROCESSABLE_ENTITY, &url, Some(&payload), body);

        assert!(message.contains("422"));
        assert!(message.contains("Validation failed"));
        assert!(message.contains("invalid_tag"));
        assert!(message.contains("Tag is invalid"));
    }

    #[test]
    fn test_format_error_message_fallback() {
        let url = reqwest::Url::parse("https://api.boringcache.com/v1/test").unwrap();
        let message = format_error_message(StatusCode::BAD_REQUEST, &url, None, "plain error body");
        assert!(message.contains("plain error body"));
    }

    #[test]
    fn test_parse_conflict_metadata_prefers_current_pointer() {
        let body = r#"{
            "message": "publish conflict",
            "current_pointer": {
                "version": "42",
                "cache_entry_id": "entry-xyz",
                "tag": "main-tag"
            }
        }"#;

        let metadata = parse_conflict_metadata(body).expect("metadata should parse");
        assert_eq!(metadata.current_version.as_deref(), Some("42"));
        assert_eq!(
            metadata.current_cache_entry_id.as_deref(),
            Some("entry-xyz")
        );
        assert_eq!(metadata.current_tag.as_deref(), Some("main-tag"));
    }

    #[test]
    fn test_parse_conflict_metadata_returns_none_for_unrecognized_payload() {
        let body = r#"{
            "message": "publish conflict",
            "status": "conflict",
            "details": ["retry later"]
        }"#;

        assert!(parse_conflict_metadata(body).is_none());
    }

    #[test]
    fn test_parse_pending_metadata_extracts_polling_fields() {
        let body = r#"{
            "success": false,
            "error": "1 blob(s) not yet verified in storage — retry after upload completes",
            "code": "pending_publish",
            "details": {
                "cache_entry_id": "entry-1",
                "upload_session_id": "session-1",
                "publish_attempt_id": "attempt-1",
                "pending_blob_count": 1,
                "retry_after_seconds": 3,
                "poll_path": "/v2/workspaces/acme/demo/upload-sessions/session-1"
            }
        }"#;

        let parsed = parse_error_payload(body).expect("payload should parse");
        let metadata = parse_pending_metadata(body, Some(&parsed)).expect("metadata should parse");

        assert_eq!(metadata.code.as_deref(), Some("pending_publish"));
        assert_eq!(metadata.upload_session_id.as_deref(), Some("session-1"));
        assert_eq!(metadata.publish_attempt_id.as_deref(), Some("attempt-1"));
        assert_eq!(
            metadata.poll_path.as_deref(),
            Some("/v2/workspaces/acme/demo/upload-sessions/session-1")
        );
        assert_eq!(metadata.retry_after_seconds, Some(3));
    }

    #[test]
    fn test_server_owned_pending_publish_requires_publish_code_and_poll_target() {
        let metadata = PendingMetadata {
            code: Some("pending_publish".to_string()),
            upload_session_id: Some("session-1".to_string()),
            publish_attempt_id: None,
            poll_path: None,
            retry_after_seconds: Some(1),
        };
        assert!(server_owned_pending_publish(&metadata));

        let wrong_code = PendingMetadata {
            code: Some("blob_verification_pending".to_string()),
            ..metadata.clone()
        };
        assert!(!server_owned_pending_publish(&wrong_code));

        let no_locator = PendingMetadata {
            code: Some("pending_publish".to_string()),
            upload_session_id: None,
            publish_attempt_id: Some("attempt-1".to_string()),
            poll_path: None,
            retry_after_seconds: Some(1),
        };
        assert!(!server_owned_pending_publish(&no_locator));
    }

    #[test]
    fn test_pending_publish_timeout_acceptance_requires_opt_in() {
        let metadata = PendingMetadata {
            code: Some("pending_publish".to_string()),
            upload_session_id: Some("session-1".to_string()),
            publish_attempt_id: None,
            poll_path: None,
            retry_after_seconds: Some(1),
        };

        assert!(!should_accept_server_owned_pending_after_timeout(
            false, &metadata
        ));
        assert!(should_accept_server_owned_pending_after_timeout(
            true, &metadata
        ));
    }

    #[test]
    fn test_pending_publish_timeout_acceptance_still_requires_server_owned_pending() {
        let metadata = PendingMetadata {
            code: Some("blob_verification_pending".to_string()),
            upload_session_id: Some("session-1".to_string()),
            publish_attempt_id: None,
            poll_path: None,
            retry_after_seconds: Some(1),
        };

        assert!(!should_accept_server_owned_pending_after_timeout(
            true, &metadata
        ));
    }

    #[test]
    fn test_shutdown_pending_publish_policy_grace_starts_when_pending_is_observed() {
        let shutdown_requested = AtomicBool::new(true);
        let policy = ShutdownPendingPublishPolicy {
            shutdown_requested: Some(&shutdown_requested),
            grace: Duration::from_secs(5),
        };
        let metadata = PendingMetadata {
            code: Some("pending_publish".to_string()),
            upload_session_id: Some("session-1".to_string()),
            publish_attempt_id: Some("attempt-1".to_string()),
            poll_path: Some("/v2/workspaces/ns/ws/upload-sessions/session-1".to_string()),
            retry_after_seconds: Some(1),
        };

        assert!(!policy.should_accept_server_owned_pending(&metadata, Instant::now()));
        assert!(policy.should_accept_server_owned_pending(
            &metadata,
            Instant::now() - Duration::from_secs(5)
        ));
    }

    #[test]
    fn test_pending_publish_poll_delay_respects_retry_after_floor_and_cap() {
        assert_eq!(
            pending_publish_poll_delay(Some(0)),
            Duration::from_secs(1),
            "retry_after=0 should floor to 1s"
        );
        assert_eq!(
            pending_publish_poll_delay(Some(1)),
            Duration::from_secs(1),
            "retry_after=1 should remain 1s"
        );
        assert_eq!(
            pending_publish_poll_delay(Some(3)),
            Duration::from_secs(3),
            "retry_after=3 should remain 3s"
        );
        assert_eq!(
            pending_publish_poll_delay(Some(60)),
            PENDING_PUBLISH_POLL_MAX_INTERVAL,
            "retry_after should cap at max interval"
        );
    }

    #[test]
    fn test_pending_publish_poll_error_delay_backs_off_on_rate_limit() {
        let throttled = anyhow::anyhow!("Transient error: 429 Too Many Requests");

        assert_eq!(
            pending_publish_poll_error_delay(Some(1), &throttled, 1),
            Duration::from_secs(2)
        );
        assert_eq!(
            pending_publish_poll_error_delay(Some(1), &throttled, 2),
            Duration::from_secs(4)
        );
        assert_eq!(
            pending_publish_poll_error_delay(Some(1), &throttled, 3),
            Duration::from_secs(8)
        );
        assert_eq!(
            pending_publish_poll_error_delay(Some(1), &throttled, 4),
            PENDING_PUBLISH_POLL_MAX_INTERVAL
        );
        assert_eq!(
            pending_publish_poll_error_delay(Some(1), &throttled, 5),
            PENDING_PUBLISH_POLL_MAX_INTERVAL,
            "rate-limit backoff should cap at max interval"
        );
    }

    #[test]
    fn test_pending_publish_poll_error_delay_uses_base_for_non_rate_limit_errors() {
        let unavailable = anyhow::anyhow!("503 Service Unavailable");
        assert_eq!(
            pending_publish_poll_error_delay(Some(2), &unavailable, 4),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn test_should_retry_pending_publish_poll_error_detects_transient_statuses() {
        let throttled = anyhow::anyhow!(
            "Failed to poll pending publish status: API request failed after 3 attempts: Transient error: 429 Too Many Requests"
        );
        assert!(should_retry_pending_publish_poll_error(&throttled));

        let throttled_message = anyhow::anyhow!("Rate limit exceeded. Please try again later.");
        assert!(should_retry_pending_publish_poll_error(&throttled_message));

        let unavailable = anyhow::anyhow!("Server returned 503 Service Unavailable");
        assert!(should_retry_pending_publish_poll_error(&unavailable));

        let permanent = anyhow::anyhow!("Server returned 403 Forbidden");
        assert!(!should_retry_pending_publish_poll_error(&permanent));
    }

    #[test]
    fn test_should_retry_confirm_publish_error_detects_transient_statuses() {
        let internal =
            anyhow::anyhow!("confirm failed: Server error (500). Please try again later.");
        assert!(should_retry_confirm_publish_error(&internal));

        let throttled =
            anyhow::anyhow!("Rate limit exceeded (429 Too Many Requests). Please try again later.");
        assert!(should_retry_confirm_publish_error(&throttled));

        let permanent = anyhow::anyhow!("Server returned 403 Forbidden");
        assert!(!should_retry_confirm_publish_error(&permanent));
    }

    #[test]
    fn test_confirm_publish_error_delay_backs_off_from_base_interval() {
        let internal = anyhow::anyhow!("confirm failed: Server error (500)");
        assert_eq!(
            confirm_publish_error_delay(&internal, 1),
            Duration::from_secs(1)
        );
        let throttled = anyhow::anyhow!("429 Too Many Requests");
        assert_eq!(
            confirm_publish_error_delay(&throttled, 1),
            Duration::from_secs(2)
        );
    }

    #[test]
    fn test_retryable_api_status_includes_transient_server_errors() {
        assert!(is_retryable_api_status(StatusCode::REQUEST_TIMEOUT));
        assert!(is_retryable_api_status(StatusCode::TOO_MANY_REQUESTS));
        assert!(is_retryable_api_status(StatusCode::INTERNAL_SERVER_ERROR));
        assert!(is_retryable_api_status(StatusCode::BAD_GATEWAY));
        assert!(is_retryable_api_status(StatusCode::SERVICE_UNAVAILABLE));
        assert!(is_retryable_api_status(StatusCode::GATEWAY_TIMEOUT));
        assert!(!is_retryable_api_status(StatusCode::FORBIDDEN));
    }

    #[test]
    fn test_confirm_publish_request_timeout_uses_default_and_env_override() {
        let _guard = test_env::lock();
        test_env::remove_var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV);
        assert_eq!(
            confirm_publish_request_timeout(),
            Duration::from_secs(DEFAULT_CONFIRM_PUBLISH_TIMEOUT_SECS)
        );

        test_env::set_var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV, "7");
        assert_eq!(confirm_publish_request_timeout(), Duration::from_secs(7));

        test_env::remove_var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV);
    }

    #[test]
    fn test_shutdown_pending_publish_grace_uses_default_and_env_override() {
        let _guard = test_env::lock();
        test_env::remove_var(SHUTDOWN_PENDING_PUBLISH_GRACE_SECS_ENV);
        assert_eq!(
            shutdown_pending_publish_grace(),
            Duration::from_secs(DEFAULT_SHUTDOWN_PENDING_PUBLISH_GRACE_SECS)
        );

        test_env::set_var(SHUTDOWN_PENDING_PUBLISH_GRACE_SECS_ENV, "0");
        assert_eq!(shutdown_pending_publish_grace(), Duration::from_secs(0));

        test_env::set_var(SHUTDOWN_PENDING_PUBLISH_GRACE_SECS_ENV, "3");
        assert_eq!(shutdown_pending_publish_grace(), Duration::from_secs(3));

        test_env::remove_var(SHUTDOWN_PENDING_PUBLISH_GRACE_SECS_ENV);
    }

    #[test]
    fn test_transfer_connect_timeout_uses_default_and_env_override() {
        let _guard = test_env::lock();
        test_env::remove_var(TRANSFER_CONNECT_TIMEOUT_SECS_ENV);
        assert_eq!(
            transfer_connect_timeout(),
            Duration::from_secs(DEFAULT_TRANSFER_CONNECT_TIMEOUT_SECS)
        );

        test_env::set_var(TRANSFER_CONNECT_TIMEOUT_SECS_ENV, "15");
        assert_eq!(transfer_connect_timeout(), Duration::from_secs(15));

        test_env::remove_var(TRANSFER_CONNECT_TIMEOUT_SECS_ENV);
    }

    #[test]
    fn test_determine_publish_mode_prefers_explicit_storage_mode() {
        let request = cache::ConfirmRequest {
            manifest_digest: "sha256:abc".to_string(),
            manifest_size: 1,
            manifest_etag: None,
            archive_size: Some(1),
            archive_etag: None,
            blob_count: Some(5),
            blob_total_size_bytes: Some(100),
            file_count: None,
            uncompressed_size: None,
            compressed_size: None,
            storage_mode: Some("archive".to_string()),
            tag: None,
            write_scope_tag: None,
        };

        assert_eq!(determine_publish_mode(&request), "replace");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_manifest_check_request_body() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!("skipping test_manifest_check_request_body: networking disabled in sandbox");
            return;
        }

        // Isolate from user config
        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/check")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .match_body(Matcher::PartialJson(json!({
                "manifest_checks": [
                    {
                        "tag": "abc123def456",
                        "manifest_root_digest": "blake3:abc"
                    }
                ]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"results":[{"tag":"abc123def456","exists":true,"manifest_root_digest":"blake3:abc"}]}"#)
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let response = client
            .check_manifests(
                "ns/ws",
                &[cache::ManifestCheckRequest {
                    tag: "abc123def456".to_string(),
                    manifest_root_digest: "blake3:abc".to_string(),
                    lookup: None,
                }],
            )
            .await
            .expect("manifest check should succeed");

        assert_eq!(response.results.len(), 1);
        let result = &response.results[0];
        assert!(result.exists);
        assert_eq!(result.tag, "abc123def456");

        mock.assert_async().await;

        // Cleanup: restore HOME and remove API URL override
        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_check_request_body() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!("skipping test_blob_check_request_body: networking disabled in sandbox");
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/check")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .match_body(Matcher::PartialJson(json!({
                "verify_storage": true,
                "blobs": [
                    {
                        "digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                        "size_bytes": 1234
                    }
                ]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"results":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","exists":true}]}"#)
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let response = client
            .check_blobs(
                "ns/ws",
                &[cache::BlobDescriptor {
                    digest:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    size_bytes: 1234,
                }],
                true,
            )
            .await
            .expect("blob check should succeed");

        assert_eq!(response.results.len(), 1);
        assert!(response.results[0].exists);

        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_check_batches_large_requests() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_blob_check_batches_large_requests: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/check")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .expect(2)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"results":[{"digest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","exists":true}]}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let blobs = (0..(BLOB_CHECK_BATCH_MAX + 1))
            .map(|index| cache::BlobDescriptor {
                digest: digest_for(index),
                size_bytes: 1,
            })
            .collect::<Vec<_>>();

        let response = client
            .check_blobs("ns/ws", &blobs, false)
            .await
            .expect("blob check should succeed");
        assert_eq!(response.results.len(), 2);

        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_upload_urls_batches_large_requests() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_blob_upload_urls_batches_large_requests: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/stage")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .expect(2)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"upload_urls":[{"digest":"sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","url":"https://example.com/upload","headers":{}}],"already_present":[]}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let blobs = (0..(BLOB_URL_BATCH_MAX + 1))
            .map(|index| cache::BlobDescriptor {
                digest: digest_for(index),
                size_bytes: 1,
            })
            .collect::<Vec<_>>();

        let response = client
            .blob_upload_urls("ns/ws", "entry-1", &blobs)
            .await
            .expect("blob upload urls should succeed");
        assert_eq!(response.upload_urls.len(), 2);

        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_upload_urls_sends_cache_entry_id() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_blob_upload_urls_sends_cache_entry_id: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/stage")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::PartialJsonString(
                r#"{"cache_entry_id":"test-entry-42"}"#.to_string(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"upload_urls":[],"already_present":["sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let blobs = vec![cache::BlobDescriptor {
            digest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_string(),
            size_bytes: 100,
        }];

        let response = client
            .blob_upload_urls("ns/ws", "test-entry-42", &blobs)
            .await
            .expect("blob upload urls should succeed");
        assert_eq!(response.already_present.len(), 1);

        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_download_urls_batches_large_requests() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_blob_download_urls_batches_large_requests: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/download-urls")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .expect(2)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"download_urls":[{"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","url":"https://example.com/download"}],"missing":[]}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let blobs = (0..(BLOB_URL_BATCH_MAX + 1))
            .map(|index| cache::BlobDescriptor {
                digest: digest_for(index),
                size_bytes: 1,
            })
            .collect::<Vec<_>>();

        let response = client
            .blob_download_urls("ns/ws", "entry-1", &blobs, false)
            .await
            .expect("blob download urls should succeed");
        assert_eq!(response.download_urls.len(), 2);

        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_download_urls_can_verify_storage() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_blob_download_urls_can_verify_storage: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/download-urls")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .match_body(Matcher::PartialJson(json!({
                "cache_entry_id": "entry-verify",
                "verify_storage": true,
                "blobs": [{
                    "digest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "size_bytes": 42
                }]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"download_urls":[{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","url":"https://example.com/download"}],"missing":[]}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let blobs = vec![cache::BlobDescriptor {
            digest: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                .to_string(),
            size_bytes: 42,
        }];

        let response = client
            .blob_download_urls("ns/ws", "entry-verify", &blobs, true)
            .await
            .expect("blob download urls should succeed");
        assert_eq!(response.download_urls.len(), 1);

        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_cache_inspect_request() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!("skipping test_cache_inspect_request: networking disabled in sandbox");
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v2/workspaces/ns/ws/caches/inspect/ruby-deps")
            .match_header("authorization", "Bearer test-token")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"workspace":{"name":"Rails","slug":"ns/ws"},"identifier":{"query":"ruby-deps","matched_by":"tag"},"entry":{"id":"entry-1","primary_tag":"ruby-deps","status":"ready","manifest_root_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","manifest_digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","manifest_format_version":1,"storage_mode":"archive","stored_size_bytes":1024,"uncompressed_size":4096,"compressed_size":1024,"archive_size":1024,"file_count":32,"compression_algorithm":"zstd","blob_count":null,"blob_total_size_bytes":null,"cas_layout":null,"storage_verified":false,"hit_count":7,"created_at":"2026-03-31T12:00:00Z","uploaded_at":"2026-03-31T12:01:00Z","last_accessed_at":"2026-03-31T12:02:00Z","expires_at":null,"encrypted":false,"encryption_algorithm":null,"encryption_recipient_hint":null,"server_signed":false,"server_signed_at":null},"tags":[{"name":"ruby-deps","primary":true,"system":false,"created_at":"2026-03-31T12:00:00Z","updated_at":"2026-03-31T12:00:00Z"}],"versions":{"tag":"ruby-deps","version_count":1,"max_versions":10,"current":true,"total_storage_bytes":1024},"performance":{"total_operations":1,"saves":0,"restores":1,"avg_restore_ms":120.0,"avg_save_ms":0.0,"errors":0,"avg_download_speed":0.0,"avg_upload_speed":0.0,"last_operation":"2026-03-31T12:02:00Z","error_rate":0.0}}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let response = client
            .inspect_cache("ns/ws", "ruby-deps")
            .await
            .expect("cache inspect should succeed")
            .expect("cache inspect should return a payload");

        assert_eq!(response.workspace.slug, "ns/ws");
        assert_eq!(response.identifier.matched_by, "tag");
        assert_eq!(response.entry.id, "entry-1");
        assert_eq!(response.tags.len(), 1);

        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_create_cli_connect_session_without_auth_token() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_create_cli_connect_session_without_auth_token: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());
        test_env::remove_var("BORINGCACHE_API_TOKEN");

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/cli-connect/sessions")
            .match_header("content-type", "application/json")
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"session_id":"abc123","poll_token":"poll-secret","user_code":"ABCD-EF12","verification_url":"https://boringcache.com/cli/connect","authorize_url":"https://boringcache.com/cli/connect/abc123","expires_at":"2026-03-02T12:00:00Z","poll_interval_seconds":3}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new().expect("client should initialize without auth token");
        let response = client
            .create_cli_connect_session()
            .await
            .expect("cli connect session should be created");

        assert_eq!(response.session_id, "abc123");
        assert_eq!(response.poll_token, "poll-secret");
        assert_eq!(response.user_code, "ABCD-EF12");
        assert_eq!(
            response.verification_url,
            "https://boringcache.com/cli/connect"
        );
        assert_eq!(response.poll_interval_seconds, 3);
        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_poll_cli_connect_session_rejects_invalid_poll_token() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_poll_cli_connect_session_rejects_invalid_poll_token: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());
        test_env::remove_var("BORINGCACHE_API_TOKEN");

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v2/cli-connect/sessions/abc123")
            .match_header("x-boringcache-connect-token", "invalid-token")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"error":"Invalid poll token"}"#)
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new().expect("client should initialize without auth token");
        let error = client
            .poll_cli_connect_session("abc123", "invalid-token")
            .await
            .expect_err("polling with invalid token should fail");
        let message = error.to_string();
        assert!(
            message.contains("CLI connect poll rejected"),
            "unexpected error message: {message}"
        );
        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_start_cli_connect_email_auth_without_auth_token() {
        let _guard = test_env::lock();

        if !networking_available() {
            eprintln!(
                "skipping test_start_cli_connect_email_auth_without_auth_token: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        test_env::set_var("HOME", temp_home.path());
        test_env::remove_var("BORINGCACHE_API_TOKEN");

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/cli-connect/sessions/abc123/email-auth")
            .match_header("content-type", "application/json")
            .match_body(
                Matcher::Json(json!({
                    "email": "new@example.com",
                    "name": "New User",
                    "username": "new-user"
                })),
            )
            .with_status(201)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"session_id":"abc123","status":"email_sent","next_step":"Check your email to continue, then return to approve CLI access.","field_errors":{}}"#,
            )
            .create_async()
            .await;

        test_env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new().expect("client should initialize without auth token");
        let response = client
            .start_cli_connect_email_auth(
                "abc123",
                &crate::api::models::cli_connect::CliConnectEmailAuthRequest {
                    email: "new@example.com".to_string(),
                    name: Some("New User".to_string()),
                    username: Some("new-user".to_string()),
                },
            )
            .await
            .expect("cli connect email auth should succeed");

        assert_eq!(response.session_id, "abc123");
        assert_eq!(response.status, "email_sent");
        mock.assert_async().await;

        if let Some(home) = original_home {
            test_env::set_var("HOME", home);
        }
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[test]
    fn test_map_restore_result_prefers_top_level_cas_fields() {
        let mapped = ApiClient::map_restore_result(cache::RestoreResult {
            tag: "cas-tag".to_string(),
            primary_tag: Some("cas-tag-root".to_string()),
            signature_tag: Some("cas-signature-tag".to_string()),
            status: "hit".to_string(),
            cache_entry_id: Some("entry-1".to_string()),
            manifest_root_digest: Some(
                "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                    .to_string(),
            ),
            manifest_digest: None,
            manifest_url: Some("https://example.test/manifest".to_string()),
            compression_algorithm: Some("zstd".to_string()),
            storage_mode: Some("cas".to_string()),
            blob_count: Some(9),
            blob_total_size_bytes: Some(4096),
            cas_layout: Some("oci-v1".to_string()),
            archive_urls: vec![],
            metadata: Some(cache::RestoreMetadata {
                manifest_root_digest: None,
                total_size_bytes: Some(99),
                storage_mode: Some("archive".to_string()),
                blob_count: Some(1),
                blob_total_size_bytes: Some(1),
                cas_layout: Some("file-v1".to_string()),
                uncompressed_size: None,
                compressed_size: None,
                file_count: None,
                compression_algorithm: None,
                signature_tag: Some("ignored-metadata-tag".to_string()),
            }),
            error: None,
            pending: false,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: false,
        });

        assert_eq!(mapped.primary_tag.as_deref(), Some("cas-tag-root"));
        assert_eq!(mapped.signature_tag.as_deref(), Some("cas-signature-tag"));
        assert_eq!(mapped.storage_mode.as_deref(), Some("cas"));
        assert_eq!(mapped.blob_count, Some(9));
        assert_eq!(mapped.blob_total_size_bytes, Some(4096));
        assert_eq!(mapped.cas_layout.as_deref(), Some("oci-v1"));
    }

    #[test]
    fn test_map_restore_result_uses_metadata_cas_fields_as_fallback() {
        let mapped = ApiClient::map_restore_result(cache::RestoreResult {
            tag: "cas-tag".to_string(),
            primary_tag: None,
            signature_tag: None,
            status: "hit".to_string(),
            cache_entry_id: Some("entry-2".to_string()),
            manifest_root_digest: None,
            manifest_digest: None,
            manifest_url: Some("https://example.test/manifest".to_string()),
            compression_algorithm: Some("zstd".to_string()),
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            archive_urls: vec![],
            metadata: Some(cache::RestoreMetadata {
                manifest_root_digest: Some(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_string(),
                ),
                total_size_bytes: Some(100),
                storage_mode: Some("cas".to_string()),
                blob_count: Some(3),
                blob_total_size_bytes: Some(2048),
                cas_layout: Some("bazel-v2".to_string()),
                uncompressed_size: None,
                compressed_size: None,
                file_count: None,
                compression_algorithm: None,
                signature_tag: Some("metadata-signature-tag".to_string()),
            }),
            error: None,
            pending: false,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: false,
        });

        assert_eq!(mapped.storage_mode.as_deref(), Some("cas"));
        assert_eq!(
            mapped.signature_tag.as_deref(),
            Some("metadata-signature-tag")
        );
        assert_eq!(mapped.blob_count, Some(3));
        assert_eq!(mapped.blob_total_size_bytes, Some(2048));
        assert_eq!(mapped.cas_layout.as_deref(), Some("bazel-v2"));
    }
}
