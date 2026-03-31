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
const BLOB_CHECK_BATCH_MAX_ENV: &str = "BORINGCACHE_CACHE_CHECK_BATCH_MAX";
const BLOB_URL_BATCH_MAX_ENV: &str = "BORINGCACHE_CACHE_URL_BATCH_MAX";
const BLOB_CHECK_BATCH_CONCURRENCY_ENV: &str = "BORINGCACHE_CACHE_CHECK_BATCH_CONCURRENCY";
const BLOB_URL_BATCH_CONCURRENCY_ENV: &str = "BORINGCACHE_CACHE_URL_BATCH_CONCURRENCY";
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
const PENDING_PUBLISH_POLL_TIMEOUT: Duration = Duration::from_secs(60);
const PENDING_PUBLISH_POLL_INTERVAL: Duration = Duration::from_millis(500);
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

impl ApiClient {
    pub fn new() -> Result<Self> {
        Self::new_with_token_override(None)
    }

    pub fn for_restore() -> Result<Self> {
        Self::new_for_purpose(AuthPurpose::Restore)
    }

    pub fn for_save() -> Result<Self> {
        Self::new_for_purpose(AuthPurpose::Save)
    }

    pub fn for_admin() -> Result<Self> {
        Self::new_for_purpose(AuthPurpose::Admin)
    }

    pub fn new_for_purpose(purpose: AuthPurpose) -> Result<Self> {
        Self::new_with_token_override_for_purpose(None, purpose)
    }

    pub fn new_with_token_override(token_override: Option<String>) -> Result<Self> {
        Self::new_with_token_override_for_purpose(token_override, AuthPurpose::Default)
    }

    pub fn new_with_token_override_for_purpose(
        token_override: Option<String>,
        purpose: AuthPurpose,
    ) -> Result<Self> {
        let config = if token_override.is_some()
            || matches!(purpose, AuthPurpose::Default | AuthPurpose::Restore)
        {
            Config::load_for_auth_purpose(purpose).ok()
        } else {
            Some(Config::load_for_auth_purpose(purpose)?)
        };

        let cli_version = env!("CARGO_PKG_VERSION");
        let user_agent = format!("BoringCache-CLI/{cli_version}");

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_str(&user_agent).context("Invalid user agent")?,
        );

        headers.insert(
            "X-BoringCache-Client-Type",
            reqwest::header::HeaderValue::from_static("CLI"),
        );

        headers.insert(
            "X-BoringCache-CLI-Version",
            reqwest::header::HeaderValue::from_str(cli_version).context("Invalid CLI version")?,
        );
        headers.insert(
            "X-BoringCache-Pending-Publish-Poll",
            reqwest::header::HeaderValue::from_static("1"),
        );

        let client = build_api_client_with_headers(Some(headers.clone()))?;
        let transfer_client = build_transfer_client_with_headers(Some(headers))?;

        let mut auth_token = normalize_optional_token(token_override);
        let mut base_url = crate::config::env_var("BORINGCACHE_API_URL");

        if let Some(cfg) = config.as_ref() {
            if auth_token.is_none() {
                auth_token = normalize_optional_token(Some(cfg.token.clone()));
            }
            if base_url.is_none() {
                base_url = Some(cfg.api_url.clone());
            }
        }

        let configured_base_url =
            base_url.unwrap_or_else(|| crate::config::Config::default_api_url_value().to_string());
        let (v1_base_url, v2_base_url) = derive_api_base_urls(&configured_base_url);

        let client = Self {
            client,
            transfer_client,
            base_url: v2_base_url.clone(),
            v1_base_url,
            v2_base_url,
            auth_token,
            capabilities: Arc::new(RwLock::new(None)),
        };

        debug!(
            "ApiClient configured base_url={} v1_base_url={} token_configured={}",
            client.base_url,
            client.v1_base_url,
            client.auth_token.is_some()
        );

        Ok(client)
    }

    pub fn get_client(&self) -> &Client {
        &self.client
    }

    pub fn transfer_client(&self) -> &Client {
        &self.transfer_client
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn v1_base_url(&self) -> &str {
        &self.v1_base_url
    }

    pub fn v2_base_url(&self) -> &str {
        &self.v2_base_url
    }

    pub fn get_token(&self) -> Result<&str> {
        self.auth_token
            .as_deref()
            .context("No authentication token configured")
    }

    fn build_url_from_base(base_url: &str, endpoint: &str) -> String {
        format!(
            "{}/{}",
            base_url.trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        )
    }

    pub fn build_url(&self, endpoint: &str) -> String {
        Self::build_url_from_base(&self.base_url, endpoint)
    }

    pub fn build_v1_url(&self, endpoint: &str) -> String {
        Self::build_url_from_base(&self.v1_base_url, endpoint)
    }

    pub fn build_v2_url(&self, endpoint: &str) -> String {
        Self::build_url_from_base(&self.v2_base_url, endpoint)
    }

    pub fn build_workspace_url(&self, workspace: &str, path: &str) -> Result<String> {
        let (namespace_slug, workspace_slug) = super::parse_workspace_slug(workspace)?;
        Ok(format!(
            "workspaces/{namespace_slug}/{workspace_slug}{path}"
        ))
    }

    fn workspace_endpoint(&self, workspace: &str, path: &str) -> Result<String> {
        let (namespace_slug, workspace_slug) = super::parse_workspace_slug(workspace)?;
        let mut endpoint = format!("workspaces/{}/{}", namespace_slug, workspace_slug);
        let trimmed = path.trim();

        if !trimmed.is_empty() {
            endpoint.push('/');
            endpoint.push_str(trimmed.trim_start_matches('/'));
        }

        Ok(endpoint)
    }

    pub async fn get<T>(&self, endpoint: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.get_v2(endpoint).await
    }

    pub async fn get_v1<T>(&self, endpoint: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.get_with_base(&self.v1_base_url, endpoint).await
    }

    pub async fn get_v2<T>(&self, endpoint: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        self.get_with_base(&self.v2_base_url, endpoint).await
    }

    async fn get_with_base<T>(&self, base_url: &str, endpoint: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self.get_response_with_base(base_url, endpoint).await?;
        self.parse_json_response(response).await
    }

    async fn get_response_with_base(&self, base_url: &str, endpoint: &str) -> Result<Response> {
        let url = Self::build_url_from_base(base_url, endpoint);
        debug!("GET {}", url);
        self.send_authenticated_request(self.client.get(&url)).await
    }

    pub async fn post<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.post_v2(endpoint, body).await
    }

    pub async fn post_v1<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.post_with_base(&self.v1_base_url, endpoint, body).await
    }

    pub async fn post_v2<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.post_with_base(&self.v2_base_url, endpoint, body).await
    }

    pub async fn optimize(
        &self,
        request: &super::models::optimize::OptimizeRequest,
    ) -> Result<super::models::optimize::OptimizeResponse> {
        self.post_v2("optimize", request).await
    }

    pub async fn create_cli_connect_session(
        &self,
    ) -> Result<super::models::cli_connect::CliConnectSessionCreateResponse> {
        let url = self.build_v2_url("cli-connect/sessions");
        debug!("POST {}", url);

        let response = self
            .send_public_request(self.client.post(&url).json(&serde_json::json!({})))
            .await?;

        self.parse_json_response(response).await
    }

    pub async fn poll_cli_connect_session(
        &self,
        session_id: &str,
        poll_token: &str,
    ) -> Result<super::models::cli_connect::CliConnectSessionPollResponse> {
        let url = self.build_v2_url(&format!("cli-connect/sessions/{session_id}"));
        debug!("GET {}", url);

        let response = self
            .send_public_request(
                self.client
                    .get(&url)
                    .header("X-BoringCache-Connect-Token", poll_token),
            )
            .await?;

        if response.status() == StatusCode::UNAUTHORIZED {
            anyhow::bail!(
                "CLI connect poll rejected. Restart onboarding and approve the new session."
            );
        }

        self.parse_json_response(response).await
    }

    async fn post_with_base<T, R>(&self, base_url: &str, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let response = self
            .post_response_with_base(base_url, endpoint, body)
            .await?;
        self.parse_json_response(response).await
    }

    async fn post_response_with_base<T>(
        &self,
        base_url: &str,
        endpoint: &str,
        body: &T,
    ) -> Result<Response>
    where
        T: Serialize,
    {
        let url = Self::build_url_from_base(base_url, endpoint);
        debug!("POST {}", url);
        self.send_authenticated_request(self.client.post(&url).json(body))
            .await
    }

    pub async fn put<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.put_v2(endpoint, body).await
    }

    pub async fn put_v2<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = self.build_v2_url(endpoint);
        debug!("PUT {}", url);
        let response = self
            .send_authenticated_request(self.client.put(&url).json(body))
            .await?;
        self.parse_json_response(response).await
    }

    pub async fn send_authenticated_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Response> {
        let (result, _retry_count) = self
            .send_authenticated_request_with_retry_count(request)
            .await;
        result
    }

    async fn send_authenticated_request_with_retry_count(
        &self,
        request: reqwest::RequestBuilder,
    ) -> (Result<Response>, u32) {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(BoringCacheError::TokenNotFound);
        let token = match token {
            Ok(token) => token,
            Err(error) => return (Err(error.into()), 0),
        };

        if request.try_clone().is_none() {
            let request = request.header("Authorization", format!("Bearer {}", token));
            return (
                match request.send().await {
                    Ok(response) => Ok(response),
                    Err(err) if err.is_connect() => Err(BoringCacheError::ConnectionError(
                        "ERROR: Cannot connect to BoringCache server. Please check:\n\
                         • Is the API URL correct? (Check with: boringcache config)\n\
                         • Is there a firewall blocking the connection?"
                            .to_string(),
                    )
                    .into()),
                    Err(err) => Err(map_request_send_error(err)),
                },
                0,
            );
        }

        let retry_config = RetryConfig::new(false);
        let token_clone = token.clone();
        let mut attempts = 0u32;
        let mut last_retry_count = 0u32;

        let result = retry_config
            .retry_with_backoff("API request", || {
                attempts = attempts.saturating_add(1);
                let retry_count = attempts.saturating_sub(1);
                last_retry_count = retry_count;
                let request = request
                    .try_clone()
                    .expect("Request cloneability already verified");
                let token = token_clone.clone();
                async move {
                    let request = request.header("Authorization", format!("Bearer {}", token));
                    match request.send().await {
                        Ok(response) => {
                            if response.status() == StatusCode::TOO_MANY_REQUESTS
                                || response.status() == StatusCode::SERVICE_UNAVAILABLE
                                || response.status() == StatusCode::GATEWAY_TIMEOUT
                            {
                                anyhow::bail!("Transient error: {}", response.status());
                            }
                            Ok((response, retry_count))
                        }
                        Err(err) if err.is_connect() => Err(BoringCacheError::ConnectionError(
                            "ERROR: Cannot connect to BoringCache server. Please check:\n\
                                 • Is the API URL correct? (Check with: boringcache config)\n\
                                 • Is there a firewall blocking the connection?"
                                .to_string(),
                        )
                        .into()),
                        Err(err) if err.is_timeout() => {
                            anyhow::bail!("Request timeout: {}", err)
                        }
                        Err(err) => Err(map_request_send_error(err)),
                    }
                }
            })
            .await
            .map(|(response, _retry_count)| response);

        (result, last_retry_count)
    }

    fn v2_metric_path(endpoint: &str) -> String {
        format!("/v2/{}", endpoint.trim_start_matches('/'))
    }

    fn metric_workspace_from_endpoint(endpoint: &str) -> Option<String> {
        let mut parts = endpoint.trim_start_matches('/').split('/');
        if parts.next()? != "workspaces" {
            return None;
        }
        let namespace = parts.next()?.trim();
        let workspace = parts.next()?.trim();
        if namespace.is_empty() || workspace.is_empty() {
            return None;
        }
        Some(format!("{namespace}/{workspace}"))
    }

    fn response_request_id(response: &Response) -> Option<String> {
        response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
    }

    async fn post_v2_with_request_metrics<T, R>(
        &self,
        endpoint: &str,
        body: &T,
        operation: &'static str,
        batch_index: Option<u64>,
        batch_count: Option<u64>,
        batch_size: Option<u64>,
    ) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = self.build_v2_url(endpoint);
        let path = Self::v2_metric_path(endpoint);
        let workspace = Self::metric_workspace_from_endpoint(endpoint);
        let request_bytes = serde_json::to_vec(body).ok().map(|buf| buf.len() as u64);
        let started_at = Instant::now();
        let (response_result, retry_count) = self
            .send_authenticated_request_with_retry_count(self.client.post(&url).json(body))
            .await;

        match response_result {
            Ok(response) => {
                let status = response.status();
                let response_bytes = response.content_length();
                let request_id = Self::response_request_id(&response);
                observability::emit(
                    observability::ObservabilityEvent::success(
                        REQUEST_METRIC_SOURCE_CLI,
                        operation,
                        "POST",
                        path,
                        status.as_u16(),
                        started_at.elapsed().as_millis() as u64,
                        request_bytes,
                        response_bytes,
                        batch_index,
                        batch_count,
                        batch_size,
                        Some(retry_count),
                    )
                    .with_workspace(workspace.clone())
                    .with_request_id(request_id),
                );

                if status.is_success() {
                    self.parse_json_response(response).await
                } else {
                    Err(self.create_error_from_response(response).await)
                }
            }
            Err(error) => {
                observability::emit(
                    observability::ObservabilityEvent::failure(
                        REQUEST_METRIC_SOURCE_CLI,
                        operation,
                        "POST",
                        path,
                        error.to_string(),
                        started_at.elapsed().as_millis() as u64,
                        Some(retry_count),
                    )
                    .with_workspace(workspace),
                );
                Err(error)
            }
        }
    }

    async fn put_v2_with_request_metrics<T, R>(
        &self,
        endpoint: &str,
        body: &T,
        if_match: Option<&str>,
        operation: &'static str,
    ) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = self.build_v2_url(endpoint);
        let path = Self::v2_metric_path(endpoint);
        let workspace = Self::metric_workspace_from_endpoint(endpoint);
        let request_bytes = serde_json::to_vec(body).ok().map(|buf| buf.len() as u64);
        let started_at = Instant::now();
        let mut request = self.client.put(&url).json(body);
        if let Some(version) = if_match {
            request = request.header("If-Match", version);
        }
        if operation == CACHE_METRIC_ENDPOINT_OPERATION_CONFIRM_PUBLISH {
            request = request.timeout(confirm_publish_request_timeout());
        }
        let (response_result, retry_count) = self
            .send_authenticated_request_with_retry_count(request)
            .await;

        match response_result {
            Ok(response) => {
                let status = response.status();
                let response_bytes = response.content_length();
                let request_id = Self::response_request_id(&response);
                observability::emit(
                    observability::ObservabilityEvent::success(
                        REQUEST_METRIC_SOURCE_CLI,
                        operation,
                        "PUT",
                        path,
                        status.as_u16(),
                        started_at.elapsed().as_millis() as u64,
                        request_bytes,
                        response_bytes,
                        None,
                        None,
                        None,
                        Some(retry_count),
                    )
                    .with_workspace(workspace.clone())
                    .with_request_id(request_id),
                );

                if status.is_success() {
                    self.parse_json_response(response).await
                } else {
                    Err(self.create_error_from_response(response).await)
                }
            }
            Err(error) => {
                observability::emit(
                    observability::ObservabilityEvent::failure(
                        REQUEST_METRIC_SOURCE_CLI,
                        operation,
                        "PUT",
                        path,
                        error.to_string(),
                        started_at.elapsed().as_millis() as u64,
                        Some(retry_count),
                    )
                    .with_workspace(workspace),
                );
                Err(error)
            }
        }
    }

    async fn send_public_request(&self, request: reqwest::RequestBuilder) -> Result<Response> {
        if request.try_clone().is_none() {
            return match request.send().await {
                Ok(response) => Ok(response),
                Err(err) if err.is_connect() => Err(BoringCacheError::ConnectionError(
                    "ERROR: Cannot connect to BoringCache server. Please check:\n\
                         • Is the API URL correct? (Check with: boringcache config)\n\
                         • Is there a firewall blocking the connection?"
                        .to_string(),
                )
                .into()),
                Err(err) => Err(map_request_send_error(err)),
            };
        }

        let retry_config = RetryConfig::new(false);
        retry_config
            .retry_with_backoff("API request", || {
                let request = request
                    .try_clone()
                    .expect("Request cloneability already verified");

                async move {
                    match request.send().await {
                        Ok(response) => {
                            if response.status() == StatusCode::TOO_MANY_REQUESTS
                                || response.status() == StatusCode::SERVICE_UNAVAILABLE
                                || response.status() == StatusCode::GATEWAY_TIMEOUT
                            {
                                anyhow::bail!("Transient error: {}", response.status());
                            }
                            Ok(response)
                        }
                        Err(err) if err.is_connect() => Err(BoringCacheError::ConnectionError(
                            "ERROR: Cannot connect to BoringCache server. Please check:\n\
                                 • Is the API URL correct? (Check with: boringcache config)\n\
                                 • Is there a firewall blocking the connection?"
                                .to_string(),
                        )
                        .into()),
                        Err(err) if err.is_timeout() => {
                            anyhow::bail!("Request timeout: {}", err)
                        }
                        Err(err) => Err(map_request_send_error(err)),
                    }
                }
            })
            .await
    }

    pub async fn parse_json_response<T>(&self, response: Response) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        if response.status().is_success() {
            response
                .json()
                .await
                .context("Failed to parse JSON response")
        } else {
            Err(self.create_error_from_response(response).await)
        }
    }

    async fn create_error_from_response(&self, response: Response) -> anyhow::Error {
        let status = response.status();
        let url = response.url().clone();

        let error_body = response.text().await.unwrap_or_default();
        let parsed_payload = parse_error_payload(&error_body);

        match status {
            StatusCode::UNAUTHORIZED => {
                if url.path().contains("/session") {
                    anyhow::anyhow!("Authentication failed: Invalid or expired token")
                } else {
                    anyhow::anyhow!(
                        "Authentication failed: Invalid or expired token.\n\
                         Please run 'boringcache auth --token <token>' to authenticate."
                    )
                }
            }
            StatusCode::FORBIDDEN => {
                let message = parsed_payload
                    .as_ref()
                    .map(|payload| payload.message.clone())
                    .unwrap_or_else(|| {
                        "Access forbidden: You don't have permission to access this resource.\n\
                         Please check your authentication token and permissions."
                            .to_string()
                    });
                anyhow::anyhow!(message)
            }
            StatusCode::NOT_FOUND => {
                anyhow::anyhow!("Resource not found: {}", url)
            }
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::anyhow!("Rate limit exceeded. Please try again later.")
            }
            StatusCode::CONFLICT | StatusCode::PRECONDITION_FAILED => {
                let message = parsed_payload
                    .as_ref()
                    .map(|p| p.message.clone())
                    .unwrap_or_else(|| {
                        format_error_message(status, &url, parsed_payload.as_ref(), &error_body)
                    });
                match parse_conflict_metadata(&error_body) {
                    Some(metadata) => {
                        BoringCacheError::cache_conflict_with_metadata(message, metadata).into()
                    }
                    None => BoringCacheError::cache_conflict(message).into(),
                }
            }
            StatusCode::LOCKED => {
                match parse_pending_metadata(&error_body, parsed_payload.as_ref()) {
                    Some(metadata) => {
                        BoringCacheError::cache_pending_with_metadata(metadata).into()
                    }
                    None => BoringCacheError::cache_pending().into(),
                }
            }
            StatusCode::INTERNAL_SERVER_ERROR => {
                anyhow::anyhow!("Server error (500). Please try again later.")
            }
            StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT => {
                anyhow::anyhow!("Service temporarily unavailable. Please try again later.")
            }
            _ => {
                anyhow::anyhow!(format_error_message(
                    status,
                    &url,
                    parsed_payload.as_ref(),
                    &error_body
                ))
            }
        }
    }

    pub async fn retry_request<F, Fut, T>(&self, operation: F, max_retries: u32) -> Result<T>
    where
        F: Fn() -> Fut,
        Fut: std::future::Future<Output = Result<T>>,
    {
        let mut last_error = None;

        for attempt in 0..=max_retries {
            let operation_result = operation().await;
            match operation_result {
                Ok(result) => return Ok(result),
                Err(error) => {
                    last_error = Some(error);

                    if attempt < max_retries {
                        let delay = Duration::from_millis(1000 * 2_u64.pow(attempt));
                        sleep(delay).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("Retry operation failed")))
    }

    pub async fn patch<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.patch_v2(endpoint, body).await
    }

    pub async fn patch_v1<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.patch_with_base(&self.v1_base_url, endpoint, body)
            .await
    }

    pub async fn patch_v2<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.patch_with_base(&self.v2_base_url, endpoint, body)
            .await
    }

    async fn patch_with_base<T, R>(&self, base_url: &str, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = Self::build_url_from_base(base_url, endpoint);
        debug!("PATCH {}", url);
        let response = self
            .send_authenticated_request(self.get_client().patch(&url).json(body))
            .await?;
        self.parse_json_response(response).await
    }

    async fn put_v2_with_if_match<T, R>(
        &self,
        endpoint: &str,
        body: &T,
        if_match: Option<&str>,
        operation: &'static str,
    ) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        self.put_v2_with_request_metrics(endpoint, body, if_match, operation)
            .await
    }

    async fn get_capabilities(&self) -> CapabilityFlags {
        if let Some(flags) = self.capabilities.read().await.clone() {
            return flags;
        }

        let mut write_guard = self.capabilities.write().await;
        if let Some(flags) = write_guard.clone() {
            return flags;
        }

        let flags = match self.fetch_capabilities().await {
            Ok(flags) => flags,
            Err(err) => {
                debug!("Capabilities negotiation unavailable: {}", err);
                CapabilityFlags::default()
            }
        };
        *write_guard = Some(flags.clone());
        flags
    }

    async fn fetch_capabilities(&self) -> Result<CapabilityFlags> {
        let mut candidates = Vec::new();
        if !self.v2_base_url.is_empty() {
            candidates.push(self.v2_base_url.clone());
        }
        if !self.v1_base_url.is_empty() {
            candidates.push(self.v1_base_url.clone());
        }
        if !self.base_url.is_empty() {
            candidates.push(self.base_url.clone());
        }

        let mut seen = HashSet::new();
        for base in candidates {
            if !seen.insert(base.clone()) {
                continue;
            }

            let url = Self::build_url_from_base(&base, "capabilities");
            debug!("GET {}", url);
            let response = self
                .send_authenticated_request(self.client.get(&url))
                .await?;
            match response.status() {
                status if status.is_success() => {
                    let payload: CapabilityResponse = response
                        .json()
                        .await
                        .context("Failed to parse capabilities response")?;
                    debug!(
                        "Capabilities negotiated from {}: entry_create_v2={} blob_stage_v2={} tag_publish_v2={} finalize_only_v2={}",
                        url,
                        payload.features.entry_create_v2,
                        payload.features.blob_stage_v2,
                        payload.features.tag_publish_v2,
                        payload.features.finalize_only_v2
                    );
                    return Ok(payload.features);
                }
                StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED => continue,
                _ => return Err(self.create_error_from_response(response).await),
            }
        }

        Ok(CapabilityFlags::default())
    }

    async fn tag_pointer_v2(&self, workspace: &str, tag: &str) -> Result<Option<TagPointer>> {
        let encoded_tag = urlencoding::encode(tag);
        let endpoint =
            self.workspace_endpoint(workspace, &format!("caches/tags/{encoded_tag}/pointer"))?;
        let url = self.build_v2_url(&endpoint);
        debug!("GET {}", url);
        let response = self
            .send_authenticated_request(self.client.get(&url))
            .await?;
        let status = response.status();

        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !status.is_success() {
            return Err(self.create_error_from_response(response).await);
        }

        let pointer: TagPointer = response
            .json()
            .await
            .context("Failed to parse tag pointer response")?;
        Ok(Some(pointer))
    }

    pub async fn check_manifests(
        &self,
        workspace: &str,
        checks: &[super::models::cache::ManifestCheckRequest],
    ) -> Result<super::models::cache::ManifestCheckResponse> {
        ensure!(!checks.is_empty(), "manifest_checks cannot be empty");
        let endpoint = self.workspace_endpoint(workspace, "caches/check")?;
        let body = super::models::cache::ManifestCheckBatchRequest {
            manifest_checks: checks.to_vec(),
        };
        self.post_v2(&endpoint, &body).await
    }

    pub async fn check_blobs(
        &self,
        workspace: &str,
        blobs: &[super::models::cache::BlobDescriptor],
    ) -> Result<super::models::cache::BlobCheckResponse> {
        ensure!(!blobs.is_empty(), "blobs cannot be empty");
        let endpoint = self.workspace_endpoint(workspace, "caches/blobs/check")?;
        let batch_max = blob_check_batch_max();
        let chunk_count = blobs.len().div_ceil(batch_max);
        let batch_count = chunk_count as u64;
        if chunk_count == 1 {
            let body = super::models::cache::BlobCheckRequest {
                blobs: blobs.to_vec(),
            };
            return self
                .post_v2_with_request_metrics(
                    &endpoint,
                    &body,
                    BLOB_METRIC_ENDPOINT_OPERATION_CHECK,
                    Some(1),
                    Some(batch_count),
                    Some(blobs.len() as u64),
                )
                .await;
        }

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
            blob_check_batch_concurrency(chunk_count),
        ));
        let mut tasks = Vec::new();
        for (batch_idx, chunk) in blobs.chunks(batch_max).enumerate() {
            let client = self.clone();
            let endpoint = endpoint.clone();
            let chunk = chunk.to_vec();
            let semaphore = semaphore.clone();
            let batch_size = chunk.len() as u64;
            let batch_index = (batch_idx + 1) as u64;
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|e| anyhow::anyhow!("Blob check semaphore closed: {e}"))?;
                let body = super::models::cache::BlobCheckRequest { blobs: chunk };
                let response = client
                    .post_v2_with_request_metrics::<_, super::models::cache::BlobCheckResponse>(
                        &endpoint,
                        &body,
                        BLOB_METRIC_ENDPOINT_OPERATION_CHECK,
                        Some(batch_index),
                        Some(batch_count),
                        Some(batch_size),
                    )
                    .await;
                drop(_permit);
                response
            }));
        }

        let mut results = Vec::with_capacity(blobs.len());
        for task in tasks {
            let response = task.await.map_err(|e| anyhow::anyhow!(e))??;
            results.extend(response.results);
        }

        Ok(super::models::cache::BlobCheckResponse { results })
    }

    pub async fn blob_upload_urls(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        blobs: &[super::models::cache::BlobDescriptor],
    ) -> Result<super::models::cache::BlobUploadUrlsResponse> {
        ensure!(!blobs.is_empty(), "blobs cannot be empty");
        let endpoint = self.workspace_endpoint(workspace, "caches/blobs/stage")?;
        let entry_id = if cache_entry_id.is_empty() {
            None
        } else {
            Some(cache_entry_id.to_string())
        };
        let batch_max = blob_url_batch_max();
        let chunk_count = blobs.len().div_ceil(batch_max);
        let batch_count = chunk_count as u64;
        if chunk_count == 1 {
            let body = super::models::cache::BlobStageRequest {
                cache_entry_id: entry_id.clone(),
                blobs: blobs.to_vec(),
            };
            return self
                .post_v2_with_request_metrics(
                    &endpoint,
                    &body,
                    BLOB_METRIC_ENDPOINT_OPERATION_UPLOAD_URLS,
                    Some(1),
                    Some(batch_count),
                    Some(blobs.len() as u64),
                )
                .await;
        }

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
            blob_url_batch_concurrency(chunk_count),
        ));
        let mut tasks = Vec::new();
        for (batch_idx, chunk) in blobs.chunks(batch_max).enumerate() {
            let client = self.clone();
            let endpoint = endpoint.clone();
            let chunk = chunk.to_vec();
            let semaphore = semaphore.clone();
            let batch_size = chunk.len() as u64;
            let batch_index = (batch_idx + 1) as u64;
            let entry_id = entry_id.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|e| anyhow::anyhow!("Blob stage semaphore closed: {e}"))?;
                let body = super::models::cache::BlobStageRequest {
                    cache_entry_id: entry_id,
                    blobs: chunk,
                };
                let response = client
                    .post_v2_with_request_metrics::<
                        _,
                        super::models::cache::BlobUploadUrlsResponse,
                    >(
                        &endpoint,
                        &body,
                        BLOB_METRIC_ENDPOINT_OPERATION_UPLOAD_URLS,
                        Some(batch_index),
                        Some(batch_count),
                        Some(batch_size),
                    )
                    .await;
                drop(_permit);
                response
            }));
        }

        let mut upload_urls = Vec::new();
        let mut already_present = Vec::new();
        let mut upload_session_id = None;
        let mut upload_state = None;
        for task in tasks {
            let response = task.await.map_err(|e| anyhow::anyhow!(e))??;
            upload_urls.extend(response.upload_urls);
            already_present.extend(response.already_present);
            if upload_session_id.is_none() {
                upload_session_id = response.upload_session_id;
            }
            if upload_state.is_none() {
                upload_state = response.upload_state;
            }
        }

        Ok(super::models::cache::BlobUploadUrlsResponse {
            upload_urls,
            already_present: dedupe_strings(already_present),
            upload_session_id,
            upload_state,
        })
    }

    pub async fn commit_blob_receipts(
        &self,
        workspace: &str,
        upload_session_id: &str,
        receipts: &[super::models::cache::BlobReceipt],
    ) -> Result<Option<super::models::cache::UploadSessionStatusResponse>> {
        ensure!(
            !upload_session_id.trim().is_empty(),
            "upload_session_id must not be empty"
        );
        if receipts.is_empty() || !self.get_capabilities().await.upload_receipts_v2 {
            return Ok(None);
        }

        let endpoint = self.workspace_endpoint(
            workspace,
            &format!("upload-sessions/{upload_session_id}/blobs/commit"),
        )?;
        let mut last_response = None;
        for chunk in receipts.chunks(BLOB_RECEIPT_COMMIT_BATCH_MAX) {
            let body = super::models::cache::BlobReceiptCommitRequest {
                receipts: chunk.to_vec(),
            };
            last_response = Some(self.post_v2(&endpoint, &body).await?);
        }
        Ok(last_response)
    }

    pub async fn commit_manifest_receipt(
        &self,
        workspace: &str,
        upload_session_id: &str,
        request: &super::models::cache::ManifestReceiptCommitRequest,
    ) -> Result<Option<super::models::cache::UploadSessionStatusResponse>> {
        ensure!(
            !upload_session_id.trim().is_empty(),
            "upload_session_id must not be empty"
        );
        if !self.get_capabilities().await.upload_receipts_v2 {
            return Ok(None);
        }

        let endpoint = self.workspace_endpoint(
            workspace,
            &format!("upload-sessions/{upload_session_id}/manifest/commit"),
        )?;
        self.post_v2(&endpoint, request).await.map(Some)
    }

    pub async fn blob_download_urls(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        blobs: &[super::models::cache::BlobDescriptor],
    ) -> Result<super::models::cache::BlobDownloadUrlsResponse> {
        ensure!(
            !cache_entry_id.trim().is_empty(),
            "cache_entry_id must not be empty"
        );
        ensure!(!blobs.is_empty(), "blobs cannot be empty");
        let endpoint = self.workspace_endpoint(workspace, "caches/blobs/download-urls")?;
        let batch_max = blob_url_batch_max();
        let chunk_count = blobs.len().div_ceil(batch_max);
        let batch_count = chunk_count as u64;
        if chunk_count == 1 {
            let body = super::models::cache::BlobDownloadUrlsRequest {
                cache_entry_id: cache_entry_id.to_string(),
                blobs: blobs.to_vec(),
            };
            return self
                .post_v2_with_request_metrics(
                    &endpoint,
                    &body,
                    BLOB_METRIC_ENDPOINT_OPERATION_DOWNLOAD_URLS,
                    Some(1),
                    Some(batch_count),
                    Some(blobs.len() as u64),
                )
                .await;
        }

        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(
            blob_url_batch_concurrency(chunk_count),
        ));
        let mut tasks = Vec::new();
        for (batch_idx, chunk) in blobs.chunks(batch_max).enumerate() {
            let client = self.clone();
            let endpoint = endpoint.clone();
            let chunk = chunk.to_vec();
            let cache_entry_id = cache_entry_id.to_string();
            let semaphore = semaphore.clone();
            let batch_size = chunk.len() as u64;
            let batch_index = (batch_idx + 1) as u64;
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore
                    .acquire_owned()
                    .await
                    .map_err(|e| anyhow::anyhow!("Blob download URL semaphore closed: {e}"))?;
                let body = super::models::cache::BlobDownloadUrlsRequest {
                    cache_entry_id,
                    blobs: chunk,
                };
                let response = client
                    .post_v2_with_request_metrics::<
                        _,
                        super::models::cache::BlobDownloadUrlsResponse,
                    >(
                        &endpoint,
                        &body,
                        BLOB_METRIC_ENDPOINT_OPERATION_DOWNLOAD_URLS,
                        Some(batch_index),
                        Some(batch_count),
                        Some(batch_size),
                    )
                    .await;
                drop(_permit);
                response
            }));
        }

        let mut download_urls = Vec::new();
        let mut missing = Vec::new();
        for task in tasks {
            let response = task.await.map_err(|e| anyhow::anyhow!(e))??;
            download_urls.extend(response.download_urls);
            missing.extend(response.missing);
        }

        Ok(super::models::cache::BlobDownloadUrlsResponse {
            download_urls,
            missing: dedupe_strings(missing),
        })
    }

    pub async fn save_entry(
        &self,
        workspace: &str,
        entry: &super::models::cache::SaveRequest,
    ) -> Result<super::models::cache::SaveResponse> {
        ensure!(!entry.tag.trim().is_empty(), "Tag must not be empty");

        #[derive(Serialize)]
        struct Payload<'a> {
            cache: &'a super::models::cache::SaveRequest,
        }

        let endpoint = self.workspace_endpoint(workspace, "caches")?;
        let payload = Payload { cache: entry };
        debug!(
            "save_entry workspace={} tag={} base_endpoint={}",
            workspace, entry.tag, endpoint
        );
        if let Ok(body) = serde_json::to_string(&payload) {
            debug!("POST {} body={}", endpoint, body);
        }

        self.post_v2_with_request_metrics(
            &endpoint,
            &payload,
            CACHE_METRIC_ENDPOINT_OPERATION_SAVE_ENTRY,
            None,
            None,
            None,
        )
        .await
    }

    pub async fn delete(
        &self,
        workspace: &str,
        tags: &[String],
    ) -> Result<Vec<super::models::cache::TagDeleteResponse>> {
        ensure!(!tags.is_empty(), "At least one tag must be provided");

        #[derive(Serialize)]
        struct Body<'a> {
            entries: &'a [String],
        }

        let endpoint = self.workspace_endpoint(workspace, "caches")?;
        let body = Body { entries: tags };
        let v2_url = self.build_v2_url(&endpoint);
        let response = self
            .send_authenticated_request(self.client.delete(&v2_url).json(&body))
            .await?;

        if response.status().is_success() {
            self.parse_json_response(response).await
        } else {
            Err(self.create_error_from_response(response).await)
        }
    }

    pub async fn restore(
        &self,
        workspace: &str,
        entries: &[String],
        require_signed: bool,
    ) -> Result<Vec<super::models::cache::CacheResolutionEntry>> {
        ensure!(
            !entries.is_empty(),
            "At least one cache tag must be provided"
        );

        let response = self
            .fetch_restore_response(workspace, entries, require_signed)
            .await?
            .unwrap_or_default();

        let mut results = Vec::with_capacity(response.len());
        for item in response {
            results.push(Self::map_restore_result(item));
        }

        Ok(results)
    }

    pub async fn fetch_manifest_entry(
        &self,
        workspace: &str,
        tag: &str,
        require_signed: bool,
    ) -> Result<Option<super::models::cache::CacheResolutionEntry>> {
        let response = self
            .fetch_restore_response(workspace, &[tag.to_string()], require_signed)
            .await?;

        let Some(items) = response else {
            return Ok(None);
        };

        for item in items {
            if item.tag == tag {
                return Ok(Some(Self::map_restore_result(item)));
            }
        }

        Ok(None)
    }

    pub async fn confirm(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        request: &super::models::cache::ConfirmRequest,
    ) -> Result<super::models::cache::CacheConfirmResponse> {
        match self
            .confirm_with_publish_poll(workspace, cache_entry_id, request, None)
            .await?
        {
            ConfirmPublishResult::Published(response) => Ok(*response),
            ConfirmPublishResult::Pending(metadata) => {
                Err(BoringCacheError::cache_pending_with_metadata(metadata).into())
            }
        }
    }

    pub async fn confirm_wait_for_publish_or_shutdown_pending(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        request: &super::models::cache::ConfirmRequest,
        shutdown_requested: &AtomicBool,
    ) -> Result<ConfirmPublishResult> {
        self.confirm_with_publish_poll(workspace, cache_entry_id, request, Some(shutdown_requested))
            .await
    }

    async fn confirm_with_publish_poll(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        request: &super::models::cache::ConfirmRequest,
        shutdown_requested: Option<&AtomicBool>,
    ) -> Result<ConfirmPublishResult> {
        let tag = request
            .tag
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Confirm request is missing tag for publish"))?;

        #[derive(Serialize)]
        struct PublishFinalizePayload {
            manifest_digest: String,
            manifest_size: u64,
            #[serde(skip_serializing_if = "Option::is_none")]
            manifest_etag: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            archive_size: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            archive_etag: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            blob_count: Option<u64>,
            #[serde(skip_serializing_if = "Option::is_none")]
            blob_total_size_bytes: Option<u64>,
        }

        #[derive(Serialize)]
        struct PublishPayload {
            cache_entry_id: String,
            publish_mode: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            write_scope_tag: Option<String>,
            cache: PublishFinalizePayload,
        }

        let capabilities = self.get_capabilities().await;
        let publish_mode = determine_publish_mode(request);
        let if_match = if publish_mode == "cas" {
            match self.tag_pointer_v2(workspace, tag).await? {
                Some(pointer) => Some(pointer.version),
                None => capabilities.cas_publish_bootstrap_if_match.clone(),
            }
        } else {
            None
        };
        if publish_mode == "cas" && if_match.is_none() {
            anyhow::bail!(
                "CAS publish requires server bootstrap If-Match capability or existing pointer version"
            );
        }

        let encoded_tag = urlencoding::encode(tag);
        let endpoint =
            self.workspace_endpoint(workspace, &format!("caches/tags/{encoded_tag}/publish"))?;
        let publish_payload = PublishPayload {
            cache_entry_id: cache_entry_id.to_string(),
            publish_mode: publish_mode.to_string(),
            write_scope_tag: request.write_scope_tag.clone(),
            cache: PublishFinalizePayload {
                manifest_digest: request.manifest_digest.clone(),
                manifest_size: request.manifest_size,
                manifest_etag: request.manifest_etag.clone(),
                archive_size: request.archive_size,
                archive_etag: request.archive_etag.clone(),
                blob_count: request.blob_count,
                blob_total_size_bytes: request.blob_total_size_bytes,
            },
        };
        let started_at = Instant::now();

        let response: TagPointer = loop {
            let publish_result = self
                .put_v2_with_if_match(
                    &endpoint,
                    &publish_payload,
                    if_match.as_deref(),
                    CACHE_METRIC_ENDPOINT_OPERATION_CONFIRM_PUBLISH,
                )
                .await;
            match publish_result {
                Ok(response) => break response,
                Err(error) => {
                    let Some(metadata) = pending_metadata_from_error(&error).cloned() else {
                        return Err(error);
                    };

                    if should_accept_server_owned_pending(shutdown_requested, &metadata) {
                        return Ok(ConfirmPublishResult::Pending(metadata));
                    }

                    if started_at.elapsed() >= PENDING_PUBLISH_POLL_TIMEOUT {
                        return Err(error);
                    }

                    if metadata.poll_path.is_some() || metadata.upload_session_id.is_some() {
                        let poll_result = self
                            .poll_pending_publish(
                                workspace,
                                tag,
                                metadata,
                                started_at,
                                shutdown_requested,
                            )
                            .await?;
                        match poll_result {
                            PendingPublishPollOutcome::Published(pointer) => break pointer,
                            PendingPublishPollOutcome::Pending(metadata) => {
                                return Ok(ConfirmPublishResult::Pending(metadata));
                            }
                        }
                    }

                    let delay = Duration::from_secs(metadata.retry_after_seconds.unwrap_or(1));
                    sleep(delay).await;
                }
            }
        };

        Ok(ConfirmPublishResult::Published(Box::new(
            cache_confirm_response_from_tag_pointer(response),
        )))
    }

    async fn poll_pending_publish(
        &self,
        workspace: &str,
        tag: &str,
        metadata: PendingMetadata,
        started_at: Instant,
        shutdown_requested: Option<&AtomicBool>,
    ) -> Result<PendingPublishPollOutcome> {
        loop {
            if should_accept_server_owned_pending(shutdown_requested, &metadata) {
                return Ok(PendingPublishPollOutcome::Pending(metadata));
            }

            if started_at.elapsed() >= PENDING_PUBLISH_POLL_TIMEOUT {
                if should_accept_server_owned_pending(shutdown_requested, &metadata) {
                    return Ok(PendingPublishPollOutcome::Pending(metadata));
                }
                return Err(BoringCacheError::cache_pending_with_metadata(metadata).into());
            }

            let status = match self.upload_session_status(workspace, &metadata).await {
                Ok(status) => status,
                Err(error) => {
                    if should_accept_server_owned_pending(shutdown_requested, &metadata) {
                        return Ok(PendingPublishPollOutcome::Pending(metadata));
                    }
                    return Err(error).context("Failed to poll pending publish status");
                }
            };

            match status
                .publish_state
                .as_deref()
                .or(Some(status.state.as_str()))
            {
                Some("published") => match self.tag_pointer_v2(workspace, tag).await? {
                    Some(pointer) => {
                        return Ok(PendingPublishPollOutcome::Published(TagPointer {
                            version: pointer.version,
                            cache_entry_id: pointer.cache_entry_id,
                            status: Some("published".to_string()),
                            uploaded_at: None,
                        }));
                    }
                    None => {
                        anyhow::bail!("Pending publish completed but tag pointer was not found")
                    }
                },
                Some("conflicted") => {
                    return Err(BoringCacheError::cache_conflict(
                        status
                            .error
                            .unwrap_or_else(|| "Tag publish conflict".to_string()),
                    )
                    .into());
                }
                Some("failed") => {
                    anyhow::bail!(
                        "{}",
                        status
                            .error
                            .unwrap_or_else(|| "Pending publish failed".to_string())
                    );
                }
                _ => {
                    if should_accept_server_owned_pending(shutdown_requested, &metadata) {
                        return Ok(PendingPublishPollOutcome::Pending(metadata));
                    }

                    let delay = Duration::from_secs(metadata.retry_after_seconds.unwrap_or(1))
                        .min(PENDING_PUBLISH_POLL_INTERVAL.max(Duration::from_secs(1)));
                    sleep(delay).await;
                }
            }
        }
    }

    async fn upload_session_status(
        &self,
        workspace: &str,
        metadata: &PendingMetadata,
    ) -> Result<super::models::cache::UploadSessionStatusResponse> {
        if let Some(path) = metadata.poll_path.as_deref() {
            let normalized = path
                .trim_start_matches('/')
                .strip_prefix("v2/")
                .unwrap_or_else(|| path.trim_start_matches('/'));
            return self.get_v2(normalized).await;
        }

        let upload_session_id = metadata
            .upload_session_id
            .as_deref()
            .context("Pending publish response did not include upload_session_id")?;
        let endpoint =
            self.workspace_endpoint(workspace, &format!("upload-sessions/{upload_session_id}"))?;
        self.get_v2(&endpoint).await
    }

    pub async fn complete_multipart(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        request: &super::models::cache::CompleteMultipartRequest,
    ) -> Result<super::models::cache::CompleteMultipartResponse> {
        let endpoint = format!(
            "{}/{}/multipart/complete",
            self.workspace_endpoint(workspace, "caches")?,
            cache_entry_id
        );
        debug!(
            "complete_multipart workspace={} cache_entry_id={} upload_id={} parts={}",
            workspace,
            cache_entry_id,
            request.upload_id,
            request.parts.len()
        );

        #[derive(Serialize)]
        struct Payload<'a> {
            multipart: &'a super::models::cache::CompleteMultipartRequest,
        }

        self.post_v2(&endpoint, &Payload { multipart: request })
            .await
    }

    fn map_restore_result(
        item: super::models::cache::RestoreResult,
    ) -> super::models::cache::CacheResolutionEntry {
        use crate::api::models::cache::{CacheResolutionEntry, RestoreResult};

        fn entry_from_result(item: RestoreResult) -> CacheResolutionEntry {
            let metadata = item.metadata.as_ref();
            let logical_size = metadata.and_then(|m| m.total_size_bytes);
            let uncompressed_size =
                metadata.and_then(|m| m.uncompressed_size.or(m.total_size_bytes));
            let compressed_size = metadata.and_then(|m| m.compressed_size);
            let storage_mode = item
                .storage_mode
                .clone()
                .or_else(|| metadata.and_then(|m| m.storage_mode.clone()));
            let blob_count = item
                .blob_count
                .or_else(|| metadata.and_then(|m| m.blob_count));
            let blob_total_size_bytes = item
                .blob_total_size_bytes
                .or_else(|| metadata.and_then(|m| m.blob_total_size_bytes));
            let cas_layout = item
                .cas_layout
                .clone()
                .or_else(|| metadata.and_then(|m| m.cas_layout.clone()));

            CacheResolutionEntry {
                tag: item.tag.clone(),
                primary_tag: item.primary_tag.clone(),
                signature_tag: item
                    .signature_tag
                    .clone()
                    .or_else(|| metadata.and_then(|m| m.signature_tag.clone())),
                status: item.status.clone(),
                cache_entry_id: item.cache_entry_id.clone(),
                manifest_url: item.manifest_url.clone(),
                manifest_root_digest: item.manifest_root_digest.clone().or_else(|| {
                    item.metadata
                        .as_ref()
                        .and_then(|m| m.manifest_root_digest.clone())
                }),
                manifest_digest: item.manifest_digest.clone(),
                compression_algorithm: item.compression_algorithm.clone().or_else(|| {
                    item.metadata
                        .as_ref()
                        .and_then(|m| m.compression_algorithm.clone())
                }),
                storage_mode,
                blob_count,
                blob_total_size_bytes,
                cas_layout,
                archive_urls: item.archive_urls.clone(),
                size: logical_size,
                uncompressed_size,
                compressed_size,
                uploaded_at: None,
                content_hash: item.manifest_root_digest.clone().or_else(|| {
                    item.metadata
                        .as_ref()
                        .and_then(|m| m.manifest_root_digest.clone())
                }),
                pending: item.pending || item.status == "pending" || item.status == "uploading",
                error: item.error.clone(),
                workspace_signing_public_key: item.workspace_signing_public_key.clone(),
                server_signature: item.server_signature.clone(),
                server_signed_at: item.server_signed_at.clone(),
                encrypted: item.encrypted,
            }
        }

        entry_from_result(item)
    }

    async fn fetch_restore_response(
        &self,
        workspace: &str,
        entries: &[String],
        require_signed: bool,
    ) -> Result<Option<super::models::cache::RestoreResponse>> {
        use crate::api::models::cache::RestoreResponse;

        ensure!(
            !entries.is_empty(),
            "At least one cache tag must be provided"
        );

        let entries_param = entries.join(",");
        let base = self.workspace_endpoint(workspace, "caches")?;
        let mut url = format!("{}?entries={}", base, urlencoding::encode(&entries_param));
        if require_signed {
            url.push_str("&require_signed=1");
        }
        let response = self.get_response_with_base(&self.v2_base_url, &url).await?;

        let status = response.status();

        if status == StatusCode::MULTI_STATUS {
            let payload: RestoreResponse = response
                .json()
                .await
                .context("Failed to parse 207 restore response")?;
            return Ok(Some(payload));
        }

        if status == StatusCode::NOT_FOUND {
            let body = response.text().await.unwrap_or_default();
            return parse_restore_not_found_body(&body);
        }

        if !status.is_success() {
            return Err(self.create_error_from_response(response).await);
        }

        let payload: RestoreResponse = response
            .json()
            .await
            .context("Failed to parse restore response")?;

        Ok(Some(payload))
    }

    pub async fn tag_pointer(
        &self,
        workspace: &str,
        tag: &str,
        if_none_match: Option<&str>,
    ) -> Result<TagPointerPollResult> {
        let endpoint = self.workspace_endpoint(
            workspace,
            &format!("caches/tags/{}/pointer", urlencoding::encode(tag)),
        )?;
        let url = Self::build_url_from_base(&self.v2_base_url, &endpoint);
        debug!("GET {} (version poll)", url);
        let mut request = self.client.get(&url);
        if let Some(etag) = if_none_match {
            request = request.header("If-None-Match", etag);
        }
        let response = self.send_authenticated_request(request).await?;
        let status = response.status();
        if status == StatusCode::NOT_MODIFIED {
            return Ok(TagPointerPollResult::NotModified);
        }
        if status == StatusCode::NOT_FOUND {
            return Ok(TagPointerPollResult::NotFound);
        }
        if !status.is_success() {
            return Err(self.create_error_from_response(response).await);
        }
        let etag = response
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let pointer: super::models::cache::TagPointerResponse = response
            .json()
            .await
            .context("Failed to parse tag pointer response")?;
        Ok(TagPointerPollResult::Changed { pointer, etag })
    }

    pub async fn list_workspaces(&self) -> Result<Vec<super::models::Workspace>> {
        self.get_v2("workspaces").await
    }

    pub async fn list(
        &self,
        workspace: &str,
        limit: Option<u32>,
        page: Option<u32>,
    ) -> Result<super::models::CacheEntriesListResponse> {
        let mut url = self.workspace_endpoint(workspace, "caches")?;
        let mut params = Vec::new();

        if let Some(limit) = limit {
            params.push(format!("limit={}", limit));
        }
        if let Some(page) = page {
            params.push(format!("page={}", page));
        }

        if !params.is_empty() {
            url.push('?');
            url.push_str(&params.join("&"));
        }

        self.get_v2(&url).await
    }

    pub async fn workspace_status(
        &self,
        workspace: &str,
        period: &str,
        limit: u32,
    ) -> Result<super::models::workspace::WorkspaceStatusResponse> {
        let endpoint = self.workspace_endpoint(workspace, "status")?;
        let url = format!("{endpoint}?period={period}&limit={limit}");
        self.get_v2(&url).await
    }

    pub async fn inspect_cache(
        &self,
        workspace: &str,
        identifier: &str,
    ) -> Result<Option<super::models::cache::CacheInspectResponse>> {
        let encoded_identifier = urlencoding::encode(identifier);
        let endpoint =
            self.workspace_endpoint(workspace, &format!("caches/inspect/{encoded_identifier}"))?;
        let url = self.build_v2_url(&endpoint);
        let response = self
            .send_authenticated_request(self.client.get(&url))
            .await?;
        let status = response.status();

        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !status.is_success() {
            return Err(self.create_error_from_response(response).await);
        }

        let inspection = response
            .json()
            .await
            .context("Failed to parse cache inspect response")?;
        Ok(Some(inspection))
    }

    pub async fn get_session_info(&self) -> Result<super::models::SessionInfo> {
        self.get_v2("session").await
    }

    pub async fn validate_token(&self, _token: &str) -> Result<super::models::SessionInfo> {
        match self.get_session_info().await {
            Ok(session_info) => Ok(session_info),
            Err(e) => {
                if e.to_string().contains("ERROR: Cannot connect") {
                    Err(anyhow::anyhow!(
                        "Token validation failed: Invalid or expired token"
                    ))
                } else {
                    Err(e)
                }
            }
        }
    }

    pub async fn send_metrics(
        &self,
        workspace: &str,
        params: super::models::MetricsParams,
    ) -> Result<()> {
        let url = self.workspace_endpoint(workspace, "metrics")?;
        let _response: serde_json::Value = self.post_v2(&url, &params).await?;
        Ok(())
    }

    pub async fn send_cache_rollups(
        &self,
        workspace: &str,
        batch: super::models::cache_rollups::BatchParams,
    ) -> Result<()> {
        let url = self.workspace_endpoint(workspace, "cache-rollups")?;
        let _response: serde_json::Value = self.post_v2(&url, &batch).await?;
        Ok(())
    }
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

fn should_accept_server_owned_pending(
    shutdown_requested: Option<&AtomicBool>,
    metadata: &PendingMetadata,
) -> bool {
    server_owned_pending_publish(metadata)
        && shutdown_requested.is_some_and(|flag| flag.load(Ordering::Acquire))
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

fn parse_usize_env(name: &str) -> Option<usize> {
    let raw = std::env::var(name).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    match trimmed.parse::<usize>() {
        Ok(value) if value > 0 => Some(value),
        Ok(_) => None,
        Err(_) => None,
    }
}

fn confirm_publish_request_timeout() -> Duration {
    let seconds = std::env::var(CONFIRM_PUBLISH_TIMEOUT_SECS_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(DEFAULT_CONFIRM_PUBLISH_TIMEOUT_SECS);
    Duration::from_secs(seconds)
}

fn blob_check_batch_max() -> usize {
    parse_usize_env(BLOB_CHECK_BATCH_MAX_ENV).unwrap_or(BLOB_CHECK_BATCH_MAX)
}

fn blob_url_batch_max() -> usize {
    parse_usize_env(BLOB_URL_BATCH_MAX_ENV).unwrap_or(BLOB_URL_BATCH_MAX)
}

fn blob_check_batch_concurrency(chunk_count: usize) -> usize {
    if chunk_count == 0 {
        return 1;
    }
    parse_usize_env(BLOB_CHECK_BATCH_CONCURRENCY_ENV)
        .unwrap_or_else(|| api_batch_concurrency(chunk_count))
        .clamp(1, chunk_count)
}

fn blob_url_batch_concurrency(chunk_count: usize) -> usize {
    if chunk_count == 0 {
        return 1;
    }
    parse_usize_env(BLOB_URL_BATCH_CONCURRENCY_ENV)
        .unwrap_or_else(|| api_batch_concurrency(chunk_count))
        .clamp(1, chunk_count)
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

fn derive_api_base_urls(configured_base_url: &str) -> (String, String) {
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
    if chunk_count == 0 {
        return 1;
    }

    let cpu_count = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let ci_cap = if std::env::var_os("CI").is_some() {
        4
    } else {
        8
    };

    chunk_count.min(ci_cap).min(cpu_count.max(1)).max(1)
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
            .connect_timeout(Duration::from_secs(3))
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
        assert_eq!(api_batch_concurrency(1), 1);

        let medium = api_batch_concurrency(4);
        assert!((1..=4).contains(&medium));

        let larger = api_batch_concurrency(32);
        assert!((1..=32).contains(&larger));
    }

    #[test]
    fn test_blob_check_batch_max_env_override() {
        let _guard = test_env::lock();

        test_env::set_var(BLOB_CHECK_BATCH_MAX_ENV, "7");
        assert_eq!(blob_check_batch_max(), 7);
        test_env::remove_var(BLOB_CHECK_BATCH_MAX_ENV);
        assert_eq!(blob_check_batch_max(), BLOB_CHECK_BATCH_MAX);
    }

    #[test]
    fn test_blob_url_batch_max_env_override() {
        let _guard = test_env::lock();

        test_env::set_var(BLOB_URL_BATCH_MAX_ENV, "9");
        assert_eq!(blob_url_batch_max(), 9);
        test_env::remove_var(BLOB_URL_BATCH_MAX_ENV);
        assert_eq!(blob_url_batch_max(), BLOB_URL_BATCH_MAX);
    }

    #[test]
    fn test_blob_check_batch_concurrency_env_override() {
        let _guard = test_env::lock();

        test_env::set_var(BLOB_CHECK_BATCH_CONCURRENCY_ENV, "16");
        assert_eq!(blob_check_batch_concurrency(4), 4);
        test_env::remove_var(BLOB_CHECK_BATCH_CONCURRENCY_ENV);
    }

    #[test]
    fn test_blob_url_batch_concurrency_env_override() {
        let _guard = test_env::lock();

        test_env::set_var(BLOB_URL_BATCH_CONCURRENCY_ENV, "3");
        assert_eq!(blob_url_batch_concurrency(10), 3);
        test_env::remove_var(BLOB_URL_BATCH_CONCURRENCY_ENV);
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
            .check_blobs("ns/ws", &blobs)
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
            .blob_download_urls("ns/ws", "entry-1", &blobs)
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
                r#"{"session_id":"abc123","poll_token":"poll-secret","authorize_url":"https://boringcache.com/cli/connect/abc123","expires_at":"2026-03-02T12:00:00Z","poll_interval_seconds":3}"#,
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
