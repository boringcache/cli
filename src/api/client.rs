use crate::config::Config;
use crate::error::BoringCacheError;
use crate::retry_resume::RetryConfig;
use crate::types::Result;
use anyhow::{ensure, Context};
use log::debug;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::time::sleep;

const BLOB_CHECK_BATCH_MAX: usize = 10_000;
const BLOB_URL_BATCH_MAX: usize = 2_000;
const API_VERSION_V1: &str = "v1";
const API_VERSION_V2: &str = "v2";
const ROUTE_KEY_WORKSPACES: &str = "workspaces";
const ROUTE_KEY_CACHE_LIST: &str = "cache_list";
const ROUTE_KEY_CACHE_RESTORE: &str = "cache_restore";
const ROUTE_KEY_SESSION: &str = "session";
const ROUTE_KEY_MANIFEST_CHECK: &str = "manifest_check";
const ROUTE_KEY_METRICS: &str = "metrics";
const ROUTE_KEY_PREFLIGHT: &str = "preflight";
const ROUTE_KEY_DELETE: &str = "delete";
const ROUTE_KEY_MULTIPART_COMPLETE: &str = "multipart_complete";

#[derive(Debug, Clone, Default, Deserialize)]
struct CapabilityResponse {
    #[serde(default)]
    features: CapabilityFlags,
}

#[derive(Debug, Clone, Default, Deserialize)]
struct CapabilityFlags {
    #[serde(default)]
    blob_stage_v2: bool,
    #[serde(default)]
    tag_pointer_v2: bool,
    #[serde(default)]
    tag_publish_v2: bool,
    #[serde(default)]
    finalize_only_v2: bool,
    #[serde(default)]
    entry_create_v2: bool,
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

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    transfer_client: Client,
    base_url: String,
    v1_base_url: String,
    v2_base_url: String,
    auth_token: Option<String>,
    capabilities: Arc<RwLock<Option<CapabilityFlags>>>,
    v2_fallback_routes: Arc<RwLock<HashSet<String>>>,
}

impl ApiClient {
    pub fn new() -> Result<Self> {
        Self::new_with_token_override(None)
    }

    pub fn new_with_token_override(token_override: Option<String>) -> Result<Self> {
        let config = Config::load().ok();

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

        let client = build_api_client_with_headers(Some(headers.clone()))?;
        let transfer_client = build_transfer_client_with_headers(Some(headers))?;

        let mut auth_token = token_override;
        let mut base_url = crate::config::env_var("BORINGCACHE_API_URL");

        if let Some(cfg) = config.as_ref() {
            if auth_token.is_none() {
                auth_token = Some(cfg.token.clone());
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
            v2_fallback_routes: Arc::new(RwLock::new(HashSet::new())),
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

    async fn use_v1_fallback_route(&self, route_key: &str) -> bool {
        self.v2_fallback_routes.read().await.contains(route_key)
    }

    async fn mark_v2_fallback_route(&self, route_key: &str) {
        self.v2_fallback_routes
            .write()
            .await
            .insert(route_key.to_string());
    }

    fn should_fallback_to_v1(status: StatusCode) -> bool {
        matches!(
            status,
            StatusCode::NOT_FOUND | StatusCode::METHOD_NOT_ALLOWED
        )
    }

    async fn get_response_with_v2_fallback(
        &self,
        route_key: &str,
        endpoint: &str,
    ) -> Result<Response> {
        if self.use_v1_fallback_route(route_key).await {
            return self
                .get_response_with_base(&self.v1_base_url, endpoint)
                .await;
        }

        let response = self
            .get_response_with_base(&self.v2_base_url, endpoint)
            .await?;
        if Self::should_fallback_to_v1(response.status()) {
            self.mark_v2_fallback_route(route_key).await;
            return self
                .get_response_with_base(&self.v1_base_url, endpoint)
                .await;
        }

        Ok(response)
    }

    async fn get_with_v2_fallback<T>(&self, route_key: &str, endpoint: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let response = self
            .get_response_with_v2_fallback(route_key, endpoint)
            .await?;
        self.parse_json_response(response).await
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

    async fn post_with_v2_fallback<T, R>(
        &self,
        route_key: &str,
        endpoint: &str,
        body: &T,
    ) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        if self.use_v1_fallback_route(route_key).await {
            return self.post_v1(endpoint, body).await;
        }

        let response = self
            .post_response_with_base(&self.v2_base_url, endpoint, body)
            .await?;
        if Self::should_fallback_to_v1(response.status()) {
            self.mark_v2_fallback_route(route_key).await;
            return self.post_v1(endpoint, body).await;
        }

        self.parse_json_response(response).await
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
        let token = self
            .auth_token
            .as_ref()
            .ok_or(BoringCacheError::TokenNotFound)?;

        if request.try_clone().is_none() {
            let request = request.header("Authorization", format!("Bearer {}", token));
            return match request.send().await {
                Ok(response) => Ok(response),
                Err(err) if err.is_connect() => Err(BoringCacheError::ConnectionError(
                    "ERROR: Cannot connect to BoringCache server. Please check:\n\
                         • Is the API URL correct? (Check with: boringcache config)\n\
                         • Is there a firewall blocking the connection?"
                        .to_string(),
                )
                .into()),
                Err(err) => Err(err.into()),
            };
        }

        let retry_config = RetryConfig::new(false);
        let token_clone = token.clone();

        retry_config
            .retry_with_backoff("API request", || {
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
                        Err(err) => Err(err.into()),
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
                anyhow::anyhow!(
                    "Access forbidden: You don't have permission to access this resource.\n\
                     Please check your authentication token and permissions."
                )
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

                BoringCacheError::CacheConflict(message).into()
            }
            StatusCode::LOCKED => BoringCacheError::CachePending.into(),
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
            match operation().await {
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
    ) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = self.build_v2_url(endpoint);
        debug!("PUT {}", url);
        let mut request = self.client.put(&url).json(body);
        if let Some(version) = if_match {
            request = request.header("If-Match", version);
        }
        let response = self.send_authenticated_request(request).await?;
        self.parse_json_response(response).await
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
        self.post_with_v2_fallback(ROUTE_KEY_MANIFEST_CHECK, &endpoint, &body)
            .await
    }

    pub async fn check_blobs(
        &self,
        workspace: &str,
        blobs: &[super::models::cache::BlobDescriptor],
    ) -> Result<super::models::cache::BlobCheckResponse> {
        ensure!(!blobs.is_empty(), "blobs cannot be empty");
        let endpoint = self.workspace_endpoint(workspace, "caches/blobs/check")?;
        if blobs.len() <= BLOB_CHECK_BATCH_MAX {
            let body = super::models::cache::BlobCheckRequest {
                blobs: blobs.to_vec(),
            };
            return self.post_v2(&endpoint, &body).await;
        }

        let chunk_count = blobs.len().div_ceil(BLOB_CHECK_BATCH_MAX);
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(api_batch_concurrency(
            chunk_count,
        )));
        let mut tasks = Vec::new();
        for chunk in blobs.chunks(BLOB_CHECK_BATCH_MAX) {
            let client = self.clone();
            let endpoint = endpoint.clone();
            let chunk = chunk.to_vec();
            let semaphore = semaphore.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let body = super::models::cache::BlobCheckRequest { blobs: chunk };
                client
                    .post_v2::<_, super::models::cache::BlobCheckResponse>(&endpoint, &body)
                    .await
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
        ensure!(
            !cache_entry_id.trim().is_empty(),
            "cache_entry_id must not be empty"
        );
        ensure!(!blobs.is_empty(), "blobs cannot be empty");
        let capabilities = self.get_capabilities().await;
        let use_v2 = capabilities.blob_stage_v2;
        let endpoint = if use_v2 {
            self.workspace_endpoint(workspace, "caches/blobs/stage")?
        } else {
            self.workspace_endpoint(workspace, "caches/blobs/upload-urls")?
        };
        if blobs.len() <= BLOB_URL_BATCH_MAX {
            if use_v2 {
                let body = super::models::cache::BlobStageRequest {
                    blobs: blobs.to_vec(),
                };
                return self.post_v2(&endpoint, &body).await;
            }

            let body = super::models::cache::BlobUploadUrlsRequest {
                cache_entry_id: cache_entry_id.to_string(),
                blobs: blobs.to_vec(),
            };
            return self.post_v2(&endpoint, &body).await;
        }

        let chunk_count = blobs.len().div_ceil(BLOB_URL_BATCH_MAX);
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(api_batch_concurrency(
            chunk_count,
        )));
        let mut tasks = Vec::new();
        for chunk in blobs.chunks(BLOB_URL_BATCH_MAX) {
            let client = self.clone();
            let endpoint = endpoint.clone();
            let chunk = chunk.to_vec();
            let cache_entry_id = cache_entry_id.to_string();
            let semaphore = semaphore.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                if use_v2 {
                    let body = super::models::cache::BlobStageRequest { blobs: chunk };
                    client
                        .post_v2::<_, super::models::cache::BlobUploadUrlsResponse>(
                            &endpoint, &body,
                        )
                        .await
                } else {
                    let body = super::models::cache::BlobUploadUrlsRequest {
                        cache_entry_id,
                        blobs: chunk,
                    };
                    client
                        .post_v2::<_, super::models::cache::BlobUploadUrlsResponse>(
                            &endpoint, &body,
                        )
                        .await
                }
            }));
        }

        let mut upload_urls = Vec::new();
        let mut already_present = Vec::new();
        for task in tasks {
            let response = task.await.map_err(|e| anyhow::anyhow!(e))??;
            upload_urls.extend(response.upload_urls);
            already_present.extend(response.already_present);
        }

        Ok(super::models::cache::BlobUploadUrlsResponse {
            upload_urls,
            already_present: dedupe_strings(already_present),
        })
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
        if blobs.len() <= BLOB_URL_BATCH_MAX {
            let body = super::models::cache::BlobDownloadUrlsRequest {
                cache_entry_id: cache_entry_id.to_string(),
                blobs: blobs.to_vec(),
            };
            return self.post_v2(&endpoint, &body).await;
        }

        let chunk_count = blobs.len().div_ceil(BLOB_URL_BATCH_MAX);
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(api_batch_concurrency(
            chunk_count,
        )));
        let mut tasks = Vec::new();
        for chunk in blobs.chunks(BLOB_URL_BATCH_MAX) {
            let client = self.clone();
            let endpoint = endpoint.clone();
            let chunk = chunk.to_vec();
            let cache_entry_id = cache_entry_id.to_string();
            let semaphore = semaphore.clone();
            tasks.push(tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                let body = super::models::cache::BlobDownloadUrlsRequest {
                    cache_entry_id,
                    blobs: chunk,
                };
                client
                    .post_v2::<_, super::models::cache::BlobDownloadUrlsResponse>(&endpoint, &body)
                    .await
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

        self.post_v2(&endpoint, &payload).await
    }

    pub async fn preflight_entry(
        &self,
        workspace: &str,
        tag: &str,
        entry: &super::models::cache::PreflightRequest,
    ) -> Result<super::models::cache::SaveResponse> {
        ensure!(!tag.trim().is_empty(), "Tag must not be empty");

        let encoded_tag = urlencoding::encode(tag);
        let endpoint =
            self.workspace_endpoint(workspace, &format!("caches/{encoded_tag}/preflight"))?;
        debug!(
            "preflight_entry workspace={} tag={} endpoint={}",
            workspace, tag, endpoint
        );
        if let Ok(body) = serde_json::to_string(entry) {
            debug!("POST {} body={}", endpoint, body);
        }

        self.post_with_v2_fallback(ROUTE_KEY_PREFLIGHT, &endpoint, entry)
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
        let response = if self.use_v1_fallback_route(ROUTE_KEY_DELETE).await {
            let url = self.build_v1_url(&endpoint);
            self.send_authenticated_request(self.client.delete(&url).json(&body))
                .await?
        } else {
            let v2_url = self.build_v2_url(&endpoint);
            let v2_response = self
                .send_authenticated_request(self.client.delete(&v2_url).json(&body))
                .await?;
            if Self::should_fallback_to_v1(v2_response.status()) {
                self.mark_v2_fallback_route(ROUTE_KEY_DELETE).await;
                let v1_url = self.build_v1_url(&endpoint);
                self.send_authenticated_request(self.client.delete(&v1_url).json(&body))
                    .await?
            } else {
                v2_response
            }
        };

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
    ) -> Result<Vec<super::models::cache::CacheResolutionEntry>> {
        ensure!(
            !entries.is_empty(),
            "At least one cache tag must be provided"
        );

        let response = self
            .fetch_restore_response(workspace, entries)
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
    ) -> Result<Option<super::models::cache::CacheResolutionEntry>> {
        let response = self
            .fetch_restore_response(workspace, &[tag.to_string()])
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
        let capabilities = self.get_capabilities().await;
        if capabilities.tag_publish_v2 {
            if let Some(tag) = request.tag.as_deref() {
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
                    cache: PublishFinalizePayload,
                }

                let publish_mode =
                    if request.blob_count.is_some() || request.blob_total_size_bytes.is_some() {
                        "cas"
                    } else {
                        "replace"
                    };

                let if_match = if publish_mode == "cas" {
                    if capabilities.tag_pointer_v2 {
                        match self.tag_pointer_v2(workspace, tag).await? {
                            Some(pointer) => Some(pointer.version),
                            None => capabilities
                                .cas_publish_bootstrap_if_match
                                .clone()
                                .or_else(|| Some("0".to_string())),
                        }
                    } else {
                        capabilities
                            .cas_publish_bootstrap_if_match
                            .clone()
                            .or_else(|| Some("0".to_string()))
                    }
                } else {
                    None
                };

                let encoded_tag = urlencoding::encode(tag);
                let endpoint = self
                    .workspace_endpoint(workspace, &format!("caches/tags/{encoded_tag}/publish"))?;

                let response: TagPointer = self
                    .put_v2_with_if_match(
                        &endpoint,
                        &PublishPayload {
                            cache_entry_id: cache_entry_id.to_string(),
                            publish_mode: publish_mode.to_string(),
                            cache: PublishFinalizePayload {
                                manifest_digest: request.manifest_digest.clone(),
                                manifest_size: request.manifest_size,
                                manifest_etag: request.manifest_etag.clone(),
                                archive_size: request.archive_size,
                                archive_etag: request.archive_etag.clone(),
                                blob_count: request.blob_count,
                                blob_total_size_bytes: request.blob_total_size_bytes,
                            },
                        },
                        if_match.as_deref(),
                    )
                    .await?;

                return Ok(super::models::cache::CacheConfirmResponse {
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
                });
            }
        }

        let endpoint = format!(
            "{}/{}",
            self.workspace_endpoint(workspace, "caches")?,
            cache_entry_id
        );
        debug!(
            "confirm workspace={} cache_entry_id={} endpoint={}",
            workspace, cache_entry_id, endpoint
        );

        #[derive(Serialize)]
        struct Payload<'a> {
            cache: &'a super::models::cache::ConfirmRequest,
        }

        self.patch_v2(&endpoint, &Payload { cache: request }).await
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

        self.post_with_v2_fallback(
            ROUTE_KEY_MULTIPART_COMPLETE,
            &endpoint,
            &Payload { multipart: request },
        )
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
    ) -> Result<Option<super::models::cache::RestoreResponse>> {
        use crate::api::models::cache::{RestorePendingResponse, RestoreResponse};

        ensure!(
            !entries.is_empty(),
            "At least one cache tag must be provided"
        );

        let entries_param = entries.join(",");
        let base = self.workspace_endpoint(workspace, "caches")?;
        let url = format!("{}?entries={}", base, urlencoding::encode(&entries_param));
        let response = if self.use_v1_fallback_route(ROUTE_KEY_CACHE_RESTORE).await {
            self.get_response_with_base(&self.v1_base_url, &url).await?
        } else {
            let v2_response = self.get_response_with_base(&self.v2_base_url, &url).await?;
            if v2_response.status() == StatusCode::METHOD_NOT_ALLOWED {
                self.mark_v2_fallback_route(ROUTE_KEY_CACHE_RESTORE).await;
                self.get_response_with_base(&self.v1_base_url, &url).await?
            } else if v2_response.status() == StatusCode::NOT_FOUND {
                let body = v2_response.text().await.unwrap_or_default();
                if is_route_not_found_body(&body) {
                    self.mark_v2_fallback_route(ROUTE_KEY_CACHE_RESTORE).await;
                    self.get_response_with_base(&self.v1_base_url, &url).await?
                } else {
                    if !body.is_empty() {
                        if let Ok(restore_response) = serde_json::from_str::<RestoreResponse>(&body)
                        {
                            return Ok(Some(restore_response));
                        }

                        if let Ok(pending_response) =
                            serde_json::from_str::<RestorePendingResponse>(&body)
                        {
                            if pending_response.pending
                                || pending_response.status.as_deref() == Some("pending")
                            {
                                return Err(BoringCacheError::CachePending.into());
                            }
                        }
                    }
                    return Ok(None);
                }
            } else {
                v2_response
            }
        };

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
            if !body.is_empty() {
                if let Ok(restore_response) = serde_json::from_str::<RestoreResponse>(&body) {
                    return Ok(Some(restore_response));
                }

                if let Ok(pending_response) = serde_json::from_str::<RestorePendingResponse>(&body)
                {
                    if pending_response.pending
                        || pending_response.status.as_deref() == Some("pending")
                    {
                        return Err(BoringCacheError::CachePending.into());
                    }
                }
            }
            return Ok(None);
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

    pub async fn list_workspaces(&self) -> Result<Vec<super::models::Workspace>> {
        self.get_with_v2_fallback(ROUTE_KEY_WORKSPACES, "workspaces")
            .await
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

        self.get_with_v2_fallback(ROUTE_KEY_CACHE_LIST, &url).await
    }

    pub async fn get_session_info(&self) -> Result<super::models::SessionInfo> {
        self.get_with_v2_fallback(ROUTE_KEY_SESSION, "session")
            .await
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
        let _response: serde_json::Value = self
            .post_with_v2_fallback(ROUTE_KEY_METRICS, &url, &params)
            .await?;
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

fn is_route_not_found_body(body: &str) -> bool {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return true;
    }

    parse_error_payload(trimmed).is_some_and(|parsed| {
        let message = parsed.message.to_ascii_lowercase();
        message.contains("route not found") || message.contains("routing error")
    })
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

fn derive_api_base_urls(configured_base_url: &str) -> (String, String) {
    let trimmed = configured_base_url.trim().trim_end_matches('/').to_string();
    if trimmed.is_empty() {
        let default_v2 = crate::config::Config::default_api_url_value().to_string();
        return derive_api_base_urls(&default_v2);
    }

    let lower = trimmed.to_ascii_lowercase();
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
        .pool_max_idle_per_host(64)
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

    let mut builder = reqwest::Client::builder()
        .http1_only()
        .pool_max_idle_per_host(64)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
        .tcp_nodelay(true)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .redirect(reqwest::redirect::Policy::limited(4));

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::cache;
    use mockito::Matcher;
    use serde_json::json;
    use std::net::TcpListener;
    use std::sync::{Mutex, OnceLock};

    static ENV_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();

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
            v2_fallback_routes: Arc::new(RwLock::new(std::collections::HashSet::new())),
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
    fn test_default_base_url_matches_config() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));
        let _guard = mutex.lock().unwrap();

        // Isolate from user config by using a temp HOME directory
        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());
        std::env::remove_var("BORINGCACHE_API_URL");

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize without BORINGCACHE_API_URL or config file");

        // Restore original HOME
        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }

        let (_v1, expected_v2) =
            derive_api_base_urls(crate::config::Config::default_api_url_value());
        assert_eq!(client.base_url(), expected_v2);
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

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_manifest_check_request_body() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));

        // Use lock() with ok() to handle poisoned mutex gracefully
        let guard_result = mutex.lock();
        let _guard = match guard_result {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !networking_available() {
            eprintln!("skipping test_manifest_check_request_body: networking disabled in sandbox");
            return;
        }

        // Isolate from user config
        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());

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

        std::env::set_var("BORINGCACHE_API_URL", server.url());

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
            std::env::set_var("HOME", home);
        }
        std::env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_check_request_body() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));
        let guard_result = mutex.lock();
        let _guard = match guard_result {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !networking_available() {
            eprintln!("skipping test_blob_check_request_body: networking disabled in sandbox");
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());

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

        std::env::set_var("BORINGCACHE_API_URL", server.url());

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
            std::env::set_var("HOME", home);
        }
        std::env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_check_batches_large_requests() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));
        let guard_result = mutex.lock();
        let _guard = match guard_result {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !networking_available() {
            eprintln!(
                "skipping test_blob_check_batches_large_requests: networking disabled in sandbox"
            );
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());

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

        std::env::set_var("BORINGCACHE_API_URL", server.url());

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
            std::env::set_var("HOME", home);
        }
        std::env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_upload_urls_batches_large_requests() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));
        let guard_result = mutex.lock();
        let _guard = match guard_result {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !networking_available() {
            eprintln!("skipping test_blob_upload_urls_batches_large_requests: networking disabled in sandbox");
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/blobs/upload-urls")
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

        std::env::set_var("BORINGCACHE_API_URL", server.url());

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
            std::env::set_var("HOME", home);
        }
        std::env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_blob_download_urls_batches_large_requests() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));
        let guard_result = mutex.lock();
        let _guard = match guard_result {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !networking_available() {
            eprintln!("skipping test_blob_download_urls_batches_large_requests: networking disabled in sandbox");
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());

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

        std::env::set_var("BORINGCACHE_API_URL", server.url());

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
            std::env::set_var("HOME", home);
        }
        std::env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)]
    async fn test_preflight_request_body() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));
        let guard_result = mutex.lock();
        let _guard = match guard_result {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };

        if !networking_available() {
            eprintln!("skipping test_preflight_request_body: networking disabled in sandbox");
            return;
        }

        let temp_home = tempfile::tempdir().expect("failed to create temp dir");
        let original_home = std::env::var("HOME").ok();
        std::env::set_var("HOME", temp_home.path());

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/v2/workspaces/ns/ws/caches/my-tag/preflight")
            .match_header("authorization", "Bearer test-token")
            .match_header("content-type", "application/json")
            .match_body(Matcher::PartialJson(json!({
                "manifest_root_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "compression_algorithm": "zstd",
                "storage_mode": "cas",
                "blob_count": 3,
                "blob_total_size_bytes": 300
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"{"tag":"my-tag","cache_entry_id":"entry-1","exists":false,"storage_mode":"cas","blob_count":3,"blob_total_size_bytes":300,"cas_layout":"file-v1","manifest_upload_url":"https://example.com/upload","archive_urls":[],"upload_headers":{}}"#,
            )
            .create_async()
            .await;

        std::env::set_var("BORINGCACHE_API_URL", server.url());

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let response = client
            .preflight_entry(
                "ns/ws",
                "my-tag",
                &cache::PreflightRequest {
                    manifest_root_digest:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_string(),
                    compression_algorithm: "zstd".to_string(),
                    storage_mode: Some("cas".to_string()),
                    blob_count: Some(3),
                    blob_total_size_bytes: Some(300),
                    cas_layout: Some("file-v1".to_string()),
                    manifest_format_version: Some(1),
                    total_size_bytes: 300,
                    uncompressed_size: None,
                    compressed_size: None,
                    file_count: Some(3),
                    expected_manifest_digest: Some(
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                            .to_string(),
                    ),
                    expected_manifest_size: Some(1024),
                    force: None,
                    ci_provider: Some("github-actions".to_string()),
                    encrypted: None,
                    encryption_algorithm: None,
                    encryption_recipient_hint: None,
                },
            )
            .await
            .expect("preflight should succeed");

        assert!(!response.exists);
        assert_eq!(response.storage_mode.as_deref(), Some("cas"));
        assert_eq!(response.cas_layout.as_deref(), Some("file-v1"));

        mock.assert_async().await;

        if let Some(home) = original_home {
            std::env::set_var("HOME", home);
        }
        std::env::remove_var("BORINGCACHE_API_URL");
    }

    #[test]
    fn test_map_restore_result_prefers_top_level_cas_fields() {
        let mapped = ApiClient::map_restore_result(cache::RestoreResult {
            tag: "cas-tag".to_string(),
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
            }),
            error: None,
            pending: false,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: false,
        });

        assert_eq!(mapped.storage_mode.as_deref(), Some("cas"));
        assert_eq!(mapped.blob_count, Some(9));
        assert_eq!(mapped.blob_total_size_bytes, Some(4096));
        assert_eq!(mapped.cas_layout.as_deref(), Some("oci-v1"));
    }

    #[test]
    fn test_map_restore_result_uses_metadata_cas_fields_as_fallback() {
        let mapped = ApiClient::map_restore_result(cache::RestoreResult {
            tag: "cas-tag".to_string(),
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
            }),
            error: None,
            pending: false,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: false,
        });

        assert_eq!(mapped.storage_mode.as_deref(), Some("cas"));
        assert_eq!(mapped.blob_count, Some(3));
        assert_eq!(mapped.blob_total_size_bytes, Some(2048));
        assert_eq!(mapped.cas_layout.as_deref(), Some("bazel-v2"));
    }
}
