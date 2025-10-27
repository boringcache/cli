/// HTTP client utilities and common request patterns
///
/// Provides reusable HTTP client functionality, request builders,
/// and error handling patterns for API communication.
use crate::config::Config;
use crate::error::BoringCacheError;
use crate::types::Result;
use anyhow::{ensure, Context};
use log::debug;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    transfer_client: Client,
    base_url: String,
    auth_token: Option<String>,
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

        let client = crate::http_client::build_api_client_with_headers(Some(headers.clone()));
        let transfer_client = crate::http_client::build_transfer_client_with_headers(Some(headers));

        let mut auth_token = token_override;
        let mut base_url = std::env::var("BORINGCACHE_API_URL").ok();

        if let Some(cfg) = config.as_ref() {
            if auth_token.is_none() {
                auth_token = Some(cfg.token.clone());
            }
            if base_url.is_none() {
                base_url = Some(cfg.api_url.clone());
            }
        }

        let base_url = base_url.unwrap_or_else(|| "http://localhost:3000".to_string());

        let client = Self {
            client,
            transfer_client,
            base_url,
            auth_token,
        };

        debug!(
            "ApiClient configured base_url={} token_configured={}",
            client.base_url,
            client.auth_token.is_some()
        );

        Ok(client)
    }

    pub fn get_client(&self) -> &Client {
        &self.client
    }

    pub fn http_client(&self) -> &Client {
        &self.client
    }

    pub fn transfer_client(&self) -> &Client {
        &self.transfer_client
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn get_token(&self) -> Result<&str> {
        self.auth_token
            .as_deref()
            .context("No authentication token configured")
    }

    /// Build a URL for the given endpoint
    pub fn build_url(&self, endpoint: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            endpoint.trim_start_matches('/')
        )
    }

    /// Build a workspace-specific URL (like the original)
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

    /// Perform a GET request with authentication
    pub async fn get<T>(&self, endpoint: &str) -> Result<T>
    where
        T: for<'de> Deserialize<'de>,
    {
        let url = self.build_url(endpoint);
        debug!("GET {}", url);
        let response = self
            .send_authenticated_request(self.client.get(&url))
            .await?;
        self.parse_json_response(response).await
    }

    /// Perform a POST request with authentication and JSON body
    pub async fn post<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = self.build_url(endpoint);
        debug!("POST {}", url);
        let response = self
            .send_authenticated_request(self.client.post(&url).json(body))
            .await?;
        self.parse_json_response(response).await
    }

    /// Perform a PUT request with authentication and JSON body
    pub async fn put<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = self.build_url(endpoint);
        debug!("PUT {}", url);
        let response = self
            .send_authenticated_request(self.client.put(&url).json(body))
            .await?;
        self.parse_json_response(response).await
    }

    /// Send a request with authentication headers
    pub async fn send_authenticated_request(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> Result<Response> {
        let token = self
            .auth_token
            .as_ref()
            .ok_or(BoringCacheError::TokenNotFound)?;
        request = request.header("Authorization", format!("Bearer {}", token));

        match request.send().await {
            Ok(response) => Ok(response),
            Err(err) if err.is_connect() => Err(BoringCacheError::ConnectionError(
                "ERROR: Cannot connect to BoringCache server. Please check:\n\
                     • Is the API URL correct? (Check with: boringcache config)\n\
                     • Is there a firewall blocking the connection?"
                    .to_string(),
            )
            .into()),
            Err(err) => Err(err.into()),
        }
    }

    /// Parse a JSON response, handling errors appropriately
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

    /// Create a descriptive error from an HTTP response
    async fn create_error_from_response(&self, response: Response) -> anyhow::Error {
        let status = response.status();
        let url = response.url().clone();

        // Try to get error details from response body
        let error_body = response.text().await.unwrap_or_default();
        let parsed_payload = parse_error_payload(&error_body);

        match status {
            StatusCode::UNAUTHORIZED => {
                // Check if this is for authentication endpoints based on URL
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
            StatusCode::CONFLICT => {
                if let Some(parsed) = parsed_payload.as_ref() {
                    let mut message = parsed.message.clone();
                    if !parsed.details.is_empty() {
                        for detail in &parsed.details {
                            message.push_str(&format!("\n  - {}", detail));
                        }
                    }
                    anyhow::anyhow!(message)
                } else {
                    anyhow::anyhow!(
                        "Cache upload conflict (409). Another upload may already be in progress for this manifest. Please wait and try again."
                    )
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

    /// Retry a request with exponential backoff
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

    /// Perform a PATCH request with authentication and JSON body
    pub async fn patch<T, R>(&self, endpoint: &str, body: &T) -> Result<R>
    where
        T: Serialize,
        R: for<'de> Deserialize<'de>,
    {
        let url = self.build_url(endpoint);
        debug!("PATCH {}", url);
        let response = self
            .send_authenticated_request(self.get_client().patch(&url).json(body))
            .await?;
        self.parse_json_response(response).await
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
        self.post(&endpoint, &body).await
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
            "save_entry workspace={} tag={} chunks={} base_endpoint={}",
            workspace,
            entry.tag,
            entry.chunk_digests.len(),
            endpoint
        );
        if let Ok(body) = serde_json::to_string(&payload) {
            debug!("POST {} body={}", endpoint, body);
        }

        self.post(&endpoint, &payload).await
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
        let url = self.build_url(&endpoint);
        let response = self
            .send_authenticated_request(self.client.delete(&url).json(&Body { entries: tags }))
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

        self.patch(&endpoint, &Payload { cache: request }).await
    }

    fn map_restore_result(
        item: super::models::cache::RestoreResult,
    ) -> super::models::cache::CacheResolutionEntry {
        use crate::api::models::cache::{CacheResolutionEntry, RestoreResult};

        fn entry_from_result(item: RestoreResult) -> CacheResolutionEntry {
            let chunk_digests: Vec<String> = item
                .chunks
                .iter()
                .map(|chunk| chunk.digest.clone())
                .collect();

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
                chunk_count: item.chunk_count.or({
                    if item.chunks.is_empty() {
                        None
                    } else {
                        Some(item.chunks.len() as u32)
                    }
                }),
                chunks: item.chunks.clone(),
                chunk_digests,
                size: item.metadata.as_ref().and_then(|m| m.total_size_bytes),
                uncompressed_size: item.metadata.as_ref().and_then(|m| m.total_size_bytes),
                compressed_size: None,
                uploaded_at: None,
                content_hash: item.manifest_root_digest.clone().or_else(|| {
                    item.metadata
                        .as_ref()
                        .and_then(|m| m.manifest_root_digest.clone())
                }),
            }
        }

        entry_from_result(item)
    }

    async fn fetch_restore_response(
        &self,
        workspace: &str,
        entries: &[String],
    ) -> Result<Option<super::models::cache::RestoreResponse>> {
        use crate::api::models::cache::RestoreResponse;

        ensure!(
            !entries.is_empty(),
            "At least one cache tag must be provided"
        );

        let entries_param = entries.join(",");
        let base = self.workspace_endpoint(workspace, "caches")?;
        let url = format!("{}?entries={}", base, urlencoding::encode(&entries_param));
        let full_url = self.build_url(&url);
        let response = self
            .send_authenticated_request(self.client.get(&full_url))
            .await?;

        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(self.create_error_from_response(response).await);
        }

        let payload: RestoreResponse = response
            .json()
            .await
            .context("Failed to parse restore response")?;

        Ok(Some(payload))
    }

    pub async fn list_workspaces(&self) -> Result<Vec<super::models::Workspace>> {
        self.get("workspaces").await
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

        self.get(&url).await
    }

    pub async fn get_session_info(&self) -> Result<super::models::SessionInfo> {
        self.get("session").await
    }

    pub async fn validate_token(&self, _token: &str) -> Result<super::models::SessionInfo> {
        match self.get_session_info().await {
            Ok(session_info) => Ok(session_info),
            Err(e) => {
                // For token validation, provide more specific error messages
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
        let _response: serde_json::Value = self.post(&url, &params).await?;
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

/// Common request/response patterns
pub mod patterns {
    use super::*;

    /// Standard API response wrapper
    #[derive(Debug, Deserialize)]
    pub struct ApiResponse<T> {
        pub data: T,
        #[serde(default)]
        pub message: Option<String>,
    }

    /// Paginated response wrapper
    #[derive(Debug, Deserialize)]
    pub struct PaginatedResponse<T> {
        pub items: Vec<T>,
        pub total: u64,
        pub page: u32,
        pub per_page: u32,
        pub has_more: bool,
    }

    /// Error response format
    #[derive(Debug, Deserialize)]
    pub struct ErrorResponse {
        pub error: String,
        #[serde(default)]
        pub details: Option<String>,
        #[serde(default)]
        pub code: Option<String>,
    }
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

    #[test]
    fn test_url_building() {
        let client = ApiClient {
            client: Client::new(),
            transfer_client: Client::new(),
            base_url: "https://api.example.com".to_string(),
            auth_token: None,
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
    async fn test_manifest_check_request_body() {
        let mutex = ENV_MUTEX.get_or_init(|| Mutex::new(()));

        {
            let _guard = mutex.lock().unwrap();
            if !networking_available() {
                eprintln!(
                    "skipping test_manifest_check_request_body: networking disabled in sandbox"
                );
                return;
            }
        }

        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("POST", "/workspaces/ns/ws/caches/check")
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
        {
            let _guard = mutex.lock().unwrap();
            std::env::set_var("BORINGCACHE_API_URL", server.url());
        }

        let client = ApiClient::new_with_token_override(Some("test-token".to_string()))
            .expect("client should initialize");

        let response = client
            .check_manifests(
                "ns/ws",
                &[cache::ManifestCheckRequest {
                    tag: "abc123def456".to_string(),
                    manifest_root_digest: "blake3:abc".to_string(),
                    chunk_digests: None,
                }],
            )
            .await
            .expect("manifest check should succeed");

        assert_eq!(response.results.len(), 1);
        let result = &response.results[0];
        assert!(result.exists);
        assert_eq!(result.tag, "abc123def456");

        mock.assert_async().await;

        if let Some(mutex) = ENV_MUTEX.get() {
            let _cleanup_guard = mutex.lock().unwrap();
            std::env::remove_var("BORINGCACHE_API_URL");
        } else {
            std::env::remove_var("BORINGCACHE_API_URL");
        }
    }
}
