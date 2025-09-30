/// HTTP client utilities and common request patterns
///
/// Provides reusable HTTP client functionality, request builders,
/// and error handling patterns for API communication.
use crate::config::Config;
use crate::error::BoringCacheError;
use crate::types::{Result, WorkspaceId};
use anyhow::Context;
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
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

        let client = Client::builder()
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(10)
            .pool_idle_timeout(Duration::from_secs(90))
            .default_headers(headers)
            .build()
            .context("Failed to create HTTP client")?;

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

        Ok(Self {
            client,
            base_url,
            auth_token,
        })
    }

    pub fn get_client(&self) -> &Client {
        &self.client
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

    /// Build a workspace-specific URL from WorkspaceId
    pub fn build_workspace_url_from_id(&self, workspace: &WorkspaceId, endpoint: &str) -> String {
        let workspace_slug = workspace.slug();
        self.build_url(&format!(
            "workspaces/{}/{}",
            workspace_slug,
            endpoint.trim_start_matches('/')
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
        let response = self
            .send_authenticated_request(self.client.put(&url).json(body))
            .await?;
        self.parse_json_response(response).await
    }

    /// Perform a DELETE request with authentication
    pub async fn delete(&self, endpoint: &str) -> Result<()> {
        let url = self.build_url(endpoint);
        let response = self
            .send_authenticated_request(self.client.delete(&url))
            .await?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(self.create_error_from_response(response).await)
        }
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
                     • Is the server running? (Start with: cd web && rails server)\n\
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
                    BoringCacheError::ConnectionError(
                        "ERROR: Cannot connect to BoringCache server. Please check:\n\
                         • Is the server running? (Start with: cd web && rails server)\n\
                         • Is the API URL correct? (Check with: boringcache config)\n\
                         • Is there a firewall blocking the connection?"
                            .to_string(),
                    )
                    .into()
                }
            }
            StatusCode::FORBIDDEN => BoringCacheError::ConnectionError(
                "ERROR: Cannot connect to BoringCache server. Please check:\n\
                 • Is the server running? (Start with: cd web && rails server)\n\
                 • Is the API URL correct? (Check with: boringcache config)\n\
                 • Is there a firewall blocking the connection?"
                    .to_string(),
            )
            .into(),
            StatusCode::NOT_FOUND => {
                anyhow::anyhow!("Resource not found: {}", url)
            }
            StatusCode::TOO_MANY_REQUESTS => {
                anyhow::anyhow!("Rate limit exceeded. Please try again later.")
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
        let response = self
            .send_authenticated_request(self.get_client().patch(&url).json(body))
            .await?;
        self.parse_json_response(response).await
    }

    // === Cache Operations ===

    pub async fn batch_check_existence(
        &self,
        workspace: &str,
        entries: &[String],
    ) -> Result<serde_json::Value> {
        let url = self.workspace_endpoint(workspace, "caches/check")?;
        let request_body = serde_json::json!({
            "entries": entries.join(",")
        });

        match self.post(&url, &request_body).await {
            Ok(result) => Ok(result),
            Err(_) => {
                // Fallback silently - old servers won't have this endpoint
                Ok(serde_json::json!({ "results": [] }))
            }
        }
    }

    pub async fn check_content_hash(
        &self,
        workspace: &str,
        content_hash: &str,
    ) -> Result<super::models::cache::CacheCheckHashResponse> {
        let url = self.workspace_endpoint(workspace, "caches/check")?;
        let request_body = serde_json::json!({
            "content_hash": content_hash
        });

        self.post(&url, &request_body).await
    }

    pub async fn batch_save_with_metadata(
        &self,
        workspace: &str,
        entries: &[String],
        metadata: Vec<serde_json::Value>,
        compression: Option<&str>,
        description: Option<&str>,
    ) -> Result<serde_json::Value> {
        use serde::Serialize;

        #[derive(Serialize)]
        struct BatchSaveParams {
            entries: String,
            entries_metadata: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            compression_algorithm: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
        }

        let batch_params = BatchSaveParams {
            entries: entries.join(","),
            entries_metadata: serde_json::to_string(&metadata)?,
            compression_algorithm: compression.map(|s| s.to_string()),
            description: description.map(|s| s.to_string()),
        };

        let url = self.workspace_endpoint(workspace, "caches")?;
        self.post(&url, &batch_params).await
    }

    pub async fn batch_restore_caches(
        &self,
        workspace: &str,
        entries: &[String],
    ) -> Result<Vec<super::models::CacheResolutionEntry>> {
        let entries_param = entries.join(",");
        let base = self.workspace_endpoint(workspace, "caches")?;
        let url = format!(
            "{}?entries={}&mode=restore",
            base,
            urlencoding::encode(&entries_param)
        );

        match self.get(&url).await {
            Ok(entries) => Ok(entries),
            Err(e) => {
                // Handle empty response
                if e.to_string().contains("EOF") {
                    Ok(vec![])
                } else {
                    Err(e)
                }
            }
        }
    }

    pub async fn confirm_upload(
        &self,
        workspace_slug: &str,
        cache_entry_id: &str,
        params: super::models::ConfirmUploadParams,
    ) -> Result<()> {
        let url = format!("workspaces/{}/caches/{}", workspace_slug, cache_entry_id);
        let _response: serde_json::Value = self.patch(&url, &params).await?;
        Ok(())
    }

    pub async fn complete_multipart_upload(
        &self,
        workspace_slug: &str,
        cache_entry_id: &str,
        upload_id: &str,
        parts: Vec<super::models::PartInfo>,
        params: super::models::ConfirmUploadParams,
    ) -> Result<()> {
        use serde::Serialize;

        #[derive(Serialize)]
        struct MultipartCompleteParams {
            multipart_complete: bool,
            upload_id: String,
            parts: Vec<super::models::PartInfo>,
            #[serde(flatten)]
            upload_params: super::models::ConfirmUploadParams,
        }

        let complete_params = MultipartCompleteParams {
            multipart_complete: true,
            upload_id: upload_id.to_string(),
            parts,
            upload_params: params,
        };

        let url = format!("workspaces/{}/caches/{}", workspace_slug, cache_entry_id);
        let _response: serde_json::Value = self.patch(&url, &complete_params).await?;
        Ok(())
    }

    pub async fn list_workspaces(&self) -> Result<Vec<super::models::Workspace>> {
        self.get("workspaces").await
    }

    pub async fn list_caches(
        &self,
        workspace: &str,
        limit: Option<u32>,
        page: Option<u32>,
    ) -> Result<super::models::ListCachesResponse> {
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

    pub async fn delete_cache_entry(&self, workspace: &str, cache_key: &str) -> Result<()> {
        let base = self.workspace_endpoint(workspace, "caches")?;
        let url = format!("{}/{}", base, urlencoding::encode(cache_key));
        self.delete(&url).await
    }

    pub async fn delete_cache(&self, workspace: &str, cache_key: &str) -> Result<()> {
        self.delete_cache_entry(workspace, cache_key).await
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

    #[test]
    fn test_url_building() {
        let client = ApiClient {
            client: Client::new(),
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
    fn test_workspace_url_building() {
        let client = ApiClient {
            client: Client::new(),
            base_url: "https://api.example.com".to_string(),
            auth_token: None,
        };

        let workspace = WorkspaceId::new("namespace".to_string(), "workspace".to_string()).unwrap();

        assert_eq!(
            client.build_workspace_url_from_id(&workspace, "caches"),
            "https://api.example.com/workspaces/namespace/workspace/caches"
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
}
