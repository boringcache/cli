use anyhow::{Context, Result};
use reqwest::{Client, Response, StatusCode};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tokio::time::sleep;

use crate::config::Config;
use crate::error::BoringCacheError;
use crate::ui::CleanUI;

pub fn parse_workspace_slug(workspace: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = workspace.split('/').collect();
    if parts.len() != 2 {
        anyhow::bail!("Invalid workspace format '{}'. Expected format: namespace/workspace (e.g., 'myorg/app')", workspace);
    }

    let namespace = parts[0];
    let workspace = parts[1];

    if namespace.is_empty() || workspace.is_empty() {
        anyhow::bail!("Namespace and workspace cannot be empty in '{}'", workspace);
    }

    let is_valid_name = |name: &str| {
        name.chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
            && !name.starts_with('-')
            && !name.ends_with('-')
            && !name.starts_with('.')
            && !name.ends_with('.')
    };

    if !is_valid_name(namespace) {
        anyhow::bail!("Invalid namespace '{}'. Must contain only alphanumeric characters, hyphens, underscores, and dots. Cannot start or end with hyphens or dots.", namespace);
    }

    if !is_valid_name(workspace) {
        anyhow::bail!("Invalid workspace '{}'. Must contain only alphanumeric characters, hyphens, underscores, and dots. Cannot start or end with hyphens or dots.", workspace);
    }

    Ok((namespace.to_string(), workspace.to_string()))
}

#[derive(Debug, Serialize)]
pub struct CacheParams {
    pub workspace_slug: String,
    pub cache_path: String,
    pub key_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct SaveCacheResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_url: Option<String>,
    pub cache_entry_id: String,
    pub storage_key: String,
    pub multipart: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub part_urls: Option<Vec<PartUpload>>,
}

#[derive(Debug, Deserialize)]
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
    pub cache_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    pub size: u64,
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[allow(dead_code)]
    pub compression_algorithm: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConfirmUploadParams {
    pub size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uncompressed_size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file_count: Option<u32>,
    pub storage_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_algorithm: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Workspace {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub slug: String,
    pub cache_entries_count: u32,
    pub total_cache_size: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

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
    pub compression_algorithm: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_level: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_threads: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub benchmark_throughput_mb_s: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub benchmark_compression_ratio: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compression_duration: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub predicted_time_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prediction_accuracy: Option<f64>,
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
    pub tags: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SessionInfo {
    #[allow(dead_code)]
    pub valid: bool,
    pub user: UserInfo,
    pub token: TokenInfo,
    pub organization: Option<OrganizationInfo>,
    pub workspace: Option<WorkspaceInfo>,
}

#[derive(Debug, Deserialize)]
pub struct UserInfo {
    #[allow(dead_code)]
    pub id: String,
    pub name: String,
    #[allow(dead_code)]
    pub email: String,
}

#[derive(Debug, Deserialize)]
pub struct OrganizationInfo {
    #[allow(dead_code)]
    pub id: String,
    pub name: String,
}

#[derive(Debug, Deserialize)]
pub struct WorkspaceInfo {
    #[allow(dead_code)]
    pub id: String,
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Deserialize)]
pub struct TokenInfo {
    pub id: String,
    pub name: String,
    pub scope_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_in_days: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct PartInfo {
    pub part_number: u32,
    pub etag: String,
}

#[derive(Clone)]
pub struct ApiClient {
    client: Client,
    base_url: String,
    token: Option<String>,
}

impl ApiClient {
    fn build_workspace_url(&self, workspace: &str, path: &str) -> Result<String> {
        let (namespace_slug, workspace_slug) = parse_workspace_slug(workspace)?;
        Ok(format!(
            "/workspaces/{namespace_slug}/{workspace_slug}{path}"
        ))
    }

    async fn execute_with_retry<F, Fut>(
        &self,
        operation_name: &str,
        mut request_fn: F,
    ) -> Result<Response>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Result<Response, reqwest::Error>>,
    {
        const MAX_RETRIES: u32 = 3;
        const BASE_DELAY_SECS: u64 = 2;

        let mut attempt = 0;

        loop {
            match request_fn().await {
                Ok(response) => return Ok(response),
                Err(err) => {
                    attempt += 1;

                    let should_retry = (err.is_connect()
                        || err.is_timeout()
                        || err.status() == Some(StatusCode::SERVICE_UNAVAILABLE))
                        && attempt <= MAX_RETRIES;

                    if !should_retry {
                        if err.is_connect() {
                            return Err(BoringCacheError::ConnectionError(
                                format!("❌ Cannot connect to BoringCache server after {attempt} attempts.\n\
                                        Please check:\n\
                                        • Is the server running? (Start with: cd web && rails server)\n\
                                        • Is the API URL correct? (Check with: boringcache config)\n\
                                        • Is there a firewall blocking the connection?")
                            ).into());
                        }
                        return Err(err.into());
                    }

                    let delay_secs = BASE_DELAY_SECS * (attempt as u64);

                    if attempt == 1 {
                        CleanUI::info(&format!(
                            "⚠️ {operation_name} failed. Connection issue detected."
                        ));
                    }

                    eprint!("🔄 Retrying in ");
                    for i in (1..=delay_secs).rev() {
                        eprint!("{i}s");
                        if i > 1 {
                            eprint!("...");
                            sleep(Duration::from_secs(1)).await;
                            eprint!("\x1b[3D");
                        } else {
                            sleep(Duration::from_secs(1)).await;
                        }
                    }
                    CleanUI::info(&format!(" (attempt {attempt}/{MAX_RETRIES})"));
                }
            }
        }
    }

    pub fn new(api_url: Option<String>) -> Result<Self> {
        let base_url = Config::get_api_url(api_url)?;
        let token = Config::load().ok().map(|c| c.token);

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

        Ok(Self {
            client,
            base_url,
            token,
        })
    }

    pub async fn save_cache(&self, params: CacheParams, size: u64) -> Result<SaveCacheResponse> {
        #[derive(serde::Serialize)]
        struct SaveParams {
            cache_path: String,
            key_hash: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            content_hash: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            compression_algorithm: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            description: Option<String>,
            #[serde(skip_serializing_if = "Option::is_none")]
            tag: Option<String>,
            size: u64,
        }

        let save_params = SaveParams {
            cache_path: params.cache_path,
            key_hash: params.key_hash,
            content_hash: params.content_hash,
            compression_algorithm: params.compression_algorithm,
            description: params.description,
            tag: params.tag,
            size,
        };

        let url = self.build_workspace_url(&params.workspace_slug, "/caches")?;
        let response = self.post(&url, &save_params).await?;
        self.parse_response(response).await
    }

    pub async fn batch_save_with_metadata(
        &self,
        workspace: &str,
        entries: &[String],               // Raw "path:tag" strings
        metadata: Vec<serde_json::Value>, // Metadata for each entry
        compression: Option<&str>,
        description: Option<&str>,
    ) -> Result<serde_json::Value> {
        #[derive(serde::Serialize)]
        struct BatchSaveParams {
            entries: String,          // Comma-separated path:tag pairs
            entries_metadata: String, // JSON array of metadata
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

        let url = self.build_workspace_url(workspace, "/caches")?;
        let response = self.post(&url, &batch_params).await?;

        if response.status().is_success() {
            let json: serde_json::Value = response.json().await?;
            Ok(json)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(
                BoringCacheError::ApiError(format!("HTTP {} - {}", status.as_u16(), error_text))
                    .into(),
            )
        }
    }

    pub async fn batch_restore_caches(
        &self,
        workspace: &str,
        entries: &[String], // Raw "tag:path" strings
    ) -> Result<Vec<CacheResolutionEntry>> {
        #[derive(serde::Serialize)]
        struct BatchRestoreParams {
            entries: String, // Comma-separated tag:path pairs
        }

        let batch_params = BatchRestoreParams {
            entries: entries.join(","),
        };

        let mut url = self.build_workspace_url(workspace, "/caches")?;
        let query_params = [
            format!("entries={}", urlencoding::encode(&batch_params.entries)),
            "mode=restore".to_string(),
        ];
        url.push('?');
        url.push_str(&query_params.join("&"));

        let response = self.get(&url).await?;

        if response.status().is_success() {
            let response_text = response.text().await?;

            if response_text.is_empty() {
                return Ok(vec![]);
            }

            let entries: Vec<CacheResolutionEntry> = serde_json::from_str(&response_text)
                .with_context(|| {
                    format!("Failed to parse batch restore response. Raw response: {response_text}")
                })?;
            Ok(entries)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(
                BoringCacheError::ApiError(format!("HTTP {} - {}", status.as_u16(), error_text))
                    .into(),
            )
        }
    }

    pub async fn confirm_upload(
        &self,
        workspace_slug: &str,
        cache_entry_id: &str,
        params: ConfirmUploadParams,
    ) -> Result<()> {
        let url = self.build_workspace_url(workspace_slug, &format!("/caches/{cache_entry_id}"))?;
        let response = self.patch(&url, &params).await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(BoringCacheError::ApiError(error_text).into())
        }
    }

    pub async fn complete_multipart_upload(
        &self,
        workspace_slug: &str,
        cache_entry_id: &str,
        upload_id: &str,
        parts: Vec<PartInfo>,
        params: ConfirmUploadParams,
    ) -> Result<()> {
        #[derive(serde::Serialize)]
        struct MultipartCompleteParams {
            multipart_complete: bool,
            upload_id: String,
            parts: Vec<PartInfo>,
            #[serde(flatten)]
            upload_params: ConfirmUploadParams,
        }

        let complete_params = MultipartCompleteParams {
            multipart_complete: true,
            upload_id: upload_id.to_string(),
            parts,
            upload_params: params,
        };

        let url = self.build_workspace_url(workspace_slug, &format!("/caches/{cache_entry_id}"))?;
        let response = self.patch(&url, &complete_params).await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(BoringCacheError::ApiError(error_text).into())
        }
    }

    pub async fn list_workspaces(&self) -> Result<Vec<Workspace>> {
        let response = self.get("/workspaces").await?;
        self.parse_response(response).await
    }

    pub async fn delete_cache(&self, workspace_slug: &str, key_hash: &str) -> Result<()> {
        let url = self.build_workspace_url(workspace_slug, &format!("/caches/{key_hash}"))?;
        let response = self.delete(&url).await?;

        if response.status().is_success() {
            Ok(())
        } else if response.status() == StatusCode::NOT_FOUND {
            Err(BoringCacheError::CacheMiss.into())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(BoringCacheError::ApiError(error_text).into())
        }
    }

    async fn get(&self, path: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.token.as_ref().ok_or(BoringCacheError::TokenNotFound)?;

        let token_clone = token.clone();
        let url_clone = url.clone();
        let client = self.client.clone();

        self.execute_with_retry("GET request", move || {
            let req = client
                .get(&url_clone)
                .header("Authorization", format!("Bearer {token_clone}"));

            req.send()
        })
        .await
    }

    async fn post<T: Serialize>(&self, path: &str, body: &T) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.token.as_ref().ok_or(BoringCacheError::TokenNotFound)?;
        let body_json = serde_json::to_value(body).context("Failed to serialize request body")?;

        let token_clone = token.clone();
        let url_clone = url.clone();
        let client = self.client.clone();

        self.execute_with_retry("POST request", move || {
            let req = client
                .post(&url_clone)
                .header("Authorization", format!("Bearer {token_clone}"))
                .json(&body_json);

            req.send()
        })
        .await
    }

    async fn patch<T: Serialize>(&self, path: &str, body: &T) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.token.as_ref().ok_or(BoringCacheError::TokenNotFound)?;
        let body_json = serde_json::to_value(body).context("Failed to serialize request body")?;

        let token_clone = token.clone();
        let url_clone = url.clone();
        let client = self.client.clone();

        self.execute_with_retry("PATCH request", move || {
            let req = client
                .patch(&url_clone)
                .header("Authorization", format!("Bearer {token_clone}"))
                .json(&body_json);

            req.send()
        })
        .await
    }

    async fn delete(&self, path: &str) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.token.as_ref().ok_or(BoringCacheError::TokenNotFound)?;

        let token_clone = token.clone();
        let url_clone = url.clone();
        let client = self.client.clone();

        self.execute_with_retry("DELETE request", move || {
            let req = client
                .delete(&url_clone)
                .header("Authorization", format!("Bearer {token_clone}"));

            req.send()
        })
        .await
    }

    async fn put<T: Serialize>(&self, path: &str, body: &T) -> Result<Response> {
        let url = format!("{}{}", self.base_url, path);
        let token = self.token.as_ref().ok_or(BoringCacheError::TokenNotFound)?;
        let body_json = serde_json::to_value(body).context("Failed to serialize request body")?;

        let token_clone = token.clone();
        let url_clone = url.clone();
        let client = self.client.clone();

        self.execute_with_retry("PUT request", move || {
            let req = client
                .put(&url_clone)
                .header("Authorization", format!("Bearer {token_clone}"))
                .json(&body_json);

            req.send()
        })
        .await
    }

    async fn parse_response<T: for<'de> Deserialize<'de>>(&self, response: Response) -> Result<T> {
        let status = response.status();
        let text = response
            .text()
            .await
            .context("Failed to read response body")?;

        if status.is_success() {
            serde_json::from_str(&text).with_context(|| format!("Failed to parse response: {text}"))
        } else if status == StatusCode::NOT_FOUND {
            let error_msg = self.parse_error_message(&text);
            Err(BoringCacheError::ApiError(format!("Not found: {error_msg}")).into())
        } else {
            let error_msg = self.parse_error_message(&text);
            Err(BoringCacheError::ApiError(format!("HTTP {status}: {error_msg}")).into())
        }
    }

    fn parse_error_message(&self, text: &str) -> String {
        if text.starts_with("<!DOCTYPE") || text.starts_with("<html") {
            return "Server returned HTML instead of JSON. Please check the API URL.".to_string();
        }

        #[derive(Deserialize)]
        struct ErrorResponse {
            error: Option<String>,
            message: Option<String>,
        }

        if let Ok(error) = serde_json::from_str::<ErrorResponse>(text) {
            error
                .error
                .or(error.message)
                .unwrap_or_else(|| text.to_string())
        } else {
            text.to_string()
        }
    }

    pub fn get_client(&self) -> &Client {
        &self.client
    }

    pub async fn validate_token(&self, token: &str) -> Result<SessionInfo> {
        let url = format!("{}/session", self.base_url);
        let token_clone = token.to_string();
        let url_clone = url.clone();
        let client = self.client.clone();

        let response = self
            .execute_with_retry("Token validation", move || {
                let req = client
                    .get(&url_clone)
                    .header("Authorization", format!("Bearer {token_clone}"));

                req.send()
            })
            .await?;

        let status = response.status();
        let text = response
            .text()
            .await
            .context("Failed to read response body")?;

        if status.is_success() {
            serde_json::from_str(&text)
                .with_context(|| format!("Failed to parse session response: {text}"))
        } else {
            let error_msg = self.parse_error_message(&text);
            Err(BoringCacheError::ApiError(format!(
                "Token validation failed: HTTP {status}: {error_msg}"
            ))
            .into())
        }
    }

    pub async fn list_caches(
        &self,
        workspace_slug: &str,
        limit: Option<u32>,
        page: Option<u32>,
    ) -> Result<ListCachesResponse> {
        let mut url = self.build_workspace_url(workspace_slug, "/caches")?;

        let mut query_params = Vec::new();
        if let Some(limit) = limit {
            query_params.push(format!("limit={limit}"));
        }
        if let Some(page) = page {
            query_params.push(format!("page={page}"));
        }

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        let response = self.get(&url).await?;
        let status = response.status();

        if status.is_success() {
            let text = response
                .text()
                .await
                .context("Failed to read response body")?;
            serde_json::from_str(&text).with_context(|| format!("Failed to parse response: {text}"))
        } else if status == StatusCode::NOT_FOUND {
            Err(BoringCacheError::WorkspaceNotFound(workspace_slug.to_string()).into())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            let error_msg = self.parse_error_message(&error_text);
            Err(BoringCacheError::ApiError(format!("HTTP {status}: {error_msg}")).into())
        }
    }

    pub async fn update_workspace_config(
        &self,
        workspace_slug: &str,
        config: &serde_json::Value,
    ) -> Result<()> {
        let url = self.build_workspace_url(workspace_slug, "/config")?;
        let response = self.put(&url, config).await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(BoringCacheError::ApiError(format!("HTTP {status}: {error_text}")).into())
        }
    }

    pub async fn get_workspace_config(&self, workspace_slug: &str) -> Result<serde_json::Value> {
        let url = self.build_workspace_url(workspace_slug, "/config")?;
        let response = self.get(&url).await?;

        if response.status().is_success() {
            let config: serde_json::Value = response.json().await?;
            Ok(config)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            Err(BoringCacheError::ApiError(format!("HTTP {status}: {error_text}")).into())
        }
    }

    pub async fn submit_metrics(
        &self,
        workspace_slug: &str,
        metrics: &MetricsParams,
    ) -> Result<()> {
        let url = self.build_workspace_url(workspace_slug, "/metrics")?;
        let response = self.post(&url, metrics).await?;

        if response.status().is_success() {
            Ok(())
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            if std::env::var("BORINGCACHE_DEBUG_TELEMETRY").is_ok() {
                CleanUI::info(&format!(
                    "Telemetry submission failed ({status}): {error_text}"
                ));
            }
            Err(
                BoringCacheError::ApiError(format!("Metrics submission failed: {error_text}"))
                    .into(),
            )
        }
    }

    pub async fn resolve_cache_keys(
        &self,
        workspace_slug: &str,
        keys: &[String],
    ) -> Result<Vec<CacheResolutionEntry>> {
        self.get_cache_entries_with_keys(workspace_slug, keys, "restore")
            .await
    }

    pub async fn get_cache_entries_with_keys(
        &self,
        workspace_slug: &str,
        keys: &[String],
        mode: &str,
    ) -> Result<Vec<CacheResolutionEntry>> {
        let mut url = self.build_workspace_url(workspace_slug, "/caches")?;

        let mut query_params = Vec::new();
        if !keys.is_empty() {
            query_params.push(format!("keys={}", urlencoding::encode(&keys.join(","))));
        }
        if mode != "ls" {
            query_params.push(format!("mode={}", urlencoding::encode(mode)));
        }

        if !query_params.is_empty() {
            url.push('?');
            url.push_str(&query_params.join("&"));
        }

        let response = self.get(&url).await?;

        if response.status().is_success() {
            let entries: Vec<CacheResolutionEntry> = response
                .json()
                .await
                .context("Failed to parse cache entries response")?;
            Ok(entries)
        } else {
            let status = response.status();
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());

            match status {
                StatusCode::NOT_FOUND => {
                    Err(BoringCacheError::WorkspaceNotFound(workspace_slug.to_string()).into())
                }
                StatusCode::UNAUTHORIZED => Err(BoringCacheError::AuthenticationFailed.into()),
                _ => Err(BoringCacheError::ApiError(format!(
                    "Cache entries request failed ({status}): {error_text}"
                ))
                .into()),
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CacheTag {
    pub name: String,
    pub id: String,
}

#[derive(Debug, Deserialize)]
pub struct CacheResolutionEntry {
    pub identifier: String,
    pub tag: Option<String>,
    pub key: Option<String>,
    pub path: String,
    pub status: String, // "hit" or "miss"
    pub url: Option<String>,
    pub source: Option<String>, // "workspace", "system", or null
    pub cache_tag: Option<CacheTag>,
    pub compression_algorithm: Option<String>,
    pub size: Option<u64>,
}
