use super::*;

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

    pub(crate) fn build_url_from_base(base_url: &str, endpoint: &str) -> String {
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
        let (namespace_slug, workspace_slug) = crate::api::parse_workspace_slug(workspace)?;
        Ok(format!(
            "workspaces/{namespace_slug}/{workspace_slug}{path}"
        ))
    }

    pub(crate) fn workspace_endpoint(&self, workspace: &str, path: &str) -> Result<String> {
        let (namespace_slug, workspace_slug) = crate::api::parse_workspace_slug(workspace)?;
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

    pub(crate) async fn get_response_with_base(
        &self,
        base_url: &str,
        endpoint: &str,
    ) -> Result<Response> {
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

    pub(crate) async fn send_authenticated_request_with_retry_count(
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
                            if is_retryable_api_status(response.status()) {
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

    pub(crate) async fn send_public_request(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Response> {
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
                            if is_retryable_api_status(response.status()) {
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

    pub(crate) async fn create_error_from_response(&self, response: Response) -> anyhow::Error {
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
                anyhow::anyhow!(
                    "Rate limit exceeded (429 Too Many Requests). Please try again later."
                )
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
            StatusCode::LOCKED => BoringCacheError::cache_pending().into(),
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

    pub(crate) async fn put_v2_with_if_match<T, R>(
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
}
