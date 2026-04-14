use super::*;

impl ApiClient {
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

    pub(crate) async fn post_v2_with_request_metrics<T, R>(
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

    pub(crate) async fn put_v2_with_request_metrics<T, R>(
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

    pub async fn send_metrics(
        &self,
        workspace: &str,
        params: crate::api::models::MetricsParams,
    ) -> Result<()> {
        let url = self.workspace_endpoint(workspace, "metrics")?;
        let _response: serde_json::Value = self.post_v2(&url, &params).await?;
        Ok(())
    }

    pub async fn send_cache_rollups(
        &self,
        workspace: &str,
        batch: crate::api::models::cache_rollups::BatchParams,
    ) -> Result<()> {
        let url = self.workspace_endpoint(workspace, "cache-rollups")?;
        let _response: serde_json::Value = self.post_v2(&url, &batch).await?;
        Ok(())
    }
}
