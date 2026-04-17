use super::*;

impl ApiClient {
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
        checks: &[crate::api::models::cache::ManifestCheckRequest],
    ) -> Result<crate::api::models::cache::ManifestCheckResponse> {
        ensure!(!checks.is_empty(), "manifest_checks cannot be empty");
        let endpoint = self.workspace_endpoint(workspace, "caches/check")?;
        let body = crate::api::models::cache::ManifestCheckBatchRequest {
            manifest_checks: checks.to_vec(),
        };
        self.post_v2(&endpoint, &body).await
    }

    pub async fn check_blobs(
        &self,
        workspace: &str,
        blobs: &[crate::api::models::cache::BlobDescriptor],
        verify_storage: bool,
    ) -> Result<crate::api::models::cache::BlobCheckResponse> {
        ensure!(!blobs.is_empty(), "blobs cannot be empty");
        let endpoint = self.workspace_endpoint(workspace, "caches/blobs/check")?;
        let batch_max = blob_check_batch_max();
        let chunk_count = blobs.len().div_ceil(batch_max);
        let batch_count = chunk_count as u64;
        if chunk_count == 1 {
            let body = crate::api::models::cache::BlobCheckRequest {
                blobs: blobs.to_vec(),
                verify_storage: verify_storage.then_some(true),
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
                let body = crate::api::models::cache::BlobCheckRequest {
                    blobs: chunk,
                    verify_storage: verify_storage.then_some(true),
                };
                let response = client
                    .post_v2_with_request_metrics::<_, crate::api::models::cache::BlobCheckResponse>(
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

        Ok(crate::api::models::cache::BlobCheckResponse { results })
    }

    pub async fn check_blobs_verified(
        &self,
        workspace: &str,
        blobs: &[crate::api::models::cache::BlobDescriptor],
    ) -> Result<crate::api::models::cache::BlobCheckResponse> {
        self.check_blobs(workspace, blobs, true).await
    }

    pub async fn blob_upload_urls(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        blobs: &[crate::api::models::cache::BlobDescriptor],
    ) -> Result<crate::api::models::cache::BlobUploadUrlsResponse> {
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
            let body = crate::api::models::cache::BlobStageRequest {
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
                let body = crate::api::models::cache::BlobStageRequest {
                    cache_entry_id: entry_id,
                    blobs: chunk,
                };
                let response = client
                .post_v2_with_request_metrics::<
                    _,
                    crate::api::models::cache::BlobUploadUrlsResponse,
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

        Ok(crate::api::models::cache::BlobUploadUrlsResponse {
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
        receipts: &[crate::api::models::cache::BlobReceipt],
    ) -> Result<Option<crate::api::models::cache::UploadSessionStatusResponse>> {
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
            let body = crate::api::models::cache::BlobReceiptCommitRequest {
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
        request: &crate::api::models::cache::ManifestReceiptCommitRequest,
    ) -> Result<Option<crate::api::models::cache::UploadSessionStatusResponse>> {
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
        blobs: &[crate::api::models::cache::BlobDescriptor],
        verify_storage: bool,
    ) -> Result<crate::api::models::cache::BlobDownloadUrlsResponse> {
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
            let body = crate::api::models::cache::BlobDownloadUrlsRequest {
                cache_entry_id: cache_entry_id.to_string(),
                blobs: blobs.to_vec(),
                verify_storage: verify_storage.then_some(true),
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
                let body = crate::api::models::cache::BlobDownloadUrlsRequest {
                    cache_entry_id,
                    blobs: chunk,
                    verify_storage: verify_storage.then_some(true),
                };
                let response = client
                .post_v2_with_request_metrics::<
                    _,
                    crate::api::models::cache::BlobDownloadUrlsResponse,
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

        Ok(crate::api::models::cache::BlobDownloadUrlsResponse {
            download_urls,
            missing: dedupe_strings(missing),
        })
    }

    pub async fn blob_download_urls_verified(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        blobs: &[crate::api::models::cache::BlobDescriptor],
    ) -> Result<crate::api::models::cache::BlobDownloadUrlsResponse> {
        self.blob_download_urls(workspace, cache_entry_id, blobs, true)
            .await
    }

    pub async fn save_entry(
        &self,
        workspace: &str,
        entry: &crate::api::models::cache::SaveRequest,
    ) -> Result<crate::api::models::cache::SaveResponse> {
        ensure!(!entry.tag.trim().is_empty(), "Tag must not be empty");

        #[derive(Serialize)]
        struct Payload<'a> {
            cache: &'a crate::api::models::cache::SaveRequest,
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
    ) -> Result<Vec<crate::api::models::cache::TagDeleteResponse>> {
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
    ) -> Result<Vec<crate::api::models::cache::CacheResolutionEntry>> {
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
    ) -> Result<Option<crate::api::models::cache::CacheResolutionEntry>> {
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
        request: &crate::api::models::cache::ConfirmRequest,
    ) -> Result<crate::api::models::cache::CacheConfirmResponse> {
        self.confirm_with_retry(workspace, cache_entry_id, request)
            .await
    }

    pub async fn confirm_with_retry(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        request: &crate::api::models::cache::ConfirmRequest,
    ) -> Result<crate::api::models::cache::CacheConfirmResponse> {
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
        let mut transient_publish_errors = 0u32;

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
                    if started_at.elapsed() < confirm_publish_request_timeout()
                        && should_retry_confirm_publish_error(&error)
                    {
                        transient_publish_errors = transient_publish_errors.saturating_add(1);
                        let delay = confirm_publish_error_delay(&error, transient_publish_errors);
                        log::warn!(
                            "Confirm publish transient error for tag={tag}: {error}; retrying in {:.1}s (consecutive_errors={})",
                            delay.as_secs_f32(),
                            transient_publish_errors
                        );
                        sleep(delay).await;
                        continue;
                    }
                    return Err(error);
                }
            }
        };

        Ok(cache_confirm_response_from_tag_pointer(response))
    }

    pub async fn complete_multipart(
        &self,
        workspace: &str,
        cache_entry_id: &str,
        request: &crate::api::models::cache::CompleteMultipartRequest,
    ) -> Result<crate::api::models::cache::CompleteMultipartResponse> {
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
            multipart: &'a crate::api::models::cache::CompleteMultipartRequest,
        }

        self.post_v2(&endpoint, &Payload { multipart: request })
            .await
    }

    pub(crate) fn map_restore_result(
        item: crate::api::models::cache::RestoreResult,
    ) -> crate::api::models::cache::CacheResolutionEntry {
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
    ) -> Result<Option<crate::api::models::cache::RestoreResponse>> {
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
        let pointer: crate::api::models::cache::TagPointerResponse = response
            .json()
            .await
            .context("Failed to parse tag pointer response")?;
        Ok(TagPointerPollResult::Changed { pointer, etag })
    }

    pub async fn list(
        &self,
        workspace: &str,
        limit: Option<u32>,
        page: Option<u32>,
    ) -> Result<crate::api::models::CacheEntriesListResponse> {
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

    pub async fn inspect_cache(
        &self,
        workspace: &str,
        identifier: &str,
    ) -> Result<Option<crate::api::models::cache::CacheInspectResponse>> {
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
}
