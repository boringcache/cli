use anyhow::{Context, Result};
use bytes::Bytes;
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

use crate::api::{ApiClient, CacheParams, PartInfo};
use crate::archive::ArchiveInfo;
use crate::platform::{Platform, SystemResources};
use crate::progress::{format_bytes, Reporter};
use crate::retry_resume::{RetryConfig, UploadResumeInfo};
use crate::transfer::create_confirm_params;

pub struct UploadProgressHandle {
    reporter: Reporter,
    session_id: String,
    total_bytes: u64,
    total_parts: u32,
    start: Instant,
    uploaded_bytes: AtomicU64,
    completed_parts: AtomicU32,
}

impl UploadProgressHandle {
    pub fn new(reporter: Reporter, session_id: String, total_bytes: u64, total_parts: u32) -> Self {
        Self {
            reporter,
            session_id,
            total_bytes,
            total_parts: total_parts.max(1),
            start: Instant::now(),
            uploaded_bytes: AtomicU64::new(0),
            completed_parts: AtomicU32::new(0),
        }
    }

    pub fn apply_resume(&self, resumed_parts: u32, resumed_bytes: u64) {
        if resumed_parts == 0 || resumed_bytes == 0 {
            return;
        }

        let bytes = resumed_bytes.min(self.total_bytes);
        let parts = resumed_parts.min(self.total_parts);

        self.uploaded_bytes.store(bytes, Ordering::Relaxed);
        self.completed_parts.store(parts, Ordering::Relaxed);
        self.emit_progress(bytes, parts);
    }

    pub fn record_part(&self, bytes_uploaded: u64) {
        let previous_bytes = self
            .uploaded_bytes
            .fetch_add(bytes_uploaded, Ordering::Relaxed);
        let uploaded = (previous_bytes + bytes_uploaded).min(self.total_bytes);

        if self.total_parts > 1 {
            let previous_parts = self.completed_parts.fetch_add(1, Ordering::Relaxed);
            let parts = (previous_parts + 1).min(self.total_parts);
            self.emit_progress(uploaded, parts);
        } else {
            self.emit_progress(uploaded, self.total_parts);
        }
    }

    pub fn complete(&self) {
        self.uploaded_bytes
            .store(self.total_bytes, Ordering::Relaxed);
        self.completed_parts
            .store(self.total_parts, Ordering::Relaxed);
        self.emit_progress(self.total_bytes, self.total_parts);
    }

    fn emit_progress(&self, uploaded_bytes: u64, completed_parts: u32) {
        let percent = if self.total_bytes > 0 {
            (uploaded_bytes as f64 / self.total_bytes as f64) * 100.0
        } else {
            100.0
        };

        let clamped_percent = percent.clamp(0.0, 100.0);
        let percent_text = format!("{:>3.0}%", clamped_percent);

        let elapsed = self.start.elapsed().as_secs_f64().max(0.001);
        let speed_mbps = (uploaded_bytes as f64 / (1024.0 * 1024.0)) / elapsed;

        let detail = if self.total_parts > 1 {
            format!(
                "[{}/{} parts, {}] {} @ {:.1} MB/s",
                completed_parts,
                self.total_parts,
                format_bytes(self.total_bytes),
                percent_text,
                speed_mbps
            )
        } else {
            format!(
                "[{}] {} @ {:.1} MB/s",
                format_bytes(self.total_bytes),
                percent_text,
                speed_mbps
            )
        };

        let _ =
            self.reporter
                .step_progress(self.session_id.clone(), 3, clamped_percent, Some(detail));
    }
}

pub struct UploadOperation {
    pub api_client: ApiClient,
    pub workspace: String,
    pub verbose: bool,
}

impl UploadOperation {
    pub fn new(api_client: ApiClient, workspace: String, verbose: bool) -> Self {
        Self {
            api_client,
            workspace,
            verbose,
        }
    }

    fn handle_tag_assignment(&self, _tag: Option<&str>) {
        // Tag assignment is now handled by the main progress system
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload_archive(
        &self,
        archive_data: &Bytes,
        archive_info: &ArchiveInfo,
        key_hash: &str,
        cache_path: &str,
        tag: Option<&str>,
        description: Option<&str>,
    ) -> Result<()> {
        use serde_json::json;

        let platform = Platform::detect()?;
        let metadata = json!({
            "platform": platform.fingerprint()
        });

        let save_params = CacheParams {
            workspace_slug: self.workspace.clone(),
            cache_path: cache_path.to_string(),
            key_hash: key_hash.to_string(),
            content_hash: Some(archive_info.content_sha256.clone()),
            compression_algorithm: Some(archive_info.compression_backend.name().to_string()),
            description: description.map(|s| s.to_string()),
            tag: tag.map(|s| s.to_string()),
            metadata: Some(metadata),
        };

        let save_response = self
            .api_client
            .save_cache(save_params, archive_info.compressed_size)
            .await
            .context("Failed to request upload URL")?;

        if save_response.multipart {
            self.upload_multipart(&save_response, archive_data, archive_info, tag, None)
                .await?;
        } else {
            self.upload_single(&save_response, archive_data, archive_info, tag, None)
                .await?;
        }

        Ok(())
    }

    pub async fn upload_single(
        &self,
        save_response: &crate::api::SaveCacheResponse,
        archive_data: &Bytes,
        archive_info: &ArchiveInfo,
        tag: Option<&str>,
        progress: Option<Arc<UploadProgressHandle>>,
    ) -> Result<()> {
        let upload_url = save_response
            .upload_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing upload_url for single upload"))?;

        let size_mb = archive_info.compressed_size as f64 / (1024.0 * 1024.0);
        let _progress_message = if size_mb > 5000.0 {
            format!(
                "{} (large file, extended timeout)",
                format_bytes(archive_info.compressed_size)
            )
        } else if size_mb > 1000.0 {
            format!(
                "{} (extended timeout)",
                format_bytes(archive_info.compressed_size)
            )
        } else {
            format_bytes(archive_info.compressed_size)
        };

        let client = self.api_client.get_client();
        let retry_config = RetryConfig::new(self.verbose);

        let _response = retry_config
            .retry_with_backoff("Single upload", || async {
                let md5_hash = {
                    let digest = md5::compute(archive_data.as_ref());
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
                };

                let request = client
                    .put(upload_url)
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", archive_data.len().to_string())
                    .header("Content-MD5", md5_hash)
                    .body(archive_data.clone());

                let response = request.send().await?;
                if response.status().is_success() {
                    Ok(response)
                } else {
                    let error_msg = match response.status().as_u16() {
                        400 => "Server validation failed (Content-MD5 mismatch or invalid data)",
                        413 => "Upload too large (exceeds server limits)",
                        422 => "Server detected data corruption (size or checksum mismatch)",
                        _ => &format!("HTTP {}", response.status()),
                    };
                    Err(anyhow::anyhow!("{}", error_msg))
                }
            })
            .await?;

        if let Some(handle) = progress.as_ref() {
            handle.record_part(archive_data.len() as u64);
        }

        let confirm_params = create_confirm_params(archive_info, save_response.storage_key.clone());

        self.api_client
            .confirm_upload(
                &self.workspace,
                &save_response.cache_entry_id,
                confirm_params,
            )
            .await
            .context("Failed to confirm upload")?;

        if let Some(handle) = progress.as_ref() {
            handle.complete();
        }

        self.handle_tag_assignment(tag);

        Ok(())
    }

    pub async fn upload_multipart(
        &self,
        save_response: &crate::api::SaveCacheResponse,
        archive_data: &Bytes,
        archive_info: &ArchiveInfo,
        tag: Option<&str>,
        progress: Option<Arc<UploadProgressHandle>>,
    ) -> Result<()> {
        self.upload_multipart_resumable(save_response, archive_data, archive_info, tag, progress)
            .await
    }

    async fn upload_multipart_resumable(
        &self,
        save_response: &crate::api::SaveCacheResponse,
        archive_data: &Bytes,
        archive_info: &ArchiveInfo,
        tag: Option<&str>,
        progress: Option<Arc<UploadProgressHandle>>,
    ) -> Result<()> {
        use std::path::PathBuf;

        let upload_id = save_response
            .upload_id
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing upload_id for multipart upload"))?;
        let part_urls = save_response
            .part_urls
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing part_urls for multipart upload"))?;

        let temp_file = PathBuf::from(format!("/tmp/boringcache-upload-{upload_id}"));

        let mut upload_resume = UploadResumeInfo::load(&temp_file).await.unwrap_or_else(|| {
            UploadResumeInfo::new(
                temp_file.clone(),
                upload_id.clone(),
                archive_data.len() as u64,
                part_urls.len(),
            )
        });

        // Progress is now handled by the command-level progress system
        let _completed_parts = if self.verbose
            && !upload_resume
                .uploaded_parts
                .iter()
                .all(|&uploaded| !uploaded)
        {
            upload_resume
                .uploaded_parts
                .iter()
                .filter(|&&uploaded| uploaded)
                .count()
        } else {
            0
        };

        let system = SystemResources::detect();
        let _total_parts = part_urls.len();
        let completed_parts = Arc::new(Mutex::new(upload_resume.get_completed_parts()));

        let mut upload_futures = FuturesUnordered::new();
        // Increase concurrency for uploads - network I/O can handle more parallelism than CPU work
        let upload_concurrency = (system.max_parallel_chunks * 2).min(32);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(upload_concurrency));

        // Use larger chunks for better throughput - 64MB default, up to 128MB for large files
        let file_size_mb = archive_data.len() / (1024 * 1024);
        let default_chunk_size = if file_size_mb > 1000 {
            128 * 1024 * 1024usize // 128MB chunks for files > 1GB
        } else if file_size_mb > 500 {
            64 * 1024 * 1024usize // 64MB chunks for files > 500MB
        } else {
            32 * 1024 * 1024usize // 32MB chunks for smaller files
        };

        let actual_chunk_size = if archive_data.len() > part_urls.len() * default_chunk_size {
            default_chunk_size
        } else {
            archive_data.len().div_ceil(part_urls.len())
        };

        if let Some(handle) = progress.as_ref() {
            let mut resumed_parts = 0u32;
            let mut resumed_bytes = 0u64;

            for (i, uploaded) in upload_resume.uploaded_parts.iter().enumerate() {
                if *uploaded {
                    let start_byte = i * actual_chunk_size;
                    let end_byte =
                        std::cmp::min(start_byte + actual_chunk_size, archive_data.len());
                    if end_byte > start_byte {
                        resumed_bytes += (end_byte - start_byte) as u64;
                        resumed_parts += 1;
                    }
                }
            }

            handle.apply_resume(resumed_parts, resumed_bytes);
        }

        // Pre-compute MD5 hashes in parallel for better performance
        let mut chunks_with_hashes = Vec::new();
        for (i, part_url) in part_urls.iter().enumerate() {
            if upload_resume.uploaded_parts[i] {
                continue; // Skip already uploaded parts
            }

            let start_byte = i * actual_chunk_size;
            let end_byte = std::cmp::min(start_byte + actual_chunk_size, archive_data.len());

            if start_byte >= archive_data.len() {
                continue;
            }

            let chunk = archive_data.slice(start_byte..end_byte);
            let chunk_len_u64 = (end_byte - start_byte) as u64;
            let md5_hash = {
                let digest = md5::compute(chunk.as_ref());
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
            };

            chunks_with_hashes.push((i, part_url.clone(), chunk, md5_hash, chunk_len_u64));
        }

        // Now upload all chunks with pre-computed hashes
        for (i, part_url, chunk, md5_hash, chunk_len_u64) in chunks_with_hashes {
            let client = self.api_client.get_client().clone();
            let url = part_url.upload_url.clone();
            let part_number = part_url.part_number;
            let parts_clone = Arc::clone(&completed_parts);
            let sem_clone = Arc::clone(&semaphore);
            let verbose = self.verbose;
            let progress_handle = progress.as_ref().map(Arc::clone);

            let upload_future = async move {
                let retry_config = RetryConfig::new(verbose);
                let operation_name = format!("Upload part {part_number}");

                let _permit = sem_clone.acquire().await.unwrap();

                let chunk_for_retry = chunk.clone();
                let md5_for_retry = md5_hash.clone();
                let client_for_retry = client.clone();
                let url_for_retry = url.clone();

                let etag = retry_config
                    .retry_with_backoff(&operation_name, move || {
                        let chunk = chunk_for_retry.clone();
                        let md5_hash = md5_for_retry.clone();
                        let client = client_for_retry.clone();
                        let url = url_for_retry.clone();
                        async move {
                            let response = client
                                .put(&url)
                                .header("Content-Type", "application/octet-stream")
                                .header("Content-Length", chunk_len_u64.to_string())
                                .header("Content-MD5", &md5_hash)
                                .body(chunk)
                                .send()
                                .await?;

                            if !response.status().is_success() {
                                let error_msg = match response.status().as_u16() {
                                    400 => format!(
                                        "Part {part_number} validation failed (Content-MD5 mismatch)"
                                    ),
                                    413 => "Part too large (exceeds server limits)".to_string(),
                                    422 => format!("Part {part_number} corrupted (checksum mismatch)"),
                                    _ => format!(
                                        "HTTP {} for part {}",
                                        response.status(),
                                        part_number
                                    ),
                                };
                                return Err(anyhow::anyhow!("{}", error_msg));
                            }

                            let etag = response
                                .headers()
                                .get("etag")
                                .and_then(|h| h.to_str().ok())
                                .map(|s| s.trim_matches('"'))
                                .unwrap_or_default()
                                .to_string();

                            Ok::<String, anyhow::Error>(etag)
                        }
                    })
                    .await?;

                if let Some(handle) = progress_handle.as_ref() {
                    handle.record_part(chunk_len_u64);
                }

                let mut parts_guard = parts_clone.lock().await;
                parts_guard.push(PartInfo {
                    part_number,
                    etag: etag.clone(),
                });

                Ok::<(usize, String), anyhow::Error>((i, etag))
            };

            upload_futures.push(upload_future);
        }

        // Upload progress is handled by command-level progress system

        while let Some(result) = upload_futures.next().await {
            let (part_index, etag) = result?;
            upload_resume.mark_part_complete(part_index, etag);

            if part_index % 10 == 0 {
                upload_resume.save().await?;
            }
        }

        // Upload phase completion handled by command-level progress system

        let mut final_parts = completed_parts.lock().await.clone();
        final_parts.sort_by_key(|p| p.part_number);

        upload_resume.cleanup()?;

        let confirm_params = create_confirm_params(archive_info, save_response.storage_key.clone());

        self.api_client
            .complete_multipart_upload(
                &self.workspace,
                &save_response.cache_entry_id,
                upload_id,
                final_parts,
                confirm_params,
            )
            .await
            .context("Failed to complete multipart upload")?;

        if let Some(handle) = progress.as_ref() {
            handle.complete();
        }

        self.handle_tag_assignment(tag);

        Ok(())
    }
}
