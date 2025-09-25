use anyhow::{Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;

use crate::api::{ApiClient, CacheParams, PartInfo};
use crate::archive::ArchiveInfo;
use crate::platform::{Platform, SystemResources};
use crate::progress::format_bytes;
use crate::retry_resume::{RetryConfig, UploadResumeInfo};
use crate::transfer::create_confirm_params;
use crate::ui::CleanUI;

pub struct UploadOperation {
    pub api_client: ApiClient,
    pub workspace: String,
    pub verbose: bool,
    pub silent: bool, // Suppress progress UI when true
}

impl UploadOperation {
    pub fn new(api_client: ApiClient, workspace: String, verbose: bool) -> Self {
        Self {
            api_client,
            workspace,
            verbose,
            silent: false,
        }
    }

    pub fn new_silent(api_client: ApiClient, workspace: String, verbose: bool) -> Self {
        Self {
            api_client,
            workspace,
            verbose,
            silent: true,
        }
    }

    fn handle_tag_assignment(&self, tag: Option<&str>, start_time: Instant) {
        if !self.silent {
            CleanUI::step_success(Some(start_time.elapsed().as_millis() as u64));
            if let Some(tag) = tag {
                CleanUI::info(&format!("Tag '{tag}' assigned"));
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn upload_archive(
        &self,
        archive_data: &[u8],
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

        let upload_url_start = Instant::now();
        CleanUI::step_start("Request upload URL", None);

        let save_response = self
            .api_client
            .save_cache(save_params, archive_info.compressed_size)
            .await
            .context("Failed to request upload URL")?;
        CleanUI::step_success(Some(upload_url_start.elapsed().as_millis() as u64));

        if save_response.multipart {
            self.upload_multipart(&save_response, archive_data, archive_info, tag)
                .await?;
        } else {
            self.upload_single(&save_response, archive_data, archive_info, tag)
                .await?;
        }

        Ok(())
    }

    pub async fn upload_single(
        &self,
        save_response: &crate::api::SaveCacheResponse,
        archive_data: &[u8],
        archive_info: &ArchiveInfo,
        tag: Option<&str>,
    ) -> Result<()> {
        let upload_url = save_response
            .upload_url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Missing upload_url for single upload"))?;

        let size_mb = archive_info.compressed_size as f64 / (1024.0 * 1024.0);
        let progress_message = if size_mb > 5000.0 {
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

        let spinner = if self.silent {
            None
        } else {
            Some(CleanUI::step_start_with_spinner(
                "Uploading",
                Some(&progress_message),
            ))
        };

        let client = self.api_client.get_client();
        let retry_config = RetryConfig::new(self.verbose);

        let _response = retry_config
            .retry_with_backoff("Single upload", || async {
                let md5_hash = {
                    let digest = md5::compute(archive_data);
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
                };

                let request = client
                    .put(upload_url)
                    .header("Content-Type", "application/octet-stream")
                    .header("Content-Length", archive_data.len().to_string())
                    .header("Content-MD5", md5_hash)
                    .body(bytes::Bytes::copy_from_slice(archive_data));

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

        if let Some(spinner) = spinner {
            spinner.stop();
        }

        if self.verbose && !self.silent {
            CleanUI::info(&format!(
                "Upload complete: {} bytes",
                archive_info.compressed_size
            ));
            CleanUI::info("Server will verify size and Content-MD5 checksum");
        }

        let confirm_params = create_confirm_params(archive_info, save_response.storage_key.clone());

        let confirm_start = Instant::now();
        if !self.silent {
            CleanUI::step_start("Confirming upload", None);
        }
        self.api_client
            .confirm_upload(
                &self.workspace,
                &save_response.cache_entry_id,
                confirm_params,
            )
            .await
            .context("Failed to confirm upload")?;
        self.handle_tag_assignment(tag, confirm_start);

        Ok(())
    }

    pub async fn upload_multipart(
        &self,
        save_response: &crate::api::SaveCacheResponse,
        archive_data: &[u8],
        archive_info: &ArchiveInfo,
        tag: Option<&str>,
    ) -> Result<()> {
        self.upload_multipart_resumable(save_response, archive_data, archive_info, tag)
            .await
    }

    async fn upload_multipart_resumable(
        &self,
        save_response: &crate::api::SaveCacheResponse,
        archive_data: &[u8],
        archive_info: &ArchiveInfo,
        tag: Option<&str>,
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

        if self.verbose
            && !upload_resume
                .uploaded_parts
                .iter()
                .all(|&uploaded| !uploaded)
        {
            let completed_parts = upload_resume
                .uploaded_parts
                .iter()
                .filter(|&&uploaded| uploaded)
                .count();
            CleanUI::info(&format!(
                "Resuming upload: {}/{} parts complete",
                completed_parts,
                part_urls.len()
            ));
        }

        let system = SystemResources::detect();
        let total_parts = part_urls.len();
        let completed_parts = Arc::new(Mutex::new(upload_resume.get_completed_parts()));

        let mut upload_futures = FuturesUnordered::new();
        let semaphore = Arc::new(tokio::sync::Semaphore::new(system.max_parallel_chunks));

        let default_chunk_size = 32 * 1024 * 1024u64;
        let actual_chunk_size =
            if archive_data.len() as u64 > part_urls.len() as u64 * default_chunk_size {
                default_chunk_size as usize
            } else {
                archive_data.len().div_ceil(part_urls.len())
            };

        for (i, part_url) in part_urls.iter().enumerate() {
            if upload_resume.uploaded_parts[i] {
                continue; // Skip already uploaded parts
            }

            let start_byte = i * actual_chunk_size;
            let end_byte = std::cmp::min(start_byte + actual_chunk_size, archive_data.len());

            if start_byte >= archive_data.len() {
                continue;
            }

            let chunk = archive_data[start_byte..end_byte].to_vec();
            let client = self.api_client.get_client().clone();
            let url = part_url.upload_url.clone();
            let part_number = part_url.part_number;
            let parts_clone = Arc::clone(&completed_parts);
            let sem_clone = Arc::clone(&semaphore);
            let verbose = self.verbose;

            let upload_future = async move {
                let retry_config = RetryConfig::new(verbose);
                let operation_name = format!("Upload part {part_number}");

                let _permit = sem_clone.acquire().await.unwrap();

                let md5_hash = {
                    let digest = md5::compute(&chunk);
                    use base64::Engine;
                    base64::engine::general_purpose::STANDARD.encode(digest.as_ref())
                };

                let etag = retry_config
                    .retry_with_backoff(&operation_name, || async {
                        let request = client
                            .put(&url)
                            .header("Content-Type", "application/octet-stream")
                            .header("Content-Length", chunk.len().to_string())
                            .header("Content-MD5", &md5_hash)
                            .body(bytes::Bytes::copy_from_slice(&chunk));

                        let response = request.send().await?;
                        if !response.status().is_success() {
                            let error_msg = match response.status().as_u16() {
                                400 => format!(
                                    "Part {part_number} validation failed (Content-MD5 mismatch)"
                                ),
                                413 => "Part too large (exceeds server limits)".to_string(),
                                422 => format!("Part {part_number} corrupted (checksum mismatch)"),
                                _ => format!("HTTP {} for part {}", response.status(), part_number),
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
                    })
                    .await?;

                let mut parts_guard = parts_clone.lock().await;
                parts_guard.push(PartInfo {
                    part_number,
                    etag: etag.clone(),
                });

                Ok::<(usize, String), anyhow::Error>((i, etag))
            };

            upload_futures.push(upload_future);
        }

        let spinner = if self.silent {
            None
        } else {
            Some(CleanUI::step_start_with_spinner(
                "Uploading",
                Some(&format!(
                    "multipart, {} parts, {}",
                    total_parts,
                    format_bytes(archive_info.compressed_size)
                )),
            ))
        };

        while let Some(result) = upload_futures.next().await {
            let (part_index, etag) = result?;
            upload_resume.mark_part_complete(part_index, etag);

            if part_index % 10 == 0 {
                upload_resume.save().await?;
            }
        }

        if let Some(spinner) = spinner {
            spinner.stop();
        }

        let mut final_parts = completed_parts.lock().await.clone();
        final_parts.sort_by_key(|p| p.part_number);

        upload_resume.cleanup()?;

        let confirm_params = create_confirm_params(archive_info, save_response.storage_key.clone());

        let complete_start = Instant::now();
        if !self.silent {
            CleanUI::step_start("Completing upload", None);
        }
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
        self.handle_tag_assignment(tag, complete_start);

        Ok(())
    }
}
