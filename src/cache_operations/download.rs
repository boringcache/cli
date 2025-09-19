use anyhow::{Context, Result};
use std::time::Instant;

use crate::api::ApiClient;
use crate::compression::CompressionBackend;
use crate::progress::format_bytes;
use crate::retry_resume::{ResumeInfo, RetryConfig};
use crate::transfer::{calculate_chunks, download_chunk_with_range, should_use_multipart};
use crate::ui::CleanUI;

async fn get_content_length(url: &str, api_client: &ApiClient) -> Result<u64> {
    let client = api_client.get_client();
    let response = client.head(url).send().await?;

    if let Some(content_length) = response.headers().get("content-length") {
        let length_str = content_length.to_str()?;
        Ok(length_str.parse()?)
    } else {
        Err(anyhow::anyhow!("No content-length header"))
    }
}

pub struct DownloadOperation {
    pub api_client: ApiClient,
    pub workspace: String,
    pub verbose: bool,
    pub silent: bool, // Suppress progress UI when true
}

impl DownloadOperation {
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

    pub async fn download_and_extract(
        &self,
        download_url: &str,
        target_path: &str,
        expected_size: u64,
        compression: Option<&str>,
    ) -> Result<()> {
        use std::fs;
        use std::path::Path;

        let expanded_path = crate::commands::utils::expand_tilde_path(target_path);
        let target_path_obj = Path::new(&expanded_path);

        let download_start = Instant::now();

        let actual_size = if expected_size == 0 {
            get_content_length(download_url, &self.api_client)
                .await
                .unwrap_or_default()
        } else {
            expected_size
        };

        let downloaded_data = if should_use_multipart(actual_size) {
            let spinner = if self.silent {
                None
            } else {
                Some(CleanUI::step_start_with_spinner(
                    "Downloading",
                    Some(&format!("multipart, {}", format_bytes(actual_size))),
                ))
            };
            let data = match self
                .download_resumable(download_url, target_path_obj, actual_size)
                .await
            {
                Ok(data) => data,
                Err(_e) => {
                    if self.verbose {
                        CleanUI::info("resumable download failed, using parallel");
                    }
                    match self.download_parallel(download_url, actual_size).await {
                        Ok(data) => data,
                        Err(_e) => {
                            if self.verbose {
                                CleanUI::info("parallel download failed, using sequential");
                            }
                            self.download_sequential(download_url).await?
                        }
                    }
                }
            };
            if let Some(spinner) = spinner {
                spinner.stop();
            }
            data
        } else {
            let spinner = if self.silent {
                None
            } else {
                Some(CleanUI::step_start_with_spinner(
                    "Downloading",
                    Some(&format_bytes(actual_size)),
                ))
            };
            let data = self.download_sequential(download_url).await?;
            if let Some(spinner) = spinner {
                spinner.stop();
            }
            data
        };
        if !self.silent {
            CleanUI::step_success(Some(download_start.elapsed().as_millis() as u64));
        }

        let extract_start = Instant::now();
        let extract_spinner = if self.silent {
            None
        } else {
            Some(CleanUI::item_extracting_start())
        };

        let backend = compression.and_then(|algo| match algo {
            "lz4" => Some(CompressionBackend::Lz4),
            "zstd" => Some(CompressionBackend::Zstd),
            _ => None,
        });

        if target_path_obj.exists() {
            if let Err(e) = tokio::fs::remove_dir_all(target_path_obj).await {
                if self.verbose {
                    CleanUI::info(&format!("Failed to clear existing directory: {e}"));
                }
            }
        }

        if let Some(parent) = target_path_obj.parent() {
            fs::create_dir_all(parent)?;
        }

        crate::archive::extract_archive_with_backend(
            &downloaded_data,
            &expanded_path,
            false,
            backend,
        )
        .await
        .with_context(|| format!("Failed to extract archive (algorithm: {backend:?})"))?;

        if let Some(extract_spinner) = extract_spinner {
            let extract_duration = extract_start.elapsed().as_millis() as u64;
            CleanUI::item_extracting_complete(extract_spinner, extract_duration);
        }

        Ok(())
    }

    async fn download_sequential(&self, download_url: &str) -> Result<Vec<u8>> {
        use futures_util::StreamExt;

        let client = self.api_client.get_client();
        let retry_config = RetryConfig::new(self.verbose);

        retry_config
            .retry_with_backoff("Sequential download", || async {
                let response = client.get(download_url).send().await?;
                if !response.status().is_success() {
                    return Err(anyhow::anyhow!("HTTP {}", response.status()));
                }

                let mut downloaded_data = Vec::new();
                let mut stream = response.bytes_stream();

                while let Some(chunk_result) = stream.next().await {
                    let chunk = chunk_result.context("Failed to download chunk")?;
                    downloaded_data.extend_from_slice(&chunk);
                }

                Ok(downloaded_data)
            })
            .await
    }

    async fn download_parallel(&self, download_url: &str, total_size: u64) -> Result<Vec<u8>> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let chunks = calculate_chunks(total_size);
        let mut futures = FuturesUnordered::new();

        for (start_byte, end_byte) in chunks.iter() {
            let client = self.api_client.get_client().clone();
            let url = download_url.to_string();
            let start = *start_byte;
            let end = *end_byte;

            let future = async move {
                let chunk_data = download_chunk_with_range(&client, &url, start, end).await?;
                Ok::<(u64, Vec<u8>), anyhow::Error>((start, chunk_data))
            };

            futures.push(future);
        }

        let mut chunk_results = Vec::new();
        while let Some(result) = futures.next().await {
            let (start_byte, chunk_data) = result?;
            chunk_results.push((start_byte, chunk_data));
        }

        chunk_results.sort_by_key(|(start_byte, _)| *start_byte);

        let mut final_data = Vec::with_capacity(total_size as usize);
        for (_, chunk_data) in chunk_results {
            final_data.extend(chunk_data);
        }

        Ok(final_data)
    }

    async fn download_resumable(
        &self,
        download_url: &str,
        target_path: &std::path::Path,
        total_size: u64,
    ) -> Result<Vec<u8>> {
        use futures_util::stream::{FuturesUnordered, StreamExt};

        let temp_file = target_path.with_extension("boringcache-temp");

        let chunks = calculate_chunks(total_size);
        let mut resume_info = ResumeInfo::load(&temp_file)
            .await
            .unwrap_or_else(|| ResumeInfo::new(temp_file.clone(), total_size, chunks.len()));

        if resume_info.is_complete() {
            if let Ok(data) = tokio::fs::read(&temp_file).await {
                resume_info.cleanup()?;
                return Ok(data);
            }
        }

        if self.verbose && resume_info.downloaded_size > 0 {
            CleanUI::info(&format!(
                "Resuming download: {:.1}% complete",
                resume_info.progress_percentage()
            ));
        }

        let mut final_data = vec![0u8; total_size as usize];
        let mut futures = FuturesUnordered::new();

        for (chunk_index, (start_byte, end_byte)) in chunks.iter().enumerate() {
            if resume_info.chunks_completed[chunk_index] {
                continue; // Skip already completed chunks
            }

            let client = self.api_client.get_client().clone();
            let url = download_url.to_string();
            let start = *start_byte;
            let end = *end_byte;
            let chunk_size = end - start + 1;
            let verbose = self.verbose;

            let future = async move {
                let retry_config = RetryConfig::new(verbose);
                retry_config
                    .retry_with_backoff(&format!("Download chunk {chunk_index}"), || async {
                        let chunk_data =
                            download_chunk_with_range(&client, &url, start, end).await?;
                        Ok::<(usize, u64, u64, Vec<u8>), anyhow::Error>((
                            chunk_index,
                            start,
                            chunk_size,
                            chunk_data,
                        ))
                    })
                    .await
            };

            futures.push(future);
        }

        while let Some(result) = futures.next().await {
            let (chunk_index, start_byte, chunk_size, chunk_data) = result?;

            let start_pos = start_byte as usize;
            let end_pos = start_pos + chunk_data.len();
            final_data[start_pos..end_pos].copy_from_slice(&chunk_data);

            resume_info.mark_chunk_complete(chunk_index, chunk_size);

            if chunk_index % 10 == 0 {
                resume_info.save().await?;
            }
        }

        tokio::fs::write(&temp_file, &final_data).await?;
        resume_info.save().await?;
        resume_info.cleanup()?;

        Ok(final_data)
    }
}
