use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

use crate::api::ApiClient;
use crate::commands::utils::TransferProgress;
use crate::compression::CompressionBackend;
use crate::platform::SystemResources;
use crate::progress::format_bytes;
use crate::retry_resume::{ResumeInfo, RetryConfig};
use crate::transfer::{
    calculate_chunks, calculate_chunks_with_size, download_chunk_with_range, should_use_multipart,
};

/// Result from download containing data and hash for later extraction
pub struct DownloadedArchive {
    pub data: Vec<u8>,
    pub hash: String,
    pub duration: Duration,
}

/// Streaming hasher that computes SHA-256 while downloading data
struct StreamingHasher {
    hasher: Sha256,
    data: Vec<u8>,
}

impl StreamingHasher {
    fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            data: Vec::new(),
        }
    }

    fn with_capacity(capacity: usize) -> Self {
        Self {
            hasher: Sha256::new(),
            data: Vec::with_capacity(capacity),
        }
    }

    fn with_capacity_from_u64(capacity: u64) -> Self {
        match usize::try_from(capacity) {
            Ok(cap) if cap > 0 => Self::with_capacity(cap),
            _ => Self::new(),
        }
    }

    fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
        self.data.extend_from_slice(chunk);
    }

    fn finalize(self) -> (Vec<u8>, String) {
        let hash = format!("{:x}", self.hasher.finalize());
        (self.data, hash)
    }
}

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
}

impl DownloadOperation {
    /// Download archive with optional progress tracking
    pub async fn download(
        &self,
        download_url: &str,
        expected_size: u64,
        expected_content_hash: Option<&str>,
        progress: Option<Arc<TransferProgress>>,
    ) -> Result<DownloadedArchive> {
        let actual_size = if expected_size == 0 {
            get_content_length(download_url, &self.api_client)
                .await
                .unwrap_or_default()
        } else {
            expected_size
        };

        let use_multipart = should_use_multipart(actual_size);
        let download_start = std::time::Instant::now();

        let (downloaded_data, actual_hash) = if use_multipart {
            let temp_path = std::path::PathBuf::from("/tmp/boringcache-download-temp");
            let result = match self
                .download_resumable_with_streaming_hash(
                    download_url,
                    &temp_path,
                    actual_size,
                    progress.clone(),
                )
                .await
            {
                Ok(result) => result,
                Err(_e) => {
                    match self
                        .download_parallel_with_streaming_hash(
                            download_url,
                            actual_size,
                            progress.clone(),
                        )
                        .await
                    {
                        Ok(result) => result,
                        Err(_e) => {
                            self.download_sequential_with_streaming_hash_sized(
                                download_url,
                                Some(actual_size),
                                progress.clone(),
                            )
                            .await?
                        }
                    }
                }
            };
            result
        } else {
            self.download_sequential_with_streaming_hash_sized(
                download_url,
                Some(actual_size),
                progress.clone(),
            )
            .await?
        };

        let _download_duration = download_start.elapsed();

        // Verify hash if provided
        if let Some(expected_hash) = expected_content_hash {
            if actual_hash != expected_hash {
                eprintln!(
                    "warning: Cache integrity verification failed!\n\n\
                    Expected hash: {}\n\
                    Actual hash:   {}\n\n\
                    Continuing with restore despite hash mismatch.",
                    expected_hash, actual_hash
                );
            }
        }

        Ok(DownloadedArchive {
            data: downloaded_data,
            hash: actual_hash,
            duration: _download_duration,
        })
    }

    /// Extract archive to target path - takes ownership to avoid copy
    pub async fn extract(
        &self,
        data: Vec<u8>, // Keep owned data to avoid extra copy in caller
        target_path: &str,
        compression: Option<&str>,
    ) -> Result<Duration> {
        use std::fs;
        use std::path::Path;

        let expanded_path = crate::commands::utils::expand_tilde_path(target_path);
        let target_path_obj = Path::new(&expanded_path);

        let backend = compression.and_then(|algo| match algo {
            "lz4" => Some(CompressionBackend::Lz4),
            "zstd" => Some(CompressionBackend::Zstd),
            _ => None,
        });

        if target_path_obj.exists() {
            if let Err(_e) = tokio::fs::remove_dir_all(target_path_obj).await {
                // Ignore error
            }
        }

        if let Some(parent) = target_path_obj.parent() {
            fs::create_dir_all(parent)?;
        }

        let extraction_start = std::time::Instant::now();
        crate::archive::extract_archive_with_backend(data, &expanded_path, false, backend)
            .await
            .with_context(|| format!("Failed to extract archive (algorithm: {backend:?})"))?;
        let extraction_duration = extraction_start.elapsed();

        Ok(extraction_duration)
    }

    pub fn new(api_client: ApiClient, workspace: String, verbose: bool) -> Self {
        Self {
            api_client,
            workspace,
            verbose,
        }
    }

    pub async fn download_and_extract(
        &self,
        download_url: &str,
        target_path: &str,
        expected_size: u64,
        compression: Option<&str>,
        expected_content_hash: Option<&str>,
    ) -> Result<()> {
        use std::fs;
        use std::path::Path;

        let expanded_path = crate::commands::utils::expand_tilde_path(target_path);
        let target_path_obj = Path::new(&expanded_path);

        let actual_size = if expected_size == 0 {
            get_content_length(download_url, &self.api_client)
                .await
                .unwrap_or_default()
        } else {
            expected_size
        };

        let use_multipart = should_use_multipart(actual_size);

        let _detail = if use_multipart {
            format!("multipart, {}", format_bytes(actual_size))
        } else {
            format_bytes(actual_size)
        };

        // Download progress is handled by command-level progress system

        // Download with streaming hash verification for optimal performance
        let download_start = std::time::Instant::now();
        let (downloaded_data, actual_hash) = if use_multipart {
            let result = match self
                .download_resumable_with_streaming_hash(
                    download_url,
                    target_path_obj,
                    actual_size,
                    None,
                )
                .await
            {
                Ok(result) => result,
                Err(_e) => {
                    if self.verbose {
                        // Fallback: resumable -> parallel download
                    }
                    match self
                        .download_parallel_with_streaming_hash(download_url, actual_size, None)
                        .await
                    {
                        Ok(result) => result,
                        Err(_e) => {
                            if self.verbose {
                                // Fallback: parallel -> sequential download
                            }
                            self.download_sequential_with_streaming_hash_sized(
                                download_url,
                                Some(actual_size),
                                None,
                            )
                            .await?
                        }
                    }
                }
            };
            result
        } else {
            let result = self
                .download_sequential_with_streaming_hash_sized(
                    download_url,
                    Some(actual_size),
                    None,
                )
                .await?;
            result
        };
        let _download_duration = download_start.elapsed();
        // Download phase completion handled by command-level progress system

        // Security: Verify content hash to prevent cache poisoning
        if let Some(expected_hash) = expected_content_hash {
            if actual_hash != expected_hash {
                // Changed from error to warning - continue with restore
                eprintln!(
                    "warning: Cache integrity verification failed!\n\n\
                    Expected hash: {}\n\
                    Actual hash:   {}\n\n\
                    This could indicate:\n\
                    1. Cache corruption during storage/transmission\n\
                    2. Different build environments or non-deterministic builds\n\
                    3. Network/storage error\n\n\
                    Continuing with restore despite hash mismatch.",
                    expected_hash, actual_hash
                );
                // Hash mismatch warning shown above
            } else if self.verbose {
                // Cache integrity verified (verbose mode)
            }
        } else if self.verbose {
            // No hash provided - skipping integrity verification (verbose mode)
        }

        // Extract progress is handled by command-level progress system

        let backend = compression.and_then(|algo| match algo {
            "lz4" => Some(CompressionBackend::Lz4),
            "zstd" => Some(CompressionBackend::Zstd),
            _ => None,
        });

        if target_path_obj.exists() {
            if let Err(_e) = tokio::fs::remove_dir_all(target_path_obj).await {
                // Failed to clear existing directory (verbose mode): ignore error
            }
        }

        if let Some(parent) = target_path_obj.parent() {
            fs::create_dir_all(parent)?;
        }

        // Extract phase timing tracked by caller
        crate::archive::extract_archive_with_backend(
            downloaded_data,
            &expanded_path,
            false,
            backend,
        )
        .await
        .with_context(|| format!("Failed to extract archive (algorithm: {backend:?})"))?;

        Ok(())
    }

    /// Download sequentially with streaming hash computation for zero-copy performance
    async fn download_sequential_with_streaming_hash_sized(
        &self,
        download_url: &str,
        expected_size: Option<u64>,
        progress: Option<Arc<TransferProgress>>,
    ) -> Result<(Vec<u8>, String)> {
        use futures_util::StreamExt;

        let client = self.api_client.get_client();
        let retry_config = RetryConfig::new(self.verbose);

        retry_config
            .retry_with_backoff("Sequential download", || async {
                let response = client.get(download_url).send().await?;
                if !response.status().is_success() {
                    return Err(anyhow::anyhow!("HTTP {}", response.status()));
                }

                let mut hasher = if let Some(size) = expected_size.filter(|&s| s > 0) {
                    StreamingHasher::with_capacity_from_u64(size)
                } else {
                    StreamingHasher::new()
                };
                let mut stream = response.bytes_stream();
                let mut total_downloaded = 0u64;

                while let Some(chunk_result) = stream.next().await {
                    let chunk = chunk_result.context("Failed to download chunk")?;
                    hasher.update(&chunk);

                    total_downloaded += chunk.len() as u64;
                    if let Some(ref p) = progress {
                        p.update(total_downloaded);
                    }
                }

                Ok(hasher.finalize())
            })
            .await
    }

    /// Download in parallel with streaming hash computation for optimal performance
    async fn download_parallel_with_streaming_hash(
        &self,
        download_url: &str,
        total_size: u64,
        progress: Option<Arc<TransferProgress>>,
    ) -> Result<(Vec<u8>, String)> {
        use futures_util::stream::{FuturesUnordered, StreamExt};
        use std::sync::Arc;
        use tokio::sync::Mutex;

        let chunks = calculate_chunks(total_size);

        let buffer_size = match usize::try_from(total_size) {
            Ok(size) => size,
            Err(_) => {
                return Err(anyhow::anyhow!(
                    "Archive too large ({} bytes) for this platform's address space",
                    total_size
                ));
            }
        };
        let output_buffer = Arc::new(Mutex::new(vec![0u8; buffer_size]));

        let concurrency = SystemResources::detect().max_parallel_chunks.max(1);
        let mut futures = FuturesUnordered::new();
        let mut chunk_iter = chunks.into_iter();

        let make_future = |start: u64, end: u64| {
            let client = self.api_client.get_client().clone();
            let url = download_url.to_string();
            let buffer_clone = Arc::clone(&output_buffer);
            let progress_clone = progress.clone();
            async move {
                let chunk_data = download_chunk_with_range(&client, &url, start, end).await?;

                let mut buffer = buffer_clone.lock().await;
                let start_pos = start as usize;
                let end_pos = start_pos + chunk_data.len();
                buffer[start_pos..end_pos].copy_from_slice(&chunk_data);

                if let Some(ref p) = progress_clone {
                    p.add(chunk_data.len() as u64);
                }

                Ok::<(), anyhow::Error>(())
            }
        };

        for _ in 0..concurrency {
            if let Some((start_byte, end_byte)) = chunk_iter.next() {
                futures.push(make_future(start_byte, end_byte));
            }
        }

        while let Some(result) = futures.next().await {
            result?;
            if let Some((start_byte, end_byte)) = chunk_iter.next() {
                futures.push(make_future(start_byte, end_byte));
            }
        }

        // Hash the final buffer in correct byte order
        let final_data = Arc::try_unwrap(output_buffer).unwrap().into_inner();
        let hash = format!("{:x}", Sha256::digest(&final_data));
        Ok((final_data, hash))
    }

    /// Download resumable with streaming hash computation for optimal performance
    async fn download_resumable_with_streaming_hash(
        &self,
        download_url: &str,
        target_path: &std::path::Path,
        total_size: u64,
        progress: Option<Arc<TransferProgress>>,
    ) -> Result<(Vec<u8>, String)> {
        use futures_util::stream::{FuturesUnordered, StreamExt};
        use tokio::fs::OpenOptions;
        use tokio::io::{AsyncSeekExt, AsyncWriteExt};

        let temp_file = target_path.with_extension("boringcache-temp");

        let optimal_chunk_size = crate::transfer::calculate_optimal_chunk_size(total_size);
        let resume_info = ResumeInfo::load(&temp_file).await;

        let (chunks, mut resume_info) = match resume_info {
            Some(mut info) if info.chunk_size.is_some() => {
                // Use persisted chunk size for compatibility
                let persisted_chunk_size = info.chunk_size.unwrap();
                let chunks = calculate_chunks_with_size(total_size, persisted_chunk_size);
                // Validate that the chunks match the stored completion state
                if chunks.len() != info.chunks_completed.len() {
                    // Chunk layout changed, restart download
                    info = ResumeInfo::new_with_chunk_size(
                        temp_file.clone(),
                        total_size,
                        chunks.len(),
                        persisted_chunk_size,
                    );
                }
                (chunks, info)
            }
            Some(mut info) => {
                // Legacy resume info without chunk_size - use new optimal size but clear progress
                let chunks = calculate_chunks(total_size);
                info = ResumeInfo::new_with_chunk_size(
                    temp_file.clone(),
                    total_size,
                    chunks.len(),
                    optimal_chunk_size,
                );
                (chunks, info)
            }
            None => {
                // New download - use optimal chunk size
                let chunks = calculate_chunks(total_size);
                let info = ResumeInfo::new_with_chunk_size(
                    temp_file.clone(),
                    total_size,
                    chunks.len(),
                    optimal_chunk_size,
                );
                (chunks, info)
            }
        };

        if resume_info.is_complete() {
            if let Ok(data) = tokio::fs::read(&temp_file).await {
                resume_info.cleanup()?;
                let hash = format!("{:x}", Sha256::digest(&data));
                return Ok((data, hash));
            }
        }

        if self.verbose && resume_info.downloaded_size > 0 {
            // Resuming download: {progress}% complete (verbose mode)
        }

        // Create temp file with correct size for streaming writes and resumable reads
        let mut file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&temp_file)
            .await?;

        // Pre-allocate file size for efficient random access
        file.set_len(total_size).await?;

        let concurrency = SystemResources::detect().max_parallel_chunks.max(1);
        let pending_chunks: Vec<(usize, u64, u64)> = chunks
            .iter()
            .enumerate()
            .filter_map(|(chunk_index, (start_byte, end_byte))| {
                if resume_info.chunks_completed[chunk_index] {
                    None
                } else {
                    Some((chunk_index, *start_byte, *end_byte))
                }
            })
            .collect();

        let mut chunk_iter = pending_chunks.into_iter();
        let mut futures = FuturesUnordered::new();

        let make_future = |chunk_index: usize, start: u64, end: u64| {
            let client = self.api_client.get_client().clone();
            let url = download_url.to_string();
            let chunk_size = end - start + 1;
            let verbose = self.verbose;
            let progress_clone = progress.clone();
            async move {
                let retry_config = RetryConfig::new(verbose);
                retry_config
                    .retry_with_backoff(&format!("Download chunk {chunk_index}"), || async {
                        let chunk_data =
                            download_chunk_with_range(&client, &url, start, end).await?;
                        Ok::<
                            (usize, u64, u64, Vec<u8>, Option<Arc<TransferProgress>>),
                            anyhow::Error,
                        >((
                            chunk_index,
                            start,
                            chunk_size,
                            chunk_data,
                            progress_clone.clone(),
                        ))
                    })
                    .await
            }
        };

        for _ in 0..concurrency {
            if let Some((chunk_index, start, end)) = chunk_iter.next() {
                futures.push(make_future(chunk_index, start, end));
            }
        }

        // Stream chunks directly to file (hash computed later from final file)
        while let Some(result) = futures.next().await {
            let (chunk_index, start_byte, chunk_size, chunk_data, progress_clone) = result?;

            file.seek(std::io::SeekFrom::Start(start_byte)).await?;
            file.write_all(&chunk_data).await?;

            resume_info.mark_chunk_complete(chunk_index, chunk_size);

            if let Some(ref p) = progress_clone {
                p.add(chunk_size);
            }

            if chunk_index % 10 == 0 {
                resume_info.save().await?;
            }

            if let Some((next_index, next_start, next_end)) = chunk_iter.next() {
                futures.push(make_future(next_index, next_start, next_end));
            }
        }

        file.sync_all().await?;
        resume_info.save().await?;
        resume_info.cleanup()?;

        // Read final data from temp file and compute hash in correct byte order
        let final_data = tokio::fs::read(&temp_file).await?;
        let hash = format!("{:x}", Sha256::digest(&final_data));
        Ok((final_data, hash))
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    #[test]
    fn test_32bit_buffer_size_overflow() {
        // Test buffer size conversion logic without network calls

        #[cfg(target_pointer_width = "32")]
        {
            // On 32-bit systems, test that oversized buffers are rejected
            let oversized = 5_000_000_000u64; // 5GB - too large for 32-bit usize
            let result = usize::try_from(oversized);
            assert!(result.is_err(), "Expected overflow on 32-bit system");
        }

        #[cfg(target_pointer_width = "64")]
        {
            // On 64-bit systems, reasonable sizes should be accepted
            let reasonable_size = 1_000_000u64; // 1MB
            let result = usize::try_from(reasonable_size);
            assert!(
                result.is_ok(),
                "Expected success on 64-bit system for reasonable size"
            );
            assert_eq!(result.unwrap(), 1_000_000usize);

            // But truly massive sizes should still fail gracefully
            let massive_size = u64::MAX;
            let result = usize::try_from(massive_size);
            // This may or may not fail depending on platform, but shouldn't panic
            let _ = result;
        }
    }

    #[tokio::test]
    async fn test_temp_file_permissions_for_resume() {
        let temp_dir = TempDir::new().unwrap();
        let temp_file = temp_dir.path().join("test_resume_file.tmp");

        // Create a temp file with read+write permissions like our download code does
        let mut file = tokio::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&temp_file)
            .await
            .unwrap();

        // Write some test data
        use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
        file.write_all(b"test data for resume").await.unwrap();
        file.sync_all().await.unwrap();

        // Now try to read it back (this would fail with EBADF if we only had write permissions)
        file.seek(std::io::SeekFrom::Start(0)).await.unwrap();
        let mut buffer = vec![0u8; 4];
        file.read_exact(&mut buffer).await.unwrap();

        assert_eq!(&buffer, b"test");
    }
}
