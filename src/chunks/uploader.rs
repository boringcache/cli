use anyhow::{Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use humansize::{format_size, DECIMAL};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use super::ChunkRef;
use crate::platform::resources::SystemResources;
use crate::progress::{format_bytes, ProgressFormat, Reporter, TransferProgress};
use crate::types::ByteSize;

#[derive(Debug, thiserror::Error)]
#[error("Upload HTTP error: {status}")]
struct UploadHttpError {
    status: reqwest::StatusCode,
    body: String,
}

struct UploadAggregate {
    total_bytes: u64,
    total_chunks: u32,
    uploaded_bytes: Arc<AtomicU64>,
    completed_chunks: Arc<AtomicU32>,
    start_time: Instant,
}

impl UploadAggregate {
    fn new(total_chunks: u32, total_bytes: u64) -> Self {
        Self {
            total_bytes,
            total_chunks,
            uploaded_bytes: Arc::new(AtomicU64::new(0)),
            completed_chunks: Arc::new(AtomicU32::new(0)),
            start_time: Instant::now(),
        }
    }

    fn snapshot(&self) -> (u64, u32) {
        (
            self.uploaded_bytes.load(Ordering::Relaxed),
            self.completed_chunks.load(Ordering::Relaxed),
        )
    }
}

struct AdaptiveConcurrency {
    semaphore: Arc<Semaphore>,
    samples: Mutex<Vec<f64>>,
    current_target: AtomicUsize,
    max_limit: usize,
    last_speed_mbps: AtomicU64,
}

impl AdaptiveConcurrency {
    fn new(initial: usize, max_limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(initial)),
            samples: Mutex::new(Vec::new()),
            current_target: AtomicUsize::new(initial),
            max_limit: max_limit.max(initial),
            last_speed_mbps: AtomicU64::new(0),
        }
    }

    async fn acquire(&self) -> OwnedSemaphorePermit {
        self.semaphore
            .clone()
            .acquire_owned()
            .await
            .expect("Adaptive semaphore closed")
    }

    async fn record_sample(&self, mbps: f64) {
        let mut samples = self.samples.lock().await;
        samples.push(mbps);
        self.update_last_speed(mbps);

        if samples.len() < 4 {
            return;
        }

        let avg = samples.iter().copied().sum::<f64>() / samples.len() as f64;
        samples.clear();
        drop(samples);

        self.update_last_speed(avg);
        self.adjust(avg).await;
    }

    async fn adjust(&self, average_mbps: f64) {
        let current = self.current_target.load(Ordering::Relaxed);
        if average_mbps >= 10.0 || current >= self.max_limit {
            return;
        }

        let new_target = (current + 2).min(self.max_limit);
        if new_target == current {
            return;
        }

        self.current_target.store(new_target, Ordering::Relaxed);
        self.semaphore.add_permits(new_target - current);
    }

    fn update_last_speed(&self, mbps: f64) {
        let clamped = mbps.max(0.01);
        let scaled = (clamped * 100.0).round() as u64;
        self.last_speed_mbps.store(scaled, Ordering::Relaxed);
    }

    fn observed_speed_mbps(&self) -> Option<f64> {
        let val = self.last_speed_mbps.load(Ordering::Relaxed);
        if val == 0 {
            None
        } else {
            Some(val as f64 / 100.0)
        }
    }

    fn estimate_timeout(&self, chunk_bytes: u64) -> Duration {
        if let Some(override_timeout) = upload_timeout_override() {
            return override_timeout;
        }

        let (min_secs, max_secs) = upload_timeout_bounds();
        let observed = self.observed_speed_mbps().unwrap_or(DEFAULT_BASELINE_MBPS);
        let effective_speed = observed.clamp(SPEED_LOWER_BOUND_MBPS, SPEED_UPPER_BOUND_MBPS);
        let chunk_mb = chunk_bytes as f64 / 1_000_000.0;

        let mut timeout_secs = (chunk_mb / effective_speed) + TIMEOUT_GRACE_SECS;
        timeout_secs = timeout_secs.max(min_secs);
        timeout_secs = timeout_secs.min(max_secs);

        Duration::from_secs_f64(timeout_secs)
    }
}

const MAX_RETRIES: usize = 5;
const VERIFY_BUFFER_SIZE: usize = 512 * 1024;
const DEFAULT_BASELINE_MBPS: f64 = 35.0;
const SPEED_LOWER_BOUND_MBPS: f64 = 2.0;
const SPEED_UPPER_BOUND_MBPS: f64 = 200.0;
const TIMEOUT_GRACE_SECS: f64 = 12.0;
const MIN_UPLOAD_TIMEOUT_SECS_DEFAULT: f64 = 40.0;
const MAX_UPLOAD_TIMEOUT_SECS_DEFAULT: f64 = 180.0;

fn upload_timeout_override() -> Option<Duration> {
    static OVERRIDE: OnceLock<Option<Duration>> = OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        std::env::var("BORINGCACHE_UPLOAD_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|secs| Duration::from_secs_f64(secs.max(1.0)))
    })
}

fn upload_timeout_bounds() -> (f64, f64) {
    static BOUNDS: OnceLock<(f64, f64)> = OnceLock::new();
    *BOUNDS.get_or_init(|| {
        let min = std::env::var("BORINGCACHE_UPLOAD_TIMEOUT_MIN_SECS")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(MIN_UPLOAD_TIMEOUT_SECS_DEFAULT)
            .max(5.0);

        let max = std::env::var("BORINGCACHE_UPLOAD_TIMEOUT_MAX_SECS")
            .ok()
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(MAX_UPLOAD_TIMEOUT_SECS_DEFAULT)
            .max(min + 5.0);

        (min, max)
    })
}

fn get_max_concurrent_uploads() -> usize {
    let resources = SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();

    if let Ok(val) = std::env::var("BORINGCACHE_UPLOAD_CONCURRENCY") {
        if let Ok(n) = val.parse::<usize>() {
            return n.clamp(4, 32);
        }
    }

    let base = resources.max_parallel_chunks;
    let capped = if is_ci { base.min(6) } else { base };
    capped.clamp(4, 16)
}

fn get_fd_limit() -> usize {
    std::env::var("BORINGCACHE_FD_LIMIT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(32)
        .clamp(16, 128)
}

fn should_retry(status: reqwest::StatusCode) -> bool {
    status.is_server_error()
        || matches!(
            status,
            reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS
        )
}

fn spawn_aggregate_ticker(
    reporter: Reporter,
    session_id: String,
    step: u8,
    agg: Arc<UploadAggregate>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let chunk_label = if agg.total_chunks == 1 {
            "chunk"
        } else {
            "chunks"
        };
        let initial_detail = format!(
            "{} / {} {} @ {} (ETA --) | 0/{} {}",
            ByteSize::new(0),
            ByteSize::new(agg.total_bytes),
            ProgressFormat::format_percent(0.0),
            ProgressFormat::format_speed(0.0),
            agg.total_chunks,
            chunk_label,
        );
        let _ = reporter.step_progress(session_id.clone(), step, 0.0, Some(initial_detail));

        let mut last_bytes = 0u64;
        let mut last_t = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        let max_runtime = Duration::from_secs(300);
        let start_time = Instant::now();

        loop {
            tick.tick().await;

            if start_time.elapsed() > max_runtime {
                log::warn!("Upload progress ticker exceeded maximum runtime, exiting");
                break;
            }

            let (bytes, parts) = agg.snapshot();

            if parts >= agg.total_chunks {
                break;
            }

            if bytes == last_bytes {
                continue;
            }

            let now = Instant::now();
            let dt = now.duration_since(last_t).as_secs_f64().max(0.001);
            let bytes_delta = bytes.saturating_sub(last_bytes);
            let speed_bytes_per_sec = if bytes_delta > 0 {
                bytes_delta as f64 / dt
            } else {
                0.0
            };

            let pct = if agg.total_bytes > 0 {
                (bytes as f64 / agg.total_bytes as f64) * 100.0
            } else {
                100.0
            }
            .min(100.0);

            let elapsed = now.duration_since(agg.start_time).as_secs_f64().max(0.001);
            let avg_bytes_per_sec = if elapsed > 0.0 {
                bytes as f64 / elapsed
            } else {
                0.0
            };
            let remain = agg.total_bytes.saturating_sub(bytes);
            let eta_str = if remain == 0 {
                "0s".to_string()
            } else {
                let eta = ProgressFormat::format_eta(remain, avg_bytes_per_sec);
                if eta == "unknown" {
                    "--".to_string()
                } else {
                    eta
                }
            };

            let detail = format!(
                "{} / {} {} @ {} (ETA {}) | {}/{} {}",
                ByteSize::new(bytes),
                ByteSize::new(agg.total_bytes),
                ProgressFormat::format_percent(pct),
                ProgressFormat::format_speed(speed_bytes_per_sec),
                eta_str,
                parts,
                agg.total_chunks,
                chunk_label,
            );

            let _ = reporter.step_progress(session_id.clone(), step, pct, Some(detail));

            last_bytes = bytes;
            last_t = now;
        }
    })
}

pub struct ChunkUploader {
    client: reqwest::Client,
    reporter: Reporter,
    session_id: String,
    max_concurrent: usize,
    fd_limit: usize,
    step_index: u8,
}

impl ChunkUploader {
    pub fn new(
        client: reqwest::Client,
        reporter: Reporter,
        session_id: String,
        step_index: u8,
    ) -> Self {
        Self {
            client,
            reporter,
            session_id,
            max_concurrent: get_max_concurrent_uploads(),
            fd_limit: get_fd_limit(),
            step_index,
        }
    }

    pub async fn upload_chunk_refs(
        &self,
        chunks: Vec<ChunkRef>,
        upload_urls: HashMap<String, String>,
        progress: Option<TransferProgress>,
        verbose: bool,
    ) -> Result<()> {
        if chunks.is_empty() {
            return Ok(());
        }

        let total_chunks = chunks.len();
        let total_bytes: u64 = chunks.iter().map(|c| c.compressed_size).sum();
        let total_uncompressed: u64 = chunks.iter().map(|c| c.uncompressed_size).sum();

        let agg = Arc::new(UploadAggregate::new(total_chunks as u32, total_bytes));

        let initial_concurrency = self.max_concurrent;
        let adaptive = Arc::new(AdaptiveConcurrency::new(
            initial_concurrency,
            self.max_concurrent,
        ));

        let has_external_progress = progress.is_some();
        let ticker_handle = if has_external_progress {
            None
        } else {
            Some(spawn_aggregate_ticker(
                self.reporter.clone(),
                self.session_id.clone(),
                self.step_index,
                agg.clone(),
            ))
        };

        let fd_semaphore = Arc::new(Semaphore::new(self.fd_limit));
        let client = self.client.clone();
        let reporter = self.reporter.clone();
        let session_id = self.session_id.clone();
        let progress = Arc::new(progress);
        let upload_urls = Arc::new(upload_urls);

        let mut upload_futures = FuturesUnordered::new();

        for (index, chunk) in chunks.into_iter().enumerate() {
            let adaptive = adaptive.clone();
            let fd_semaphore = fd_semaphore.clone();
            let client = client.clone();
            let upload_urls = upload_urls.clone();
            let progress = progress.clone();
            let agg = agg.clone();
            let reporter = reporter.clone();
            let session_id = session_id.clone();

            let upload_future = async move {
                let permit = adaptive.acquire().await;
                let fd_permit = fd_semaphore.acquire().await.expect("FD semaphore closed");

                verify_chunk_on_disk(&chunk).await?;

                let url = upload_urls
                    .get(&chunk.key)
                    .ok_or_else(|| anyhow::anyhow!("No upload URL for chunk key: {}", chunk.key))?;

                let short_digest = &chunk.hash.split(':').next_back().unwrap_or(&chunk.hash)
                    [..12.min(chunk.hash.len())];

                reporter.substep_start(
                    session_id.clone(),
                    self.step_index,
                    (index + 1) as u32,
                    total_chunks as u32,
                    format!("Chunk {}…", short_digest),
                    None,
                )?;

                let chunk_start = Instant::now();
                let timeout = adaptive.estimate_timeout(chunk.compressed_size);
                let result = upload_chunk_with_retries(
                    &client,
                    url,
                    &chunk,
                    MAX_RETRIES,
                    agg.uploaded_bytes.clone(),
                    timeout,
                )
                .await;

                drop(permit);
                drop(fd_permit);

                let duration = chunk_start.elapsed();

                match result {
                    Ok(()) => {
                        agg.completed_chunks.fetch_add(1, Ordering::Relaxed);

                        if let Some(ref prog) = *progress {
                            prog.record_bytes(chunk.compressed_size)?;
                        }

                        let mbps = (chunk.compressed_size as f64 / 1_000_000.0)
                            / duration.as_secs_f64().max(0.001);

                        adaptive.record_sample(mbps).await;

                        let detail = if verbose {
                            format!(
                                "{} → {} @ {:.1} MB/s",
                                format_bytes(chunk.uncompressed_size),
                                format_bytes(chunk.compressed_size),
                                mbps
                            )
                        } else {
                            format!("{} @ {:.1} MB/s", format_bytes(chunk.compressed_size), mbps)
                        };

                        reporter.substep_complete(
                            session_id.clone(),
                            self.step_index,
                            (index + 1) as u32,
                            total_chunks as u32,
                            duration,
                            Some(detail),
                        )?;

                        Ok(chunk.compressed_size)
                    }
                    Err(err) => {
                        let err_msg = err.to_string();
                        reporter.substep_complete(
                            session_id.clone(),
                            self.step_index,
                            (index + 1) as u32,
                            total_chunks as u32,
                            duration,
                            Some(format!("failed: {}", err_msg)),
                        )?;
                        Err(err)
                    }
                }
            };

            upload_futures.push(upload_future);
        }

        let upload_result: Result<()> = async {
            while let Some(result) = upload_futures.next().await {
                result?;
            }
            Ok(())
        }
        .await;

        // Abort the ticker task regardless of success or failure
        if let Some(handle) = ticker_handle {
            handle.abort();
        }

        // Propagate any upload errors
        upload_result?;

        if let Some(ref prog) = *progress {
            prog.complete()?;
        }

        let elapsed_secs = agg.start_time.elapsed().as_secs_f64();
        if total_bytes > 0 && elapsed_secs > 0.0 {
            let avg_speed = (total_bytes as f64 / 1_000_000.0) / elapsed_secs;
            let compression_pct = if total_uncompressed > 0 {
                (total_bytes as f64 / total_uncompressed as f64) * 100.0
            } else {
                100.0
            };

            let summary = format!(
                "Uploaded {} → {} ({:.0}% of original) in {:.1}s across {} chunks @ {:.1} MB/s",
                format_size(total_uncompressed, DECIMAL),
                format_size(total_bytes, DECIMAL),
                compression_pct,
                elapsed_secs,
                total_chunks,
                avg_speed
            );
            let _ = reporter.info(summary);
        }

        Ok(())
    }
}

async fn verify_chunk_on_disk(chunk: &ChunkRef) -> Result<()> {
    let metadata = tokio::fs::metadata(&chunk.path)
        .await
        .with_context(|| format!("Failed to stat chunk file: {}", chunk.path.display()))?;

    if metadata.len() != chunk.compressed_size {
        anyhow::bail!(
            "Chunk size mismatch for {} (expected {} bytes, found {})",
            chunk.hash,
            chunk.compressed_size,
            metadata.len()
        );
    }

    let file = File::open(&chunk.path).await.with_context(|| {
        format!(
            "Failed to open chunk for verification: {}",
            chunk.path.display()
        )
    })?;

    let mut reader = BufReader::with_capacity(VERIFY_BUFFER_SIZE, file);
    let mut buffer = vec![0u8; VERIFY_BUFFER_SIZE];
    let mut hasher = blake3::Hasher::new();

    loop {
        let read = reader.read(&mut buffer).await.with_context(|| {
            format!(
                "Failed to read chunk during verification: {}",
                chunk.path.display()
            )
        })?;

        if read == 0 {
            break;
        }

        hasher.update(&buffer[..read]);
    }

    let computed = format!("blake3:{}", hasher.finalize().to_hex());
    if computed != chunk.compressed_hash {
        anyhow::bail!(
            "Chunk hash mismatch for {} (expected {}, computed {})",
            chunk.hash,
            chunk.compressed_hash,
            computed
        );
    }

    Ok(())
}

async fn upload_chunk_with_retries(
    client: &reqwest::Client,
    url: &str,
    chunk: &ChunkRef,
    max_retries: usize,
    uploaded_bytes: Arc<AtomicU64>,
    timeout: Duration,
) -> Result<()> {
    for attempt in 0..=max_retries {
        match try_upload_chunk_streaming(client, url, chunk, uploaded_bytes.clone(), timeout).await
        {
            Ok(()) => return Ok(()),
            Err(e) => {
                if let Some(http_err) = e.downcast_ref::<UploadHttpError>() {
                    if !should_retry(http_err.status) || attempt == max_retries {
                        return Err(e);
                    }
                } else if attempt == max_retries {
                    return Err(e);
                }

                let backoff = 500 * (1u64 << attempt);
                let jitter = fastrand::u64(..100);
                tokio::time::sleep(Duration::from_millis(backoff + jitter)).await;
            }
        }
    }

    unreachable!()
}

/// Verify that the uploaded object in S3 matches the expected size
///
/// Uses a HEAD request to check the Content-Length of the stored object.
/// Returns Ok(true) if size matches, Ok(false) if mismatch, Err if verification failed.
async fn verify_upload_size(
    client: &reqwest::Client,
    url: &str,
    expected_size: u64,
    chunk_hash: &str,
) -> Result<bool> {
    // Try HEAD request with a short timeout (don't want to slow down uploads too much)
    let response = client
        .head(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await
        .with_context(|| format!("Failed to send HEAD request for chunk {}", chunk_hash))?;

    if !response.status().is_success() {
        anyhow::bail!(
            "HEAD request returned non-success status: {} (chunk: {})",
            response.status(),
            chunk_hash
        );
    }

    // Check Content-Length header
    if let Some(content_length) = response.headers().get("content-length") {
        if let Ok(length_str) = content_length.to_str() {
            if let Ok(actual_size) = length_str.parse::<u64>() {
                if actual_size == expected_size {
                    return Ok(true);
                } else {
                    log::error!(
                        "Upload size mismatch: uploaded {} bytes, S3 has {} bytes (chunk: {})",
                        expected_size,
                        actual_size,
                        chunk_hash
                    );
                    return Ok(false);
                }
            }
        }
    }

    // Content-Length header missing or unparseable
    log::warn!(
        "HEAD response missing or invalid Content-Length header (chunk: {})",
        chunk_hash
    );
    anyhow::bail!("Could not parse Content-Length from HEAD response");
}

async fn try_upload_chunk_streaming(
    client: &reqwest::Client,
    url: &str,
    chunk: &ChunkRef,
    uploaded_bytes: Arc<AtomicU64>,
    timeout: Duration,
) -> Result<()> {
    let file = File::open(&chunk.path)
        .await
        .with_context(|| format!("Failed to open chunk file: {:?}", chunk.path))?;

    let file_size = file.metadata().await?.len();

    if file_size != chunk.compressed_size {
        anyhow::bail!(
            "Chunk {} size changed between staging and upload (expected {} bytes, found {})",
            chunk.hash,
            chunk.compressed_size,
            file_size
        );
    }

    let body = reqwest::Body::from(file);

    let response = client
        .put(url)
        .header("Content-Type", "application/octet-stream")
        .header("Content-Length", file_size.to_string())
        .timeout(timeout)
        .body(body)
        .send()
        .await
        .map_err(|e| {
            let error_detail = if e.is_timeout() {
                "timeout - upload may be incomplete"
            } else if e.is_connect() {
                "connection failed"
            } else if e.is_body() {
                "body streaming error - upload incomplete"
            } else if e.is_request() {
                "request error - upload may be incomplete"
            } else {
                "unknown error - upload status unknown"
            };
            anyhow::anyhow!(
                "Failed to upload chunk: {} ({}) (chunk: {}, size: {} bytes). \
                 If this error persists, the cache entry may be corrupted and should be deleted.",
                e,
                error_detail,
                chunk.hash,
                chunk.compressed_size
            )
        })?;

    let status = response.status();
    let headers = response.headers().clone();

    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read response body".to_string());

        if status == reqwest::StatusCode::FORBIDDEN
            && (body.contains("Signature") || body.contains("expired"))
        {
            return Err(anyhow::anyhow!(
                "Upload URL expired (403). Re-request presigned URLs from server."
            ));
        }

        let error_context = if status.is_server_error() {
            format!(
                "Storage service error ({}). This may be a temporary issue with the storage backend. Response: {}",
                status,
                if body.len() > 200 { &body[..200] } else { &body }
            )
        } else {
            format!("Upload failed with status {}: {}", status, body)
        };

        return Err(UploadHttpError {
            status,
            body: error_context,
        }
        .into());
    }

    // Verify upload integrity using ETag from S3
    // For single-part uploads, S3 returns ETag as the MD5 of the uploaded object
    let upload_etag = headers.get("etag").and_then(|e| e.to_str().ok());

    if let Some(etag_str) = upload_etag {
        log::debug!(
            "Upload completed with ETag: {} (chunk: {}, size: {} bytes)",
            etag_str,
            chunk.hash,
            file_size
        );
    } else {
        // Missing ETag is suspicious - S3 should always return it for successful uploads
        log::warn!(
            "Upload response missing ETag header (chunk: {}, size: {} bytes). \
             Upload may not be verified. This could indicate a partial upload or proxy interference.",
            chunk.hash,
            file_size
        );
    }

    // Verify the uploaded object size with a HEAD request
    // This catches incomplete uploads where the connection dropped mid-stream
    // but S3 still returned 200 OK
    match verify_upload_size(client, url, file_size, &chunk.hash).await {
        Ok(true) => {
            log::debug!(
                "Upload size verified: {} bytes (chunk: {})",
                file_size,
                chunk.hash
            );
        }
        Ok(false) => {
            return Err(anyhow::anyhow!(
                "Upload size mismatch detected! Expected {} bytes but S3 object is different size. \
                 This indicates a partial/corrupted upload (chunk: {}). \
                 The cache entry should be deleted and re-uploaded.",
                file_size,
                chunk.hash
            ));
        }
        Err(e) => {
            // HEAD request failed - log warning but don't fail the upload
            // The download verification will catch any corruption later
            log::warn!(
                "Could not verify upload size for chunk {}: {}. \
                 Upload may be incomplete. Download verification will validate integrity.",
                chunk.hash,
                e
            );
        }
    }

    uploaded_bytes.fetch_add(file_size, Ordering::Relaxed);

    Ok(())
}
