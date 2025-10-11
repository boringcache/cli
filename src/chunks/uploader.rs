use anyhow::{Context, Result};
use futures_util::stream::{FuturesUnordered, StreamExt};
use humansize::{format_size, DECIMAL};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::io::{AsyncReadExt, BufReader};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};

use super::ChunkRef;
use crate::platform::resources::SystemResources;
use crate::progress::{format_bytes, Reporter, TransferProgress};

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
}

impl AdaptiveConcurrency {
    fn new(initial: usize, max_limit: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(initial)),
            samples: Mutex::new(Vec::new()),
            current_target: AtomicUsize::new(initial),
            max_limit: max_limit.max(initial),
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

        if samples.len() < 4 {
            return;
        }

        let avg = samples.iter().copied().sum::<f64>() / samples.len() as f64;
        samples.clear();
        drop(samples);

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
}

const MAX_RETRIES: usize = 5;
const VERIFY_BUFFER_SIZE: usize = 512 * 1024;

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
            reqwest::StatusCode::REQUEST_TIMEOUT
                | reqwest::StatusCode::TOO_MANY_REQUESTS
                | reqwest::StatusCode::CONFLICT
        )
}

fn spawn_aggregate_ticker(
    reporter: Reporter,
    session_id: String,
    step: u8,
    agg: Arc<UploadAggregate>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let initial_detail = format!(
            "[{} parts, {}] 0% @ 0 MB/s (ETA --)",
            agg.total_chunks,
            format_size(agg.total_bytes, DECIMAL),
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
            let speed = (bytes_delta as f64 / dt) / 1_000_000.0;

            let pct = if agg.total_bytes > 0 {
                (bytes as f64 / agg.total_bytes as f64) * 100.0
            } else {
                0.0
            };

            let elapsed = now.duration_since(agg.start_time).as_secs_f64().max(0.001);
            let avg_speed = (bytes as f64 / elapsed) / 1_000_000.0;
            let remain = agg.total_bytes.saturating_sub(bytes);
            let eta_secs = if avg_speed > 0.0 {
                (remain as f64 / 1_000_000.0) / avg_speed
            } else {
                0.0
            };

            let detail = format!(
                "[{} parts, {}] {:.0}% @ {:.0} MB/s (ETA {}s)",
                agg.total_chunks,
                format_size(agg.total_bytes, DECIMAL),
                pct,
                speed,
                eta_secs.round()
            );

            let _ = reporter.step_progress(session_id.clone(), step, pct / 100.0, Some(detail));

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

        let ticker_handle = spawn_aggregate_ticker(
            self.reporter.clone(),
            self.session_id.clone(),
            self.step_index,
            agg.clone(),
        );

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
                let result = upload_chunk_with_retries(
                    &client,
                    url,
                    &chunk,
                    MAX_RETRIES,
                    agg.uploaded_bytes.clone(),
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
        ticker_handle.abort();

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
) -> Result<()> {
    for attempt in 0..=max_retries {
        match try_upload_chunk_streaming(client, url, chunk, uploaded_bytes.clone()).await {
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

async fn try_upload_chunk_streaming(
    client: &reqwest::Client,
    url: &str,
    chunk: &ChunkRef,
    uploaded_bytes: Arc<AtomicU64>,
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
        .timeout(Duration::from_secs(300))
        .body(body)
        .send()
        .await
        .map_err(|e| {
            let error_detail = if e.is_timeout() {
                "timeout"
            } else if e.is_connect() {
                "connection failed"
            } else if e.is_body() {
                "body error"
            } else if e.is_request() {
                "request error"
            } else {
                "unknown error"
            };
            anyhow::anyhow!(
                "Failed to send chunk upload request: {} ({}) (chunk: {}, size: {} bytes)",
                e,
                error_detail,
                chunk.hash,
                chunk.compressed_size
            )
        })?;

    let status = response.status();

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

    uploaded_bytes.fetch_add(file_size, Ordering::Relaxed);

    Ok(())
}
