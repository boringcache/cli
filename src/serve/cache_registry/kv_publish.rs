use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use crate::api::models::cache::{BlobDescriptor, BlobReceipt};
use crate::progress::TransferProgress;
use crate::serve::state::AppState;

const KV_BLOB_UPLOAD_MAX_ATTEMPTS: u32 = 3;
const KV_BLOB_UPLOAD_RETRY_BASE_MS: u64 = 300;
const KV_BLOB_UPLOAD_RETRY_MAX_MS: u64 = 1_500;
const KV_BLOB_UPLOAD_MAX_CONCURRENCY: usize = 64;
const KV_BLOB_UPLOAD_CONCURRENCY_ENV: &str = "BORINGCACHE_KV_BLOB_UPLOAD_CONCURRENCY";
const KV_BLOB_UPLOAD_INITIAL_CONCURRENCY: usize = 8;

#[derive(Default, Clone)]
pub(super) struct BlobUploadStats {
    pub(super) uploaded_count: u64,
    pub(super) already_present_count: u64,
    pub(super) missing_local_count: u64,
    pub(super) uploaded_receipts: Vec<BlobReceipt>,
}

#[derive(Clone, Copy)]
enum BlobUploadOutcome {
    Uploaded,
    UploadedAfterRetry,
    AlreadyPresent,
}

struct AdaptiveUploadConcurrency {
    semaphore: Arc<tokio::sync::Semaphore>,
    current: std::sync::atomic::AtomicUsize,
    max: usize,
    ramp_frozen: std::sync::atomic::AtomicBool,
}

impl AdaptiveUploadConcurrency {
    fn new(initial: usize, max: usize) -> Self {
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(initial)),
            current: std::sync::atomic::AtomicUsize::new(initial),
            max,
            ramp_frozen: std::sync::atomic::AtomicBool::new(false),
        }
    }

    fn semaphore(&self) -> &Arc<tokio::sync::Semaphore> {
        &self.semaphore
    }

    fn on_upload_complete(&self, had_retry: bool) {
        if had_retry {
            self.ramp_frozen
                .store(true, std::sync::atomic::Ordering::Release);
            return;
        }
        if self.ramp_frozen.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        let current = self.current.load(std::sync::atomic::Ordering::Acquire);
        if current < self.max
            && self
                .current
                .compare_exchange(
                    current,
                    current + 1,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_ok()
        {
            self.semaphore.add_permits(1);
        }
    }

    fn current(&self) -> usize {
        self.current.load(std::sync::atomic::Ordering::Acquire)
    }
}

fn kv_blob_upload_retry_delay(attempt: u32) -> std::time::Duration {
    let exponent = attempt.saturating_sub(1);
    let backoff = KV_BLOB_UPLOAD_RETRY_BASE_MS.saturating_mul(2_u64.pow(exponent));
    std::time::Duration::from_millis(backoff.min(KV_BLOB_UPLOAD_RETRY_MAX_MS))
}

fn is_retryable_blob_upload_error(message: &str) -> bool {
    let lower = message.to_ascii_lowercase();
    lower.contains("http 408")
        || lower.contains("http 429")
        || lower.contains("http 500")
        || lower.contains("http 502")
        || lower.contains("http 503")
        || lower.contains("http 504")
        || lower.contains("timeout")
        || lower.contains("timed out")
        || lower.contains("deadline has elapsed")
        || lower.contains("connect error")
        || lower.contains("connection reset")
        || lower.contains("broken pipe")
        || lower.contains("connection refused")
        || lower.contains("unexpected eof")
        || lower.contains("unexpected-eof")
        || lower.contains("close_notify")
        || lower.contains("temporarily unavailable")
}

fn kv_blob_upload_concurrency(operation_count: usize) -> (usize, usize) {
    if operation_count == 0 {
        return (1, 1);
    }

    if let Ok(val) = std::env::var(KV_BLOB_UPLOAD_CONCURRENCY_ENV)
        && let Ok(v) = val.trim().parse::<usize>()
        && v > 0
    {
        let fixed = v.min(operation_count).max(1);
        return (fixed, fixed);
    }

    let max = KV_BLOB_UPLOAD_MAX_CONCURRENCY.min(operation_count).max(1);
    let initial = KV_BLOB_UPLOAD_INITIAL_CONCURRENCY
        .min(max)
        .min(operation_count)
        .max(1);
    (initial, max)
}

async fn upload_single_blob_with_retry(
    state: AppState,
    cache_entry_id: String,
    blob: Option<BlobDescriptor>,
    upload_digest: String,
    mut upload_url: String,
    mut upload_headers: HashMap<String, String>,
    blob_path: PathBuf,
) -> anyhow::Result<(String, BlobUploadOutcome)> {
    let mut last_error: Option<anyhow::Error> = None;

    for attempt in 1..=KV_BLOB_UPLOAD_MAX_ATTEMPTS {
        let progress = TransferProgress::new_noop();
        let upload_result = crate::multipart_upload::upload_via_single_url(
            blob_path.as_path(),
            &upload_url,
            &progress,
            state.api_client.transfer_client(),
            &upload_headers,
        )
        .await;
        match upload_result {
            Ok(_) => {
                let outcome = if attempt > 1 {
                    BlobUploadOutcome::UploadedAfterRetry
                } else {
                    BlobUploadOutcome::Uploaded
                };
                return Ok((upload_digest, outcome));
            }
            Err(error) => {
                let error_text = format!("{error:#}");
                log::warn!(
                    "KV blob upload attempt {attempt}/{} failed for {upload_digest}: {error_text}",
                    KV_BLOB_UPLOAD_MAX_ATTEMPTS,
                );
                last_error = Some(error);
                if attempt >= KV_BLOB_UPLOAD_MAX_ATTEMPTS {
                    break;
                }

                let retryable = last_error
                    .as_ref()
                    .map(|err| is_retryable_blob_upload_error(&format!("{err:#}")))
                    .unwrap_or(false);
                if !retryable {
                    break;
                }

                if let Some(blob) = &blob {
                    let retry_plan_result = state
                        .api_client
                        .blob_upload_urls(
                            &state.workspace,
                            &cache_entry_id,
                            std::slice::from_ref(blob),
                        )
                        .await;
                    match retry_plan_result {
                        Ok(retry_plan) => {
                            if retry_plan
                                .already_present
                                .iter()
                                .any(|d| d == &upload_digest)
                            {
                                return Ok((upload_digest, BlobUploadOutcome::AlreadyPresent));
                            }
                            if let Some(fresh_upload) = retry_plan
                                .upload_urls
                                .iter()
                                .find(|item| item.digest == upload_digest)
                            {
                                upload_url = fresh_upload.url.clone();
                                upload_headers = fresh_upload.headers.clone();
                            }
                        }
                        Err(stage_error) => {
                            log::warn!(
                                "KV batch flush: failed to refresh upload URL for {}: {stage_error}",
                                upload_digest
                            );
                        }
                    }
                }

                tokio::time::sleep(kv_blob_upload_retry_delay(attempt)).await;
            }
        }
    }

    let error = last_error.unwrap_or_else(|| anyhow::anyhow!("unknown blob upload error"));
    Err(anyhow::anyhow!(
        "Failed to upload blob {}: {:#}",
        upload_digest,
        error
    ))
}

pub(super) async fn upload_blobs(
    state: &AppState,
    cache_entry_id: &str,
    blobs: &[BlobDescriptor],
    local_blob_paths: &HashMap<String, PathBuf>,
) -> anyhow::Result<BlobUploadStats> {
    let upload_plan = state
        .api_client
        .blob_upload_urls(&state.workspace, cache_entry_id, blobs)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to get blob upload URLs: {e}"))?;

    let mut stats = BlobUploadStats {
        uploaded_count: 0,
        already_present_count: upload_plan.already_present.len() as u64,
        missing_local_count: 0,
        uploaded_receipts: Vec::new(),
    };

    let blobs_by_digest: HashMap<String, BlobDescriptor> = blobs
        .iter()
        .map(|blob| (blob.digest.clone(), blob.clone()))
        .collect();

    let (initial, max) = kv_blob_upload_concurrency(upload_plan.upload_urls.len());
    let limiter = Arc::new(AdaptiveUploadConcurrency::new(initial, max));
    let total_requested = upload_plan.upload_urls.len() as u64;
    eprintln!(
        "KV blob upload plan: requested={} already_present={} concurrency={}/{}",
        total_requested,
        upload_plan.already_present.len(),
        initial,
        max,
    );
    let mut tasks = tokio::task::JoinSet::new();

    for upload in upload_plan.upload_urls {
        let blob_path = match local_blob_paths.get(&upload.digest).cloned() {
            Some(path) => path,
            None => {
                log::warn!(
                    "KV batch flush: skipping blob {} (no local file)",
                    upload.digest
                );
                stats.missing_local_count = stats.missing_local_count.saturating_add(1);
                continue;
            }
        };

        let state = state.clone();
        let cache_entry_id = cache_entry_id.to_string();
        let blob = blobs_by_digest.get(&upload.digest).cloned();
        let semaphore = limiter.semaphore().clone();
        tasks.spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|e| anyhow::anyhow!("KV upload semaphore closed: {e}"))?;
            let result = upload_single_blob_with_retry(
                state,
                cache_entry_id,
                blob,
                upload.digest,
                upload.url,
                upload.headers,
                blob_path,
            )
            .await;
            drop(_permit);
            result
        });
    }

    loop {
        let next_task_result = tasks.join_next().await;
        let Some(task_result) = next_task_result else {
            break;
        };
        let (digest, outcome) = match task_result {
            Ok(Ok(outcome)) => outcome,
            Ok(Err(error)) => {
                tasks.abort_all();
                loop {
                    if tasks.join_next().await.is_none() {
                        break;
                    }
                }
                return Err(error);
            }
            Err(error) => {
                tasks.abort_all();
                loop {
                    if tasks.join_next().await.is_none() {
                        break;
                    }
                }
                return Err(anyhow::anyhow!("Blob upload task failed: {error}"));
            }
        };

        let had_retry = matches!(outcome, BlobUploadOutcome::UploadedAfterRetry);
        limiter.on_upload_complete(had_retry);

        match outcome {
            BlobUploadOutcome::Uploaded | BlobUploadOutcome::UploadedAfterRetry => {
                stats.uploaded_count = stats.uploaded_count.saturating_add(1);
                stats
                    .uploaded_receipts
                    .push(BlobReceipt { digest, etag: None });
            }
            BlobUploadOutcome::AlreadyPresent => {
                stats.already_present_count = stats.already_present_count.saturating_add(1);
            }
        }

        let completed_requested = stats
            .uploaded_count
            .saturating_add(stats.missing_local_count);
        if total_requested > 0
            && (completed_requested == total_requested
                || completed_requested.is_multiple_of(1000)
                || completed_requested == 1)
        {
            eprintln!(
                "KV blob upload progress: uploaded={}/{} missing_local={} current_concurrency={}",
                completed_requested,
                total_requested,
                stats.missing_local_count,
                limiter.current(),
            );
        }
    }

    eprintln!(
        "KV blob upload complete: uploaded={} already_present={} missing_local={} final_concurrency={}",
        stats.uploaded_count,
        stats.already_present_count,
        stats.missing_local_count,
        limiter.current(),
    );

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::is_retryable_blob_upload_error;

    #[test]
    fn retryable_blob_upload_errors_keep_legacy_transient_matches() {
        for message in [
            "broken pipe",
            "connection refused",
            "temporarily unavailable",
        ] {
            assert!(
                is_retryable_blob_upload_error(message),
                "expected retryable match for {message}"
            );
        }
    }

    #[test]
    fn retryable_blob_upload_errors_treat_tls_unexpected_eof_as_retryable() {
        let message = "client error (SendRequest): connection error: peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof";
        assert!(is_retryable_blob_upload_error(message));
    }
}
