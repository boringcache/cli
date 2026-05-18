use crate::api::models::cache::BlobDescriptor;
use crate::api::{ApiClient, CacheResolutionEntry};
use crate::progress::TransferProgress;
use crate::telemetry::StorageMetrics;
use crate::transfer::send_manifest_request_with_retry;
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::task::JoinSet;

const RESTORE_MAX_CONCURRENCY_ENV: &str = "BORINGCACHE_RESTORE_MAX_CONCURRENCY";
const MANY_CAS_RESTORE_BLOB_COUNT: usize = 256;
const SMALL_CAS_RESTORE_BLOB_BYTES: u64 = 1024 * 1024;
const MEDIUM_CAS_RESTORE_BLOB_BYTES: u64 = 4 * 1024 * 1024;
const TARGET_CAS_RESTORE_INFLIGHT_BYTES: u64 = 192 * 1024 * 1024;
const CAS_RESTORE_HARD_CONCURRENCY_CAP: usize = 64;
const CAS_RESTORE_ADAPTIVE_WINDOW: Duration = Duration::from_millis(250);
const CAS_RESTORE_ADAPTIVE_MIN_COMPLETIONS: usize = 4;
const CAS_RESTORE_GOODPUT_GAIN_THRESHOLD: f64 = 1.05;
const CAS_RESTORE_GOODPUT_DROP_THRESHOLD: f64 = 0.70;

#[derive(Debug)]
pub(crate) enum CasPointer {
    Oci(crate::cas_oci::OciPointer),
    File(crate::cas_file::FilePointer),
    Pkg(crate::cache::cas_pkg::PkgPointer),
}

#[derive(Debug)]
pub(crate) struct FetchedCasPointer {
    pub resolved_manifest_root_digest: String,
    pub pointer: Box<CasPointer>,
}

#[derive(Debug)]
pub(crate) enum FetchCasPointerOutcome {
    Ready(FetchedCasPointer),
    Ignored { reason: String },
}

#[derive(Debug, Clone)]
pub(crate) struct BlobDownloadTarget {
    pub digest: String,
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Debug, Default)]
pub(crate) struct BlobDownloadOutcome {
    pub bytes_downloaded: u64,
    pub storage_metrics: StorageMetrics,
}

impl BlobDownloadOutcome {
    fn record_download(&mut self, bytes_downloaded: u64, storage_metrics: StorageMetrics) {
        self.bytes_downloaded += bytes_downloaded;
        if self.storage_metrics.region.is_none() {
            self.storage_metrics = storage_metrics;
        }
    }
}

pub(crate) async fn fetch_cas_pointer<F>(
    api_client: &ApiClient,
    hit: &CacheResolutionEntry,
    cas_adapter: crate::adapters::CasAdapterKind,
    verify_signature: F,
) -> Result<FetchCasPointerOutcome>
where
    F: FnOnce(&CacheResolutionEntry, &str) -> Result<()>,
{
    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow!("No manifest URL in response"))?;
    let transfer_client = api_client.transfer_client().clone();

    let response = send_manifest_request_with_retry("CAS index fetch", || async {
        Ok(transfer_client.get(manifest_url).send().await?)
    })
    .await?
    .error_for_status()
    .context("CAS index request failed")?;
    let pointer_bytes = response.bytes().await?.to_vec();
    let actual_manifest_hex = sha256_hex(cas_adapter, &pointer_bytes);

    if let Some(expected_digest) = hit.manifest_digest.as_ref()
        && !digest_matches(cas_adapter, expected_digest, &actual_manifest_hex)
    {
        return Ok(FetchCasPointerOutcome::Ignored {
            reason: format!(
                "CAS index digest mismatch for {} (expected {}, got sha256:{})",
                hit.tag, expected_digest, actual_manifest_hex
            ),
        });
    }

    let (pointer, actual_root_hex) = match cas_adapter {
        crate::adapters::CasAdapterKind::Oci => {
            let pointer = crate::cas_oci::parse_pointer(&pointer_bytes)?;
            let index_json = pointer.index_json_bytes()?;
            (
                CasPointer::Oci(pointer),
                crate::cas_oci::sha256_hex(&index_json),
            )
        }
        crate::adapters::CasAdapterKind::File => (
            CasPointer::File(crate::cas_file::parse_pointer(&pointer_bytes)?),
            actual_manifest_hex.clone(),
        ),
        crate::adapters::CasAdapterKind::Pkg => (
            CasPointer::Pkg(crate::cache::cas_pkg::parse_pointer(&pointer_bytes)?),
            actual_manifest_hex.clone(),
        ),
    };

    let resolved_manifest_root_digest = hit
        .manifest_root_digest
        .clone()
        .unwrap_or_else(|| format!("sha256:{actual_root_hex}"));
    if !digest_matches(
        cas_adapter,
        &resolved_manifest_root_digest,
        &actual_root_hex,
    ) {
        return Ok(FetchCasPointerOutcome::Ignored {
            reason: format!(
                "CAS manifest root digest mismatch for {} (expected {}, got sha256:{})",
                hit.tag, resolved_manifest_root_digest, actual_root_hex
            ),
        });
    }

    verify_signature(hit, &resolved_manifest_root_digest)?;

    Ok(FetchCasPointerOutcome::Ready(FetchedCasPointer {
        resolved_manifest_root_digest,
        pointer: Box::new(pointer),
    }))
}

pub(crate) async fn download_blob_targets(
    api_client: &ApiClient,
    workspace: &str,
    hit: &CacheResolutionEntry,
    download_targets: &[BlobDownloadTarget],
    progress: TransferProgress,
    writer_capacity: usize,
) -> Result<BlobDownloadOutcome> {
    if download_targets.is_empty() {
        return Ok(BlobDownloadOutcome::default());
    }

    let cache_entry_id = hit
        .cache_entry_id
        .as_deref()
        .ok_or_else(|| anyhow!("Missing cache_entry_id for CAS restore"))?;
    let mut concurrency =
        CasBlobDownloadConcurrency::new(cas_blob_download_concurrency_plan(download_targets));
    let transfer_client = api_client.transfer_client().clone();
    let mut outcome = BlobDownloadOutcome::default();
    let mut tasks = JoinSet::new();
    let batch_max = crate::api::client::blob_url_batch_max();

    let mut ordered_targets = download_targets.to_vec();
    ordered_targets.sort_by(|left, right| {
        right
            .size_bytes
            .cmp(&left.size_bytes)
            .then_with(|| left.digest.cmp(&right.digest))
    });

    for batch in ordered_targets.chunks(batch_max) {
        let blobs = batch_blob_descriptors(batch);
        let download_plan = api_client
            .blob_download_urls_verified(workspace, cache_entry_id, &blobs)
            .await
            .context("Failed to request CAS blob download URLs")?;

        if !download_plan.missing.is_empty() {
            anyhow::bail!(
                "Server reported missing blobs for CAS restore: {}",
                download_plan.missing.join(", ")
            );
        }

        let download_items = build_download_items(batch, &download_plan)?;
        for download_item in download_items {
            spawn_download_task(
                &mut tasks,
                download_item,
                progress.clone(),
                transfer_client.clone(),
                writer_capacity,
            );
            while tasks.len() >= concurrency.current() {
                let task_outcome = drain_download_task(&mut tasks).await?;
                let bytes_downloaded = task_outcome.bytes_downloaded;
                let elapsed = task_outcome.elapsed;
                outcome.record_download(bytes_downloaded, task_outcome.storage_metrics);
                concurrency.record_success(bytes_downloaded, elapsed);
            }
        }
    }

    while !tasks.is_empty() {
        let task_outcome = drain_download_task(&mut tasks).await?;
        let bytes_downloaded = task_outcome.bytes_downloaded;
        let elapsed = task_outcome.elapsed;
        outcome.record_download(bytes_downloaded, task_outcome.storage_metrics);
        concurrency.record_success(bytes_downloaded, elapsed);
    }

    Ok(outcome)
}

#[derive(Debug, Clone)]
struct BlobDownloadItem {
    digest: String,
    url: String,
    path: PathBuf,
    size_bytes: u64,
}

fn batch_blob_descriptors(download_targets: &[BlobDownloadTarget]) -> Vec<BlobDescriptor> {
    download_targets
        .iter()
        .map(|target| BlobDescriptor {
            digest: target.digest.clone(),
            size_bytes: target.size_bytes,
        })
        .collect()
}

fn spawn_download_task(
    tasks: &mut JoinSet<Result<BlobDownloadTaskOutcome>>,
    download_target: BlobDownloadItem,
    progress: TransferProgress,
    transfer_client: reqwest::Client,
    writer_capacity: usize,
) {
    tasks.spawn(async move {
        let started_at = Instant::now();
        let result = crate::cas_transport::download_blob_file(
            &transfer_client,
            &download_target.url,
            &download_target.path,
            Some(&progress),
            download_target.size_bytes,
            writer_capacity,
            Some(&download_target.digest),
        )
        .await;
        let elapsed = started_at.elapsed();
        let (bytes_downloaded, storage_metrics) = result?;
        Ok(BlobDownloadTaskOutcome {
            bytes_downloaded,
            storage_metrics,
            elapsed,
        })
    });
}

async fn drain_download_task(
    tasks: &mut JoinSet<Result<BlobDownloadTaskOutcome>>,
) -> Result<BlobDownloadTaskOutcome> {
    let Some(task_result) = tasks.join_next().await else {
        return Err(anyhow!("No CAS blob download task to drain"));
    };
    task_result.context("Blob download task panicked")?
}

#[derive(Debug)]
struct BlobDownloadTaskOutcome {
    bytes_downloaded: u64,
    storage_metrics: StorageMetrics,
    elapsed: Duration,
}

fn build_download_items(
    download_targets: &[BlobDownloadTarget],
    download_plan: &crate::api::models::cache::BlobDownloadUrlsResponse,
) -> Result<Vec<BlobDownloadItem>> {
    let download_urls: HashMap<&str, &str> = download_plan
        .download_urls
        .iter()
        .map(|download_url| (download_url.digest.as_str(), download_url.url.as_str()))
        .collect();

    let mut items = Vec::with_capacity(download_targets.len());
    for target in download_targets {
        let url = download_urls
            .get(target.digest.as_str())
            .copied()
            .ok_or_else(|| {
                anyhow!(
                    "Server did not provide download URL for blob {}",
                    target.digest
                )
            })?;
        items.push(BlobDownloadItem {
            digest: target.digest.clone(),
            url: url.to_string(),
            path: target.path.clone(),
            size_bytes: target.size_bytes,
        });
    }

    Ok(items)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CasBlobDownloadConcurrencyPlan {
    initial: usize,
    ceiling: usize,
    adaptive: bool,
}

#[derive(Debug)]
struct CasBlobDownloadConcurrency {
    current: usize,
    ceiling: usize,
    adaptive: bool,
    window_started_at: Instant,
    window_completed: usize,
    window_bytes: u64,
    smoothed_goodput_bps: Option<f64>,
}

impl CasBlobDownloadConcurrency {
    fn new(plan: CasBlobDownloadConcurrencyPlan) -> Self {
        Self {
            current: plan.initial.max(1),
            ceiling: plan.ceiling.max(1),
            adaptive: plan.adaptive,
            window_started_at: Instant::now(),
            window_completed: 0,
            window_bytes: 0,
            smoothed_goodput_bps: None,
        }
    }

    fn current(&self) -> usize {
        self.current.max(1)
    }

    fn record_success(&mut self, bytes_downloaded: u64, elapsed: Duration) {
        if !self.adaptive {
            return;
        }

        self.window_completed += 1;
        self.window_bytes = self.window_bytes.saturating_add(bytes_downloaded);

        let window_elapsed = self.window_started_at.elapsed();
        if window_elapsed < CAS_RESTORE_ADAPTIVE_WINDOW
            && self.window_completed < CAS_RESTORE_ADAPTIVE_MIN_COMPLETIONS
        {
            return;
        }

        let observed_elapsed = window_elapsed.max(elapsed).as_secs_f64().max(0.001);
        let goodput_bps = self.window_bytes as f64 / observed_elapsed;
        let previous_goodput = self.smoothed_goodput_bps;
        let next_goodput = previous_goodput
            .map(|previous| previous * 0.70 + goodput_bps * 0.30)
            .unwrap_or(goodput_bps);
        self.smoothed_goodput_bps = Some(next_goodput);

        if previous_goodput
            .map(|previous| goodput_bps < previous * CAS_RESTORE_GOODPUT_DROP_THRESHOLD)
            .unwrap_or(false)
        {
            self.current = ((self.current as f64) * 0.85).floor().max(1.0) as usize;
        } else if self.current < self.ceiling
            && previous_goodput
                .map(|previous| goodput_bps > previous * CAS_RESTORE_GOODPUT_GAIN_THRESHOLD)
                .unwrap_or(true)
        {
            let step = ((self.current as f64) * 0.25).ceil() as usize;
            self.current = self.current.saturating_add(step.max(4)).min(self.ceiling);
        }

        self.window_started_at = Instant::now();
        self.window_completed = 0;
        self.window_bytes = 0;
    }
}

fn cas_blob_download_concurrency_plan(
    download_targets: &[BlobDownloadTarget],
) -> CasBlobDownloadConcurrencyPlan {
    let operation_count = download_targets.len();
    if operation_count == 0 {
        return CasBlobDownloadConcurrencyPlan {
            initial: 1,
            ceiling: 1,
            adaptive: false,
        };
    }

    let base = crate::command_support::get_optimal_concurrency(operation_count, "restore").max(1);
    let total_bytes = download_targets
        .iter()
        .map(|target| target.size_bytes)
        .sum::<u64>();
    let average_blob_bytes = total_bytes / operation_count as u64;
    let profile_floor = if operation_count >= MANY_CAS_RESTORE_BLOB_COUNT
        && average_blob_bytes <= MEDIUM_CAS_RESTORE_BLOB_BYTES
    {
        32
    } else if operation_count >= 64 && average_blob_bytes <= SMALL_CAS_RESTORE_BLOB_BYTES {
        24
    } else {
        base
    };
    let inflight_cap = if average_blob_bytes == 0 {
        CAS_RESTORE_HARD_CONCURRENCY_CAP
    } else {
        TARGET_CAS_RESTORE_INFLIGHT_BYTES
            .saturating_div(average_blob_bytes)
            .clamp(1, CAS_RESTORE_HARD_CONCURRENCY_CAP as u64) as usize
    };
    let explicit_cap = parse_restore_concurrency_cap()
        .unwrap_or(CAS_RESTORE_HARD_CONCURRENCY_CAP)
        .clamp(1, 128);

    let ceiling = inflight_cap.min(explicit_cap).min(operation_count).max(1);
    let initial = base
        .max(profile_floor)
        .min(ceiling)
        .min(operation_count)
        .max(1);
    let adaptive = ceiling > initial && operation_count >= 2;

    CasBlobDownloadConcurrencyPlan {
        initial,
        ceiling,
        adaptive,
    }
}

fn parse_restore_concurrency_cap() -> Option<usize> {
    let raw = std::env::var(RESTORE_MAX_CONCURRENCY_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<usize>().ok().filter(|value| *value > 0)
}

fn sha256_hex(cas_adapter: crate::adapters::CasAdapterKind, bytes: &[u8]) -> String {
    match cas_adapter {
        crate::adapters::CasAdapterKind::Oci => crate::cas_oci::sha256_hex(bytes),
        crate::adapters::CasAdapterKind::File => crate::cas_file::sha256_hex(bytes),
        crate::adapters::CasAdapterKind::Pkg => crate::cas_file::sha256_hex(bytes),
    }
}

fn digest_matches(
    cas_adapter: crate::adapters::CasAdapterKind,
    expected_digest: &str,
    actual_manifest_hex: &str,
) -> bool {
    match cas_adapter {
        crate::adapters::CasAdapterKind::Oci => {
            crate::cas_oci::digest_matches(expected_digest, actual_manifest_hex)
        }
        crate::adapters::CasAdapterKind::File => {
            crate::cas_file::digest_matches(expected_digest, actual_manifest_hex)
        }
        crate::adapters::CasAdapterKind::Pkg => {
            crate::cas_file::digest_matches(expected_digest, actual_manifest_hex)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;

    #[test]
    fn build_download_items_rejects_missing_url() {
        let targets = vec![BlobDownloadTarget {
            digest: "sha256:abc".to_string(),
            path: PathBuf::from("/tmp/blob"),
            size_bytes: 42,
        }];
        let plan = crate::api::models::cache::BlobDownloadUrlsResponse {
            download_urls: Vec::new(),
            missing: Vec::new(),
        };

        let error = build_download_items(&targets, &plan).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Server did not provide download URL")
        );
    }

    #[test]
    fn batch_blob_descriptors_preserve_digest_and_size() {
        let targets = vec![
            BlobDownloadTarget {
                digest: "sha256:abc".to_string(),
                path: PathBuf::from("/tmp/blob-a"),
                size_bytes: 42,
            },
            BlobDownloadTarget {
                digest: "sha256:def".to_string(),
                path: PathBuf::from("/tmp/blob-b"),
                size_bytes: 84,
            },
        ];

        let blobs = batch_blob_descriptors(&targets);

        assert_eq!(blobs.len(), 2);
        assert_eq!(blobs[0].digest, "sha256:abc");
        assert_eq!(blobs[0].size_bytes, 42);
        assert_eq!(blobs[1].digest, "sha256:def");
        assert_eq!(blobs[1].size_bytes, 84);
    }

    #[test]
    fn file_digest_matching_accepts_prefixed_sha() {
        assert!(digest_matches(
            crate::adapters::CasAdapterKind::File,
            "sha256:abc",
            "abc"
        ));
    }

    #[test]
    fn cas_blob_download_concurrency_boosts_many_medium_blobs() {
        let _guard = test_env::lock();
        test_env::remove_var(RESTORE_MAX_CONCURRENCY_ENV);
        let targets = blob_targets(300, 2 * 1024 * 1024);

        let plan = cas_blob_download_concurrency_plan(&targets);

        assert_eq!(plan.initial, 32);
        assert!(plan.ceiling > plan.initial);
        assert!(plan.adaptive);
    }

    #[test]
    fn cas_blob_download_concurrency_respects_restore_cap() {
        let _guard = test_env::lock();
        test_env::set_var(RESTORE_MAX_CONCURRENCY_ENV, "12");
        let targets = blob_targets(300, 2 * 1024 * 1024);

        let plan = cas_blob_download_concurrency_plan(&targets);

        assert_eq!(plan.initial, 12);
        assert_eq!(plan.ceiling, 12);
        assert!(!plan.adaptive);
        test_env::remove_var(RESTORE_MAX_CONCURRENCY_ENV);
    }

    #[test]
    fn cas_blob_download_concurrency_ramps_up_on_healthy_windows() {
        let mut controller = CasBlobDownloadConcurrency::new(CasBlobDownloadConcurrencyPlan {
            initial: 16,
            ceiling: 64,
            adaptive: true,
        });

        controller.window_started_at = Instant::now() - CAS_RESTORE_ADAPTIVE_WINDOW;
        controller.record_success(16 * 1024 * 1024, CAS_RESTORE_ADAPTIVE_WINDOW);

        assert!(controller.current() > 16);
    }

    #[test]
    fn cas_blob_download_concurrency_drops_when_goodput_falls() {
        let mut controller = CasBlobDownloadConcurrency::new(CasBlobDownloadConcurrencyPlan {
            initial: 32,
            ceiling: 64,
            adaptive: true,
        });
        controller.smoothed_goodput_bps = Some(100.0);
        controller.window_started_at = Instant::now() - CAS_RESTORE_ADAPTIVE_WINDOW;

        controller.record_success(1, CAS_RESTORE_ADAPTIVE_WINDOW);

        assert!(controller.current() < 32);
    }

    fn blob_targets(count: usize, size_bytes: u64) -> Vec<BlobDownloadTarget> {
        (0..count)
            .map(|index| BlobDownloadTarget {
                digest: format!("sha256:{index:064x}"),
                path: PathBuf::from(format!("/tmp/blob-{index}")),
                size_bytes,
            })
            .collect()
    }
}
