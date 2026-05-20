use crate::api::ApiClient;
use crate::api::models::cache::{
    BlobDescriptor, BlobReceipt, BlobUploadUrlsResponse, ConfirmRequest, SaveRequest, SaveResponse,
};
use crate::cache::receipts::{maybe_commit_blob_receipts, maybe_commit_manifest_receipt};
use crate::command_support::save_support::apply_detected_ci_context;
use crate::progress::TransferProgress;
use crate::telemetry::StorageMetrics;
use anyhow::{Context, Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

const SAVE_MAX_CONCURRENCY_ENV: &str = "BORINGCACHE_SAVE_MAX_CONCURRENCY";
const CAS_UPLOAD_HARD_CONCURRENCY_CAP: usize = 32;
const TARGET_CAS_UPLOAD_INFLIGHT_BYTES: u64 = 256 * 1024 * 1024;
const MANY_CAS_UPLOAD_BLOB_COUNT: usize = 256;
const SOME_CAS_UPLOAD_BLOB_COUNT: usize = 64;
const SMALL_CAS_UPLOAD_BLOB_BYTES: u64 = 1024 * 1024;
const MEDIUM_CAS_UPLOAD_BLOB_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone)]
pub(crate) struct BlobUploadSource {
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Debug, Default)]
pub(crate) struct BlobUploadOutcome {
    pub receipts: Vec<BlobReceipt>,
    pub storage_metrics: StorageMetrics,
}

#[derive(Debug, Clone)]
pub(crate) struct CasConfirmSpec {
    pub manifest_digest: String,
    pub manifest_size: u64,
    pub blob_count: u64,
    pub blob_total_size_bytes: u64,
    pub file_count: u32,
    pub tag: String,
}

#[derive(Debug, Default)]
pub(crate) struct CasPublishResult {
    pub manifest_etag: Option<String>,
    pub storage_metrics: StorageMetrics,
}

#[derive(Debug, Clone)]
struct BlobUploadItem {
    digest: String,
    path: PathBuf,
    url: String,
    headers: HashMap<String, String>,
    size_bytes: u64,
}

pub(crate) async fn check_missing_blobs(
    api_client: &ApiClient,
    workspace: &str,
    blobs: &[BlobDescriptor],
) -> Result<Vec<BlobDescriptor>> {
    if blobs.is_empty() {
        return Ok(Vec::new());
    }

    let check_response = api_client
        .check_blobs_verified(workspace, blobs)
        .await
        .context("Failed to check remote blob presence")?;
    let existing: HashSet<&str> = check_response
        .results
        .iter()
        .filter_map(|result| result.exists.then_some(result.digest.as_str()))
        .collect();

    Ok(blobs
        .iter()
        .filter(|blob| !existing.contains(blob.digest.as_str()))
        .cloned()
        .collect())
}

pub(crate) async fn upload_missing_blobs(
    api_client: &ApiClient,
    workspace: &str,
    cache_entry_id: &str,
    missing_blobs: &[BlobDescriptor],
    blob_sources: &HashMap<String, BlobUploadSource>,
    progress: TransferProgress,
) -> Result<BlobUploadOutcome> {
    if missing_blobs.is_empty() {
        return Ok(BlobUploadOutcome::default());
    }

    let upload_plan = api_client
        .blob_upload_urls(workspace, cache_entry_id, missing_blobs)
        .await
        .context("Failed to request CAS blob upload URLs")?;
    let upload_items = build_upload_items(missing_blobs, &upload_plan, blob_sources)?;
    if upload_items.is_empty() {
        return Ok(BlobUploadOutcome::default());
    }

    let max_concurrent = cas_blob_upload_concurrency(&upload_items);
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let transfer_client = api_client.transfer_client().clone();
    let mut tasks = Vec::with_capacity(upload_items.len());

    for upload_item in upload_items {
        let semaphore = semaphore.clone();
        let progress = progress.clone();
        let transfer_client = transfer_client.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow!("CAS upload semaphore closed: {error}"))?;
            let (etag, metrics) = crate::multipart_upload::upload_via_single_url(
                &upload_item.path,
                &upload_item.url,
                &progress,
                &transfer_client,
                &upload_item.headers,
            )
            .await
            .with_context(|| format!("Failed to upload blob {}", upload_item.path.display()))?;
            Ok::<(String, Option<String>, StorageMetrics), anyhow::Error>((
                upload_item.digest,
                etag,
                metrics,
            ))
        });
        tasks.push(task);
    }

    let mut outcome = BlobUploadOutcome::default();
    for task in tasks {
        let (digest, etag, metrics) = task.await.context("Blob upload task panicked")??;
        outcome.receipts.push(BlobReceipt { digest, etag });
        if outcome.storage_metrics.region.is_none() {
            outcome.storage_metrics = metrics;
        }
    }

    Ok(outcome)
}

pub(crate) async fn upload_manifest(
    api_client: &ApiClient,
    manifest_upload_url: &str,
    pointer_bytes: &[u8],
    upload_headers: &HashMap<String, String>,
) -> Result<Option<String>> {
    crate::cas_transport::upload_payload(
        api_client.transfer_client(),
        manifest_upload_url,
        pointer_bytes,
        "application/cbor",
        upload_headers,
    )
    .await
}

pub(crate) fn ensure_server_adapter(
    tag: &str,
    expected_adapter: crate::adapters::CasAdapterKind,
    save_response: &SaveResponse,
) -> Result<()> {
    let server_adapter = crate::cache_adapter::detect_restore_transport(
        save_response.storage_mode.as_deref(),
        save_response.cas_layout.as_deref(),
    );
    if expected_adapter.accepts_server_kind(server_adapter) {
        return Ok(());
    }

    let expected_name = match expected_adapter {
        crate::adapters::CasAdapterKind::Oci => "OCI",
        crate::adapters::CasAdapterKind::File => "file",
        crate::adapters::CasAdapterKind::Pkg => "package",
    };
    anyhow::bail!(
        "Server did not negotiate {} CAS mode for {} (adapter '{}')",
        expected_name,
        tag,
        server_adapter.as_str()
    );
}

pub(crate) fn build_confirm_request(
    spec: &CasConfirmSpec,
    manifest_etag: Option<String>,
) -> ConfirmRequest {
    ConfirmRequest {
        manifest_digest: spec.manifest_digest.clone(),
        manifest_size: spec.manifest_size,
        manifest_etag,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(spec.blob_count),
        blob_total_size_bytes: Some(spec.blob_total_size_bytes),
        file_count: Some(spec.file_count),
        uncompressed_size: None,
        compressed_size: None,
        storage_mode: Some("cas".to_string()),
        tag: Some(spec.tag.clone()),
        write_scope_tag: None,
    }
}

pub(crate) fn build_save_request(
    tag: String,
    manifest_root_digest: String,
    total_size_bytes: u64,
    cas_layout: Option<String>,
    confirm_spec: &CasConfirmSpec,
    force: bool,
) -> SaveRequest {
    let mut request = SaveRequest {
        tag,
        write_scope_tag: None,
        manifest_root_digest,
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(confirm_spec.blob_count),
        blob_total_size_bytes: Some(confirm_spec.blob_total_size_bytes),
        cas_layout,
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(confirm_spec.file_count),
        expected_manifest_digest: Some(confirm_spec.manifest_digest.clone()),
        expected_manifest_size: Some(confirm_spec.manifest_size),
        force: force.then_some(true),
        use_multipart: None,
        ci_provider: None,
        ci_run_uid: None,
        ci_run_attempt: None,
        ci_ref_type: None,
        ci_ref_name: None,
        ci_default_branch: None,
        ci_pr_number: None,
        ci_commit_sha: None,
        ci_run_started_at: None,
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };
    apply_detected_ci_context(&mut request);
    request
}

pub(crate) async fn confirm_upload(
    api_client: &ApiClient,
    workspace: &str,
    cache_entry_id: &str,
    confirm_spec: &CasConfirmSpec,
    manifest_etag: Option<String>,
) -> Result<()> {
    let confirm_request = build_confirm_request(confirm_spec, manifest_etag);
    api_client
        .confirm(workspace, cache_entry_id, &confirm_request)
        .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn upload_missing_blobs_and_manifest(
    api_client: &ApiClient,
    workspace: &str,
    save_response: &SaveResponse,
    missing_blobs: &[BlobDescriptor],
    all_blob_digests: &[String],
    blob_sources: &HashMap<String, BlobUploadSource>,
    pointer_bytes: &[u8],
    manifest_digest: String,
    manifest_size: u64,
    progress: TransferProgress,
) -> Result<CasPublishResult> {
    let mut result = CasPublishResult::default();
    if !missing_blobs.is_empty() {
        let upload_outcome = upload_missing_blobs(
            api_client,
            workspace,
            &save_response.cache_entry_id,
            missing_blobs,
            blob_sources,
            progress,
        )
        .await?;
        maybe_commit_blob_receipts(
            api_client,
            workspace,
            save_response.upload_session_id.as_deref(),
            upload_outcome.receipts,
        )
        .await;
        result.storage_metrics = upload_outcome.storage_metrics;
    }

    let manifest_upload_url = save_response
        .manifest_upload_url
        .as_ref()
        .ok_or_else(|| anyhow!("Missing manifest_upload_url in response"))?;
    let manifest_etag = upload_manifest(
        api_client,
        manifest_upload_url,
        pointer_bytes,
        &save_response.upload_headers,
    )
    .await?;
    let blob_digests = if all_blob_digests.is_empty() {
        None
    } else {
        Some(all_blob_digests.to_vec())
    };
    maybe_commit_manifest_receipt(
        api_client,
        workspace,
        save_response.upload_session_id.as_deref(),
        manifest_digest,
        manifest_size,
        manifest_etag.clone(),
        blob_digests,
    )
    .await;
    result.manifest_etag = manifest_etag;

    Ok(result)
}

fn build_upload_items(
    missing_blobs: &[BlobDescriptor],
    upload_plan: &BlobUploadUrlsResponse,
    blob_sources: &HashMap<String, BlobUploadSource>,
) -> Result<Vec<BlobUploadItem>> {
    let upload_urls: HashMap<&str, (&str, &HashMap<String, String>)> = upload_plan
        .upload_urls
        .iter()
        .map(|upload| {
            (
                upload.digest.as_str(),
                (upload.url.as_str(), &upload.headers),
            )
        })
        .collect();
    let already_present: HashSet<&str> = upload_plan
        .already_present
        .iter()
        .map(String::as_str)
        .collect();

    let mut items = Vec::new();
    for blob in missing_blobs {
        if already_present.contains(blob.digest.as_str()) {
            continue;
        }

        let (url, headers) = upload_urls
            .get(blob.digest.as_str())
            .copied()
            .ok_or_else(|| anyhow!("Server did not provide upload URL for blob {}", blob.digest))?;
        let source = blob_sources
            .get(&blob.digest)
            .ok_or_else(|| anyhow!("Missing local file for blob {}", blob.digest))?;
        if source.size_bytes != blob.size_bytes {
            anyhow::bail!(
                "Local metadata mismatch for blob {} (expected {}, got {})",
                blob.digest,
                blob.size_bytes,
                source.size_bytes
            );
        }

        items.push(BlobUploadItem {
            digest: blob.digest.clone(),
            path: source.path.clone(),
            url: url.to_string(),
            headers: headers.clone(),
            size_bytes: blob.size_bytes,
        });
    }

    items.sort_by(|left, right| {
        left.size_bytes
            .cmp(&right.size_bytes)
            .then_with(|| left.digest.cmp(&right.digest))
    });

    Ok(items)
}

fn cas_blob_upload_concurrency(upload_items: &[BlobUploadItem]) -> usize {
    let operation_count = upload_items.len();
    if operation_count == 0 {
        return 1;
    }

    let base = crate::command_support::get_optimal_concurrency(operation_count, "save").max(1);
    let total_bytes = upload_items.iter().map(|item| item.size_bytes).sum::<u64>();
    let average_blob_bytes = total_bytes / operation_count as u64;
    let profile_floor = if operation_count >= MANY_CAS_UPLOAD_BLOB_COUNT
        && average_blob_bytes <= MEDIUM_CAS_UPLOAD_BLOB_BYTES
    {
        32
    } else if operation_count >= SOME_CAS_UPLOAD_BLOB_COUNT
        && average_blob_bytes <= SMALL_CAS_UPLOAD_BLOB_BYTES
    {
        24
    } else {
        base
    };
    let inflight_cap = if average_blob_bytes == 0 {
        CAS_UPLOAD_HARD_CONCURRENCY_CAP
    } else {
        TARGET_CAS_UPLOAD_INFLIGHT_BYTES
            .saturating_div(average_blob_bytes)
            .clamp(1, CAS_UPLOAD_HARD_CONCURRENCY_CAP as u64) as usize
    };
    let explicit_cap = parse_save_concurrency_cap()
        .unwrap_or(CAS_UPLOAD_HARD_CONCURRENCY_CAP)
        .clamp(1, 128);

    base.max(profile_floor)
        .min(inflight_cap)
        .min(explicit_cap)
        .min(operation_count)
        .max(1)
}

fn parse_save_concurrency_cap() -> Option<usize> {
    let raw = std::env::var(SAVE_MAX_CONCURRENCY_ENV).ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    trimmed.parse::<usize>().ok().filter(|value| *value > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env;

    #[test]
    fn build_upload_items_uses_local_sources_for_missing_blobs() {
        let missing_blobs = vec![BlobDescriptor {
            digest: "sha256:abc".to_string(),
            size_bytes: 42,
        }];
        let upload_plan = BlobUploadUrlsResponse {
            upload_urls: vec![crate::api::models::cache::BlobUploadUrl {
                digest: "sha256:abc".to_string(),
                url: "https://example.test/blob".to_string(),
                headers: HashMap::new(),
            }],
            already_present: Vec::new(),
            upload_session_id: None,
            upload_state: None,
        };
        let blob_sources = HashMap::from([(
            "sha256:abc".to_string(),
            BlobUploadSource {
                path: PathBuf::from("/tmp/blob"),
                size_bytes: 42,
            },
        )]);

        let upload_items = build_upload_items(&missing_blobs, &upload_plan, &blob_sources).unwrap();

        assert_eq!(upload_items.len(), 1);
        assert_eq!(upload_items[0].digest, "sha256:abc");
        assert_eq!(upload_items[0].path, PathBuf::from("/tmp/blob"));
    }

    #[test]
    fn build_upload_items_rejects_missing_upload_url() {
        let missing_blobs = vec![BlobDescriptor {
            digest: "sha256:abc".to_string(),
            size_bytes: 42,
        }];
        let upload_plan = BlobUploadUrlsResponse {
            upload_urls: Vec::new(),
            already_present: Vec::new(),
            upload_session_id: None,
            upload_state: None,
        };
        let blob_sources = HashMap::from([(
            "sha256:abc".to_string(),
            BlobUploadSource {
                path: PathBuf::from("/tmp/blob"),
                size_bytes: 42,
            },
        )]);

        let error = build_upload_items(&missing_blobs, &upload_plan, &blob_sources).unwrap_err();

        assert!(
            error
                .to_string()
                .contains("Server did not provide upload URL")
        );
    }

    fn blob_upload_items(count: usize, size_bytes: u64) -> Vec<BlobUploadItem> {
        (0..count)
            .map(|index| BlobUploadItem {
                digest: format!("sha256:{index:064x}"),
                path: PathBuf::from(format!("/tmp/blob-{index}")),
                url: "https://example.test/blob".to_string(),
                headers: HashMap::new(),
                size_bytes,
            })
            .collect()
    }

    #[test]
    fn cas_blob_upload_concurrency_boosts_many_medium_blobs() {
        let _guard = test_env::lock();
        test_env::remove_var(SAVE_MAX_CONCURRENCY_ENV);
        let items = blob_upload_items(MANY_CAS_UPLOAD_BLOB_COUNT, SMALL_CAS_UPLOAD_BLOB_BYTES);

        assert_eq!(cas_blob_upload_concurrency(&items), 32);
    }

    #[test]
    fn cas_blob_upload_concurrency_respects_save_cap() {
        let _guard = test_env::lock();
        test_env::set_var(SAVE_MAX_CONCURRENCY_ENV, "3");
        let items = blob_upload_items(MANY_CAS_UPLOAD_BLOB_COUNT, SMALL_CAS_UPLOAD_BLOB_BYTES);

        assert_eq!(cas_blob_upload_concurrency(&items), 3);
        test_env::remove_var(SAVE_MAX_CONCURRENCY_ENV);
    }

    #[test]
    fn cas_blob_upload_concurrency_limits_large_blob_inflight() {
        let _guard = test_env::lock();
        test_env::remove_var(SAVE_MAX_CONCURRENCY_ENV);
        let items = blob_upload_items(8, 512 * 1024 * 1024);

        assert_eq!(cas_blob_upload_concurrency(&items), 1);
    }
}
