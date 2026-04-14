use crate::api::models::cache::BlobDescriptor;
use crate::api::{ApiClient, CacheResolutionEntry};
use crate::progress::TransferProgress;
use crate::telemetry::StorageMetrics;
use crate::transfer::send_transfer_request_with_retry;
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Debug)]
pub(crate) enum CasPointer {
    Oci(crate::cas_oci::OciPointer),
    File(crate::cas_file::FilePointer),
}

#[derive(Debug)]
pub(crate) struct FetchedCasPointer {
    pub resolved_manifest_root_digest: String,
    pub pointer: CasPointer,
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

    let response = send_transfer_request_with_retry("CAS index fetch", || async {
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

    let resolved_manifest_root_digest = hit
        .manifest_root_digest
        .clone()
        .unwrap_or_else(|| format!("sha256:{actual_manifest_hex}"));
    if !digest_matches(
        cas_adapter,
        &resolved_manifest_root_digest,
        &actual_manifest_hex,
    ) {
        return Ok(FetchCasPointerOutcome::Ignored {
            reason: format!(
                "CAS manifest root digest mismatch for {} (expected {}, got sha256:{})",
                hit.tag, resolved_manifest_root_digest, actual_manifest_hex
            ),
        });
    }

    verify_signature(hit, &resolved_manifest_root_digest)?;

    let pointer = match cas_adapter {
        crate::adapters::CasAdapterKind::Oci => {
            CasPointer::Oci(crate::cas_oci::parse_pointer(&pointer_bytes)?)
        }
        crate::adapters::CasAdapterKind::File => {
            CasPointer::File(crate::cas_file::parse_pointer(&pointer_bytes)?)
        }
    };

    Ok(FetchCasPointerOutcome::Ready(FetchedCasPointer {
        resolved_manifest_root_digest,
        pointer,
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
    let blobs: Vec<BlobDescriptor> = download_targets
        .iter()
        .map(|target| BlobDescriptor {
            digest: target.digest.clone(),
            size_bytes: target.size_bytes,
        })
        .collect();
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

    let download_items = build_download_items(download_targets, &download_plan)?;
    let max_concurrent =
        crate::command_support::get_optimal_concurrency(download_items.len(), "restore");
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let transfer_client = api_client.transfer_client().clone();
    let mut tasks = Vec::with_capacity(download_items.len());

    for download_target in download_items {
        let semaphore = semaphore.clone();
        let progress = progress.clone();
        let transfer_client = transfer_client.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|error| anyhow!("Restore blob download semaphore closed: {error}"))?;
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
            drop(_permit);
            result
        });
        tasks.push(task);
    }

    let mut outcome = BlobDownloadOutcome::default();
    for task in tasks {
        let (bytes_downloaded, storage_metrics) =
            task.await.context("Blob download task panicked")??;
        outcome.bytes_downloaded += bytes_downloaded;
        if outcome.storage_metrics.region.is_none() {
            outcome.storage_metrics = storage_metrics;
        }
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

fn sha256_hex(cas_adapter: crate::adapters::CasAdapterKind, bytes: &[u8]) -> String {
    match cas_adapter {
        crate::adapters::CasAdapterKind::Oci => crate::cas_oci::sha256_hex(bytes),
        crate::adapters::CasAdapterKind::File => crate::cas_file::sha256_hex(bytes),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn file_digest_matching_accepts_prefixed_sha() {
        assert!(digest_matches(
            crate::adapters::CasAdapterKind::File,
            "sha256:abc",
            "abc"
        ));
    }
}
