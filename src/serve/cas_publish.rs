use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crate::api::ApiClient;
use crate::api::models::cache::{BlobReceipt, SaveResponse};
use crate::multipart_upload::upload_via_single_url;
use crate::serve::error::OciError;
use crate::serve::state::UploadSessionStore;
use crate::upload_receipts::{maybe_commit_blob_receipts, maybe_commit_manifest_receipt};
use tokio::sync::{RwLock, Semaphore};

struct TrackedBlobUploadJob {
    digest: String,
    temp_path: PathBuf,
    url: String,
    headers: HashMap<String, String>,
    size_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_after_save<
    C,
    E,
    UploadBlobs,
    UploadBlobsFuture,
    UploadManifest,
    UploadManifestFuture,
    Confirm,
    ConfirmFuture,
>(
    api_client: &ApiClient,
    workspace: &str,
    save_response: &SaveResponse,
    manifest_digest: String,
    manifest_size: u64,
    upload_blobs: UploadBlobs,
    upload_manifest: UploadManifest,
    confirm: Confirm,
) -> Result<C, E>
where
    UploadBlobs: FnOnce(&SaveResponse) -> UploadBlobsFuture,
    UploadBlobsFuture: Future<Output = Result<Vec<BlobReceipt>, E>>,
    UploadManifest: FnOnce(&SaveResponse) -> UploadManifestFuture,
    UploadManifestFuture: Future<Output = Result<Option<String>, E>>,
    Confirm: FnOnce(Option<String>) -> ConfirmFuture,
    ConfirmFuture: Future<Output = Result<C, E>>,
{
    let manifest_etag = if save_response.exists {
        None
    } else {
        let blob_receipts = upload_blobs(save_response).await?;
        maybe_commit_blob_receipts(
            api_client,
            workspace,
            save_response.upload_session_id.as_deref(),
            blob_receipts,
        )
        .await;

        let manifest_etag = upload_manifest(save_response).await?;
        maybe_commit_manifest_receipt(
            api_client,
            workspace,
            save_response.upload_session_id.as_deref(),
            manifest_digest,
            manifest_size,
            manifest_etag.clone(),
        )
        .await;
        manifest_etag
    };

    confirm(manifest_etag).await
}

pub(crate) async fn upload_tracked_blobs(
    api_client: &ApiClient,
    workspace: &str,
    cache_entry_id: &str,
    blob_descriptors: &[crate::api::models::cache::BlobDescriptor],
    upload_sessions: &Arc<RwLock<UploadSessionStore>>,
    max_concurrent: usize,
    transfer_timeout: Duration,
) -> Result<Vec<BlobReceipt>, OciError> {
    if blob_descriptors.is_empty() {
        return Ok(Vec::new());
    }

    let upload_plan = api_client
        .blob_upload_urls(workspace, cache_entry_id, blob_descriptors)
        .await
        .map_err(|e| OciError::internal(format!("blob_upload_urls failed: {e}")))?;
    let size_by_digest: HashMap<&str, u64> = blob_descriptors
        .iter()
        .map(|blob| (blob.digest.as_str(), blob.size_bytes))
        .collect();
    let mut upload_jobs = {
        let sessions = upload_sessions.read().await;
        let mut jobs = Vec::with_capacity(upload_plan.upload_urls.len());
        for upload_url_info in &upload_plan.upload_urls {
            let session = sessions
                .find_by_digest(&upload_url_info.digest)
                .ok_or_else(|| {
                    OciError::internal(format!(
                        "No upload session for blob {}",
                        upload_url_info.digest
                    ))
                })?;
            jobs.push(TrackedBlobUploadJob {
                digest: upload_url_info.digest.clone(),
                temp_path: session.temp_path.clone(),
                url: upload_url_info.url.clone(),
                headers: upload_url_info.headers.clone(),
                size_bytes: size_by_digest
                    .get(upload_url_info.digest.as_str())
                    .copied()
                    .unwrap_or(0),
            });
        }
        jobs
    };

    upload_jobs.sort_by(|left, right| {
        left.size_bytes
            .cmp(&right.size_bytes)
            .then_with(|| left.digest.cmp(&right.digest))
    });

    let semaphore = Arc::new(Semaphore::new(max_concurrent.max(1)));
    let transfer_client = api_client.transfer_client().clone();
    let mut tasks = Vec::with_capacity(upload_jobs.len());
    for upload_job in upload_jobs {
        let semaphore = semaphore.clone();
        let transfer_client = transfer_client.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore
                .acquire()
                .await
                .map_err(|e| OciError::internal(format!("Blob upload semaphore closed: {e}")))?;
            let progress = crate::progress::TransferProgress::new_noop();
            tokio::time::timeout(
                transfer_timeout,
                upload_via_single_url(
                    upload_job.temp_path.as_path(),
                    &upload_job.url,
                    &progress,
                    &transfer_client,
                    &upload_job.headers,
                ),
            )
            .await
            .map_err(|_| {
                OciError::internal(format!(
                    "Blob upload timed out for {} after {}s",
                    upload_job.digest,
                    transfer_timeout.as_secs()
                ))
            })?
            .map_err(|e| {
                OciError::internal(format!(
                    "Blob upload failed for {}: {}",
                    upload_job.digest, e
                ))
            })?;
            Ok::<BlobReceipt, OciError>(BlobReceipt {
                digest: upload_job.digest,
                etag: None,
            })
        });
        tasks.push(task);
    }

    let mut receipts = Vec::with_capacity(tasks.len());
    for task in tasks {
        receipts.push(
            task.await
                .map_err(|e| OciError::internal(format!("Blob upload task failed: {e}")))??,
        );
    }

    Ok(receipts)
}
