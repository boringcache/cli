use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::api::ApiClient;
use crate::api::models::cache::{
    BlobDescriptor, BlobReceipt, BlobUploadUrlsResponse, SaveResponse,
};
use crate::cache::receipts::{try_commit_blob_receipts, try_commit_manifest_receipt};
use crate::multipart_upload::upload_via_single_url_range;
use crate::serve::engines::oci::PresentBlob;
use crate::serve::error::OciError;
use crate::serve::state::UploadSessionStore;
use tokio::sync::{RwLock, Semaphore};

#[derive(Debug)]
struct TrackedBlobUploadJob {
    digest: String,
    source_path: PathBuf,
    source_offset: u64,
    url: String,
    headers: HashMap<String, String>,
    size_bytes: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_after_save_requiring_receipts<
    C,
    E,
    UploadBlobs,
    UploadBlobsFuture,
    UploadManifest,
    UploadManifestFuture,
    Confirm,
    ConfirmFuture,
    MapReceiptError,
>(
    api_client: &ApiClient,
    workspace: &str,
    save_response: &SaveResponse,
    manifest_digest: String,
    manifest_size: u64,
    blob_digests: Option<Vec<String>>,
    upload_blobs: UploadBlobs,
    upload_manifest: UploadManifest,
    confirm: Confirm,
    map_receipt_error: MapReceiptError,
) -> Result<C, E>
where
    UploadBlobs: FnOnce(&SaveResponse) -> UploadBlobsFuture,
    UploadBlobsFuture: Future<Output = Result<Vec<BlobReceipt>, E>>,
    UploadManifest: FnOnce(&SaveResponse) -> UploadManifestFuture,
    UploadManifestFuture: Future<Output = Result<Option<String>, E>>,
    Confirm: FnOnce(Option<String>) -> ConfirmFuture,
    ConfirmFuture: Future<Output = Result<C, E>>,
    MapReceiptError: Fn(String) -> E,
{
    publish_after_save_inner(
        api_client,
        workspace,
        save_response,
        manifest_digest,
        manifest_size,
        blob_digests,
        upload_blobs,
        upload_manifest,
        confirm,
        map_receipt_error,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn publish_after_save_inner<
    C,
    E,
    UploadBlobs,
    UploadBlobsFuture,
    UploadManifest,
    UploadManifestFuture,
    Confirm,
    ConfirmFuture,
    MapReceiptError,
>(
    api_client: &ApiClient,
    workspace: &str,
    save_response: &SaveResponse,
    manifest_digest: String,
    manifest_size: u64,
    blob_digests: Option<Vec<String>>,
    upload_blobs: UploadBlobs,
    upload_manifest: UploadManifest,
    confirm: Confirm,
    map_receipt_error: MapReceiptError,
) -> Result<C, E>
where
    UploadBlobs: FnOnce(&SaveResponse) -> UploadBlobsFuture,
    UploadBlobsFuture: Future<Output = Result<Vec<BlobReceipt>, E>>,
    UploadManifest: FnOnce(&SaveResponse) -> UploadManifestFuture,
    UploadManifestFuture: Future<Output = Result<Option<String>, E>>,
    Confirm: FnOnce(Option<String>) -> ConfirmFuture,
    ConfirmFuture: Future<Output = Result<C, E>>,
    MapReceiptError: Fn(String) -> E,
{
    let manifest_etag = if save_response.should_skip_existing_uploads() {
        None
    } else {
        let blob_receipts = upload_blobs(save_response).await?;
        commit_blob_receipts_for_publish(
            api_client,
            workspace,
            save_response.upload_session_id.as_deref(),
            blob_receipts,
            &map_receipt_error,
        )
        .await?;

        let manifest_etag = upload_manifest(save_response).await?;
        commit_manifest_receipt_for_publish(
            api_client,
            workspace,
            save_response.upload_session_id.as_deref(),
            manifest_digest,
            manifest_size,
            manifest_etag.clone(),
            blob_digests,
            &map_receipt_error,
        )
        .await?;
        manifest_etag
    };

    confirm(manifest_etag).await
}

async fn commit_blob_receipts_for_publish<E, MapReceiptError>(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    receipts: Vec<BlobReceipt>,
    map_receipt_error: &MapReceiptError,
) -> Result<(), E>
where
    MapReceiptError: Fn(String) -> E,
{
    let receipt_count = receipts.len();
    if receipt_count == 0 {
        return Ok(());
    }
    let upload_session_id = receipt_upload_session_id(
        upload_session_id,
        &format!("{receipt_count} blob"),
        map_receipt_error,
    )?;
    let session_label = upload_session_id;
    if let Err(error) =
        try_commit_blob_receipts(api_client, workspace, Some(upload_session_id), receipts).await
    {
        let message = format!(
            "Failed to commit {receipt_count} blob receipts for upload_session_id={session_label}: {error:#}"
        );
        return Err(map_receipt_error(message));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn commit_manifest_receipt_for_publish<E, MapReceiptError>(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    manifest_digest: String,
    manifest_size: u64,
    manifest_etag: Option<String>,
    blob_digests: Option<Vec<String>>,
    map_receipt_error: &MapReceiptError,
) -> Result<(), E>
where
    MapReceiptError: Fn(String) -> E,
{
    let upload_session_id =
        receipt_upload_session_id(upload_session_id, "manifest", map_receipt_error)?;
    let session_label = upload_session_id;
    if let Err(error) = try_commit_manifest_receipt(
        api_client,
        workspace,
        Some(upload_session_id),
        manifest_digest,
        manifest_size,
        manifest_etag,
        blob_digests,
    )
    .await
    {
        let message = format!(
            "Failed to commit manifest receipt for upload_session_id={session_label}: {error:#}"
        );
        return Err(map_receipt_error(message));
    }
    Ok(())
}

fn receipt_upload_session_id<'a, E, MapReceiptError>(
    upload_session_id: Option<&'a str>,
    receipt_kind: &str,
    map_receipt_error: &MapReceiptError,
) -> Result<&'a str, E>
where
    MapReceiptError: Fn(String) -> E,
{
    upload_session_id
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            map_receipt_error(format!(
                "Server did not return upload_session_id; cannot commit {receipt_kind} receipts for receipt-strict publish"
            ))
        })
}

pub(crate) async fn upload_tracked_blobs(
    api_client: &ApiClient,
    workspace: &str,
    cache_entry_id: &str,
    present_blobs: &[PresentBlob],
    upload_sessions: &Arc<RwLock<UploadSessionStore>>,
    max_concurrent: usize,
    transfer_timeout: Duration,
) -> Result<Vec<BlobReceipt>, OciError> {
    if present_blobs.is_empty() {
        return Ok(Vec::new());
    }

    let batch_started_at = Instant::now();
    let requested_blob_count = present_blobs.len();
    let requested_blob_bytes = present_blobs
        .iter()
        .fold(0u64, |sum, blob| sum.saturating_add(blob.size_bytes));
    let blob_descriptors = present_blob_descriptors(present_blobs);
    let upload_plan = api_client
        .blob_upload_urls(workspace, cache_entry_id, &blob_descriptors)
        .await
        .map_err(|e| OciError::internal(format!("blob_upload_urls failed: {e}")))?;
    crate::observability::emit(
        crate::observability::ObservabilityEvent::event(
            "cli",
            "oci_blob_upload_plan",
            "POST",
            "/v2/cache/blobs/upload-urls".to_string(),
            format!(
                "requested_blobs={} upload_urls={} already_present={} requested_bytes={} max_concurrent={} timeout_secs={}",
                requested_blob_count,
                upload_plan.upload_urls.len(),
                upload_plan.already_present.len(),
                requested_blob_bytes,
                max_concurrent.max(1),
                transfer_timeout.as_secs()
            ),
        )
        .with_workspace(Some(workspace.to_string()))
        .with_cache_entry_id(Some(cache_entry_id.to_string())),
    );
    let mut upload_jobs =
        tracked_blob_upload_jobs(&upload_plan, present_blobs, upload_sessions).await?;

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
        let workspace = workspace.to_string();
        let cache_entry_id = cache_entry_id.to_string();
        let task = tokio::spawn(async move {
            let upload_started_at = Instant::now();
            let _permit = semaphore
                .acquire()
                .await
                .map_err(|e| OciError::internal(format!("Blob upload semaphore closed: {e}")))?;
            let progress = crate::progress::TransferProgress::new_noop();
            let digest = upload_job.digest;
            let source_path = upload_job.source_path;
            let source_offset = upload_job.source_offset;
            let url = upload_job.url;
            let headers = upload_job.headers;
            let size_bytes = upload_job.size_bytes;
            let metric_path = format!("/v2/cache/blobs/{digest}");

            match tokio::time::timeout(
                transfer_timeout,
                upload_via_single_url_range(
                    source_path.as_path(),
                    source_offset,
                    size_bytes,
                    &url,
                    &progress,
                    &transfer_client,
                    &headers,
                ),
            )
            .await
            {
                Ok(Ok((etag, _storage_metrics))) => {
                    crate::observability::emit(
                        crate::observability::ObservabilityEvent::success(
                            "cli",
                            "oci_blob_upload",
                            "PUT",
                            metric_path,
                            200,
                            upload_started_at.elapsed().as_millis() as u64,
                            Some(size_bytes),
                            None,
                            None,
                            None,
                            None,
                            None,
                        )
                        .with_workspace(Some(workspace))
                        .with_cache_entry_id(Some(cache_entry_id))
                        .with_details(Some(format!(
                            "digest={digest} timeout_secs={}",
                            transfer_timeout.as_secs()
                        ))),
                    );
                    Ok::<BlobReceipt, OciError>(BlobReceipt { digest, etag })
                }
                Ok(Err(error)) => {
                    let message = format!("Blob upload failed for {digest}: {error}");
                    crate::observability::emit(
                        crate::observability::ObservabilityEvent::failure(
                            "cli",
                            "oci_blob_upload",
                            "PUT",
                            metric_path,
                            message.clone(),
                            upload_started_at.elapsed().as_millis() as u64,
                            None,
                        )
                        .with_workspace(Some(workspace))
                        .with_cache_entry_id(Some(cache_entry_id))
                        .with_details(Some(format!("digest={digest} size_bytes={size_bytes}"))),
                    );
                    Err(OciError::internal(message))
                }
                Err(_) => {
                    let message = format!(
                        "Blob upload timed out for {digest} after {}s",
                        transfer_timeout.as_secs()
                    );
                    crate::observability::emit(
                        crate::observability::ObservabilityEvent::failure(
                            "cli",
                            "oci_blob_upload",
                            "PUT",
                            metric_path,
                            message.clone(),
                            upload_started_at.elapsed().as_millis() as u64,
                            None,
                        )
                        .with_workspace(Some(workspace))
                        .with_cache_entry_id(Some(cache_entry_id))
                        .with_details(Some(format!("digest={digest} size_bytes={size_bytes}"))),
                    );
                    Err(OciError::internal(message))
                }
            }
        });
        tasks.push(task);
    }

    let mut receipts = Vec::with_capacity(tasks.len());
    let total_tasks = tasks.len();
    let mut failure_count = 0usize;
    let mut first_error: Option<OciError> = None;
    for task in tasks {
        match task.await {
            Ok(Ok(receipt)) => receipts.push(receipt),
            Ok(Err(error)) => {
                failure_count += 1;
                if first_error.is_none() {
                    first_error = Some(error);
                }
            }
            Err(error) => {
                failure_count += 1;
                if first_error.is_none() {
                    first_error = Some(OciError::internal(format!(
                        "Blob upload task failed: {error}"
                    )));
                }
            }
        }
    }

    if let Some(error) = first_error {
        crate::observability::emit(
            crate::observability::ObservabilityEvent::failure(
                "cli",
                "oci_blob_upload_batch",
                "PUT",
                "/v2/cache/blobs".to_string(),
                error.message().to_string(),
                batch_started_at.elapsed().as_millis() as u64,
                None,
            )
            .with_workspace(Some(workspace.to_string()))
            .with_cache_entry_id(Some(cache_entry_id.to_string()))
            .with_details(Some(format!(
                "successful_blobs={} failed_blobs={} requested_blobs={} requested_bytes={}",
                receipts.len(),
                failure_count,
                total_tasks,
                requested_blob_bytes
            ))),
        );
        return Err(OciError::internal(format!(
            "Blob upload batch failed after {}/{} successful uploads: {}",
            receipts.len(),
            total_tasks,
            error.message()
        )));
    }

    crate::observability::emit(
        crate::observability::ObservabilityEvent::success(
            "cli",
            "oci_blob_upload_batch",
            "PUT",
            "/v2/cache/blobs".to_string(),
            200,
            batch_started_at.elapsed().as_millis() as u64,
            Some(requested_blob_bytes),
            None,
            None,
            None,
            Some(receipts.len() as u64),
            None,
        )
        .with_workspace(Some(workspace.to_string()))
        .with_cache_entry_id(Some(cache_entry_id.to_string()))
        .with_details(Some(format!(
            "successful_blobs={} requested_blobs={} already_present={}",
            receipts.len(),
            requested_blob_count,
            upload_plan.already_present.len()
        ))),
    );

    Ok(receipts)
}

fn present_blob_descriptors(present_blobs: &[PresentBlob]) -> Vec<BlobDescriptor> {
    present_blobs
        .iter()
        .map(|blob| BlobDescriptor {
            digest: blob.digest.clone(),
            size_bytes: blob.size_bytes,
        })
        .collect()
}

async fn tracked_blob_upload_jobs(
    upload_plan: &BlobUploadUrlsResponse,
    present_blobs: &[PresentBlob],
    upload_sessions: &Arc<RwLock<UploadSessionStore>>,
) -> Result<Vec<TrackedBlobUploadJob>, OciError> {
    let proofs_by_digest: HashMap<&str, &PresentBlob> = present_blobs
        .iter()
        .map(|blob| (blob.digest.as_str(), blob))
        .collect();

    let sessions = upload_sessions.read().await;
    let mut jobs = Vec::with_capacity(upload_plan.upload_urls.len());
    for upload_url_info in &upload_plan.upload_urls {
        let proof = proofs_by_digest
            .get(upload_url_info.digest.as_str())
            .ok_or_else(|| {
                OciError::internal(format!(
                    "Blob upload plan returned unproven digest {}",
                    upload_url_info.digest
                ))
            })?;
        let session_id = proof.upload_session_id.as_deref().ok_or_else(|| {
            OciError::internal(format!(
                "Blob upload plan requested {} from {} proof without local bytes",
                proof.digest,
                proof.source.as_str()
            ))
        })?;
        let session = sessions.get(session_id).ok_or_else(|| {
            OciError::internal(format!(
                "Blob upload proof session {session_id} for {} is missing",
                proof.digest
            ))
        })?;
        if session.finalized_digest.as_deref() != Some(proof.digest.as_str()) {
            return Err(OciError::internal(format!(
                "Blob upload proof session {session_id} digest mismatch for {}",
                proof.digest
            )));
        }
        let session_size = session.finalized_size.unwrap_or(session.bytes_received);
        if session_size != proof.size_bytes {
            return Err(OciError::digest_invalid(format!(
                "descriptor size mismatch for {} from {} proof: expected {}, got {}",
                proof.digest,
                proof.source.as_str(),
                proof.size_bytes,
                session_size
            )));
        }

        jobs.push(TrackedBlobUploadJob {
            digest: upload_url_info.digest.clone(),
            source_path: session.body_path().to_path_buf(),
            source_offset: session.body_offset(),
            url: upload_url_info.url.clone(),
            headers: upload_url_info.headers.clone(),
            size_bytes: proof.size_bytes,
        });
    }

    Ok(jobs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::models::cache::BlobUploadUrl;
    use crate::serve::engines::oci::PresentBlobSource;
    use crate::serve::state::{BlobReadCache, UploadSession, UploadSessionStore};
    use axum::http::StatusCode;

    fn string_error(message: String) -> String {
        message
    }

    fn upload_plan_for(digest: &str) -> BlobUploadUrlsResponse {
        BlobUploadUrlsResponse {
            upload_urls: vec![BlobUploadUrl {
                digest: digest.to_string(),
                url: "https://example.com/upload".to_string(),
                headers: HashMap::new(),
            }],
            already_present: Vec::new(),
            upload_session_id: None,
            upload_state: None,
        }
    }

    #[test]
    fn receipt_strict_publish_requires_upload_session_id() {
        let error = receipt_upload_session_id(None, "manifest", &string_error)
            .expect_err("missing upload session must fail receipt-strict publish");

        assert!(error.contains("Server did not return upload_session_id"));
        assert!(error.contains("manifest receipts"));
    }

    #[test]
    fn receipt_strict_publish_rejects_blank_upload_session_id() {
        let error = receipt_upload_session_id(Some("  "), "2 blob", &string_error)
            .expect_err("blank upload session must fail receipt-strict publish");

        assert!(error.contains("2 blob receipts"));
    }

    #[tokio::test]
    async fn tracked_blob_upload_jobs_use_present_blob_session_id() {
        let digest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let proof_path = PathBuf::from("proof-session");
        let unrelated_path = PathBuf::from("unrelated-session");
        let mut sessions = UploadSessionStore::default();
        sessions.create(UploadSession::owned_temp_file(
            "proof-session".to_string(),
            "cache".to_string(),
            proof_path.clone(),
            5,
            Some(digest.to_string()),
            Some(5),
        ));
        sessions.create(UploadSession::owned_temp_file(
            "unrelated-session".to_string(),
            "other".to_string(),
            unrelated_path,
            100,
            Some(digest.to_string()),
            Some(100),
        ));
        let sessions = Arc::new(RwLock::new(sessions));
        let present_blobs = vec![PresentBlob {
            digest: digest.to_string(),
            size_bytes: 5,
            source: PresentBlobSource::UploadSession,
            upload_session_id: Some("proof-session".to_string()),
        }];

        let jobs = tracked_blob_upload_jobs(&upload_plan_for(digest), &present_blobs, &sessions)
            .await
            .expect("proof session should create upload job");

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].source_path, proof_path);
        assert_eq!(jobs[0].source_offset, 0);
        assert_eq!(jobs[0].size_bytes, 5);
    }

    #[tokio::test]
    async fn tracked_blob_upload_jobs_preserve_borrowed_body_offset() {
        let digest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
        let payload = b"borrowed upload body";
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let cache = BlobReadCache::new_at(temp_dir.path().join("blob-cache"), 1024 * 1024)
            .expect("blob cache");
        cache.insert(digest, payload).await.expect("insert blob");
        let lease = cache.lease_handle(digest).await.expect("leased blob");
        let source_path = lease.path().to_path_buf();
        let source_offset = lease.offset();
        assert!(source_offset > 0, "test should exercise segment offsets");

        let mut sessions = UploadSessionStore::default();
        sessions.create(UploadSession::borrowed_blob_read(
            "borrowed-session".to_string(),
            "cache".to_string(),
            digest.to_string(),
            payload.len() as u64,
            lease,
        ));
        let sessions = Arc::new(RwLock::new(sessions));
        let present_blobs = vec![PresentBlob {
            digest: digest.to_string(),
            size_bytes: payload.len() as u64,
            source: PresentBlobSource::LocalBodyCache,
            upload_session_id: Some("borrowed-session".to_string()),
        }];

        let jobs = tracked_blob_upload_jobs(&upload_plan_for(digest), &present_blobs, &sessions)
            .await
            .expect("borrowed proof session should create upload job");

        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].source_path, source_path);
        assert_eq!(jobs[0].source_offset, source_offset);
        assert_eq!(jobs[0].size_bytes, payload.len() as u64);
    }

    #[tokio::test]
    async fn tracked_blob_upload_jobs_reject_remote_proof_upload_request() {
        let digest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
        let sessions = Arc::new(RwLock::new(UploadSessionStore::default()));
        let present_blobs = vec![PresentBlob {
            digest: digest.to_string(),
            size_bytes: 7,
            source: PresentBlobSource::RemoteStorage,
            upload_session_id: None,
        }];

        let error = tracked_blob_upload_jobs(&upload_plan_for(digest), &present_blobs, &sessions)
            .await
            .expect_err("remote storage proof has no upload bytes");

        assert_eq!(error.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            error
                .message()
                .contains("remote-storage proof without local bytes")
        );
    }
}
