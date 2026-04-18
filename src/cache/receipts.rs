use anyhow::Result;

use crate::api::ApiClient;
use crate::api::models::cache::{BlobReceipt, ManifestReceiptCommitRequest};

pub async fn try_commit_blob_receipts(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    receipts: Vec<BlobReceipt>,
) -> Result<()> {
    if let Some(upload_session_id) = upload_session_id.filter(|_| !receipts.is_empty()) {
        api_client
            .commit_blob_receipts(workspace, upload_session_id, &receipts)
            .await?;
    }

    Ok(())
}

pub async fn try_commit_manifest_receipt(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    manifest_digest: String,
    manifest_size: u64,
    manifest_etag: Option<String>,
    blob_digests: Option<Vec<String>>,
) -> Result<()> {
    if let Some(upload_session_id) = upload_session_id {
        let request = ManifestReceiptCommitRequest {
            manifest_digest,
            manifest_size,
            manifest_etag,
            blob_digests,
        };
        api_client
            .commit_manifest_receipt(workspace, upload_session_id, &request)
            .await?;
    }

    Ok(())
}

pub async fn maybe_commit_blob_receipts(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    receipts: Vec<BlobReceipt>,
) {
    let receipt_count = receipts.len();
    let session_label = upload_session_id.unwrap_or("-");
    if let Err(error) =
        try_commit_blob_receipts(api_client, workspace, upload_session_id, receipts).await
    {
        log::warn!(
            "Failed to commit {receipt_count} blob receipts for upload_session_id={session_label}: {error:#}"
        );
    }
}

pub async fn maybe_commit_manifest_receipt(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    manifest_digest: String,
    manifest_size: u64,
    manifest_etag: Option<String>,
    blob_digests: Option<Vec<String>>,
) {
    let session_label = upload_session_id.unwrap_or("-");
    if let Err(error) = try_commit_manifest_receipt(
        api_client,
        workspace,
        upload_session_id,
        manifest_digest,
        manifest_size,
        manifest_etag,
        blob_digests,
    )
    .await
    {
        log::warn!(
            "Failed to commit manifest receipt for upload_session_id={session_label}: {error:#}"
        );
    }
}
