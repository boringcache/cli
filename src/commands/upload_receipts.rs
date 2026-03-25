use crate::api::models::cache::{BlobReceipt, ManifestReceiptCommitRequest};
use crate::api::ApiClient;

pub(crate) async fn maybe_commit_blob_receipts(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    receipts: Vec<BlobReceipt>,
) {
    if let Some(upload_session_id) = upload_session_id.filter(|_| !receipts.is_empty()) {
        if let Err(error) = api_client
            .commit_blob_receipts(workspace, upload_session_id, &receipts)
            .await
        {
            log::warn!(
                "Failed to commit blob receipts for upload session {upload_session_id}: {error:#}"
            );
        }
    }
}

pub(crate) async fn maybe_commit_manifest_receipt(
    api_client: &ApiClient,
    workspace: &str,
    upload_session_id: Option<&str>,
    manifest_digest: String,
    manifest_size: u64,
    manifest_etag: Option<String>,
) {
    if let Some(upload_session_id) = upload_session_id {
        let request = ManifestReceiptCommitRequest {
            manifest_digest,
            manifest_size,
            manifest_etag,
        };
        if let Err(error) = api_client
            .commit_manifest_receipt(workspace, upload_session_id, &request)
            .await
        {
            log::warn!(
                "Failed to commit manifest receipt for upload session {upload_session_id}: {error:#}"
            );
        }
    }
}
