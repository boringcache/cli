use crate::api::models::cache::{BlobReceipt, ManifestReceiptCommitRequest};
use crate::serve::state::AppState;

pub(crate) async fn maybe_commit_blob_receipts(
    state: &AppState,
    upload_session_id: Option<&str>,
    receipts: Vec<BlobReceipt>,
) {
    if let Some(upload_session_id) = upload_session_id.filter(|_| !receipts.is_empty()) {
        if let Err(e) = state
            .api_client
            .commit_blob_receipts(&state.workspace, upload_session_id, &receipts)
            .await
        {
            log::warn!(
                "blob receipt commit failed for upload session {}: {}",
                upload_session_id,
                e
            );
        }
    }
}

pub(crate) async fn maybe_commit_manifest_receipt(
    state: &AppState,
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
        if let Err(e) = state
            .api_client
            .commit_manifest_receipt(&state.workspace, upload_session_id, &request)
            .await
        {
            log::warn!(
                "manifest receipt commit failed for upload session {}: {}",
                upload_session_id,
                e
            );
        }
    }
}
