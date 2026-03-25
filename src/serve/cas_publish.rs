use std::future::Future;

use crate::api::models::cache::{BlobReceipt, SaveResponse};
use crate::api::ApiClient;
use crate::upload_receipts::{maybe_commit_blob_receipts, maybe_commit_manifest_receipt};

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
