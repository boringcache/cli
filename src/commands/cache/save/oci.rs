use super::SaveStatus;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::OnceCell;

use crate::api::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cache::cas_publish::{self, BlobUploadSource};

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_single_oci_entry(
    shared_api_client: Arc<OnceCell<ApiClient>>,
    workspace: String,
    tag: String,
    path: String,
    _verbose: bool,
    force: bool,
    _entry_index: usize,
    _total_entries: usize,
) -> Result<SaveStatus> {
    let bundle_tag = tag.clone();
    super::cas::save_single_cas_entry(
        shared_api_client,
        workspace,
        tag,
        path,
        force,
        "Scanning OCI layout",
        "OCI scan task panicked",
        move |scan_path| {
            let scan = crate::cache::cas_oci::scan_layout(&scan_path)?;
            let pointer_bytes = crate::cache::cas_oci::build_pointer(&scan)?;
            let manifest_root_digest =
                crate::cache::cas_oci::prefixed_sha256_digest(&pointer_bytes);
            let manifest_size = pointer_bytes.len() as u64;
            let blob_count = scan.blobs.len() as u64;
            let file_count = blob_count.min(u32::MAX as u64) as u32;
            let blob_total_size_bytes = scan.total_blob_bytes;
            let total_size_bytes =
                blob_total_size_bytes + scan.index_json.len() as u64 + scan.oci_layout.len() as u64;
            let blobs = scan
                .blobs
                .iter()
                .map(|blob| BlobDescriptor {
                    digest: blob.digest.clone(),
                    size_bytes: blob.size_bytes,
                })
                .collect();
            let blob_sources = scan
                .blobs
                .iter()
                .map(|blob| {
                    (
                        blob.digest.clone(),
                        BlobUploadSource {
                            path: blob.path.clone(),
                            size_bytes: blob.size_bytes,
                        },
                    )
                })
                .collect();

            Ok(super::cas::CasSaveBundle {
                expected_adapter: crate::adapters::CasAdapterKind::Oci,
                cas_layout: Some("oci-v1".to_string()),
                pointer_bytes,
                manifest_root_digest: manifest_root_digest.clone(),
                total_size_bytes,
                blob_total_size_bytes,
                blobs,
                blob_sources,
                confirm_spec: cas_publish::CasConfirmSpec {
                    manifest_digest: manifest_root_digest.clone(),
                    manifest_size,
                    blob_count,
                    blob_total_size_bytes,
                    file_count,
                    tag: bundle_tag.clone(),
                },
                empty_payload_error: None,
            })
        },
    )
    .await
}
