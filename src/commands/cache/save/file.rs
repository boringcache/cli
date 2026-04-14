use super::SaveStatus;
use anyhow::Result;
use std::sync::Arc;
use tokio::sync::OnceCell;

use crate::api::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cache::cas_publish::{self, BlobUploadSource};
use crate::manifest::EntryType;

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_single_file_entry(
    shared_api_client: Arc<OnceCell<ApiClient>>,
    workspace: String,
    tag: String,
    path: String,
    _verbose: bool,
    force: bool,
    _entry_index: usize,
    _total_entries: usize,
    exclude: Vec<String>,
    detected_kind: crate::cache_adapter::CacheAdapterKind,
) -> Result<SaveStatus> {
    let bundle_tag = tag.clone();
    let bundle_path = path.clone();
    super::cas::save_single_cas_entry(
        shared_api_client,
        workspace,
        tag,
        path,
        force,
        "Scanning file layout",
        "File CAS scan task panicked",
        move |scan_path| {
            let scan = crate::cache::cas_file::scan_path(&scan_path, exclude)?;
            let pointer_bytes = crate::cache::cas_file::build_pointer(&scan)?;
            let manifest_root_digest =
                crate::cache::cas_file::prefixed_sha256_digest(&pointer_bytes);
            let manifest_size = pointer_bytes.len() as u64;
            let blob_count = scan.blobs.len() as u64;
            let file_count = scan
                .entries
                .iter()
                .filter(|entry| entry.entry_type == EntryType::File)
                .count()
                .min(u32::MAX as usize) as u32;
            let blob_total_size_bytes = scan.total_blob_bytes;
            let total_size_bytes = blob_total_size_bytes;
            let cas_layout = crate::adapters::AdapterDispatchKind::File
                .cas_layout(detected_kind)
                .map(str::to_string);
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
                expected_adapter: crate::adapters::CasAdapterKind::File,
                cas_layout,
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
                empty_payload_error: (total_size_bytes == 0).then(|| {
                    format!(
                        "Cannot save {} -> {}: no file content to upload (0 bytes)",
                        bundle_tag, bundle_path
                    )
                }),
            })
        },
    )
    .await
}
