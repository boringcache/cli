use super::SaveStatus;
use anyhow::{Result, anyhow};
use std::sync::Arc;
use tokio::sync::OnceCell;

use crate::api::ApiClient;
use crate::api::models::cache::BlobDescriptor;
use crate::cache::cas_publish::{self, BlobUploadSource};

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_single_pkg_entry(
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
    let bundle_path = path.clone();
    super::cas::save_single_cas_entry(
        shared_api_client,
        workspace,
        tag,
        path,
        force,
        "Scanning package layout",
        "Package CAS scan task panicked",
        move |scan_path| {
            let detected = crate::pkg_adapters::detect_pkg_layout(&scan_path)
                .ok_or_else(|| anyhow!("Package CAS detection no longer matches"))?;
            let compatibility = detected.adapter.compatibility(&detected.detection)?;
            let scan = crate::cache::cas_pkg::scan_packages(
                &detected.detection.install_root,
                detected.detection.ecosystem,
                compatibility,
                &detected.packages,
            )?;
            let pointer_bytes = crate::cache::cas_pkg::build_pointer(&scan)?;
            let manifest_root_digest =
                crate::cache::cas_file::prefixed_sha256_digest(&pointer_bytes);
            let manifest_size = pointer_bytes.len() as u64;
            let blob_count = scan.blobs.len() as u64;
            let package_count = scan.packages.len() as u32;
            let blob_total_size_bytes = scan.total_blob_bytes;
            let total_size_bytes = blob_total_size_bytes;
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
            let temp_dir = scan.temp_dir;

            Ok(super::cas::CasSaveBundle {
                expected_adapter: crate::adapters::CasAdapterKind::Pkg,
                cas_layout: Some("pkg-v1".to_string()),
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
                    file_count: package_count,
                    tag: bundle_tag.clone(),
                },
                empty_payload_error: (total_size_bytes == 0 || package_count == 0).then(|| {
                    format!(
                        "Cannot save {} -> {}: no package content to upload",
                        bundle_tag, bundle_path
                    )
                }),
                _temp_dir: Some(temp_dir),
            })
        },
    )
    .await
}
