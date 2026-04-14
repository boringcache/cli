use anyhow::{Context, Result};
use std::path::Path;
use tokio::task;

use crate::api::ApiClient;
use crate::cache::cas_restore::{self, BlobDownloadTarget, FetchCasPointerOutcome};
use crate::signing::policy::verify_restore_signature;
use crate::ui;

use super::RestoreAction;

pub(super) fn local_oci_manifest_digest(path: &Path) -> Result<Option<String>> {
    if crate::cache_adapter::detect_layout(path).kind
        != crate::cache_adapter::CacheAdapterKind::CasOci
    {
        return Ok(None);
    }

    let scan = crate::cache::cas_oci::scan_layout(path)?;
    let pointer_bytes = crate::cache::cas_oci::build_pointer(&scan)?;
    Ok(Some(crate::cache::cas_oci::prefixed_sha256_digest(
        &pointer_bytes,
    )))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn initial_restore_oci(
    api_client: &ApiClient,
    workspace: &str,
    hit: &crate::api::models::cache::CacheResolutionEntry,
    local_path: &Path,
    verbose: bool,
    force: bool,
    require_server_signature: bool,
) -> Result<RestoreAction> {
    let remote_manifest_digest = hit
        .manifest_root_digest
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest root digest in response"))?;

    if super::has_content(local_path)? {
        let local_path_buf = local_path.to_path_buf();
        let local_digest = task::spawn_blocking(move || local_oci_manifest_digest(&local_path_buf))
            .await
            .context("OCI digest task panicked")??;
        if let Some(local_digest) = local_digest {
            let local_hex = local_digest
                .strip_prefix("sha256:")
                .unwrap_or(local_digest.as_str());
            if crate::cache::cas_oci::digest_matches(remote_manifest_digest, local_hex) {
                if verbose {
                    ui::info("  Local OCI layout matches remote");
                }
                return Ok(RestoreAction::AlreadyInSync);
            }
        }

        if verbose {
            ui::info("  Local OCI layout differs from remote, will sync local changes");
        }
        return Ok(RestoreAction::LocalDiffers);
    }

    if verbose {
        ui::info("  Downloading CAS index...");
    }

    let fetched_pointer = match cas_restore::fetch_cas_pointer(
        api_client,
        hit,
        crate::adapters::CasAdapterKind::Oci,
        |hit, root_digest| {
            verify_restore_signature(
                hit,
                root_digest,
                None,
                verbose,
                None,
                require_server_signature,
            )
        },
    )
    .await?
    {
        FetchCasPointerOutcome::Ready(fetched_pointer) => fetched_pointer,
        FetchCasPointerOutcome::Ignored { reason } => {
            ui::warn(&reason);
            return Ok(RestoreAction::NoRemoteCache);
        }
    };
    let pointer = match fetched_pointer.pointer {
        cas_restore::CasPointer::Oci(pointer) => pointer,
        cas_restore::CasPointer::File(_) => unreachable!(),
    };

    if local_path.exists() && force {
        tokio::fs::remove_dir_all(local_path)
            .await
            .with_context(|| {
                format!(
                    "Failed to clear existing directory: {}",
                    local_path.display()
                )
            })?;
    }
    tokio::fs::create_dir_all(local_path)
        .await
        .with_context(|| format!("Failed to create {}", local_path.display()))?;

    let blobs_dir = local_path.join("blobs").join("sha256");
    tokio::fs::create_dir_all(&blobs_dir)
        .await
        .with_context(|| format!("Failed to create {}", blobs_dir.display()))?;

    let mut download_targets = Vec::new();
    for blob in &pointer.blobs {
        let Some(hex) = crate::cache::cas_oci::digest_hex_component(&blob.digest) else {
            anyhow::bail!("Invalid OCI digest {}", blob.digest);
        };
        let blob_path = blobs_dir.join(hex);
        let is_ready = match tokio::fs::metadata(&blob_path).await {
            Ok(metadata) => metadata.is_file() && metadata.len() == blob.size_bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => false,
            Err(err) => {
                return Err(err).with_context(|| format!("Failed to stat {}", blob_path.display()));
            }
        };
        if !is_ready {
            download_targets.push(BlobDownloadTarget {
                digest: blob.digest.clone(),
                path: blob_path,
                size_bytes: blob.size_bytes,
            });
        }
    }

    if !download_targets.is_empty() {
        cas_restore::download_blob_targets(
            api_client,
            workspace,
            hit,
            &download_targets,
            crate::progress::TransferProgress::new_noop(),
            super::CAS_BLOB_WRITER_CAPACITY,
        )
        .await?;
    }

    tokio::fs::write(local_path.join("index.json"), pointer.index_json_bytes()?)
        .await
        .with_context(|| {
            format!(
                "Failed to write {}",
                local_path.join("index.json").display()
            )
        })?;
    tokio::fs::write(local_path.join("oci-layout"), pointer.oci_layout_bytes()?)
        .await
        .with_context(|| {
            format!(
                "Failed to write {}",
                local_path.join("oci-layout").display()
            )
        })?;

    Ok(RestoreAction::Downloaded)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn sync_to_remote_oci(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
) -> Result<()> {
    let scan_path = local_path.to_path_buf();
    let scan = task::spawn_blocking(move || crate::cache::cas_oci::scan_layout(&scan_path))
        .await
        .context("OCI scan task panicked")??;

    let pointer_bytes = crate::cache::cas_oci::build_pointer(&scan)?;
    let manifest_root_digest = crate::cache::cas_oci::prefixed_sha256_digest(&pointer_bytes);
    let manifest_size = pointer_bytes.len() as u64;
    let blob_count = scan.blobs.len() as u64;
    let file_count = blob_count.min(u32::MAX as u64) as u32;
    let blob_total_size_bytes = scan.total_blob_bytes;
    let total_size_bytes =
        blob_total_size_bytes + scan.index_json.len() as u64 + scan.oci_layout.len() as u64;

    let blobs: Vec<crate::api::models::cache::BlobDescriptor> = scan
        .blobs
        .iter()
        .map(|blob| crate::api::models::cache::BlobDescriptor {
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
                crate::cache::cas_publish::BlobUploadSource {
                    path: blob.path.clone(),
                    size_bytes: blob.size_bytes,
                },
            )
        })
        .collect();

    super::cas::sync_to_remote_cas(
        api_client,
        workspace,
        base_tag,
        resolved_tag,
        verbose,
        super::cas::MountCasSyncBundle {
            expected_adapter: crate::adapters::CasAdapterKind::Oci,
            cas_layout: Some("oci-v1".to_string()),
            pointer_bytes,
            manifest_root_digest: manifest_root_digest.clone(),
            total_size_bytes,
            blobs,
            blob_sources,
            confirm_spec: crate::cache::cas_publish::CasConfirmSpec {
                manifest_digest: manifest_root_digest,
                manifest_size,
                blob_count,
                blob_total_size_bytes,
                file_count,
                tag: resolved_tag.to_string(),
            },
            success_unit: "blobs",
            success_size_bytes: blob_total_size_bytes,
            empty_payload_error: None,
        },
    )
    .await
}
