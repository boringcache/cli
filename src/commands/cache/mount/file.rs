use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;
use tokio::task;

use crate::api::ApiClient;
use crate::cache::cas_restore::{self, BlobDownloadTarget, FetchCasPointerOutcome};
use crate::cache::file_materialize::materialize_file_cas_entries;
use crate::manifest::EntryType;
use crate::signing::policy::verify_restore_signature;
use crate::ui;

use super::RestoreAction;

pub(super) fn local_file_manifest_digest(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }

    let scan = crate::cache::cas_file::scan_path(path, Vec::new())?;
    let pointer_bytes = crate::cache::cas_file::build_pointer(&scan)?;
    Ok(Some(crate::cache::cas_file::prefixed_sha256_digest(
        &pointer_bytes,
    )))
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn initial_restore_file(
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
        let local_digest =
            task::spawn_blocking(move || local_file_manifest_digest(&local_path_buf))
                .await
                .context("File CAS digest task panicked")??;
        if let Some(local_digest) = local_digest {
            let local_hex = local_digest
                .strip_prefix("sha256:")
                .unwrap_or(local_digest.as_str());
            if crate::cache::cas_file::digest_matches(remote_manifest_digest, local_hex) {
                if verbose {
                    ui::info("  Local file CAS layout matches remote");
                }
                return Ok(RestoreAction::AlreadyInSync);
            }
        }

        if verbose {
            ui::info("  Local file CAS layout differs from remote, will sync local changes");
        }
        return Ok(RestoreAction::LocalDiffers);
    }

    if verbose {
        ui::info("  Downloading CAS index...");
    }

    let fetched_pointer = match cas_restore::fetch_cas_pointer(
        api_client,
        hit,
        crate::adapters::CasAdapterKind::File,
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
        cas_restore::CasPointer::File(pointer) => pointer,
        cas_restore::CasPointer::Oci(_) => unreachable!(),
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

    let temp_dir = tempfile::tempdir().context("Failed to create CAS temp directory")?;
    let blobs_dir = temp_dir.path().join("blobs").join("sha256");
    tokio::fs::create_dir_all(&blobs_dir)
        .await
        .with_context(|| format!("Failed to create {}", blobs_dir.display()))?;

    let mut destination_by_digest: HashMap<String, std::path::PathBuf> = HashMap::new();
    for blob in &pointer.blobs {
        let Some(hex) = crate::cache::cas_oci::digest_hex_component(&blob.digest) else {
            anyhow::bail!("Invalid digest {}", blob.digest);
        };
        destination_by_digest.insert(blob.digest.clone(), blobs_dir.join(hex));
    }

    let download_targets: Vec<BlobDownloadTarget> = pointer
        .blobs
        .iter()
        .map(|blob| {
            let path = destination_by_digest
                .get(&blob.digest)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Missing destination for blob {}", blob.digest))?;
            Ok::<BlobDownloadTarget, anyhow::Error>(BlobDownloadTarget {
                digest: blob.digest.clone(),
                path,
                size_bytes: blob.size_bytes,
            })
        })
        .collect::<Result<_>>()?;

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

    materialize_file_cas_entries(local_path, &pointer.entries, &destination_by_digest, false)
        .await?;

    Ok(RestoreAction::Downloaded)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn sync_to_remote_file(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    detected_kind: crate::cache_adapter::CacheAdapterKind,
) -> Result<()> {
    let scan_path = local_path.to_path_buf();
    let scan =
        task::spawn_blocking(move || crate::cache::cas_file::scan_path(&scan_path, Vec::new()))
            .await
            .context("File CAS scan task panicked")??;

    let pointer_bytes = crate::cache::cas_file::build_pointer(&scan)?;
    let manifest_root_digest = crate::cache::cas_file::prefixed_sha256_digest(&pointer_bytes);
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
            expected_adapter: crate::adapters::CasAdapterKind::File,
            cas_layout,
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
            success_unit: "files",
            success_size_bytes: blob_total_size_bytes,
            empty_payload_error: (total_size_bytes == 0).then(|| {
                format!(
                    "Cannot sync {} -> {}: no file content to upload (0 bytes)",
                    resolved_tag,
                    local_path.display()
                )
            }),
        },
    )
    .await
}
