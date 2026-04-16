use super::{EnsureTargetStatus, RestoreOutcome, download_buffer_size, ensure_empty_target};
use crate::api::{ApiClient, CacheResolutionEntry};
use crate::cache::cas_restore::{self, BlobDownloadTarget, FetchCasPointerOutcome};
use crate::cache::file_materialize::materialize_file_cas_entries;
use crate::progress::{ProgressSession, Summary, TransferProgress};
use crate::signing::policy::verify_restore_signature;
use crate::ui;
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use tokio::fs;

#[allow(clippy::too_many_arguments)]
pub(super) async fn process_restore_file(
    api_client: &ApiClient,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    verbose: bool,
    allow_external_symlinks: bool,
    require_server_signature: bool,
) -> Result<RestoreOutcome> {
    match ensure_empty_target(&target_path).await? {
        EnsureTargetStatus::Ready => {}
        EnsureTargetStatus::Occupied { existing_path } => {
            let reason = format!(
                "Restore target '{}' is not empty; skipping restore for {}",
                existing_path, hit.tag
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            return Ok(RestoreOutcome::Skipped {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }

    let mut session = ProgressSession::new(reporter.clone(), session_id.clone(), title, 3)?;

    let fetch_step = session.start_step("Fetch CAS index".to_string(), None)?;
    let fetched_pointer = match cas_restore::fetch_cas_pointer(
        api_client,
        &hit,
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
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            session.error(reason.clone())?;
            return Ok(RestoreOutcome::Ignored {
                tag: hit.tag.clone(),
                reason,
            });
        }
    };
    fetch_step.complete()?;
    let resolved_manifest_root_digest = fetched_pointer.resolved_manifest_root_digest;
    let pointer = match fetched_pointer.pointer {
        cas_restore::CasPointer::File(pointer) => pointer,
        cas_restore::CasPointer::Oci(_) => unreachable!(),
    };

    let tmp_dir = tempdir().context("Failed to create CAS download temp directory")?;
    let blobs_dir = tmp_dir.path().join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)
        .await
        .with_context(|| format!("Failed to create {}", blobs_dir.display()))?;

    let mut blob_path_by_digest: HashMap<String, PathBuf> = HashMap::new();
    for blob in &pointer.blobs {
        let digest_hex = crate::cache::cas_oci::digest_hex_component(&blob.digest)
            .ok_or_else(|| anyhow!("Invalid blob digest {}", blob.digest))?;
        blob_path_by_digest.insert(blob.digest.clone(), blobs_dir.join(digest_hex));
    }

    let download_step = session.start_step(
        "Download blobs".to_string(),
        Some(format!("{} blobs", pointer.blobs.len())),
    )?;
    let download_started = std::time::Instant::now();
    let download_targets: Vec<BlobDownloadTarget> = pointer
        .blobs
        .iter()
        .map(|blob| {
            let blob_path = blob_path_by_digest
                .get(&blob.digest)
                .cloned()
                .ok_or_else(|| anyhow!("Missing destination path for blob {}", blob.digest))?;
            Ok::<BlobDownloadTarget, anyhow::Error>(BlobDownloadTarget {
                digest: blob.digest.clone(),
                path: blob_path,
                size_bytes: blob.size_bytes,
            })
        })
        .collect::<Result<_>>()?;
    let total_download_bytes = download_targets
        .iter()
        .map(|target| target.size_bytes)
        .sum::<u64>();
    let progress = TransferProgress::new(
        reporter.clone(),
        session_id.clone(),
        download_step.step_number(),
        total_download_bytes,
    );
    let download_outcome = cas_restore::download_blob_targets(
        api_client,
        &workspace,
        &hit,
        &download_targets,
        progress,
        download_buffer_size(),
    )
    .await?;
    let download_elapsed = download_started.elapsed();
    download_step.complete()?;
    let bytes_downloaded = download_outcome.bytes_downloaded;
    let download_storage_metrics = download_outcome.storage_metrics;

    let materialize_step = session.start_step("Materialize files".to_string(), None)?;
    let materialize_started = std::time::Instant::now();
    let target_root = Path::new(&target_path);
    materialize_file_cas_entries(
        target_root,
        &pointer.entries,
        &blob_path_by_digest,
        allow_external_symlinks,
    )
    .await?;

    materialize_step.complete()?;
    let materialize_elapsed = materialize_started.elapsed();

    if verbose {
        let _ = reporter.info(format!(
            "  Restored file CAS layout ({} blobs, {} downloaded)",
            pointer.blobs.len(),
            crate::progress::format_bytes(bytes_downloaded)
        ));
    }

    let file_count = pointer
        .entries
        .iter()
        .filter(|entry| entry.entry_type == crate::manifest::EntryType::File)
        .count()
        .min(u32::MAX as usize) as u32;
    let summary = Summary {
        size_bytes: hit.blob_total_size_bytes.unwrap_or(bytes_downloaded),
        file_count,
        digest: Some(resolved_manifest_root_digest.clone()),
        path: Some(target_path.clone()),
    };
    session.complete(summary)?;

    let download_duration_ms = download_elapsed.as_millis() as u64;
    let extract_duration_ms = materialize_elapsed.as_millis() as u64;
    let total_duration_ms = download_duration_ms + extract_duration_ms;

    Ok(RestoreOutcome::Restored {
        tag: hit.tag.clone(),
        manifest_root_digest: Some(resolved_manifest_root_digest),
        storage_metrics: download_storage_metrics,
        total_duration_ms,
        download_duration_ms,
        extract_duration_ms,
        bytes_downloaded,
    })
}
