use super::{EnsureTargetStatus, RestoreOutcome, download_buffer_size, ensure_empty_target};
use crate::api::{ApiClient, CacheResolutionEntry};
use crate::cache::cas_restore::{self, BlobDownloadTarget, FetchCasPointerOutcome};
use crate::progress::{ProgressSession, Summary, TransferProgress};
use crate::signing::policy::verify_restore_signature;
use crate::ui;
use anyhow::{Context, Result, anyhow};
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::tempdir;
use tokio::fs;

#[allow(clippy::too_many_arguments)]
pub(super) async fn process_restore_pkg(
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
        EnsureTargetStatus::Occupied {
            existing_path,
            blocking_path,
        } => {
            let reason = format!(
                "Restore target '{}' is not empty (found '{}'); skipping restore for {}",
                existing_path, blocking_path, hit.tag
            );
            let _ = reporter.warning(reason.clone());
            return Ok(RestoreOutcome::Skipped {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }

    let mut session = ProgressSession::new(reporter.clone(), session_id.clone(), title, 3)?;

    let fetch_step = session.start_step("Fetch package CAS index".to_string(), None)?;
    let fetched_pointer = match cas_restore::fetch_cas_pointer(
        api_client,
        &hit,
        crate::adapters::CasAdapterKind::Pkg,
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
    let pointer = match *fetched_pointer.pointer {
        cas_restore::CasPointer::Pkg(pointer) => pointer,
        cas_restore::CasPointer::Oci(_) | cas_restore::CasPointer::File(_) => unreachable!(),
    };

    if let Some(reason) = platform_mismatch_reason(&pointer) {
        let _ = reporter.warning(reason.clone());
        ui::warn(&reason);
        session.error(reason.clone())?;
        return Ok(RestoreOutcome::Ignored {
            tag: hit.tag.clone(),
            reason,
        });
    }

    let tmp_dir = tempdir().context("Failed to create package CAS download temp directory")?;
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
        "Download package blobs".to_string(),
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

    let materialize_step = session.start_step("Materialize packages".to_string(), None)?;
    let materialize_started = std::time::Instant::now();
    crate::cache::cas_pkg::materialize_pkg_cas_entries(
        std::path::Path::new(&target_path),
        &pointer,
        &blob_path_by_digest,
        allow_external_symlinks,
    )
    .await?;
    materialize_step.complete()?;
    let materialize_elapsed = materialize_started.elapsed();

    if verbose {
        let _ = reporter.info(format!(
            "  Restored package CAS layout ({} packages, {} blobs, {} downloaded)",
            pointer.packages.len(),
            pointer.blobs.len(),
            crate::progress::format_bytes(bytes_downloaded)
        ));
    }

    let summary = Summary {
        size_bytes: hit.blob_total_size_bytes.unwrap_or(bytes_downloaded),
        file_count: pointer.packages.len().min(u32::MAX as usize) as u32,
        digest: Some(resolved_manifest_root_digest.clone()),
        path: Some(target_path.clone()),
    };
    session.complete(summary)?;

    let download_duration_ms = download_elapsed.as_millis() as u64;
    let extract_duration_ms = materialize_elapsed.as_millis() as u64;
    let total_duration_ms = download_duration_ms + extract_duration_ms;

    Ok(RestoreOutcome::Restored {
        tool: crate::telemetry::canonical_tool_for_cas_layout(hit.cas_layout.as_deref())
            .to_string(),
        tag: hit.tag.clone(),
        manifest_root_digest: Some(resolved_manifest_root_digest),
        storage_metrics: Box::new(download_storage_metrics),
        total_duration_ms,
        download_duration_ms,
        extract_duration_ms,
        bytes_downloaded,
        retry_count: 0,
        archive_transfer_plan: None,
    })
}

fn platform_mismatch_reason(pointer: &crate::cache::cas_pkg::PkgPointer) -> Option<String> {
    let expected = pointer.compatibility.as_ref()?.platform.as_ref()?;
    let current = crate::platform::Platform::detect().ok()?.to_tag_suffix();
    if expected == &current {
        return None;
    }

    Some(format!(
        "Package CAS platform mismatch for {} (cache {}, current {}); skipping restore",
        pointer.ecosystem, expected, current
    ))
}
