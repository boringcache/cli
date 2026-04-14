use super::{RestoreOutcome, download_buffer_size};
use crate::api::{ApiClient, CacheResolutionEntry};
use crate::cache::cas_restore::{self, BlobDownloadTarget, FetchCasPointerOutcome};
use crate::progress::{ProgressSession, Summary, TransferProgress};
use crate::signing::policy::verify_restore_signature;
use crate::ui;
use anyhow::{Context, Result, anyhow};
use std::io::ErrorKind;
use std::path::Path;
use tokio::fs;

#[allow(clippy::too_many_arguments)]
pub(super) async fn process_restore_oci(
    api_client: &ApiClient,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    verbose: bool,
    require_server_signature: bool,
) -> Result<RestoreOutcome> {
    let mut session = ProgressSession::new(reporter.clone(), session_id.clone(), title, 3)?;

    let fetch_step = session.start_step("Fetch CAS index".to_string(), None)?;
    let fetched_pointer = match cas_restore::fetch_cas_pointer(
        api_client,
        &hit,
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
        cas_restore::CasPointer::Oci(pointer) => pointer,
        cas_restore::CasPointer::File(_) => unreachable!(),
    };

    let blobs_dir = Path::new(&target_path).join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)
        .await
        .with_context(|| format!("Failed to create {}", blobs_dir.display()))?;

    let mut download_targets = Vec::new();
    for blob in &pointer.blobs {
        let digest_hex = crate::cache::cas_oci::digest_hex_component(&blob.digest)
            .ok_or_else(|| anyhow!("Invalid blob digest {}", blob.digest))?;
        let blob_path = blobs_dir.join(digest_hex);
        let is_present = match fs::metadata(&blob_path).await {
            Ok(metadata) => metadata.is_file() && metadata.len() == blob.size_bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => false,
            Err(err) => {
                return Err(err).with_context(|| format!("Failed to stat {}", blob_path.display()));
            }
        };
        if !is_present {
            download_targets.push(BlobDownloadTarget {
                digest: blob.digest.clone(),
                path: blob_path,
                size_bytes: blob.size_bytes,
            });
        }
    }

    let download_step = session.start_step(
        "Download blobs".to_string(),
        Some(format!("{} missing", download_targets.len())),
    )?;
    let download_started = std::time::Instant::now();
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

    let materialize_step = session.start_step("Materialize OCI layout".to_string(), None)?;
    let materialize_started = std::time::Instant::now();
    let target = Path::new(&target_path);
    fs::create_dir_all(target)
        .await
        .with_context(|| format!("Failed to create {}", target.display()))?;
    fs::write(target.join("index.json"), pointer.index_json_bytes()?)
        .await
        .with_context(|| format!("Failed to write {}", target.join("index.json").display()))?;
    fs::write(target.join("oci-layout"), pointer.oci_layout_bytes()?)
        .await
        .with_context(|| format!("Failed to write {}", target.join("oci-layout").display()))?;
    materialize_step.complete()?;
    let materialize_elapsed = materialize_started.elapsed();

    if verbose {
        let _ = reporter.info(format!(
            "  Restored OCI CAS layout ({} blobs, {} downloaded)",
            pointer.blobs.len(),
            crate::progress::format_bytes(bytes_downloaded)
        ));
    }

    let summary = Summary {
        size_bytes: hit.blob_total_size_bytes.unwrap_or(bytes_downloaded),
        file_count: pointer.blobs.len().min(u32::MAX as usize) as u32,
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
