use super::{
    EnsureTargetStatus, RestoreOutcome, download_archive, ensure_empty_target,
    format_phase_duration, probe_archive_size,
};
use crate::api::{ApiClient, CacheResolutionEntry};
use crate::progress::{ProgressSession, Summary};
use crate::signing::policy::verify_restore_signature;
use crate::telemetry::StorageMetrics;
use crate::transfer::send_transfer_request_with_retry;
use crate::ui;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tempfile::{TempPath, tempdir};

#[allow(clippy::too_many_arguments)]
pub(super) async fn process_restore_archive(
    api_client: ApiClient,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    _workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    verbose: bool,
    identity: Option<String>,
    passphrase_cache: Arc<Mutex<crate::encryption::PassphraseCache>>,
    allow_external_symlinks: bool,
    require_server_signature: bool,
) -> Result<RestoreOutcome> {
    let client = api_client.transfer_client().clone();

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

    if hit.archive_urls.is_empty() {
        anyhow::bail!("No archive URLs in response");
    }
    let archive_url = hit.archive_urls[0].clone();

    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest URL in response"))?
        .clone();

    let total_steps = if hit.encrypted { 4 } else { 3 };
    let mut session =
        ProgressSession::new(reporter.clone(), session_id.clone(), title, total_steps)?;

    let manifest_step = session.start_step("Fetch manifest".to_string(), None)?;

    let manifest_future = send_transfer_request_with_retry("Manifest fetch", || async {
        Ok(client.get(&manifest_url).send().await?)
    });
    let archive_head_future = client.head(&archive_url).send();

    let (manifest_result, head_result) = tokio::join!(manifest_future, archive_head_future);

    let manifest_response = manifest_result?
        .error_for_status()
        .context("Manifest request failed")?;

    let (head_storage_metrics, mut actual_archive_size) = match head_result {
        Ok(resp) => {
            if !resp.status().is_success() {
                log::debug!(
                    "Archive HEAD warm failed (non-fatal): HTTP {}",
                    resp.status()
                );
                (StorageMetrics::default(), None)
            } else {
                let metrics = StorageMetrics::from_headers(resp.headers());
                let size = resp
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                (metrics, size)
            }
        }
        Err(e) => {
            log::debug!("Archive HEAD warm failed (non-fatal): {}", e);
            (StorageMetrics::default(), None)
        }
    };

    let manifest_bytes_raw = manifest_response.bytes().await?.to_vec();

    if let Some(expected_digest) = hit.manifest_digest.as_ref() {
        let actual_digest = crate::manifest::io::compute_manifest_digest(&manifest_bytes_raw);
        if expected_digest != &actual_digest {
            let reason = format!(
                "Manifest bytes digest mismatch for {} (expected {}, got {})",
                hit.tag, expected_digest, actual_digest
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            session.error(reason.clone())?;
            return Ok(RestoreOutcome::Ignored {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }
    let manifest_encrypted = crate::encryption::is_age_encrypted(&manifest_bytes_raw);
    let age_identity = if hit.encrypted || manifest_encrypted {
        crate::encryption::load_identity_for_decryption(identity.as_ref())?
    } else {
        None
    };

    let manifest_payload = if manifest_encrypted {
        let cached_passphrase = crate::encryption::cached_passphrase(&passphrase_cache)?;
        let decrypt_result = crate::encryption::decrypt_bytes(
            &manifest_bytes_raw,
            age_identity.as_ref(),
            cached_passphrase.as_deref(),
        );
        match decrypt_result {
            Ok(bytes) => bytes,
            Err(err) if crate::encryption::is_passphrase_required(&err) => {
                let passphrase = crate::encryption::get_or_prompt_passphrase(
                    &passphrase_cache,
                    "Age passphrase (leave blank to skip): ",
                )?;
                let passphrase_ref = passphrase.as_deref();
                if passphrase_ref.is_none() {
                    return Err(err);
                }
                crate::encryption::decrypt_bytes(
                    &manifest_bytes_raw,
                    age_identity.as_ref(),
                    passphrase_ref,
                )?
            }
            Err(err) => return Err(err),
        }
    } else {
        manifest_bytes_raw
    };

    let manifest_bytes = crate::manifest::io::decompress_manifest_if_needed(&manifest_payload)?;

    let manifest: crate::manifest::Manifest =
        ciborium::from_reader(&manifest_bytes[..]).context("Failed to parse manifest")?;
    manifest_step.complete()?;

    if let Some(expected_digest) = hit.manifest_root_digest.as_ref()
        && expected_digest != &manifest.root.digest
    {
        let reason = format!(
            "Manifest digest mismatch for {} (expected {}, got {})",
            hit.tag, expected_digest, manifest.root.digest
        );
        let _ = reporter.warning(reason.clone());
        ui::warn(&reason);
        session.error(reason.clone())?;
        return Ok(RestoreOutcome::Ignored {
            tag: hit.tag.clone(),
            reason,
        });
    }

    verify_restore_signature(
        &hit,
        &manifest.root.digest,
        Some(manifest.tag.as_str()),
        verbose,
        Some(&reporter),
        require_server_signature,
    )?;

    if actual_archive_size.is_none() && hit.compressed_size.is_none() {
        actual_archive_size = probe_archive_size(&client, &archive_url).await;
    }

    let total_uncompressed = manifest.summary.raw_size;
    let expected_compressed = actual_archive_size.or(hit.compressed_size).unwrap_or(0);

    let download_detail = if expected_compressed > 0 {
        Some(format!(
            "[archive, {}]",
            crate::progress::format_bytes(expected_compressed)
        ))
    } else {
        None
    };
    let download_step = session.start_step("Download archive".to_string(), download_detail)?;
    let download_step_number = download_step.step_number();

    let progress = if expected_compressed > 0 {
        Some(crate::progress::TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            download_step_number,
            expected_compressed,
        ))
    } else {
        None
    };

    let stage_start = Instant::now();

    let temp_dir = tempdir().context("Failed to create temporary directory for restore")?;
    let archive_file_path = temp_dir
        .path()
        .join(format!("boringcache-{}.tar.zst", hit.tag));

    let archive_size = expected_compressed;

    if let Some(ref region) = head_storage_metrics.region {
        log::info!("Tigris storage region: {}", region);
    }
    if let Some(ref cache_status) = head_storage_metrics.cache_status {
        log::info!("Tigris cache status: {}", cache_status);
    }
    if let Some(ref block_loc) = head_storage_metrics.block_location {
        log::info!("Tigris block location: {}", block_loc);
    }

    log::debug!(
        "Archive size: expected_compressed={}, actual_from_head={}",
        expected_compressed,
        archive_size
    );

    let (bytes_downloaded, download_storage_metrics) = download_archive(
        &client,
        &archive_url,
        &archive_file_path,
        archive_size,
        progress.as_ref(),
    )
    .await
    .context("Archive download failed")?;

    if let Some(expected_archive_digest) = manifest
        .archive
        .as_ref()
        .and_then(|archive| archive.content_hash.as_ref())
    {
        let actual_archive_digest = tokio::task::spawn_blocking({
            let archive_path = archive_file_path.clone();
            move || crate::cache::archive::compute_archive_digest(&archive_path)
        })
        .await
        .context("Archive digest task failed")??;

        if expected_archive_digest != &actual_archive_digest {
            let reason = format!(
                "Archive bytes digest mismatch for {} (expected {}, got {})",
                hit.tag, expected_archive_digest, actual_archive_digest
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            session.error(reason.clone())?;
            return Ok(RestoreOutcome::Ignored {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }

    let download_elapsed = stage_start.elapsed();
    download_step.complete()?;

    let decrypted_temp_path: Option<TempPath>;
    let final_archive_path: PathBuf = if hit.encrypted || manifest.encryption.is_some() {
        let decrypt_step = session.start_step("Decrypting archive".to_string(), None)?;

        let cached_passphrase = crate::encryption::cached_passphrase(&passphrase_cache)?;
        let decrypt_result = tokio::task::spawn_blocking({
            let archive_path = archive_file_path.clone();
            let passphrase = cached_passphrase.clone();
            let age_identity = age_identity.clone();
            move || {
                crate::cache::archive::decrypt_archive(
                    &archive_path,
                    age_identity.as_ref(),
                    passphrase.as_deref(),
                )
            }
        })
        .await
        .context("Decryption task failed")?;

        let decrypted_path = match decrypt_result {
            Ok(path) => path,
            Err(err) if crate::encryption::is_passphrase_required(&err) => {
                let passphrase = crate::encryption::get_or_prompt_passphrase(
                    &passphrase_cache,
                    "Age passphrase (leave blank to skip): ",
                )?;
                let passphrase_ref = passphrase.as_deref();
                if passphrase_ref.is_none() {
                    return Err(err);
                }
                let decrypt_retry = tokio::task::spawn_blocking({
                    let archive_path = archive_file_path.clone();
                    let passphrase = passphrase.clone();
                    let age_identity = age_identity.clone();
                    move || {
                        crate::cache::archive::decrypt_archive(
                            &archive_path,
                            age_identity.as_ref(),
                            passphrase.as_deref(),
                        )
                    }
                })
                .await
                .context("Decryption task failed")?;
                decrypt_retry?
            }
            Err(err) => return Err(err),
        };

        if verbose {
            let encrypted_size = std::fs::metadata(&archive_file_path)?.len();
            let decrypted_size = std::fs::metadata::<&Path>(decrypted_path.as_ref())?.len();
            let _ = reporter.info(format!(
                "  Decrypted archive: {} → {}",
                crate::progress::format_bytes(encrypted_size),
                crate::progress::format_bytes(decrypted_size)
            ));
        }

        decrypt_step.complete()?;
        let path = decrypted_path.to_path_buf();
        decrypted_temp_path = Some(decrypted_path);
        path
    } else {
        decrypted_temp_path = None;
        archive_file_path.clone()
    };

    let total_files = manifest.files.len() as u64;
    let extract_step = session.start_step(
        "Extract archive".to_string(),
        Some(format!("{} files", total_files)),
    )?;
    let extract_step_number = extract_step.step_number();
    let extract_start = Instant::now();

    let extract_reporter = reporter.clone();
    let extract_session_id = session_id.clone();
    let progress_callback: std::sync::Arc<dyn Fn(u64) + Send + Sync> =
        std::sync::Arc::new(move |files_extracted| {
            let progress = files_extracted as f64 / total_files as f64;
            let detail = format!("{} / {} files", files_extracted, total_files);
            let _ = extract_reporter.step_progress(
                extract_session_id.clone(),
                extract_step_number,
                progress,
                Some(detail),
            );
        });

    let extraction_result = crate::cache::archive::extract_tar_archive(
        &final_archive_path,
        Path::new(&target_path),
        verbose,
        allow_external_symlinks,
        Some(progress_callback),
    )
    .await;

    drop(decrypted_temp_path);

    match extraction_result {
        Ok(()) => {
            crate::manifest::ManifestApplier::apply(&manifest, Path::new(&target_path)).await?;
            extract_step.complete()?;
            drop(temp_dir);

            let extract_elapsed = extract_start.elapsed();
            let total_duration = download_elapsed + extract_elapsed;
            let total_secs = total_duration.as_secs_f64().max(0.001);
            let compression_pct = if total_uncompressed > 0 && bytes_downloaded > 0 {
                (bytes_downloaded as f64 / total_uncompressed as f64) * 100.0
            } else {
                100.0
            };

            let download_secs = download_elapsed.as_secs_f64().max(0.001);
            let download_speed = (bytes_downloaded as f64 / 1_000_000.0) / download_secs;

            let summary_line = format!(
                "Restored {} → {} ({:.0}% of original) in {:.1}s (download: {:.1} MB/s, extract: {})",
                crate::progress::format_bytes(total_uncompressed),
                crate::progress::format_bytes(bytes_downloaded),
                compression_pct,
                total_secs,
                download_speed,
                format_phase_duration(extract_elapsed),
            );
            let _ = reporter.info(summary_line);

            if verbose {
                let mut storage_info = Vec::new();
                if let Some(ref region) = download_storage_metrics.region {
                    storage_info.push(format!("region={}", region));
                }
                if let Some(ref cache_status) = download_storage_metrics.cache_status {
                    storage_info.push(format!("cache={}", cache_status));
                }
                if let Some(ref block_loc) = download_storage_metrics.block_location {
                    storage_info.push(format!("block={}", block_loc));
                }
                if !storage_info.is_empty() {
                    let _ = reporter.info(format!("  Storage: {}", storage_info.join(", ")));
                }
            }

            let summary = Summary {
                size_bytes: bytes_downloaded,
                file_count: manifest.files.len() as u32,
                digest: hit.content_hash.clone(),
                path: Some(target_path),
            };

            session.complete(summary)?;

            let download_duration_ms = download_elapsed.as_millis() as u64;
            let extract_duration_ms = extract_start.elapsed().as_millis() as u64;
            let total_duration_ms = download_duration_ms + extract_duration_ms;

            Ok(RestoreOutcome::Restored {
                tag: hit.tag.clone(),
                manifest_root_digest: hit.manifest_root_digest.clone(),
                storage_metrics: download_storage_metrics,
                total_duration_ms,
                download_duration_ms,
                extract_duration_ms,
                bytes_downloaded,
            })
        }
        Err(e) => {
            session.error(e.to_string())?;
            Err(e)
        }
    }
}
