use anyhow::{anyhow, Context, Error, Result};
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::task;
use tokio::time::sleep;

use crate::api::models::cache::{
    CompleteMultipartRequest, ConfirmRequest, ManifestCheckRequest, SaveRequest,
};
use crate::api::ApiClient;
use crate::archive::{create_tar_archive, TarArchiveInfo};
use crate::manifest::diff::compute_digest_from_draft;
use crate::manifest::{EntryType, ManifestBuilder, ManifestFile};
use crate::multipart_upload::{upload_via_part_urls, upload_via_single_url};
use crate::progress::{
    format_bytes, ProgressSession, Summary, System as ProgressSystem, TransferProgress,
};
use crate::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaveStatus {
    AlreadyExists,
    Uploaded,
}

pub async fn execute_batch_save(
    workspace: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    force: bool,
) -> Result<()> {
    let workspace = workspace.context("Workspace is required")?;
    crate::api::parse_workspace_slug(&workspace)?;
    let api_client = ApiClient::new()?;

    let parsed_pairs: Vec<crate::commands::utils::SaveSpec> = tag_path_pairs
        .into_iter()
        .map(|pair| crate::commands::utils::parse_save_format(&pair).map_err(Error::from))
        .collect::<Result<_, _>>()?;

    let mut skipped_paths = 0usize;

    let platform = if no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };

    let mut prepared_entries: Vec<(String, String)> = Vec::new();

    for crate::commands::utils::SaveSpec {
        tag: base_tag,
        path,
    } in parsed_pairs
    {
        crate::tag_utils::validate_tag(&base_tag)?;
        let tag =
            crate::tag_utils::apply_platform_to_tag_with_instance(&base_tag, platform.as_ref());
        crate::tag_utils::validate_tag(&tag)?;
        let expanded_path = crate::commands::utils::expand_tilde_path(&path);

        let path_obj = std::path::Path::new(&expanded_path);
        if !path_obj.exists() {
            if path != expanded_path {
                ui::warn(&format!(
                    "Skipping {} -> {} (expanded from {}) (path not found)",
                    tag, expanded_path, path
                ));
            } else {
                ui::warn(&format!(
                    "Skipping {} -> {} (path not found)",
                    tag, expanded_path
                ));
            }
            skipped_paths += 1;
            continue;
        }

        prepared_entries.push((tag, expanded_path));
    }

    let attempted_saves = prepared_entries.len();

    if attempted_saves == 0 {
        if skipped_paths > 0 {
            anyhow::bail!("No valid paths found to save");
        } else {
            return Ok(());
        }
    }

    let total_entries = attempted_saves;
    let mut successful_saves = 0usize;
    let mut failed_attempts = 0usize;
    let mut errors: Vec<anyhow::Error> = Vec::new();

    for (position, (tag, expanded_path)) in prepared_entries.into_iter().enumerate() {
        match save_single_entry(
            api_client.clone(),
            workspace.clone(),
            tag.clone(),
            expanded_path.clone(),
            verbose,
            force,
            position,
            total_entries,
        )
        .await
        {
            Ok(_status) => {
                successful_saves += 1;
            }
            Err(err) => {
                failed_attempts += 1;
                errors.push(err.context(format!("Failed to save {}", tag)));
            }
        }
    }

    log::debug!(
        "Completed save command for workspace={} attempted={} succeeded={} skipped_paths={}",
        workspace,
        attempted_saves,
        successful_saves,
        skipped_paths
    );

    if attempted_saves > 0 {
        ui::workflow_summary("saved", successful_saves, attempted_saves, &workspace);
        if skipped_paths > 0 {
            ui::warn(&format!(
                "Skipped {} entr{} due to missing paths",
                skipped_paths,
                if skipped_paths == 1 { "y" } else { "ies" }
            ));
        }
    }

    if !errors.is_empty() {
        let message = errors
            .into_iter()
            .map(|err| format!("{:#}", err))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(message);
    }

    if failed_attempts > 0 {
        anyhow::bail!(
            "Failed to save {} of {} cache entr{}",
            failed_attempts,
            attempted_saves,
            if attempted_saves == 1 { "y" } else { "ies" }
        );
    }

    if verbose && successful_saves > 0 {
        ui::info(&format!(
            "Successfully saved {} entr{}",
            successful_saves,
            if successful_saves == 1 { "y" } else { "ies" }
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn save_single_entry(
    api_client: ApiClient,
    workspace: String,
    tag: String,
    path: String,
    verbose: bool,
    force: bool,
    entry_index: usize,
    total_entries: usize,
) -> Result<SaveStatus> {
    ui::info(&format!(
        "\nSaving ({}/{}) {} -> {}",
        entry_index + 1,
        total_entries,
        tag,
        path
    ));
    log::debug!(
        "Starting save {} of {} for tag={} path={} workspace={}",
        entry_index + 1,
        total_entries,
        tag,
        path,
        workspace
    );

    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();
    let session_id = format!("save-{}", tag);
    let mut session = ProgressSession::new(
        reporter.clone(),
        session_id.clone(),
        format!("Saving {}", tag),
        6,
    )?;
    let overall_started = Instant::now();
    let mut upload_duration: Option<Duration> = None;

    let step1 = session.start_step("Building manifest".to_string(), None)?;
    let path_buf = PathBuf::from(&path);
    let draft = task::spawn_blocking(move || {
        let builder = ManifestBuilder::new(&path_buf);
        builder.build()
    })
    .await
    .context("Manifest build task panicked")??;
    step1.complete()?;

    let manifest_root_digest = compute_digest_from_draft(&draft);
    let file_count = draft
        .descriptors
        .iter()
        .filter(|d| d.entry_type == EntryType::File)
        .count() as u32;
    let total_size_bytes = draft.raw_size;

    let check_step = session.start_step("Checking cache".to_string(), None)?;
    let check_response = api_client
        .check_manifests(
            &workspace,
            &[ManifestCheckRequest {
                tag: tag.clone(),
                manifest_root_digest: manifest_root_digest.clone(),
            }],
        )
        .await;

    let mut cache_exists = false;
    match check_response {
        Ok(response) => {
            if let Some(result) = response.results.first() {
                if result.exists {
                    cache_exists = true;
                    check_step.update_progress(100.0, Some("cache hit".to_string()))?;
                }
            }
        }
        Err(err) => {
            let err_string = err.to_string();
            if err_string.contains("Authentication failed") || err_string.contains("Cannot connect")
            {
                check_step.complete()?;
                session.error(err.to_string())?;
                drop(reporter);
                progress_system.shutdown()?;
                return Err(err);
            }
            ui::warn(&format!("  Check failed ({}); proceeding", err));
        }
    }
    check_step.complete()?;

    if cache_exists && !force {
        ui::info("  Cache exists; skipping");
        complete_skipped_step(&mut session, "Creating archive", "skipped — cache exists")?;
        complete_skipped_step(
            &mut session,
            "Creating cache entry",
            "skipped — cache exists",
        )?;
        complete_skipped_step(&mut session, "Uploading archive", "skipped — cache exists")?;
        complete_skipped_step(&mut session, "Confirming upload", "skipped — cache exists")?;

        let summary = Summary {
            size_bytes: total_size_bytes,
            file_count,
            digest: Some(manifest_root_digest),
            path: Some(path),
        };
        session.complete(summary)?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(SaveStatus::AlreadyExists);
    }

    let archive_step = session.start_step("Creating archive".to_string(), None)?;
    let archive_started = Instant::now();

    let reporter_clone = reporter.clone();
    let session_id_clone = session_id.clone();
    let step_number = archive_step.step_number();

    let progress_callback = Box::new(move |processed: usize, total: usize| {
        let percent = if total > 0 {
            (processed as f64 / total as f64 * 100.0).min(100.0)
        } else {
            0.0
        };
        let detail = format!("{}/{} files", processed, total);
        let _ = reporter_clone.step_progress(
            session_id_clone.clone(),
            step_number,
            percent,
            Some(detail),
        );
    });

    let archive_info: TarArchiveInfo =
        match create_tar_archive(&draft, path.as_str(), verbose, Some(progress_callback)).await {
            Ok(info) => info,
            Err(err) => {
                log::error!(
                    "Archive creation failed for tag={} path={}: {}",
                    tag,
                    path,
                    err
                );
                archive_step.complete()?;
                session.error(format!("Archive creation failed: {}", err))?;
                drop(reporter);
                progress_system.shutdown()?;
                return Err(err.context(format!("Failed to create archive for {}", tag)));
            }
        };

    let archive_duration = archive_started.elapsed();
    archive_step.complete()?;

    let file_count = draft.entry_count as u32;
    let total_size_bytes = draft.raw_size;
    let all_manifest_files = archive_info.manifest_files;
    let total_uncompressed_size = archive_info.uncompressed_size;
    let total_compressed_size = archive_info.compressed_size;

    let manifest_files_combined: Vec<ManifestFile> = all_manifest_files;

    let manifest_bytes = serialize_manifest(&tag, &manifest_root_digest, &manifest_files_combined)?;
    let expected_manifest_digest = compute_manifest_digest(&manifest_bytes);
    let expected_manifest_size = manifest_bytes.len() as u64;

    let use_multipart = crate::archive::should_use_multipart_upload(total_compressed_size);

    let request = SaveRequest {
        tag: tag.clone(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: Some(total_uncompressed_size),
        compressed_size: Some(total_compressed_size),
        file_count: Some(file_count),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(expected_manifest_size),
        force: if force { Some(true) } else { None },
        use_multipart: Some(use_multipart),
    };

    let create_step = session.start_step(
        "Creating cache entry".to_string(),
        Some("1 archive".to_string()),
    )?;

    let save_response;
    let mut create_attempt = 0u32;
    let max_conflict_retries = 3u32;

    loop {
        let create_result = api_client.save_entry(&workspace, &request).await;

        match create_result {
            Ok(response) => {
                save_response = response;
                break;
            }
            Err(err) => {
                let retryable_message = err
                    .downcast_ref::<crate::error::BoringCacheError>()
                    .and_then(|bc_err| match bc_err {
                        crate::error::BoringCacheError::CachePending => {
                            Some("Another job is uploading this cache".to_string())
                        }
                        crate::error::BoringCacheError::CacheConflict(message) => {
                            Some(message.clone())
                        }
                        _ => None,
                    });

                if let Some(message) = retryable_message {
                    if create_attempt < max_conflict_retries {
                        let delay_ms = 500 * 2u64.pow(create_attempt);
                        let delay = Duration::from_millis(delay_ms);
                        create_attempt += 1;
                        ui::info(&format!(
                            "  {message}; retrying in {:.2}s (attempt {}/{})",
                            delay.as_secs_f64(),
                            create_attempt,
                            max_conflict_retries + 1
                        ));
                        sleep(delay).await;
                        continue;
                    }

                    create_step.complete()?;
                    ui::info(&format!(
                        "  {message}; treating as already uploading after retries"
                    ));
                    complete_skipped_step(
                        &mut session,
                        "Uploading archive",
                        "skipped — another job is uploading",
                    )?;
                    complete_skipped_step(
                        &mut session,
                        "Uploading manifest",
                        "skipped — another job is uploading",
                    )?;
                    complete_skipped_step(
                        &mut session,
                        "Confirming upload",
                        "skipped — another job is uploading",
                    )?;

                    let summary = Summary {
                        size_bytes: total_size_bytes,
                        file_count,
                        digest: Some(manifest_root_digest.clone()),
                        path: Some(path.clone()),
                    };
                    session.complete(summary)?;
                    drop(reporter);
                    progress_system.shutdown()?;
                    return Ok(SaveStatus::AlreadyExists);
                }

                create_step.complete()?;
                session.error(err.to_string())?;
                drop(reporter);
                progress_system.shutdown()?;
                return Err(err);
            }
        }
    }
    create_step.complete()?;

    let archive_urls = save_response.get_archive_urls();
    let needs_upload = !archive_urls.is_empty();

    log::debug!(
        "Server accepted cache entry tag={} exists={} archive_urls={}",
        tag,
        save_response.exists,
        archive_urls.len()
    );

    if save_response.exists {
        // Content already exists - piggyback on existing upload by binding our tag
        complete_skipped_step(
            &mut session,
            "Uploading archive",
            "skipped — server reports entry already exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading manifest",
            "skipped — server reports entry already exists",
        )?;

        // Still call confirm to bind our tag to the existing entry
        let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
        let piggyback_confirm_request = ConfirmRequest {
            manifest_digest: expected_manifest_digest.clone(),
            manifest_size: manifest_bytes.len() as u64,
            manifest_etag: None,
            archive_size: archive_info.compressed_size,
            archive_etag: None,
            file_count: Some(file_count),
            uncompressed_size: Some(archive_info.uncompressed_size),
            compressed_size: Some(archive_info.compressed_size),
            tag: Some(tag.clone()),
        };

        let piggyback_confirm_response = api_client
            .confirm(
                &workspace,
                &save_response.cache_entry_id,
                &piggyback_confirm_request,
            )
            .await
            .with_context(|| format!("Failed to confirm piggybacked upload for {}", tag))?;

        // Handle tag_status response
        match piggyback_confirm_response.tag_status.as_deref() {
            Some("ready") => {
                log::debug!("Tag {} bound synchronously", tag);
            }
            Some("pending") => {
                ui::info("  Tag will be bound when upload completes");
                log::debug!("Tag {} binding deferred until upload completes", tag);
            }
            Some(status) => {
                log::debug!("Tag {} binding status: {}", tag, status);
            }
            None => {
                log::debug!("No tag_status in confirm response for {}", tag);
            }
        }

        confirm_step.complete()?;

        let summary = Summary {
            size_bytes: total_size_bytes,
            file_count,
            digest: Some(manifest_root_digest.clone()),
            path: Some(path.clone()),
        };
        session.complete(summary)?;
        drop(reporter);
        progress_system.shutdown()?;
        ui::info(&format!(
            "Completed saving {} ({} files, {})",
            tag,
            file_count,
            format_bytes(total_size_bytes)
        ));
        ui::info(&format!("    Path: {}", path));
        return Ok(SaveStatus::AlreadyExists);
    }

    ui::info(&format!(
        "  Backend response: {} archive total, {} needs upload ({} exists)",
        1,
        if needs_upload { 1 } else { 0 },
        if needs_upload { 0 } else { 1 },
    ));

    let cache_entry_id = &save_response.cache_entry_id;
    let mut archive_etag: Option<String> = None;

    if !needs_upload {
        complete_skipped_step(
            &mut session,
            "Uploading archive",
            "skipped — archive already exists",
        )?;
        ui::info("  Archive already present on server; skipping upload");
    } else {
        let step6 = session.start_step(
            "Uploading archive".to_string(),
            Some(format!(
                "1 archive ({})",
                crate::progress::format_bytes(total_compressed_size)
            )),
        )?;
        let upload_step_number = step6.step_number();

        let progress = TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            upload_step_number,
            total_compressed_size,
        );
        progress.record_bytes(0)?;

        let upload_started = Instant::now();

        let is_multipart = save_response.get_upload_id().is_some();

        if is_multipart {
            let upload_id = save_response.get_upload_id().unwrap();

            log::info!(
                "Using multipart upload: {} parts, upload_id={}",
                archive_urls.len(),
                upload_id
            );
            if verbose {
                ui::info(&format!(
                    "  Using multipart upload with {} parts",
                    archive_urls.len()
                ));
            }

            archive_etag = upload_archive_multipart(
                archive_info.archive_path.as_ref(),
                archive_urls,
                upload_id,
                &progress,
                api_client.transfer_client(),
                &api_client,
                &workspace,
                cache_entry_id,
            )
            .await
            .with_context(|| format!("Failed to upload archive parts for {}", tag))?;
        } else {
            log::info!("Using single-part upload");
            archive_etag = upload_archive_file(
                archive_info.archive_path.as_ref(),
                &archive_urls[0],
                &progress,
                api_client.transfer_client(),
            )
            .await
            .with_context(|| format!("Failed to upload archive for {}", tag))?;
        }

        upload_duration = Some(upload_started.elapsed());
        step6.complete()?;

        let compression_ratio_percent = if total_uncompressed_size > 0 {
            total_compressed_size as f64 / total_uncompressed_size as f64 * 100.0
        } else {
            0.0
        };
        ui::info(&format!(
            "info: Uploaded {} → {} ({:.1}% of original)",
            crate::progress::format_bytes(total_uncompressed_size),
            crate::progress::format_bytes(total_compressed_size),
            compression_ratio_percent
        ));
    }

    let manifest_step = session.start_step("Uploading manifest".to_string(), None)?;
    let manifest_etag = upload_manifest(
        api_client.transfer_client(),
        save_response
            .manifest_upload_url
            .as_ref()
            .ok_or_else(|| anyhow!("Missing manifest_upload_url in response"))?,
        &manifest_bytes,
    )
    .await?;
    manifest_step.complete()?;

    let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
    let confirm_request = ConfirmRequest {
        manifest_digest: expected_manifest_digest.clone(),
        manifest_size: manifest_bytes.len() as u64,
        manifest_etag,
        archive_size: archive_info.compressed_size,
        archive_etag,
        file_count: Some(file_count),
        uncompressed_size: Some(archive_info.uncompressed_size),
        compressed_size: Some(archive_info.compressed_size),
        tag: None, // Tag already bound via save API for full uploads
    };

    let confirm_response = api_client
        .confirm(&workspace, cache_entry_id, &confirm_request)
        .await
        .with_context(|| format!("Failed to confirm upload for {}", tag))?;
    if let Some(winner_id) = confirm_response
        .cache_entry_id
        .as_deref()
        .filter(|winner| *winner != cache_entry_id)
    {
        ui::info(&format!(
            "  Cache already confirmed as entry {}; using existing entry",
            winner_id
        ));
    }
    confirm_step.complete()?;

    let summary = Summary {
        size_bytes: total_size_bytes,
        file_count,
        digest: Some(manifest_root_digest.clone()),
        path: Some(path.clone()),
    };
    session.complete(summary)?;
    drop(reporter);
    progress_system.shutdown()?;
    ui::info(&format!(
        "Completed saving {} ({} files, {})",
        tag,
        file_count,
        format_bytes(total_size_bytes)
    ));
    ui::info(&format!("    Path: {}", path));

    let total_elapsed = overall_started.elapsed();
    let archive_ms = archive_duration.as_millis();
    let upload_ms = upload_duration.map(|d| d.as_millis()).unwrap_or(0);
    log::debug!(
        "save timing tag={} archive_ms={} upload_ms={} total_ms={}",
        tag,
        archive_ms,
        upload_ms,
        total_elapsed.as_millis()
    );

    Ok(SaveStatus::Uploaded)
}

fn complete_skipped_step(session: &mut ProgressSession, title: &str, detail: &str) -> Result<()> {
    let step = session.start_step(title.to_string(), Some(detail.to_string()))?;
    step.complete()?;
    Ok(())
}

async fn upload_manifest(
    client: &reqwest::Client,
    url: &str,
    data: &[u8],
) -> Result<Option<String>> {
    let response = client
        .put(url)
        .header("Content-Type", "application/cbor")
        .header("Content-Length", data.len().to_string())
        .timeout(std::time::Duration::from_secs(300))
        .body(data.to_vec())
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to send manifest upload request: {} (URL: {})",
                e,
                url
            )
        })?;

    let status = response.status();
    let headers = response.headers().clone();

    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_else(|_| "Unable to read response body".to_string());
        anyhow::bail!("Failed to upload manifest: HTTP {} - {}", status, body);
    }

    let etag = headers
        .get("etag")
        .and_then(|e| e.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());

    if etag.is_some() {
        log::debug!("Manifest uploaded with ETag: {:?}", etag);
    } else {
        log::warn!("Manifest upload response missing ETag header");
    }

    Ok(etag)
}

fn compute_manifest_digest(manifest_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(manifest_bytes);
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn serialize_manifest(tag: &str, root_digest: &str, files: &[ManifestFile]) -> Result<Vec<u8>> {
    let manifest = crate::manifest::Manifest {
        format_version: 1,
        tag: tag.to_string(),
        root: crate::manifest::ManifestRoot {
            digest: root_digest.to_string(),
            algo: "sha256".to_string(),
        },
        summary: crate::manifest::ManifestSummary {
            file_count: files.len() as u64,
            raw_size: files.iter().map(|f| f.size).sum(),
            changed_count: files.len() as u64,
            removed_count: 0,
        },
        entry: None,
        archive: None,
        files: files.to_vec(),
    };

    let mut buffer = Vec::new();
    ciborium::into_writer(&manifest, &mut buffer).context("Failed to serialize manifest")?;
    Ok(buffer)
}

async fn upload_archive_file(
    archive_path: &std::path::Path,
    upload_url: &str,
    progress: &TransferProgress,
    transfer_client: &reqwest::Client,
) -> Result<Option<String>> {
    log::debug!(
        "Starting archive upload: path={} url={}",
        archive_path.display(),
        upload_url
    );

    upload_via_single_url(archive_path, upload_url, progress, transfer_client).await
}

#[allow(clippy::too_many_arguments)]
async fn upload_archive_multipart(
    archive_path: &std::path::Path,
    part_urls: &[String],
    upload_id: &str,
    progress: &TransferProgress,
    transfer_client: &reqwest::Client,
    api_client: &ApiClient,
    workspace: &str,
    cache_entry_id: &str,
) -> Result<Option<String>> {
    log::info!(
        "Starting multipart archive upload: path={} parts={} upload_id={}",
        archive_path.display(),
        part_urls.len(),
        upload_id
    );

    let uploaded_parts =
        upload_via_part_urls(archive_path, part_urls, progress, transfer_client).await?;

    let response = api_client
        .complete_multipart(
            workspace,
            cache_entry_id,
            &CompleteMultipartRequest {
                upload_id: upload_id.to_string(),
                parts: uploaded_parts,
            },
        )
        .await
        .context("Failed to finalize multipart upload")?;

    Ok(Some(response.archive_etag))
}

#[cfg(test)]
mod tests {}
