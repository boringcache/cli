use super::{SaveStatus, shared_save_api_client};
use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::OnceCell;
use tokio::task;

use crate::api::ApiClient;
use crate::api::models::cache::{
    ConfirmRequest, ManifestCheckRequest, ManifestCheckResult, SaveRequest,
};
use crate::cache::archive::{TarArchiveInfo, create_tar_archive};
use crate::command_support::save_support::{
    apply_detected_ci_context, archive_cache_root_digest, build_manifest_bytes,
    complete_skipped_step, format_phase_duration, format_phase_duration_ms,
    manifest_files_from_draft, progress_info, progress_warning, upload_archive_file,
    upload_archive_multipart, upload_manifest,
};
use crate::manifest::diff::compute_digest_from_draft;
use crate::manifest::{EntryType, ManifestBuilder};
use crate::progress::{
    ProgressSession, Summary, System as ProgressSystem, TransferProgress, format_bytes,
};
use crate::telemetry::{SaveMetrics, StorageMetrics};
use crate::ui;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum ArchiveConfirmOutcome {
    Published { winner_id: Option<String> },
}

impl ArchiveConfirmOutcome {
    pub(super) fn from_response(
        cache_entry_id: &str,
        response: crate::api::models::cache::CacheConfirmResponse,
    ) -> Self {
        let winner_id = response
            .cache_entry_id
            .filter(|winner| winner.as_str() != cache_entry_id);
        Self::Published { winner_id }
    }
}

fn is_missing_multipart_upload_session_error(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<crate::cache::multipart_upload::MissingMultipartUploadSessionError>()
            .is_some()
    })
}

async fn request_fresh_multipart_upload(
    api_client: &ApiClient,
    workspace: &str,
    request: &SaveRequest,
    tag: &str,
) -> Result<crate::api::models::cache::SaveResponse> {
    let mut retry_request = request.clone();
    retry_request.force = Some(true);

    let response = api_client
        .save_entry(workspace, &retry_request)
        .await
        .with_context(|| {
            format!(
                "Failed to request a fresh multipart upload session for {}",
                tag
            )
        })?;

    if response.exists {
        anyhow::bail!(
            "Fresh multipart retry for {} unexpectedly returned an existing cache entry",
            tag
        );
    }

    if response.get_archive_urls().is_empty() {
        anyhow::bail!(
            "Fresh multipart retry for {} did not return archive upload URLs",
            tag
        );
    }

    Ok(response)
}

async fn confirm_archive_upload(
    api_client: &ApiClient,
    workspace: &str,
    cache_entry_id: &str,
    request: &ConfirmRequest,
) -> Result<ArchiveConfirmOutcome> {
    let response = api_client
        .confirm_with_retry(workspace, cache_entry_id, request)
        .await?;
    Ok(ArchiveConfirmOutcome::from_response(
        cache_entry_id,
        response,
    ))
}

pub(super) fn build_archive_manifest_checks(
    tag: &str,
    manifest_root_digest: &str,
    force: bool,
) -> Vec<ManifestCheckRequest> {
    let mut checks = Vec::with_capacity(if force { 1 } else { 2 });
    checks.push(ManifestCheckRequest {
        tag: tag.to_string(),
        manifest_root_digest: manifest_root_digest.to_string(),
        lookup: None,
    });
    if !force {
        checks.push(ManifestCheckRequest {
            tag: tag.to_string(),
            manifest_root_digest: manifest_root_digest.to_string(),
            lookup: Some("digest".to_string()),
        });
    }
    checks
}

pub(super) fn digest_existing_cache_entry_id_from_result(
    result: &ManifestCheckResult,
) -> Option<String> {
    let digest_exists = result.exists
        && result
            .status
            .as_deref()
            .map(|status| status != "pending" && status != "uploading")
            .unwrap_or(true);

    if digest_exists {
        return result.cache_entry_id.as_deref().map(str::to_string);
    }
    None
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn save_single_archive_entry(
    shared_api_client: Arc<OnceCell<ApiClient>>,
    workspace: String,
    tag: String,
    path: String,
    verbose: bool,
    force: bool,
    _entry_index: usize,
    _total_entries: usize,
    exclude: Vec<String>,
    encrypt: bool,
    recipient: Option<String>,
) -> Result<SaveStatus> {
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
    let exclude_patterns = exclude;
    let draft = task::spawn_blocking(move || {
        let builder = ManifestBuilder::new(&path_buf).with_exclude_patterns(exclude_patterns);
        builder.build()
    })
    .await
    .context("Manifest build task panicked")??;
    step1.complete()?;

    let content_root_digest = compute_digest_from_draft(&draft);
    let file_count = draft
        .descriptors
        .iter()
        .filter(|d| d.entry_type == EntryType::File)
        .count() as u32;
    let total_size_bytes = draft.raw_size;

    if total_size_bytes == 0 {
        let message = format!(
            "Cannot save {} -> {}: no file content to upload (0 bytes)",
            tag, path
        );
        session.error(message.clone())?;
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!(message);
    }

    let recipient_str = if encrypt {
        Some(
            recipient.as_deref().ok_or_else(|| {
                anyhow!(
                    "Encryption enabled but no recipient configured. Run `boringcache setup-encryption <workspace>` or pass --recipient."
                )
            })?,
        )
    } else {
        None
    };
    let age_recipient = recipient_str
        .map(crate::encryption::parse_recipient)
        .transpose()?;
    let manifest_root_digest = archive_cache_root_digest(&content_root_digest, recipient_str);

    let manifest_files = manifest_files_from_draft(&draft);
    let api_client = shared_save_api_client(shared_api_client.as_ref()).await?;

    let check_step = session.start_step("Checking cache".to_string(), None)?;
    let check_requests = build_archive_manifest_checks(&tag, &manifest_root_digest, force);
    let check_response = api_client
        .check_manifests(&workspace, &check_requests)
        .await;

    let mut cache_exists = false;
    let mut cache_pending = false;
    let mut digest_existing_cache_entry_id: Option<String> = None;
    match check_response {
        Ok(response) => {
            if let Some(result) = response.results.first()
                && result.exists
            {
                cache_exists = true;
                cache_pending = result.pending
                    || result.status.as_deref() == Some("pending")
                    || result.status.as_deref() == Some("uploading");
                let status_msg = if cache_pending {
                    "cache pending"
                } else {
                    "cache hit"
                };
                check_step.update_progress(100.0, Some(status_msg.to_string()))?;
            }
            if !force
                && !cache_exists
                && let Some(result) = response.results.get(1)
            {
                digest_existing_cache_entry_id = digest_existing_cache_entry_id_from_result(result);
            }
        }
        Err(err) => {
            if crate::error::is_connection_error(&err) {
                check_step.complete()?;
                session.error(format!("Skipped: {}", err))?;
                drop(reporter);
                progress_system.shutdown()?;
                ui::warn(&format!("Cache unavailable, skipping save: {}", err));
                return Ok(SaveStatus::AlreadyExists);
            }
            progress_warning(&reporter, format!("  Check failed ({}); proceeding", err));
        }
    }
    check_step.complete()?;

    if cache_exists && cache_pending && !force {
        progress_info(&reporter, "  Cache upload in progress; skipping wait");
    }

    if cache_exists && !force {
        progress_info(&reporter, "  Cache exists; skipping");
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

    let (final_archive_path, final_compressed_size, archive_content_hash) = if encrypt {
        let encrypt_step = session.start_step("Encrypting archive".to_string(), None)?;
        let age_recipient = age_recipient.as_ref().ok_or_else(|| {
            anyhow!(
                "Encryption enabled but no recipient configured. Run `boringcache setup-encryption <workspace>` or pass --recipient."
            )
        })?;

        let encrypted_archive = crate::cache::archive::encrypt_archive(
            archive_info.archive_path.as_ref(),
            age_recipient,
        )?;

        progress_info(
            &reporter,
            format!(
                "  Encrypted archive: {} → {}",
                crate::progress::format_bytes(archive_info.compressed_size),
                crate::progress::format_bytes(encrypted_archive.size_bytes)
            ),
        );

        encrypt_step.complete()?;
        (
            encrypted_archive.archive_path,
            encrypted_archive.size_bytes,
            encrypted_archive.content_hash,
        )
    } else {
        (
            archive_info.archive_path,
            archive_info.compressed_size,
            archive_info.content_hash.clone(),
        )
    };

    let total_uncompressed_size = archive_info.uncompressed_size;
    let total_compressed_size = final_compressed_size;
    let (manifest_bytes, expected_manifest_digest, expected_manifest_size) = build_manifest_bytes(
        &tag,
        &manifest_root_digest,
        &manifest_files,
        &archive_content_hash,
        encrypt,
        recipient_str,
        age_recipient.as_ref(),
    )?;

    if let Some(cache_entry_id) = digest_existing_cache_entry_id.as_deref() {
        progress_info(&reporter, "  Cache exists under another tag; binding");
        let confirm_request = ConfirmRequest {
            manifest_digest: expected_manifest_digest.clone(),
            manifest_size: expected_manifest_size,
            manifest_etag: None,
            archive_size: Some(0),
            archive_etag: None,
            blob_count: None,
            blob_total_size_bytes: None,
            file_count: Some(file_count),
            uncompressed_size: Some(total_size_bytes),
            compressed_size: None,
            storage_mode: Some("archive".to_string()),
            tag: Some(tag.clone()),
            write_scope_tag: None,
        };

        match api_client
            .confirm(&workspace, cache_entry_id, &confirm_request)
            .await
        {
            Ok(_) => {
                complete_skipped_step(
                    &mut session,
                    "Creating cache entry",
                    "skipped — digest exists",
                )?;
                complete_skipped_step(
                    &mut session,
                    "Uploading archive",
                    "skipped — digest exists",
                )?;
                complete_skipped_step(
                    &mut session,
                    "Confirming upload",
                    "skipped — digest exists",
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
            Err(err) => {
                progress_warning(
                    &reporter,
                    format!(
                        "  Failed to bind tag to existing cache ({}); proceeding",
                        err
                    ),
                );
            }
        }
    }

    let use_multipart = crate::cache::archive::should_use_multipart_upload(total_compressed_size);

    let mut request = SaveRequest {
        tag: tag.clone(),
        write_scope_tag: None,
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: None,
        blob_count: None,
        blob_total_size_bytes: None,
        cas_layout: None,
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: Some(total_uncompressed_size),
        compressed_size: Some(total_compressed_size),
        file_count: Some(file_count),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(expected_manifest_size),
        force: if force { Some(true) } else { None },
        use_multipart: Some(use_multipart),
        ci_provider: None,
        ci_run_uid: None,
        ci_run_attempt: None,
        ci_ref_type: None,
        ci_ref_name: None,
        ci_default_branch: None,
        ci_pr_number: None,
        ci_commit_sha: None,
        ci_run_started_at: None,
        encrypted: if encrypt { Some(true) } else { None },
        encryption_algorithm: if encrypt {
            Some(crate::encryption::ENCRYPTION_ALGORITHM_AGE_X25519.to_string())
        } else {
            None
        },
        encryption_recipient_hint: recipient_str.map(crate::encryption::recipient_hint),
    };
    apply_detected_ci_context(&mut request);

    let create_step = session.start_step(
        "Creating cache entry".to_string(),
        Some("1 archive".to_string()),
    )?;

    let mut save_response = match api_client.save_entry(&workspace, &request).await {
        Ok(response) => response,
        Err(err) => {
            let bc_error = err.downcast_ref::<crate::error::BoringCacheError>();

            if let Some(message) = bc_error.and_then(|e| e.conflict_message()) {
                create_step.complete()?;
                progress_warning(&reporter, format!("  Conflict: {}", message));
                progress_info(
                    &reporter,
                    "  Tag already exists with different content; skipping save",
                );
                complete_skipped_step(&mut session, "Uploading archive", "skipped — tag conflict")?;
                complete_skipped_step(
                    &mut session,
                    "Uploading manifest",
                    "skipped — tag conflict",
                )?;
                complete_skipped_step(&mut session, "Confirming upload", "skipped — tag conflict")?;

                let summary = Summary {
                    size_bytes: total_size_bytes,
                    file_count,
                    digest: Some(manifest_root_digest.clone()),
                    path: Some(path.clone()),
                };
                session.complete(summary)?;
                drop(reporter);
                progress_system.shutdown()?;
                return Ok(SaveStatus::Skipped);
            }

            if let Some(crate::error::BoringCacheError::CachePending) = bc_error {
                create_step.complete()?;
                progress_info(
                    &reporter,
                    "  Another job is uploading this cache; skipping wait",
                );
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
    };
    create_step.complete()?;

    let server_adapter = crate::cache_adapter::detect_restore_transport(
        save_response.storage_mode.as_deref(),
        save_response.cas_layout.as_deref(),
    );
    log::debug!(
        "Save response transport tag={} adapter={} storage_mode={:?} cas_layout={:?}",
        tag,
        server_adapter.as_str(),
        save_response.storage_mode.as_deref(),
        save_response.cas_layout.as_deref()
    );

    if server_adapter != crate::cache_adapter::CacheAdapterKind::Archive {
        let message = format!(
            "Cache adapter '{}' is not supported by this CLI build",
            server_adapter.as_str()
        );
        session.error(message.clone())?;
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!(message);
    }

    let needs_upload = !save_response.get_archive_urls().is_empty();

    log::debug!(
        "Server accepted cache entry tag={} exists={} archive_urls={}",
        tag,
        save_response.exists,
        save_response.get_archive_urls().len()
    );

    if save_response.exists {
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

        let save_status_pending = save_response.status.as_deref() == Some("pending");
        let same_tag = save_response.tag == tag;

        if save_status_pending && save_response.get_archive_urls().is_empty() {
            if same_tag {
                progress_info(&reporter, "  Cache upload in progress; skipping wait");
            } else {
                progress_info(
                    &reporter,
                    "  Cache upload in progress; binding tag and exiting",
                );
            }
        }

        if save_status_pending && save_response.get_archive_urls().is_empty() && same_tag {
            complete_skipped_step(
                &mut session,
                "Confirming upload",
                "skipped — another job is uploading",
            )?;
        } else {
            let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
            let piggyback_confirm_request = ConfirmRequest {
                manifest_digest: expected_manifest_digest.clone(),
                manifest_size: manifest_bytes.len() as u64,
                manifest_etag: None,
                archive_size: Some(archive_info.compressed_size),
                archive_etag: None,
                blob_count: None,
                blob_total_size_bytes: None,
                file_count: Some(file_count),
                uncompressed_size: Some(archive_info.uncompressed_size),
                compressed_size: Some(archive_info.compressed_size),
                storage_mode: Some("archive".to_string()),
                tag: Some(tag.clone()),
                write_scope_tag: None,
            };

            let piggyback_confirm_response = api_client
                .confirm(
                    &workspace,
                    &save_response.cache_entry_id,
                    &piggyback_confirm_request,
                )
                .await
                .with_context(|| format!("Failed to confirm piggybacked upload for {}", tag))?;

            match piggyback_confirm_response.tag_status.as_deref() {
                Some("ready") => {
                    log::debug!("Tag {} bound synchronously", tag);
                }
                Some("pending") => {
                    log::debug!("Tag {} binding deferred until upload completes", tag);
                    progress_info(&reporter, "  Tag will be bound when upload completes");
                }
                Some(status) => {
                    log::debug!("Tag {} binding status: {}", tag, status);
                }
                None => {
                    log::debug!("No tag_status in confirm response for {}", tag);
                }
            }

            confirm_step.complete()?;
        }

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

    progress_info(
        &reporter,
        format!(
            "  Backend response: {} archive total, {} needs upload ({} exists)",
            1,
            if needs_upload { 1 } else { 0 },
            if needs_upload { 0 } else { 1 },
        ),
    );

    let mut archive_etag: Option<String> = None;
    let mut upload_storage_metrics = StorageMetrics::default();

    if !needs_upload {
        complete_skipped_step(
            &mut session,
            "Uploading archive",
            "skipped — archive already exists",
        )?;
        progress_info(
            &reporter,
            "  Archive already present on server; skipping upload",
        );
    } else {
        let step6 = session.start_step(
            "Uploading archive".to_string(),
            Some(format!(
                "1 archive ({})",
                crate::progress::format_bytes(total_compressed_size)
            )),
        )?;
        let upload_step_number = step6.step_number();

        let mut multipart_retry_count = 0u32;

        loop {
            let archive_urls = save_response.get_archive_urls().to_vec();
            let progress = TransferProgress::new(
                reporter.clone(),
                session_id.clone(),
                upload_step_number,
                total_compressed_size,
            );
            progress.record_bytes(0)?;

            let upload_started = Instant::now();

            if verbose
                && !save_response.upload_headers.is_empty()
                && let Some(regions) = save_response.upload_headers.get("x-tigris-regions")
            {
                let count = regions.split(',').count();
                progress_info(
                    &reporter,
                    format!("  Replication: {} regions ({})", count, regions),
                );
            }

            let upload_result = if let Some(upload_id) = save_response.get_upload_id() {
                log::info!(
                    "Using multipart upload: {} parts, upload_id={}",
                    archive_urls.len(),
                    upload_id
                );
                if verbose {
                    progress_info(
                        &reporter,
                        format!("  Using multipart upload with {} parts", archive_urls.len()),
                    );
                }

                upload_archive_multipart(
                    final_archive_path.as_ref(),
                    &archive_urls,
                    upload_id,
                    &progress,
                    api_client.transfer_client(),
                    &api_client,
                    &workspace,
                    save_response.cache_entry_id.as_str(),
                    &save_response.upload_headers,
                )
                .await
                .with_context(|| format!("Failed to upload archive parts for {}", tag))
            } else {
                log::info!("Using single-part upload");
                upload_archive_file(
                    final_archive_path.as_ref(),
                    &archive_urls[0],
                    &progress,
                    api_client.transfer_client(),
                    &save_response.upload_headers,
                )
                .await
                .with_context(|| format!("Failed to upload archive for {}", tag))
            };

            match upload_result {
                Ok((etag, metrics)) => {
                    archive_etag = etag;
                    upload_storage_metrics = metrics;
                    upload_duration = Some(upload_started.elapsed());
                    break;
                }
                Err(err)
                    if save_response.get_upload_id().is_some()
                        && is_missing_multipart_upload_session_error(&err)
                        && multipart_retry_count < 1 =>
                {
                    multipart_retry_count += 1;
                    progress_warning(
                        &reporter,
                        "  Multipart upload session disappeared; retrying once with a fresh upload session",
                    );
                    save_response =
                        request_fresh_multipart_upload(&api_client, &workspace, &request, &tag)
                            .await?;
                }
                Err(err) => return Err(err),
            }
        }

        let upload_elapsed = upload_duration.unwrap_or_default();
        step6.complete()?;

        let compression_ratio_percent = if total_uncompressed_size > 0 {
            total_compressed_size as f64 / total_uncompressed_size as f64 * 100.0
        } else {
            0.0
        };

        let upload_secs = upload_elapsed.as_secs_f64().max(0.001);
        let upload_speed = (total_compressed_size as f64 / 1_000_000.0) / upload_secs;

        progress_info(
            &reporter,
            format!(
                "Uploaded {} → {} ({:.1}% of original) @ {:.1} MB/s",
                crate::progress::format_bytes(total_uncompressed_size),
                crate::progress::format_bytes(total_compressed_size),
                compression_ratio_percent,
                upload_speed
            ),
        );
    }

    let manifest_step = session.start_step("Uploading manifest".to_string(), None)?;
    let manifest_etag = upload_manifest(
        api_client.transfer_client(),
        save_response
            .manifest_upload_url
            .as_ref()
            .ok_or_else(|| anyhow!("Missing manifest_upload_url in response"))?,
        &manifest_bytes,
        &save_response.upload_headers,
    )
    .await?;
    manifest_step.complete()?;

    let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
    let confirm_request = ConfirmRequest {
        manifest_digest: expected_manifest_digest.clone(),
        manifest_size: manifest_bytes.len() as u64,
        manifest_etag,
        archive_size: Some(final_compressed_size),
        archive_etag,
        blob_count: None,
        blob_total_size_bytes: None,
        file_count: Some(file_count),
        uncompressed_size: Some(total_uncompressed_size),
        compressed_size: Some(final_compressed_size),
        storage_mode: Some("archive".to_string()),
        tag: Some(tag.clone()),
        write_scope_tag: None,
    };

    let confirm_outcome = confirm_archive_upload(
        &api_client,
        &workspace,
        save_response.cache_entry_id.as_str(),
        &confirm_request,
    )
    .await
    .with_context(|| format!("Failed to confirm upload for {}", tag))?;
    match confirm_outcome {
        ArchiveConfirmOutcome::Published {
            winner_id: Some(winner_id),
        } => {
            progress_info(
                &reporter,
                format!(
                    "  Cache already confirmed as entry {}; using existing entry",
                    winner_id
                ),
            );
        }
        ArchiveConfirmOutcome::Published { winner_id: None } => {}
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

    let total_elapsed = overall_started.elapsed();
    let archive_ms = archive_duration.as_millis() as u64;
    let upload_ms = upload_duration.map(|d| d.as_millis() as u64).unwrap_or(0);

    let archive_time_str = format_phase_duration_ms(archive_ms);
    let upload_time_str = if upload_ms > 0 {
        format!(", upload: {}", format_phase_duration_ms(upload_ms))
    } else {
        String::new()
    };
    let total_time_str = format_phase_duration(total_elapsed);

    ui::info(&format!(
        "Completed saving {} ({} files, {}) in {} (archive: {}{})",
        tag,
        file_count,
        format_bytes(total_size_bytes),
        total_time_str,
        archive_time_str,
        upload_time_str
    ));
    ui::info(&format!("    Path: {}", path));

    log::debug!(
        "save timing tag={} archive_ms={} upload_ms={} total_ms={}",
        tag,
        archive_ms,
        upload_ms,
        total_elapsed.as_millis()
    );

    SaveMetrics {
        tag,
        manifest_root_digest,
        total_duration_ms: total_elapsed.as_millis() as u64,
        archive_duration_ms: archive_ms,
        upload_duration_ms: upload_ms,
        uncompressed_size: total_uncompressed_size,
        compressed_size: total_compressed_size,
        file_count,
        part_count: if save_response.get_upload_id().is_some() {
            Some(save_response.get_archive_urls().len() as u32)
        } else {
            None
        },
        storage_metrics: upload_storage_metrics,
    }
    .send(&api_client, &workspace)
    .await;

    Ok(SaveStatus::Uploaded)
}
