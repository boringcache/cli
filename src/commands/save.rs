use anyhow::{anyhow, Context, Error, Result};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::task;

use crate::api::models::cache::{
    BlobDescriptor, CompleteMultipartRequest, ConfirmRequest, ManifestCheckRequest, SaveRequest,
};
use crate::api::ApiClient;
use crate::archive::{create_tar_archive, TarArchiveInfo};
use crate::ci_detection::detect_ci_environment;
use crate::manifest::diff::compute_digest_from_draft;
use crate::manifest::{EntryType, ManifestBuilder, ManifestFile};
use crate::multipart_upload::{upload_via_part_urls, upload_via_single_url};
use crate::progress::{
    format_bytes, ProgressSession, Summary, System as ProgressSystem, TransferProgress,
};
use crate::telemetry::{SaveMetrics, StorageMetrics};
use crate::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaveStatus {
    AlreadyExists,
    Uploaded,
    Skipped,
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_batch_save(
    workspace: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: Vec<String>,
    recipient: Option<String>,
) -> Result<()> {
    if let Err(err) = execute_batch_save_inner(
        workspace,
        tag_path_pairs,
        verbose,
        no_platform,
        no_git,
        force,
        exclude,
        recipient,
    )
    .await
    {
        ui::warn(&format!("{:#}", err));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn execute_batch_save_inner(
    workspace: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: Vec<String>,
    recipient: Option<String>,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace)?;
    crate::api::parse_workspace_slug(&workspace)?;
    let api_client = ApiClient::new()?;

    let (encrypt, recipient) =
        crate::commands::utils::resolve_encryption_config(&workspace, recipient)?;

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
    let git_enabled = !no_git && !crate::git::is_git_disabled_by_env();

    let mut prepared_entries: Vec<(String, String)> = Vec::new();

    for crate::commands::utils::SaveSpec {
        tag: base_tag,
        path,
    } in parsed_pairs
    {
        let expanded_path = crate::commands::utils::expand_tilde_path(&path);
        let git_context = if git_enabled {
            crate::git::GitContext::detect_with_path(Some(&expanded_path))
        } else {
            crate::git::GitContext::default()
        };
        let tag_resolver =
            crate::tag_utils::TagResolver::new(platform.clone(), git_context, git_enabled);

        let tag = tag_resolver.effective_save_tag(&base_tag)?;

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
            exclude.clone(),
            encrypt,
            recipient.clone(),
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
    exclude: Vec<String>,
    encrypt: bool,
    recipient: Option<String>,
) -> Result<SaveStatus> {
    ui::info(&format!(
        "\nSaving ({}/{}) {} -> {}",
        entry_index + 1,
        total_entries,
        tag,
        path
    ));

    let adapter_detection = crate::cache_adapter::detect_layout(std::path::Path::new(&path));
    log::debug!(
        "Starting save {} of {} for tag={} path={} workspace={}",
        entry_index + 1,
        total_entries,
        tag,
        path,
        workspace
    );
    log::debug!(
        "Save adapter selection tag={} path={} adapter={} reason={}",
        tag,
        path,
        adapter_detection.kind.as_str(),
        adapter_detection.reason
    );

    let adapter_selection =
        crate::adapters::select_layout_adapter(adapter_detection.kind, encrypt)?;
    if adapter_selection.used_encryption_fallback {
        ui::warn(crate::adapters::CONTENT_ADDRESSED_ENCRYPTION_FALLBACK_WARNING);
    }
    let adapter = adapter_selection.adapter;
    log::debug!(
        "Save adapter dispatch tag={} adapter={}",
        tag,
        adapter.transport_kind().as_str()
    );

    match adapter {
        crate::adapters::AdapterDispatchKind::Archive => {
            save_single_archive_entry(
                api_client,
                workspace,
                tag,
                path,
                verbose,
                force,
                entry_index,
                total_entries,
                exclude,
                encrypt,
                recipient,
            )
            .await
        }
        crate::adapters::AdapterDispatchKind::Oci => {
            save_single_oci_entry(
                api_client,
                workspace,
                tag,
                path,
                verbose,
                force,
                entry_index,
                total_entries,
            )
            .await
        }
        crate::adapters::AdapterDispatchKind::File => {
            save_single_file_entry(
                api_client,
                workspace,
                tag,
                path,
                verbose,
                force,
                entry_index,
                total_entries,
                exclude,
                adapter_detection.kind,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn save_single_archive_entry(
    api_client: ApiClient,
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

    let manifest_root_digest = compute_digest_from_draft(&draft);
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

    let manifest_files = manifest_files_from_draft(&draft);
    let (manifest_bytes, expected_manifest_digest, expected_manifest_size) = build_manifest_bytes(
        &tag,
        &manifest_root_digest,
        &manifest_files,
        encrypt,
        recipient_str,
        age_recipient.as_ref(),
    )?;

    let check_step = session.start_step("Checking cache".to_string(), None)?;
    let check_response = api_client
        .check_manifests(
            &workspace,
            &[ManifestCheckRequest {
                tag: tag.clone(),
                manifest_root_digest: manifest_root_digest.clone(),
                lookup: None,
            }],
        )
        .await;

    let mut cache_exists = false;
    let mut cache_pending = false;
    match check_response {
        Ok(response) => {
            if let Some(result) = response.results.first() {
                if result.exists {
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

    if !cache_exists && !force {
        let digest_check_response = api_client
            .check_manifests(
                &workspace,
                &[ManifestCheckRequest {
                    tag: tag.clone(),
                    manifest_root_digest: manifest_root_digest.clone(),
                    lookup: Some("digest".to_string()),
                }],
            )
            .await;

        match digest_check_response {
            Ok(response) => {
                if let Some(result) = response.results.first() {
                    let digest_exists = result.exists
                        && result
                            .status
                            .as_deref()
                            .map(|status| status != "pending" && status != "uploading")
                            .unwrap_or(true);

                    if digest_exists {
                        if let Some(cache_entry_id) = result.cache_entry_id.as_deref() {
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
                            };

                            match api_client
                                .confirm(&workspace, cache_entry_id, &confirm_request)
                                .await
                            {
                                Ok(_) => {
                                    complete_skipped_step(
                                        &mut session,
                                        "Creating archive",
                                        "skipped — digest exists",
                                    )?;
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
                    }
                }
            }
            Err(err) => {
                progress_warning(
                    &reporter,
                    format!("  Digest check failed ({}); proceeding", err),
                );
            }
        }
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

    let (final_archive_path, final_compressed_size) = if encrypt {
        let encrypt_step = session.start_step("Encrypting archive".to_string(), None)?;
        let age_recipient = age_recipient.as_ref().ok_or_else(|| {
            anyhow!(
                "Encryption enabled but no recipient configured. Run `boringcache setup-encryption <workspace>` or pass --recipient."
            )
        })?;

        let encrypted_path =
            crate::archive::encrypt_archive(archive_info.archive_path.as_ref(), age_recipient)?;
        let encrypted_size = std::fs::metadata::<&std::path::Path>(encrypted_path.as_ref())?.len();

        progress_info(
            &reporter,
            format!(
                "  Encrypted archive: {} → {}",
                crate::progress::format_bytes(archive_info.compressed_size),
                crate::progress::format_bytes(encrypted_size)
            ),
        );

        encrypt_step.complete()?;
        (encrypted_path, encrypted_size)
    } else {
        (archive_info.archive_path, archive_info.compressed_size)
    };

    let total_uncompressed_size = archive_info.uncompressed_size;
    let total_compressed_size = final_compressed_size;

    let use_multipart = crate::archive::should_use_multipart_upload(total_compressed_size);

    let ci_provider = detect_ci_environment();
    let request = SaveRequest {
        tag: tag.clone(),
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
        ci_provider: Some(ci_provider),
        encrypted: if encrypt { Some(true) } else { None },
        encryption_algorithm: if encrypt {
            Some(crate::encryption::ENCRYPTION_ALGORITHM_AGE_X25519.to_string())
        } else {
            None
        },
        encryption_recipient_hint: recipient_str.map(crate::encryption::recipient_hint),
    };

    let create_step = session.start_step(
        "Creating cache entry".to_string(),
        Some("1 archive".to_string()),
    )?;

    let save_response = match api_client.save_entry(&workspace, &request).await {
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

    let archive_urls = save_response.get_archive_urls();
    let needs_upload = !archive_urls.is_empty();

    log::debug!(
        "Server accepted cache entry tag={} exists={} archive_urls={}",
        tag,
        save_response.exists,
        archive_urls.len()
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

        if save_status_pending && archive_urls.is_empty() {
            if same_tag {
                progress_info(&reporter, "  Cache upload in progress; skipping wait");
            } else {
                progress_info(
                    &reporter,
                    "  Cache upload in progress; binding tag and exiting",
                );
            }
        }

        if save_status_pending && archive_urls.is_empty() && same_tag {
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

    let cache_entry_id = &save_response.cache_entry_id;
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

        let progress = TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            upload_step_number,
            total_compressed_size,
        );
        progress.record_bytes(0)?;

        let upload_started = Instant::now();

        if verbose && !save_response.upload_headers.is_empty() {
            if let Some(regions) = save_response.upload_headers.get("x-tigris-regions") {
                let count = regions.split(',').count();
                progress_info(
                    &reporter,
                    format!("  Replication: {} regions ({})", count, regions),
                );
            }
        }

        let is_multipart = save_response.get_upload_id().is_some();

        if is_multipart {
            let upload_id = save_response.get_upload_id().unwrap();

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

            (archive_etag, upload_storage_metrics) = upload_archive_multipart(
                final_archive_path.as_ref(),
                archive_urls,
                upload_id,
                &progress,
                api_client.transfer_client(),
                &api_client,
                &workspace,
                cache_entry_id,
                &save_response.upload_headers,
            )
            .await
            .with_context(|| format!("Failed to upload archive parts for {}", tag))?;
        } else {
            log::info!("Using single-part upload");
            (archive_etag, upload_storage_metrics) = upload_archive_file(
                final_archive_path.as_ref(),
                &archive_urls[0],
                &progress,
                api_client.transfer_client(),
                &save_response.upload_headers,
            )
            .await
            .with_context(|| format!("Failed to upload archive for {}", tag))?;
        }

        let upload_elapsed = upload_started.elapsed();
        upload_duration = Some(upload_elapsed);
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
        progress_info(
            &reporter,
            format!(
                "  Cache already confirmed as entry {}; using existing entry",
                winner_id
            ),
        );
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

#[allow(clippy::too_many_arguments)]
async fn save_single_file_entry(
    api_client: ApiClient,
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

    let scan_step = session.start_step("Scanning file layout".to_string(), None)?;
    let scan_started = Instant::now();
    let scan_path = PathBuf::from(&path);
    let scan = task::spawn_blocking(move || crate::cas_file::scan_path(&scan_path, exclude))
        .await
        .context("File CAS scan task panicked")??;
    let scan_duration = scan_started.elapsed();
    scan_step.complete()?;

    let pointer_bytes = crate::cas_file::build_pointer(&scan)?;
    let manifest_root_digest = crate::cas_file::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_digest = manifest_root_digest.clone();
    let expected_manifest_size = pointer_bytes.len() as u64;
    let blob_count = scan.blobs.len() as u64;
    let file_count = scan
        .entries
        .iter()
        .filter(|entry| entry.entry_type == EntryType::File)
        .count()
        .min(u32::MAX as usize) as u32;
    let blob_total_size_bytes = scan.total_blob_bytes;
    let total_size_bytes = blob_total_size_bytes;
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

    let cas_layout =
        crate::adapters::cas_layout_for(detected_kind, crate::adapters::AdapterDispatchKind::File)
            .map(|layout| layout.to_string());

    let blobs: Vec<BlobDescriptor> = scan
        .blobs
        .iter()
        .map(|blob| BlobDescriptor {
            digest: blob.digest.clone(),
            size_bytes: blob.size_bytes,
        })
        .collect();
    let blob_paths: HashMap<String, PathBuf> = scan
        .blobs
        .iter()
        .map(|blob| (blob.digest.clone(), blob.path.clone()))
        .collect();
    let blob_sizes: HashMap<String, u64> = blobs
        .iter()
        .map(|blob| (blob.digest.clone(), blob.size_bytes))
        .collect();

    let create_step = session.start_step("Creating cache entry".to_string(), None)?;
    let ci_provider = detect_ci_environment();
    let request = SaveRequest {
        tag: tag.clone(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout,
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(file_count),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(expected_manifest_size),
        force: if force { Some(true) } else { None },
        use_multipart: None,
        ci_provider: Some(ci_provider),
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let save_response = api_client
        .save_entry(&workspace, &request)
        .await
        .with_context(|| format!("Failed to create CAS entry for {}", tag))?;
    create_step.complete()?;

    let server_adapter = crate::cache_adapter::detect_restore_transport(
        save_response.storage_mode.as_deref(),
        save_response.cas_layout.as_deref(),
    );
    if !matches!(
        server_adapter,
        crate::cache_adapter::CacheAdapterKind::Cas
            | crate::cache_adapter::CacheAdapterKind::CasBazel
    ) {
        let message = format!(
            "Server did not negotiate file CAS mode for {} (adapter '{}')",
            tag,
            server_adapter.as_str()
        );
        session.error(message.clone())?;
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!(message);
    }

    if save_response.exists {
        complete_skipped_step(
            &mut session,
            "Checking remote blobs",
            "skipped — server reports entry exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading blobs",
            "skipped — server reports entry exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading CAS index",
            "skipped — server reports entry exists",
        )?;

        let save_status_pending = save_response.status.as_deref() == Some("pending");
        let same_tag = save_response.tag == tag;

        if save_status_pending && same_tag {
            complete_skipped_step(
                &mut session,
                "Confirming upload",
                "skipped — another job is uploading",
            )?;
        } else {
            let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
            let confirm_request = ConfirmRequest {
                manifest_digest: expected_manifest_digest.clone(),
                manifest_size: expected_manifest_size,
                manifest_etag: None,
                archive_size: None,
                archive_etag: None,
                blob_count: Some(blob_count),
                blob_total_size_bytes: Some(blob_total_size_bytes),
                file_count: Some(file_count),
                uncompressed_size: None,
                compressed_size: None,
                storage_mode: Some("cas".to_string()),
                tag: Some(tag.clone()),
            };
            api_client
                .confirm(&workspace, &save_response.cache_entry_id, &confirm_request)
                .await
                .with_context(|| format!("Failed to confirm existing CAS entry for {}", tag))?;
            confirm_step.complete()?;
        }

        let summary = Summary {
            size_bytes: total_size_bytes,
            file_count,
            digest: Some(manifest_root_digest.clone()),
            path: Some(path),
        };
        session.complete(summary)?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(SaveStatus::AlreadyExists);
    }

    let check_step = session.start_step(
        "Checking remote blobs".to_string(),
        Some(format!("{} blobs", blobs.len())),
    )?;
    let missing_blobs = if blobs.is_empty() {
        Vec::new()
    } else {
        let check_response = api_client
            .check_blobs(&workspace, &blobs)
            .await
            .context("Failed to check remote blob presence")?;
        let existing: std::collections::HashSet<&str> = check_response
            .results
            .iter()
            .filter_map(|result| result.exists.then_some(result.digest.as_str()))
            .collect();
        blobs
            .iter()
            .filter(|blob| !existing.contains(blob.digest.as_str()))
            .cloned()
            .collect::<Vec<_>>()
    };
    check_step.complete()?;

    let mut upload_storage_metrics = StorageMetrics::default();
    let upload_step = session.start_step(
        "Uploading blobs".to_string(),
        Some(format!("{} missing", missing_blobs.len())),
    )?;
    let upload_started = Instant::now();
    if !blobs.is_empty() {
        let upload_plan = api_client
            .blob_upload_urls(&workspace, &save_response.cache_entry_id, &blobs)
            .await
            .context("Failed to request CAS blob upload URLs")?;

        let mut items = Vec::new();
        for upload in &upload_plan.upload_urls {
            let blob_path = blob_paths
                .get(&upload.digest)
                .cloned()
                .ok_or_else(|| anyhow!("Missing local file for blob {}", upload.digest))?;
            let size_bytes = blob_sizes
                .get(&upload.digest)
                .copied()
                .ok_or_else(|| anyhow!("Missing local metadata for blob {}", upload.digest))?;
            items.push((
                upload.digest.clone(),
                blob_path,
                upload.url.clone(),
                upload.headers.clone(),
                size_bytes,
            ));
        }

        if !items.is_empty() {
            let total_upload_bytes = items.iter().map(|item| item.4).sum::<u64>();
            let progress = TransferProgress::new(
                reporter.clone(),
                session_id.clone(),
                upload_step.step_number(),
                total_upload_bytes,
            );
            let max_concurrent =
                crate::commands::utils::get_optimal_concurrency(items.len(), "save");
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));
            let transfer_client = api_client.transfer_client().clone();
            let mut tasks = Vec::new();

            for (_digest, blob_path, upload_url, headers, size_bytes) in items {
                let semaphore = semaphore.clone();
                let progress = progress.clone();
                let transfer_client = transfer_client.clone();
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let (_etag, metrics) = upload_via_single_url(
                        &blob_path,
                        &upload_url,
                        &progress,
                        &transfer_client,
                        &headers,
                    )
                    .await
                    .with_context(|| format!("Failed to upload blob {}", blob_path.display()))?;
                    Ok::<(u64, StorageMetrics), anyhow::Error>((size_bytes, metrics))
                });
                tasks.push(task);
            }

            for task in tasks {
                let (_uploaded_bytes, metrics) =
                    task.await.context("Blob upload task panicked")??;
                if upload_storage_metrics.region.is_none() {
                    upload_storage_metrics = metrics;
                }
            }
        }
    }
    let upload_duration = upload_started.elapsed();
    upload_step.complete()?;

    let index_step = session.start_step("Uploading CAS index".to_string(), None)?;
    let manifest_etag = upload_payload(
        api_client.transfer_client(),
        save_response
            .manifest_upload_url
            .as_ref()
            .ok_or_else(|| anyhow!("Missing manifest_upload_url in response"))?,
        &pointer_bytes,
        "application/cbor",
        &save_response.upload_headers,
    )
    .await?;
    index_step.complete()?;

    let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
    let confirm_request = ConfirmRequest {
        manifest_digest: expected_manifest_digest.clone(),
        manifest_size: expected_manifest_size,
        manifest_etag,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        file_count: Some(file_count),
        uncompressed_size: None,
        compressed_size: None,
        storage_mode: Some("cas".to_string()),
        tag: Some(tag.clone()),
    };
    api_client
        .confirm(&workspace, &save_response.cache_entry_id, &confirm_request)
        .await
        .with_context(|| format!("Failed to confirm CAS upload for {}", tag))?;
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

    SaveMetrics {
        tag,
        manifest_root_digest,
        total_duration_ms: total_elapsed.as_millis() as u64,
        archive_duration_ms: scan_duration.as_millis() as u64,
        upload_duration_ms: upload_duration.as_millis() as u64,
        uncompressed_size: total_size_bytes,
        compressed_size: blob_total_size_bytes,
        file_count,
        part_count: if blob_count > 0 {
            Some(blob_count.min(u32::MAX as u64) as u32)
        } else {
            None
        },
        storage_metrics: upload_storage_metrics,
    }
    .send(&api_client, &workspace)
    .await;

    Ok(SaveStatus::Uploaded)
}

#[allow(clippy::too_many_arguments)]
async fn save_single_oci_entry(
    api_client: ApiClient,
    workspace: String,
    tag: String,
    path: String,
    _verbose: bool,
    force: bool,
    _entry_index: usize,
    _total_entries: usize,
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

    let scan_step = session.start_step("Scanning OCI layout".to_string(), None)?;
    let scan_started = Instant::now();
    let scan_path = PathBuf::from(&path);
    let scan = task::spawn_blocking(move || crate::cas_oci::scan_layout(&scan_path))
        .await
        .context("OCI scan task panicked")??;
    let scan_duration = scan_started.elapsed();
    scan_step.complete()?;

    let pointer_bytes = crate::cas_oci::build_pointer(&scan)?;
    let manifest_root_digest = crate::cas_oci::prefixed_sha256_digest(&pointer_bytes);
    let expected_manifest_digest = manifest_root_digest.clone();
    let expected_manifest_size = pointer_bytes.len() as u64;
    let blob_count = scan.blobs.len() as u64;
    let file_count = blob_count.min(u32::MAX as u64) as u32;
    let blob_total_size_bytes = scan.total_blob_bytes;
    let total_size_bytes =
        blob_total_size_bytes + scan.index_json.len() as u64 + scan.oci_layout.len() as u64;

    let blobs: Vec<BlobDescriptor> = scan
        .blobs
        .iter()
        .map(|blob| BlobDescriptor {
            digest: blob.digest.clone(),
            size_bytes: blob.size_bytes,
        })
        .collect();
    let blob_paths: HashMap<String, PathBuf> = scan
        .blobs
        .iter()
        .map(|blob| (blob.digest.clone(), blob.path.clone()))
        .collect();
    let blob_sizes: HashMap<String, u64> = blobs
        .iter()
        .map(|blob| (blob.digest.clone(), blob.size_bytes))
        .collect();

    let create_step = session.start_step("Creating cache entry".to_string(), None)?;
    let ci_provider = detect_ci_environment();
    let request = SaveRequest {
        tag: tag.clone(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: Some("cas".to_string()),
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        cas_layout: Some("oci-v1".to_string()),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: None,
        compressed_size: None,
        file_count: Some(file_count),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(expected_manifest_size),
        force: if force { Some(true) } else { None },
        use_multipart: None,
        ci_provider: Some(ci_provider),
        encrypted: None,
        encryption_algorithm: None,
        encryption_recipient_hint: None,
    };

    let save_response = api_client
        .save_entry(&workspace, &request)
        .await
        .with_context(|| format!("Failed to create CAS entry for {}", tag))?;
    create_step.complete()?;

    let server_adapter = crate::cache_adapter::detect_restore_transport(
        save_response.storage_mode.as_deref(),
        save_response.cas_layout.as_deref(),
    );
    if !matches!(
        server_adapter,
        crate::cache_adapter::CacheAdapterKind::Cas
            | crate::cache_adapter::CacheAdapterKind::CasOci
    ) {
        let message = format!(
            "Server did not negotiate OCI CAS mode for {} (adapter '{}')",
            tag,
            server_adapter.as_str()
        );
        session.error(message.clone())?;
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!(message);
    }

    if save_response.exists {
        complete_skipped_step(
            &mut session,
            "Checking remote blobs",
            "skipped — server reports entry exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading blobs",
            "skipped — server reports entry exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading CAS index",
            "skipped — server reports entry exists",
        )?;

        let save_status_pending = save_response.status.as_deref() == Some("pending");
        let same_tag = save_response.tag == tag;

        if save_status_pending && same_tag {
            complete_skipped_step(
                &mut session,
                "Confirming upload",
                "skipped — another job is uploading",
            )?;
        } else {
            let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
            let confirm_request = ConfirmRequest {
                manifest_digest: expected_manifest_digest.clone(),
                manifest_size: expected_manifest_size,
                manifest_etag: None,
                archive_size: None,
                archive_etag: None,
                blob_count: Some(blob_count),
                blob_total_size_bytes: Some(blob_total_size_bytes),
                file_count: Some(file_count),
                uncompressed_size: None,
                compressed_size: None,
                storage_mode: Some("cas".to_string()),
                tag: Some(tag.clone()),
            };
            api_client
                .confirm(&workspace, &save_response.cache_entry_id, &confirm_request)
                .await
                .with_context(|| format!("Failed to confirm existing CAS entry for {}", tag))?;
            confirm_step.complete()?;
        }

        let summary = Summary {
            size_bytes: total_size_bytes,
            file_count,
            digest: Some(manifest_root_digest.clone()),
            path: Some(path),
        };
        session.complete(summary)?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(SaveStatus::AlreadyExists);
    }

    let check_step = session.start_step(
        "Checking remote blobs".to_string(),
        Some(format!("{} blobs", blobs.len())),
    )?;
    let missing_blobs = if blobs.is_empty() {
        Vec::new()
    } else {
        let check_response = api_client
            .check_blobs(&workspace, &blobs)
            .await
            .context("Failed to check remote blob presence")?;
        let existing: std::collections::HashSet<&str> = check_response
            .results
            .iter()
            .filter_map(|result| result.exists.then_some(result.digest.as_str()))
            .collect();
        blobs
            .iter()
            .filter(|blob| !existing.contains(blob.digest.as_str()))
            .cloned()
            .collect::<Vec<_>>()
    };
    check_step.complete()?;

    let mut upload_storage_metrics = StorageMetrics::default();
    let upload_step = session.start_step(
        "Uploading blobs".to_string(),
        Some(format!("{} missing", missing_blobs.len())),
    )?;
    let upload_started = Instant::now();
    if !blobs.is_empty() {
        let upload_plan = api_client
            .blob_upload_urls(&workspace, &save_response.cache_entry_id, &blobs)
            .await
            .context("Failed to request CAS blob upload URLs")?;

        let mut items = Vec::new();
        for upload in &upload_plan.upload_urls {
            let path = blob_paths
                .get(&upload.digest)
                .cloned()
                .ok_or_else(|| anyhow!("Missing local file for blob {}", upload.digest))?;
            let size_bytes = blob_sizes
                .get(&upload.digest)
                .copied()
                .ok_or_else(|| anyhow!("Missing local metadata for blob {}", upload.digest))?;
            items.push((
                upload.digest.clone(),
                path,
                upload.url.clone(),
                upload.headers.clone(),
                size_bytes,
            ));
        }

        if !items.is_empty() {
            let total_upload_bytes = items.iter().map(|item| item.4).sum::<u64>();
            let progress = TransferProgress::new(
                reporter.clone(),
                session_id.clone(),
                upload_step.step_number(),
                total_upload_bytes,
            );
            let max_concurrent =
                crate::commands::utils::get_optimal_concurrency(items.len(), "save");
            let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));
            let transfer_client = api_client.transfer_client().clone();
            let mut tasks = Vec::new();

            for (_digest, file_path, upload_url, headers, size_bytes) in items {
                let semaphore = semaphore.clone();
                let progress = progress.clone();
                let transfer_client = transfer_client.clone();
                let task = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    let (_etag, metrics) = upload_via_single_url(
                        &file_path,
                        &upload_url,
                        &progress,
                        &transfer_client,
                        &headers,
                    )
                    .await
                    .with_context(|| format!("Failed to upload blob {}", file_path.display()))?;
                    Ok::<(u64, StorageMetrics), anyhow::Error>((size_bytes, metrics))
                });
                tasks.push(task);
            }

            for task in tasks {
                let (_uploaded_bytes, metrics) =
                    task.await.context("Blob upload task panicked")??;
                if upload_storage_metrics.region.is_none() {
                    upload_storage_metrics = metrics;
                }
            }
        }
    }
    let upload_duration = upload_started.elapsed();
    upload_step.complete()?;

    let index_step = session.start_step("Uploading CAS index".to_string(), None)?;
    let manifest_etag = upload_payload(
        api_client.transfer_client(),
        save_response
            .manifest_upload_url
            .as_ref()
            .ok_or_else(|| anyhow!("Missing manifest_upload_url in response"))?,
        &pointer_bytes,
        "application/cbor",
        &save_response.upload_headers,
    )
    .await?;
    index_step.complete()?;

    let confirm_step = session.start_step("Confirming upload".to_string(), None)?;
    let confirm_request = ConfirmRequest {
        manifest_digest: expected_manifest_digest.clone(),
        manifest_size: expected_manifest_size,
        manifest_etag,
        archive_size: None,
        archive_etag: None,
        blob_count: Some(blob_count),
        blob_total_size_bytes: Some(blob_total_size_bytes),
        file_count: Some(file_count),
        uncompressed_size: None,
        compressed_size: None,
        storage_mode: Some("cas".to_string()),
        tag: Some(tag.clone()),
    };
    api_client
        .confirm(&workspace, &save_response.cache_entry_id, &confirm_request)
        .await
        .with_context(|| format!("Failed to confirm CAS upload for {}", tag))?;
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

    SaveMetrics {
        tag,
        manifest_root_digest,
        total_duration_ms: total_elapsed.as_millis() as u64,
        archive_duration_ms: scan_duration.as_millis() as u64,
        upload_duration_ms: upload_duration.as_millis() as u64,
        uncompressed_size: total_size_bytes,
        compressed_size: blob_total_size_bytes,
        file_count,
        part_count: if blob_count > 0 {
            Some(blob_count.min(u32::MAX as u64) as u32)
        } else {
            None
        },
        storage_metrics: upload_storage_metrics,
    }
    .send(&api_client, &workspace)
    .await;

    Ok(SaveStatus::Uploaded)
}

fn complete_skipped_step(session: &mut ProgressSession, title: &str, detail: &str) -> Result<()> {
    let step = session.start_step(title.to_string(), Some(detail.to_string()))?;
    step.complete()?;
    Ok(())
}

fn progress_info(reporter: &crate::progress::Reporter, message: impl Into<String>) {
    let message = message.into();
    if reporter.info(message.clone()).is_err() {
        ui::info(&message);
    }
}

fn progress_warning(reporter: &crate::progress::Reporter, message: impl Into<String>) {
    let message = message.into();
    if reporter.warning(message.clone()).is_err() {
        ui::warn(&message);
    }
}

fn manifest_files_from_draft(draft: &crate::manifest::ManifestDraft) -> Vec<ManifestFile> {
    draft
        .descriptors
        .iter()
        .map(|desc| ManifestFile {
            path: desc.path.clone(),
            entry_type: desc.entry_type,
            size: desc.size,
            executable: desc.executable,
            hash: desc.hash.clone(),
            target: desc.target.clone(),
            state: crate::manifest::EntryState::Present,
        })
        .collect()
}

fn build_manifest_bytes(
    tag: &str,
    manifest_root_digest: &str,
    manifest_files: &[ManifestFile],
    encrypt: bool,
    recipient_str: Option<&str>,
    age_recipient: Option<&age::x25519::Recipient>,
) -> Result<(Vec<u8>, String, u64)> {
    let encryption_metadata = if encrypt {
        Some(crate::manifest::EncryptionMetadata {
            algorithm: crate::encryption::ENCRYPTION_ALGORITHM_AGE_X25519.to_string(),
            recipient_hint: recipient_str.map(crate::encryption::recipient_hint),
            encrypted_at: chrono::Utc::now(),
        })
    } else {
        None
    };
    let signature_metadata: Option<crate::manifest::SignatureMetadata> = None;

    let manifest_cbor = serialize_manifest(
        tag,
        manifest_root_digest,
        manifest_files,
        encryption_metadata,
        signature_metadata,
    )?;
    let mut manifest_bytes = crate::manifest::io::compress_manifest(&manifest_cbor)?;
    if let Some(recipient) = age_recipient {
        manifest_bytes = crate::encryption::encrypt_data(&manifest_bytes, recipient)?;
    }
    log::debug!(
        "Manifest compressed: {} -> {} bytes ({:.1}%)",
        manifest_cbor.len(),
        manifest_bytes.len(),
        (manifest_bytes.len() as f64 / manifest_cbor.len() as f64) * 100.0
    );
    let expected_manifest_digest = crate::manifest::io::compute_manifest_digest(&manifest_bytes);
    let expected_manifest_size = manifest_bytes.len() as u64;

    Ok((
        manifest_bytes,
        expected_manifest_digest,
        expected_manifest_size,
    ))
}

async fn upload_manifest(
    client: &reqwest::Client,
    url: &str,
    data: &[u8],
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<Option<String>> {
    upload_payload(client, url, data, "application/cbor", upload_headers).await
}

async fn upload_payload(
    client: &reqwest::Client,
    url: &str,
    data: &[u8],
    content_type: &str,
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<Option<String>> {
    let etag =
        crate::cas_transport::upload_payload(client, url, data, content_type, upload_headers)
            .await?;

    if etag.is_some() {
        log::debug!("Manifest uploaded with ETag: {:?}", etag);
    } else {
        log::warn!("Manifest upload response missing ETag header");
    }

    Ok(etag)
}

fn serialize_manifest(
    tag: &str,
    root_digest: &str,
    files: &[ManifestFile],
    encryption: Option<crate::manifest::EncryptionMetadata>,
    signature: Option<crate::manifest::SignatureMetadata>,
) -> Result<Vec<u8>> {
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
        encryption,
        signature,
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
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<(Option<String>, StorageMetrics)> {
    log::debug!(
        "Starting archive upload: path={} url={}",
        archive_path.display(),
        upload_url
    );

    upload_via_single_url(
        archive_path,
        upload_url,
        progress,
        transfer_client,
        upload_headers,
    )
    .await
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
    upload_headers: &std::collections::HashMap<String, String>,
) -> Result<(Option<String>, StorageMetrics)> {
    log::info!(
        "Starting multipart archive upload: path={} parts={} upload_id={}",
        archive_path.display(),
        part_urls.len(),
        upload_id
    );

    let (uploaded_parts, storage_metrics) = upload_via_part_urls(
        archive_path,
        part_urls,
        progress,
        transfer_client,
        upload_headers,
    )
    .await?;

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

    Ok((Some(response.archive_etag), storage_metrics))
}

fn format_phase_duration(duration: Duration) -> String {
    if duration.as_millis() >= 1_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

fn format_phase_duration_ms(ms: u64) -> String {
    if ms >= 1_000 {
        format!("{:.1}s", ms as f64 / 1000.0)
    } else {
        format!("{}ms", ms)
    }
}

#[cfg(test)]
mod tests {}
