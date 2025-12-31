use anyhow::{Context, Result};
use notify_debouncer_mini::{new_debouncer, notify::RecursiveMode, DebounceEventResult};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

use crate::api::models::cache::{ConfirmRequest, ManifestCheckRequest, SaveRequest};
use crate::api::ApiClient;
use crate::archive::create_tar_archive;
use crate::manifest::{EntryType, ManifestBuilder};
use crate::ui;

const DEBOUNCE_TIMEOUT_SECS: u64 = 5;
const MIN_CHANGES_TO_SYNC: usize = 50;
const IDLE_SYNC_SECS: u64 = 60;

enum RestoreAction {
    Downloaded,
    AlreadyInSync,
    LocalDiffers,
    NoRemoteCache,
}

pub async fn execute(workspace: String, tag_path: String, verbose: bool) -> Result<()> {
    let (tag, local_path) = parse_tag_path(&tag_path)?;
    let expanded_path = crate::commands::utils::expand_tilde_path(&local_path);
    let local_path = PathBuf::from(&expanded_path);

    crate::api::parse_workspace_slug(&workspace)?;
    crate::tag_utils::validate_tag(&tag)?;

    let platform = Some(crate::platform::Platform::detect()?);
    let resolved_tag =
        crate::tag_utils::apply_platform_to_tag_with_instance(&tag, platform.as_ref());

    let api_client = ApiClient::new()?;

    api_client
        .get_token()
        .context("No configuration found. Run 'boringcache auth' to authenticate.")?;

    ui::info(&format!(
        "Mounting {} -> {}",
        resolved_tag,
        local_path.display()
    ));

    let restore_result =
        initial_restore(&api_client, &workspace, &resolved_tag, &local_path, verbose).await?;

    match restore_result {
        RestoreAction::Downloaded => {
            ui::info("  Restored from remote cache");
        }
        RestoreAction::AlreadyInSync => {
            ui::info("  Local content in sync with remote");
        }
        RestoreAction::LocalDiffers => {
            ui::info("  Local content differs, syncing to remote...");
            sync_to_remote(
                &api_client,
                &workspace,
                &tag,
                &resolved_tag,
                &local_path,
                verbose,
            )
            .await?;
        }
        RestoreAction::NoRemoteCache => {
            ui::info("  No remote cache found, using local state");
            ensure_local_directory(&local_path)?;

            if has_content(&local_path)? {
                ui::info("  Performing initial sync of existing content...");
                sync_to_remote(
                    &api_client,
                    &workspace,
                    &tag,
                    &resolved_tag,
                    &local_path,
                    verbose,
                )
                .await?;
            }
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    ui::info(&format!(
        "Watching {} for changes (Ctrl+C to stop)...",
        local_path.display()
    ));

    watch_and_sync(
        &api_client,
        &workspace,
        &tag,
        &resolved_tag,
        &local_path,
        verbose,
        shutdown,
    )
    .await
}

fn parse_tag_path(tag_path: &str) -> Result<(String, String)> {
    let parts: Vec<&str> = tag_path.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "Invalid tag:path format. Expected 'tag:path', got '{}'",
            tag_path
        );
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn ensure_local_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
    }
    Ok(())
}

fn has_content(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let entries = std::fs::read_dir(path)
        .with_context(|| format!("Failed to read directory: {}", path.display()))?;
    Ok(entries.count() > 0)
}

async fn initial_restore(
    api_client: &ApiClient,
    workspace: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
) -> Result<RestoreAction> {
    let resolution_result = api_client
        .restore(workspace, &[resolved_tag.to_string()])
        .await;

    let hits = match resolution_result {
        Ok(entries) => entries
            .into_iter()
            .filter(|e| e.status == "hit")
            .collect::<Vec<_>>(),
        Err(e) => {
            if verbose {
                ui::warn(&format!("  Failed to check remote cache: {}", e));
            }
            return Ok(RestoreAction::NoRemoteCache);
        }
    };

    if hits.is_empty() {
        return Ok(RestoreAction::NoRemoteCache);
    }

    let hit = &hits[0];

    let remote_manifest_digest = hit
        .manifest_root_digest
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest root digest in response"))?;

    if has_content(local_path)? {
        if verbose {
            ui::info("  Computing local manifest digest...");
        }
        let path_buf = local_path.to_path_buf();
        let local_digest = tokio::task::spawn_blocking(move || {
            let builder = ManifestBuilder::new(&path_buf);
            builder
                .build()
                .map(|draft| crate::manifest::diff::compute_digest_from_draft(&draft))
        })
        .await
        .context("Manifest build task panicked")??;

        if &local_digest == remote_manifest_digest {
            if verbose {
                ui::info("  Local content matches remote");
            }
            return Ok(RestoreAction::AlreadyInSync);
        }
        // Local differs from remote - local is source of truth, will sync on watch
        if verbose {
            ui::info("  Local content differs from remote, will sync local changes");
        }
        return Ok(RestoreAction::LocalDiffers);
    }

    let archive_url = hit
        .archive_urls
        .first()
        .ok_or_else(|| anyhow::anyhow!("No archive URL in response"))?;

    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest URL in response"))?;

    if verbose {
        ui::info("  Downloading manifest...");
    }

    let client = api_client.transfer_client();

    let manifest_bytes = client
        .get(manifest_url)
        .send()
        .await?
        .error_for_status()
        .context("Manifest request failed")?
        .bytes()
        .await?
        .to_vec();

    let manifest: crate::manifest::Manifest =
        ciborium::from_reader(&manifest_bytes[..]).context("Failed to parse manifest")?;

    if verbose {
        ui::info(&format!(
            "  Downloading archive ({} files, {})...",
            manifest.files.len(),
            crate::types::ByteSize::new(hit.size.unwrap_or(0))
        ));
    }

    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let archive_path = temp_dir.path().join("archive.tar.zst");

    download_archive(client, archive_url, &archive_path).await?;

    if local_path.exists() {
        std::fs::remove_dir_all(local_path).with_context(|| {
            format!(
                "Failed to clear existing directory: {}",
                local_path.display()
            )
        })?;
    }
    std::fs::create_dir_all(local_path)?;

    crate::archive::extract_tar_archive(&archive_path, local_path, verbose, None)
        .await
        .context("Failed to extract archive")?;

    Ok(RestoreAction::Downloaded)
}

async fn download_archive(client: &reqwest::Client, url: &str, file_path: &Path) -> Result<()> {
    use futures_util::StreamExt;
    use tokio::io::{AsyncWriteExt, BufWriter};

    let response = client.get(url).send().await?.error_for_status()?;
    let file = tokio::fs::File::create(file_path).await?;
    let mut writer = BufWriter::new(file);
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        writer.write_all(&chunk).await?;
    }

    writer.flush().await?;
    Ok(())
}

async fn watch_and_sync(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<DebounceEventResult>(100);

    let tx_clone = tx.clone();
    let mut debouncer = new_debouncer(
        Duration::from_secs(DEBOUNCE_TIMEOUT_SECS),
        move |res: DebounceEventResult| {
            let _ = tx_clone.blocking_send(res);
        },
    )
    .context("Failed to create file watcher")?;

    debouncer
        .watcher()
        .watch(local_path, RecursiveMode::Recursive)
        .with_context(|| format!("Failed to watch directory: {}", local_path.display()))?;

    let mut pending_changes: usize = 0;
    let mut last_change_time = std::time::Instant::now();
    let mut has_pending = false;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            ui::info("Shutting down...");

            if let Err(e) = sync_to_remote(
                api_client,
                workspace,
                base_tag,
                resolved_tag,
                local_path,
                verbose,
            )
            .await
            {
                ui::warn(&format!("  Final sync failed: {}", e));
            }
            break;
        }

        let should_sync = has_pending
            && (pending_changes >= MIN_CHANGES_TO_SYNC
                || last_change_time.elapsed() >= Duration::from_secs(IDLE_SYNC_SECS));

        if should_sync {
            if verbose {
                ui::info(&format!(
                    "  Syncing {} accumulated change(s)...",
                    pending_changes
                ));
            }
            if let Err(e) = sync_to_remote(
                api_client,
                workspace,
                base_tag,
                resolved_tag,
                local_path,
                verbose,
            )
            .await
            {
                ui::warn(&format!("  Sync failed: {}", e));
            }
            pending_changes = 0;
            has_pending = false;
        }

        tokio::select! {
            Some(event_result) = rx.recv() => {
                match event_result {
                    Ok(events) => {
                        if !events.is_empty() {
                            pending_changes += events.len();
                            last_change_time = std::time::Instant::now();
                            has_pending = true;

                            // Drain any additional pending events
                            while let Ok(more) = rx.try_recv() {
                                if let Ok(more_events) = more {
                                    pending_changes += more_events.len();
                                }
                            }

                            if verbose {
                                ui::info(&format!(
                                    "  Detected changes ({} pending, sync at {} or after {}s idle)",
                                    pending_changes, MIN_CHANGES_TO_SYNC, IDLE_SYNC_SECS
                                ));
                            }
                        }
                    }
                    Err(errors) => {
                        ui::warn(&format!("  Watch error: {:?}", errors));
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                // Check shutdown flag and idle timeout periodically
            }
        }
    }

    Ok(())
}

async fn sync_to_remote(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    use tokio::task;

    let path_buf = local_path.to_path_buf();
    let draft = task::spawn_blocking(move || {
        let builder = ManifestBuilder::new(&path_buf);
        builder.build()
    })
    .await
    .context("Manifest build task panicked")??;

    let manifest_root_digest = crate::manifest::diff::compute_digest_from_draft(&draft);
    let file_count = draft
        .descriptors
        .iter()
        .filter(|d| d.entry_type == EntryType::File)
        .count() as u32;
    let total_size_bytes = draft.raw_size;

    let check_response = api_client
        .check_manifests(
            workspace,
            &[ManifestCheckRequest {
                tag: resolved_tag.to_string(),
                manifest_root_digest: manifest_root_digest.clone(),
            }],
        )
        .await;

    if let Ok(response) = check_response {
        if let Some(result) = response.results.first() {
            if result.exists {
                if verbose {
                    ui::info("  Cache already up to date");
                }
                return Ok(());
            }
        }
    }

    if verbose {
        ui::info("  Creating archive...");
    }

    let local_path_str = local_path.to_string_lossy().to_string();
    let archive_info = create_tar_archive(&draft, &local_path_str, verbose, None)
        .await
        .context("Failed to create archive")?;

    let manifest = crate::manifest::Manifest {
        format_version: 1,
        tag: resolved_tag.to_string(),
        root: crate::manifest::ManifestRoot {
            digest: manifest_root_digest.clone(),
            algo: "blake3".to_string(),
        },
        summary: crate::manifest::ManifestSummary {
            file_count: file_count as u64,
            raw_size: draft.raw_size,
            changed_count: file_count as u64,
            removed_count: 0,
        },
        entry: None,
        archive: None,
        files: archive_info.manifest_files.clone(),
    };

    let mut manifest_buffer = Vec::new();
    ciborium::into_writer(&manifest, &mut manifest_buffer)
        .context("Failed to serialize manifest")?;

    let mut hasher = Sha256::new();
    hasher.update(&manifest_buffer);
    let manifest_digest_bytes = hasher.finalize();
    let expected_manifest_digest = manifest_digest_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    let use_multipart = crate::archive::should_use_multipart_upload(archive_info.compressed_size);

    let request = SaveRequest {
        tag: resolved_tag.to_string(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: Some(archive_info.uncompressed_size),
        compressed_size: Some(archive_info.compressed_size),
        file_count: Some(file_count),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(manifest_buffer.len() as u64),
        force: None,
        use_multipart: Some(use_multipart),
    };

    if verbose {
        ui::info("  Requesting upload URLs...");
    }

    let save_response = api_client.save_entry(workspace, &request).await?;

    if save_response.exists {
        if verbose {
            ui::info("  Cache already exists on server");
        }
        return Ok(());
    }

    let archive_urls = save_response.get_archive_urls();
    if archive_urls.is_empty() {
        anyhow::bail!("No archive upload URL in response");
    }

    if verbose {
        ui::info(&format!(
            "  Uploading archive ({})...",
            crate::types::ByteSize::new(archive_info.compressed_size)
        ));
    }

    let transfer_client = api_client.transfer_client();
    let progress = crate::progress::TransferProgress::new_noop();

    let archive_etag = if save_response.get_upload_id().is_some() {
        let upload_id = save_response.get_upload_id().unwrap();
        let uploaded_parts = crate::multipart_upload::upload_via_part_urls(
            archive_info.archive_path.as_ref(),
            archive_urls,
            &progress,
            transfer_client,
        )
        .await?;

        let complete_response = api_client
            .complete_multipart(
                workspace,
                &save_response.cache_entry_id,
                &crate::api::models::cache::CompleteMultipartRequest {
                    upload_id: upload_id.to_string(),
                    parts: uploaded_parts,
                },
            )
            .await?;
        Some(complete_response.archive_etag)
    } else {
        crate::multipart_upload::upload_via_single_url(
            archive_info.archive_path.as_ref(),
            &archive_urls[0],
            &progress,
            transfer_client,
        )
        .await?
    };

    if verbose {
        ui::info("  Uploading manifest...");
    }

    let manifest_url = save_response
        .manifest_upload_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest upload URL in response"))?;

    let manifest_response = transfer_client
        .put(manifest_url)
        .header("Content-Type", "application/cbor")
        .header("Content-Length", manifest_buffer.len().to_string())
        .body(manifest_buffer.clone())
        .send()
        .await?;

    if !manifest_response.status().is_success() {
        anyhow::bail!(
            "Manifest upload failed: HTTP {}",
            manifest_response.status()
        );
    }

    let manifest_etag = manifest_response
        .headers()
        .get("etag")
        .and_then(|e| e.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());

    if verbose {
        ui::info("  Confirming upload...");
    }

    let confirm_request = ConfirmRequest {
        manifest_digest: expected_manifest_digest,
        manifest_size: manifest_buffer.len() as u64,
        manifest_etag,
        archive_size: archive_info.compressed_size,
        archive_etag,
        file_count: Some(file_count),
        uncompressed_size: Some(archive_info.uncompressed_size),
        compressed_size: Some(archive_info.compressed_size),
        tag: None,
    };

    api_client
        .confirm(workspace, &save_response.cache_entry_id, &confirm_request)
        .await?;

    if verbose {
        ui::info(&format!(
            "  Synced {} ({} files, {})",
            base_tag,
            file_count,
            crate::progress::format_bytes(archive_info.compressed_size)
        ));
    }

    Ok(())
}
