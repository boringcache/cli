use anyhow::{Context, Result};
use notify_debouncer_mini::{new_debouncer, notify::RecursiveMode, DebounceEventResult};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::api::models::cache::{ConfirmRequest, ManifestCheckRequest, SaveRequest};
use crate::api::ApiClient;
use crate::archive::create_tar_archive;
use crate::ci_detection::detect_ci_environment;
use crate::manifest::{EntryType, ManifestBuilder};
use crate::transfer::send_transfer_request_with_retry;
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

pub async fn execute(
    workspace: String,
    tag_path: String,
    verbose: bool,
    force: bool,
    recipient: Option<String>,
    identity: Option<String>,
) -> Result<()> {
    let (tag, local_path) = parse_tag_path(&tag_path)?;
    let expanded_path = crate::commands::utils::expand_tilde_path(&local_path);
    let local_path = PathBuf::from(&expanded_path);

    crate::api::parse_workspace_slug(&workspace)?;
    crate::tag_utils::validate_tag(&tag)?;

    let platform = Some(crate::platform::Platform::detect()?);
    let git_enabled = !crate::git::is_git_disabled_by_env();
    let git_context = if git_enabled {
        crate::git::GitContext::detect_with_path(Some(&expanded_path))
    } else {
        crate::git::GitContext::default()
    };
    let tag_resolver = crate::tag_utils::TagResolver::new(platform, git_context, git_enabled);
    let resolved_tag = tag_resolver.effective_save_tag(&tag)?;

    let api_client = ApiClient::new()?;

    api_client
        .get_token()
        .context("No configuration found. Run 'boringcache auth' to authenticate.")?;

    let (encrypt, recipient) =
        crate::commands::utils::resolve_encryption_config(&workspace, recipient)?;
    let passphrase_cache = Arc::new(Mutex::new(crate::encryption::PassphraseCache::default()));

    ui::info(&format!(
        "Mounting {} -> {}",
        resolved_tag,
        local_path.display()
    ));

    let restore_result = initial_restore(
        &api_client,
        &workspace,
        &resolved_tag,
        &local_path,
        verbose,
        force,
        identity.clone(),
        passphrase_cache.clone(),
    )
    .await?;

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
                encrypt,
                recipient.clone(),
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
                    encrypt,
                    recipient.clone(),
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
        encrypt,
        recipient,
    )
    .await
}

fn parse_tag_path(tag_path: &str) -> Result<(String, String)> {
    let trimmed = tag_path.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "Invalid tag:path format. Expected 'tag:path', got '{}'",
            tag_path
        );
    }

    let (tag_raw, path_raw) = trimmed.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid tag:path format. Expected 'tag:path', got '{}'",
            tag_path
        )
    })?;

    let tag = tag_raw.trim();
    if tag.is_empty() {
        anyhow::bail!("Tag is missing in '{}'. Add a tag before ':'.", tag_path);
    }

    let path = path_raw.trim();
    if path.is_empty() {
        anyhow::bail!("Path is missing in '{}'. Add a path after ':'.", tag_path);
    }

    Ok((tag.to_string(), path.to_string()))
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

fn unsafe_mount_path_reason(path: &Path) -> Result<Option<&'static str>> {
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let canonical_path = absolute_path.canonicalize().unwrap_or(absolute_path);

    let is_root = canonical_path.has_root()
        && !canonical_path
            .components()
            .any(|component| matches!(component, Component::Normal(_)));
    if is_root {
        return Ok(Some("root directory"));
    }

    if let Some(home_dir) = dirs::home_dir() {
        let home_dir = home_dir.canonicalize().unwrap_or(home_dir);
        if canonical_path == home_dir {
            return Ok(Some("home directory"));
        }
    }

    let cwd = std::env::current_dir()?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    if canonical_path == cwd {
        return Ok(Some("workspace root"));
    }

    Ok(None)
}

#[allow(clippy::too_many_arguments)]
async fn initial_restore(
    api_client: &ApiClient,
    workspace: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    force: bool,
    identity: Option<String>,
    passphrase_cache: Arc<Mutex<crate::encryption::PassphraseCache>>,
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

    let manifest_future = send_transfer_request_with_retry("Manifest fetch", || async {
        Ok(client.get(manifest_url).send().await?)
    });
    let archive_head_future = client.head(archive_url).send();
    let (manifest_result, head_result) = tokio::join!(manifest_future, archive_head_future);

    let manifest_response = manifest_result?
        .error_for_status()
        .context("Manifest request failed")?;

    let mut actual_archive_size = match head_result {
        Ok(resp) => {
            if !resp.status().is_success() {
                log::debug!(
                    "Archive HEAD warm failed (non-fatal): HTTP {}",
                    resp.status()
                );
                None
            } else {
                resp.headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok())
            }
        }
        Err(e) => {
            log::debug!("Archive HEAD warm failed (non-fatal): {}", e);
            None
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
            ui::warn(&reason);
            return Ok(RestoreAction::NoRemoteCache);
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
        match crate::encryption::decrypt_bytes(
            &manifest_bytes_raw,
            age_identity.as_ref(),
            cached_passphrase.as_deref(),
        ) {
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

    if remote_manifest_digest != &manifest.root.digest {
        let reason = format!(
            "Manifest digest mismatch for {} (expected {}, got {})",
            hit.tag, remote_manifest_digest, manifest.root.digest
        );
        ui::warn(&reason);
        return Ok(RestoreAction::NoRemoteCache);
    }

    match (&hit.workspace_signing_public_key, &hit.server_signature) {
        (Some(workspace_key), Some(server_sig)) => {
            match crate::signing::parse_public_key(workspace_key)
                .and_then(|pk| {
                    crate::signing::signature_from_base64(server_sig).map(|sig| (pk, sig))
                })
                .and_then(|(pk, sig)| {
                    let data = format!("{}:{}", manifest.tag.as_str(), manifest.root.digest);
                    crate::signing::verify_signature(data.as_bytes(), &sig, &pk)
                }) {
                Ok(()) => {
                    if verbose {
                        ui::info("  Server signature verified");
                    }
                }
                Err(e) => {
                    ui::warn(&format!("Server signature verification failed: {}", e));
                }
            }
        }
        (Some(_), None) => {
            ui::warn(&format!(
                "Server signature missing for {}; authenticity not verified",
                manifest.tag.as_str()
            ));
        }
        (None, Some(_)) => {
            ui::warn(&format!(
                "Workspace signing key missing for {}; cannot verify server signature",
                manifest.tag.as_str()
            ));
        }
        (None, None) => {}
    }

    if actual_archive_size.is_none() && hit.compressed_size.is_none() {
        actual_archive_size =
            crate::commands::restore::probe_archive_size(client, archive_url).await;
    }

    let expected_compressed = actual_archive_size.or(hit.compressed_size).unwrap_or(0);

    if verbose {
        ui::info(&format!(
            "  Downloading archive ({} files, {})...",
            manifest.files.len(),
            crate::types::ByteSize::new(expected_compressed)
        ));
    }

    let temp_dir = tempfile::tempdir().context("Failed to create temp directory")?;
    let archive_path = temp_dir.path().join("archive.tar.zst");

    let _bytes_downloaded = crate::commands::restore::download_archive(
        client,
        archive_url,
        &archive_path,
        expected_compressed,
        None,
    )
    .await?;

    let final_archive_path = if hit.encrypted || manifest.encryption.is_some() {
        if verbose {
            ui::info("  Decrypting archive...");
        }

        let cached_passphrase = crate::encryption::cached_passphrase(&passphrase_cache)?;
        let decrypt_result = tokio::task::spawn_blocking({
            let archive_path = archive_path.clone();
            let passphrase = cached_passphrase.clone();
            let age_identity = age_identity.clone();
            move || {
                crate::archive::decrypt_archive(
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
                tokio::task::spawn_blocking({
                    let archive_path = archive_path.clone();
                    let passphrase = passphrase.clone();
                    let age_identity = age_identity.clone();
                    move || {
                        crate::archive::decrypt_archive(
                            &archive_path,
                            age_identity.as_ref(),
                            passphrase.as_deref(),
                        )
                    }
                })
                .await
                .context("Decryption task failed")??
            }
            Err(err) => return Err(err),
        };

        if verbose {
            let encrypted_size = std::fs::metadata(&archive_path)?.len();
            let decrypted_size = std::fs::metadata::<&Path>(decrypted_path.as_ref())?.len();
            ui::info(&format!(
                "  Decrypted archive: {} → {}",
                crate::progress::format_bytes(encrypted_size),
                crate::progress::format_bytes(decrypted_size)
            ));
        }

        decrypted_path.to_path_buf()
    } else {
        archive_path.clone()
    };

    if local_path.exists() {
        if !force {
            let path_buf = local_path.to_path_buf();
            let unsafe_reason =
                tokio::task::spawn_blocking(move || unsafe_mount_path_reason(&path_buf))
                    .await
                    .context("Path safety check panicked")??;
            if let Some(reason) = unsafe_reason {
                let message = format!(
                    "Refusing to clear {} ({}) without --force",
                    local_path.display(),
                    reason
                );
                ui::warn(&message);
                return Ok(RestoreAction::NoRemoteCache);
            }
        }

        tokio::fs::remove_dir_all(local_path)
            .await
            .with_context(|| {
                format!(
                    "Failed to clear existing directory: {}",
                    local_path.display()
                )
            })?;
    }
    tokio::fs::create_dir_all(local_path).await?;

    crate::archive::extract_tar_archive(&final_archive_path, local_path, verbose, None)
        .await
        .context("Failed to extract archive")?;

    Ok(RestoreAction::Downloaded)
}

#[allow(clippy::too_many_arguments)]
async fn watch_and_sync(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    shutdown: Arc<AtomicBool>,
    encrypt: bool,
    recipient: Option<String>,
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
                encrypt,
                recipient.clone(),
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
                encrypt,
                recipient.clone(),
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

            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sync_to_remote(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    encrypt: bool,
    recipient: Option<String>,
) -> Result<()> {
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

    if total_size_bytes == 0 {
        anyhow::bail!(
            "Cannot sync {} -> {}: no file content to upload (0 bytes)",
            resolved_tag,
            local_path.display()
        );
    }

    let check_response = api_client
        .check_manifests(
            workspace,
            &[ManifestCheckRequest {
                tag: resolved_tag.to_string(),
                manifest_root_digest: manifest_root_digest.clone(),
                lookup: None,
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

    let recipient_str = if encrypt {
        Some(
            recipient.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
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

    let (final_archive_path, final_compressed_size) = if encrypt {
        if verbose {
            ui::info("  Encrypting archive...");
        }
        let age_recipient = age_recipient.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Encryption enabled but no recipient configured. Run `boringcache setup-encryption <workspace>` or pass --recipient."
            )
        })?;

        let encrypted_path =
            crate::archive::encrypt_archive(archive_info.archive_path.as_ref(), age_recipient)?;
        let encrypted_size = std::fs::metadata::<&std::path::Path>(encrypted_path.as_ref())?.len();

        if verbose {
            ui::info(&format!(
                "  Encrypted archive: {} → {}",
                crate::progress::format_bytes(archive_info.compressed_size),
                crate::progress::format_bytes(encrypted_size)
            ));
        }

        (encrypted_path.to_path_buf(), encrypted_size)
    } else {
        (
            archive_info.archive_path.to_path_buf(),
            archive_info.compressed_size,
        )
    };

    let encryption_metadata = if encrypt {
        Some(crate::manifest::EncryptionMetadata {
            algorithm: crate::encryption::ENCRYPTION_ALGORITHM_AGE_X25519.to_string(),
            recipient_hint: recipient_str.map(crate::encryption::recipient_hint),
            encrypted_at: chrono::Utc::now(),
        })
    } else {
        None
    };

    let manifest = crate::manifest::Manifest {
        format_version: 1,
        tag: resolved_tag.to_string(),
        root: crate::manifest::ManifestRoot {
            digest: manifest_root_digest.clone(),
            algo: "sha256".to_string(),
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
        encryption: encryption_metadata,
        signature: None,
    };

    let mut manifest_cbor = Vec::new();
    ciborium::into_writer(&manifest, &mut manifest_cbor).context("Failed to serialize manifest")?;
    let manifest_bytes = crate::manifest::io::compress_manifest(&manifest_cbor)?;
    let manifest_bytes = if let Some(ref recipient) = age_recipient {
        crate::encryption::encrypt_data(&manifest_bytes, recipient)?
    } else {
        manifest_bytes
    };

    let expected_manifest_digest = crate::manifest::io::compute_manifest_digest(&manifest_bytes);

    let use_multipart = crate::archive::should_use_multipart_upload(final_compressed_size);

    let ci_provider = detect_ci_environment();
    let request = SaveRequest {
        tag: resolved_tag.to_string(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: Some(archive_info.uncompressed_size),
        compressed_size: Some(final_compressed_size),
        file_count: Some(file_count),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(manifest_bytes.len() as u64),
        force: None,
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
            crate::types::ByteSize::new(final_compressed_size)
        ));
        if !save_response.upload_headers.is_empty() {
            if let Some(regions) = save_response.upload_headers.get("x-tigris-regions") {
                let count = regions.split(',').count();
                ui::info(&format!("  Replication: {} regions ({})", count, regions));
            }
        }
    }

    let transfer_client = api_client.transfer_client();
    let progress = crate::progress::TransferProgress::new_noop();

    let archive_etag = if save_response.get_upload_id().is_some() {
        let upload_id = save_response.get_upload_id().unwrap();
        let (uploaded_parts, _storage_metrics) = crate::multipart_upload::upload_via_part_urls(
            &final_archive_path,
            archive_urls,
            &progress,
            transfer_client,
            &save_response.upload_headers,
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
        let (etag, _storage_metrics) = crate::multipart_upload::upload_via_single_url(
            &final_archive_path,
            &archive_urls[0],
            &progress,
            transfer_client,
            &save_response.upload_headers,
        )
        .await?;
        etag
    };

    if verbose {
        ui::info("  Uploading manifest...");
    }

    let manifest_url = save_response
        .manifest_upload_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest upload URL in response"))?;

    let manifest_response = send_transfer_request_with_retry("Manifest upload", || async {
        let mut manifest_request = transfer_client
            .put(manifest_url)
            .header("Content-Type", "application/cbor")
            .header("Content-Length", manifest_bytes.len().to_string());

        for (key, value) in &save_response.upload_headers {
            manifest_request = manifest_request.header(key.as_str(), value.as_str());
        }

        Ok(manifest_request.body(manifest_bytes.clone()).send().await?)
    })
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
        manifest_size: manifest_bytes.len() as u64,
        manifest_etag,
        archive_size: final_compressed_size,
        archive_etag,
        file_count: Some(file_count),
        uncompressed_size: Some(archive_info.uncompressed_size),
        compressed_size: Some(final_compressed_size),
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
            crate::progress::format_bytes(final_compressed_size)
        ));
    }

    Ok(())
}
