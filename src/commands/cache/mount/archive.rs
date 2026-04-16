use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::api::ApiClient;
use crate::api::models::cache::{ConfirmRequest, SaveRequest};
use crate::cache::archive::create_tar_archive;
use crate::ci_detection::detect_ci_environment;
use crate::manifest::{EntryType, ManifestBuilder};
use crate::signing::policy::verify_restore_signature;
use crate::transfer::send_transfer_request_with_retry;
use crate::ui;

use super::RestoreAction;

#[allow(clippy::too_many_arguments)]
pub(super) async fn initial_restore_archive(
    api_client: &ApiClient,
    hit: &crate::api::models::cache::CacheResolutionEntry,
    local_path: &Path,
    verbose: bool,
    force: bool,
    identity: Option<String>,
    passphrase_cache: Arc<Mutex<crate::encryption::PassphraseCache>>,
    require_server_signature: bool,
) -> Result<RestoreAction> {
    let remote_manifest_digest = hit
        .manifest_root_digest
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest root digest in response"))?;

    if super::has_content(local_path)? {
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

    if remote_manifest_digest != &manifest.root.digest {
        let reason = format!(
            "Manifest digest mismatch for {} (expected {}, got {})",
            hit.tag, remote_manifest_digest, manifest.root.digest
        );
        ui::warn(&reason);
        return Ok(RestoreAction::NoRemoteCache);
    }

    verify_restore_signature(
        hit,
        &manifest.root.digest,
        Some(manifest.tag.as_str()),
        verbose,
        None,
        require_server_signature,
    )?;

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

    if let Some(expected_archive_digest) = manifest
        .archive
        .as_ref()
        .and_then(|archive| archive.content_hash.as_ref())
    {
        let actual_archive_digest = tokio::task::spawn_blocking({
            let archive_path = archive_path.clone();
            move || crate::cache::archive::compute_archive_digest(&archive_path)
        })
        .await
        .context("Archive digest task failed")??;

        if expected_archive_digest != &actual_archive_digest {
            let reason = format!(
                "Archive bytes digest mismatch for {} (expected {}, got {})",
                hit.tag, expected_archive_digest, actual_archive_digest
            );
            ui::warn(&reason);
            return Ok(RestoreAction::NoRemoteCache);
        }
    }

    let decrypted_temp_path;
    let final_archive_path: PathBuf = if hit.encrypted || manifest.encryption.is_some() {
        if verbose {
            ui::info("  Decrypting archive...");
        }

        let cached_passphrase = crate::encryption::cached_passphrase(&passphrase_cache)?;
        let decrypt_result = tokio::task::spawn_blocking({
            let archive_path = archive_path.clone();
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
                    let archive_path = archive_path.clone();
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
            let encrypted_size = std::fs::metadata(&archive_path)?.len();
            let decrypted_size = std::fs::metadata::<&Path>(decrypted_path.as_ref())?.len();
            ui::info(&format!(
                "  Decrypted archive: {} → {}",
                crate::progress::format_bytes(encrypted_size),
                crate::progress::format_bytes(decrypted_size)
            ));
        }

        let path = decrypted_path.to_path_buf();
        decrypted_temp_path = Some(decrypted_path);
        path
    } else {
        decrypted_temp_path = None;
        archive_path.clone()
    };

    if local_path.exists() {
        if !force {
            let path_buf = local_path.to_path_buf();
            let unsafe_reason =
                tokio::task::spawn_blocking(move || super::unsafe_mount_path_reason(&path_buf))
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

    crate::cache::archive::extract_tar_archive(
        &final_archive_path,
        local_path,
        verbose,
        false,
        None,
    )
    .await
    .context("Failed to extract archive")?;

    drop(decrypted_temp_path);

    Ok(RestoreAction::Downloaded)
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn sync_to_remote_archive(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    encrypt: bool,
    recipient: Option<String>,
) -> Result<()> {
    let path_buf = local_path.to_path_buf();
    let draft = tokio::task::spawn_blocking(move || {
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
            &[crate::api::models::cache::ManifestCheckRequest {
                tag: resolved_tag.to_string(),
                manifest_root_digest: manifest_root_digest.clone(),
                lookup: None,
            }],
        )
        .await;

    if let Ok(response) = check_response
        && let Some(result) = response.results.first()
    {
        if super::manifest_check_is_ready(result) {
            if verbose {
                ui::info("  Cache already up to date");
            }
            return Ok(());
        }

        if super::manifest_check_is_pending(result) {
            if verbose {
                ui::info("  Remote cache publish pending; skipping duplicate publish");
            }
            return Ok(());
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

    let (final_archive_path, final_compressed_size, archive_content_hash) = if encrypt {
        if verbose {
            ui::info("  Encrypting archive...");
        }
        let age_recipient = age_recipient.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "Encryption enabled but no recipient configured. Run `boringcache setup-encryption <workspace>` or pass --recipient."
            )
        })?;

        let encrypted_archive = crate::cache::archive::encrypt_archive(
            archive_info.archive_path.as_ref(),
            age_recipient,
        )?;

        if verbose {
            ui::info(&format!(
                "  Encrypted archive: {} → {}",
                crate::progress::format_bytes(archive_info.compressed_size),
                crate::progress::format_bytes(encrypted_archive.size_bytes)
            ));
        }

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
        archive: Some(crate::manifest::ManifestArchive {
            content_hash: Some(archive_content_hash),
            compression: "zstd".to_string(),
            created_at: chrono::Utc::now(),
        }),
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
    let use_multipart = crate::cache::archive::should_use_multipart_upload(final_compressed_size);

    let ci_provider = detect_ci_environment();
    let request = SaveRequest {
        tag: resolved_tag.to_string(),
        write_scope_tag: None,
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        storage_mode: None,
        blob_count: None,
        blob_total_size_bytes: None,
        cas_layout: None,
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: Some(archive_info.uncompressed_size),
        compressed_size: Some(final_compressed_size),
        file_count: Some(file_count),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(manifest_bytes.len() as u64),
        force: Some(true),
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
        if !save_response.upload_headers.is_empty()
            && let Some(regions) = save_response.upload_headers.get("x-tigris-regions")
        {
            let count = regions.split(',').count();
            ui::info(&format!("  Replication: {} regions ({})", count, regions));
        }
    }

    let transfer_client = api_client.transfer_client();
    let progress = crate::progress::TransferProgress::new_noop();

    let archive_etag = if let Some(upload_id) = save_response.get_upload_id() {
        let (uploaded_parts, _storage_metrics) =
            crate::cache::multipart_upload::upload_via_part_urls(
                final_archive_path.as_ref(),
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
        let (etag, _storage_metrics) = crate::cache::multipart_upload::upload_via_single_url(
            final_archive_path.as_ref(),
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
        archive_size: Some(final_compressed_size),
        archive_etag,
        blob_count: None,
        blob_total_size_bytes: None,
        file_count: Some(file_count),
        uncompressed_size: Some(archive_info.uncompressed_size),
        compressed_size: Some(final_compressed_size),
        storage_mode: Some("archive".to_string()),
        tag: Some(resolved_tag.to_string()),
        write_scope_tag: None,
    };

    let confirm_response = api_client
        .confirm(workspace, &save_response.cache_entry_id, &confirm_request)
        .await?;
    super::ensure_mount_sync_won(
        &save_response.cache_entry_id,
        &confirm_response,
        resolved_tag,
    )?;

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
