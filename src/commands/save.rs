use anyhow::{anyhow, Context, Error, Result};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::task;

use crate::api::models::cache::{
    ConfirmRequest, ManifestCheckRequest, SaveChunkMetadata, SaveRequest,
};
use crate::api::ApiClient;
use crate::chunks::{chunk_all_files_streaming, ChunkRef, ChunkUploader};
use crate::manifest::diff::compute_digest_from_draft;
use crate::manifest::{EntryType, ManifestBuilder, ManifestFile};
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
            .map(|err| err.to_string())
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
        8,
    )?;
    let overall_started = Instant::now();
    let fetch_manifest_duration: Option<Duration> = None;
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

    let step2 = session.start_step("Computing digest".to_string(), None)?;
    let manifest_root_digest = compute_digest_from_draft(&draft);
    step2.complete()?;

    let file_count = draft
        .descriptors
        .iter()
        .filter(|d| d.entry_type == EntryType::File)
        .count() as u32;
    let total_size_bytes = draft.raw_size;

    let check_step = session.start_step("Checking existing cache".to_string(), None)?;
    let check_response = api_client
        .check_manifests(
            &workspace,
            &[ManifestCheckRequest {
                tag: tag.clone(),
                manifest_root_digest: manifest_root_digest.clone(),
                chunk_digests: None,
            }],
        )
        .await;

    let mut manifest_exists_on_server = false;

    match check_response {
        Ok(response) => {
            if let Some(result) = response.results.first() {
                let is_pending = result.status.as_deref() == Some("pending");
                if result.exists && !is_pending {
                    manifest_exists_on_server = true;
                    check_step.update_progress(100.0, Some("cache hit on server".to_string()))?;
                }
            }
        }
        Err(err) => {
            log::warn!(
                "cache manifest check failed for tag {} in workspace {}: {}",
                tag,
                workspace,
                err
            );
            ui::warn(&format!(
                "  Manifest check failed ({}); proceeding with full upload",
                err
            ));
            check_step.update_progress(100.0, Some("failed; proceeding".to_string()))?;
        }
    }

    check_step.complete()?;

    if manifest_exists_on_server && !force {
        ui::info("  Cache entry already present on server; skipping upload");
        complete_skipped_step(
            &mut session,
            "Chunking files",
            "skipped — cache already exists on server",
        )?;
        complete_skipped_step(
            &mut session,
            "Creating cache entry",
            "skipped — cache already exists on server",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading chunks",
            "skipped — all chunks already exist",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading manifest",
            "skipped — cache already exists on server",
        )?;
        complete_skipped_step(
            &mut session,
            "Confirming upload",
            "skipped — cache already exists on server",
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
        ui::info(&format!(
            "Completed saving {} ({} files, {})",
            tag,
            file_count,
            format_bytes(total_size_bytes)
        ));
        ui::info(&format!("    Path: {}", path));
        return Ok(SaveStatus::AlreadyExists);
    }

    // Simplified model: always rebuild manifest fresh. No previous-manifest fetch or reuse.
    // This avoids stale metadata and keeps client generic across cache types.

    let total_uncompressed_size: u64 = draft.raw_size;

    // Always chunk all files and build a brand-new manifest
    let mut _temp_dir: Option<tempfile::TempDir> = None;

    let detail = Some(format!("{} files", file_count));
    let chunk_step = session.start_step("Chunking files".to_string(), detail)?;
    _temp_dir = Some(tempfile::tempdir()?);
    let chunks_dir = _temp_dir
        .as_ref()
        .expect("temporary directory should exist")
        .path()
        .join("chunks");

    let chunk_started = Instant::now();
    let (all_chunk_refs, all_manifest_files) =
        chunk_all_files_streaming(&draft, path.as_str(), chunks_dir, verbose).await?;
    let chunk_duration = chunk_started.elapsed();
    chunk_step.complete()?;

    // Deduplicate chunk refs by digest and sort by start_offset
    let mut unique_new: HashMap<String, ChunkRef> = HashMap::new();
    for chunk in all_chunk_refs {
        unique_new.entry(chunk.hash.clone()).or_insert(chunk);
    }
    let mut unique_chunk_refs: Vec<ChunkRef> = unique_new.into_values().collect();
    unique_chunk_refs.sort_by_key(|chunk| chunk.start_offset);

    // Build chunk metadata map for manifest
    let mut chunk_metadata: HashMap<String, crate::manifest::ChunkMeta> = HashMap::new();
    for chunk in &unique_chunk_refs {
        chunk_metadata.insert(chunk.hash.clone(), chunk_meta_from_ref(chunk));
    }

    let manifest_files_combined: Vec<ManifestFile> = all_manifest_files;

    let chunk_digests = collect_required_chunk_digests(&manifest_files_combined);
    let mut manifest_chunk_metadata = Vec::with_capacity(chunk_digests.len());
    for digest in &chunk_digests {
        let meta = chunk_metadata
            .get(digest)
            .cloned()
            .with_context(|| format!("Missing chunk metadata for {}", digest))?;
        manifest_chunk_metadata.push(meta);
    }

    let total_compressed_size: u64 = manifest_chunk_metadata
        .iter()
        .map(|meta| meta.compressed_size)
        .sum();

    let chunk_metadata_for_request = build_chunk_metadata_for_request(&manifest_chunk_metadata);

    // Precompute expected manifest (CBOR) to include digest and size in save request
    // This must match the manifest we later upload.
    let manifest_bytes = serialize_manifest(
        &tag,
        &manifest_root_digest,
        &manifest_files_combined,
        &manifest_chunk_metadata,
    )?;
    let expected_manifest_digest = compute_manifest_digest(&manifest_bytes);
    let expected_manifest_size = manifest_bytes.len() as u64;

    let request = SaveRequest {
        tag: tag.clone(),
        manifest_root_digest: manifest_root_digest.clone(),
        compression_algorithm: "zstd".to_string(),
        manifest_format_version: Some(1),
        total_size_bytes,
        uncompressed_size: Some(total_uncompressed_size),
        compressed_size: Some(total_compressed_size),
        file_count: Some(file_count),
        chunk_digests: chunk_digests.clone(),
        chunk_metadata: Some(chunk_metadata_for_request),
        expected_manifest_digest: Some(expected_manifest_digest.clone()),
        expected_manifest_size: Some(expected_manifest_size),
        force: if force { Some(true) } else { None },
    };

    let create_step = session.start_step(
        "Creating cache entry".to_string(),
        Some(format!("{} chunks", request.chunk_digests.len())),
    )?;

    let create_result = api_client
        .save_entry(&workspace, &request)
        .await
        .with_context(|| format!("Failed to create cache entry {}", tag));

    let save_response = match create_result {
        Ok(response) => response,
        Err(err) => {
            create_step.complete()?;
            session.error(format!("Failed to create cache entry: {}", err))?;
            drop(reporter);
            progress_system.shutdown()?;
            return Err(err);
        }
    };
    create_step.complete()?;

    log::debug!(
        "Server accepted cache entry tag={} exists={} missing_chunks={}",
        tag,
        save_response.exists,
        save_response.missing_chunk_digests.len()
    );

    if save_response.exists {
        complete_skipped_step(
            &mut session,
            "Uploading chunks",
            "skipped — server reports entry already exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Uploading manifest",
            "skipped — server reports entry already exists",
        )?;
        complete_skipped_step(
            &mut session,
            "Confirming upload",
            "skipped — server reports entry already exists",
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
        "  Backend response: {} chunks total, {} missing ({} reused)",
        chunk_digests.len(),
        save_response.missing_chunk_digests.len(),
        chunk_digests.len() - save_response.missing_chunk_digests.len(),
    ));

    let cache_entry_id = &save_response.cache_entry_id;

    let unique_map: HashMap<&str, &ChunkRef> = unique_chunk_refs
        .iter()
        .map(|chunk| (chunk.hash.as_str(), chunk))
        .collect();

    let mut unexpected_missing = Vec::new();
    let mut chunks_to_upload: Vec<ChunkRef> = Vec::new();

    for digest in &save_response.missing_chunk_digests {
        if let Some(chunk) = unique_map.get(digest.as_str()) {
            chunks_to_upload.push((**chunk).clone());
        } else {
            unexpected_missing.push(digest.clone());
        }
    }

    if !unexpected_missing.is_empty() {
        session.error(format!(
            "Server requested {} chunk{} not available locally: {}",
            unexpected_missing.len(),
            if unexpected_missing.len() == 1 {
                ""
            } else {
                "s"
            },
            unexpected_missing.join(", ")
        ))?;
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!("Missing local data for server-requested chunks");
    }

    chunks_to_upload.sort_by_key(|chunk| chunk.start_offset);

    if chunks_to_upload.is_empty() {
        complete_skipped_step(
            &mut session,
            "Uploading chunks",
            "skipped — all chunks already exist",
        )?;
        ui::info("  All chunks already present on server; skipping upload");
    } else {
        let chunk_upload_count = chunks_to_upload.len();
        let uploaded_compressed: u64 = chunks_to_upload.iter().map(|c| c.compressed_size).sum();
        let uploaded_uncompressed: u64 = chunks_to_upload.iter().map(|c| c.uncompressed_size).sum();
        let step6 = session.start_step(
            "Uploading chunks".to_string(),
            Some(format!(
                "{} missing chunks ({})",
                chunk_upload_count,
                crate::progress::format_bytes(uploaded_compressed)
            )),
        )?;
        let upload_step_number = step6.step_number();

        let progress = TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            upload_step_number,
            uploaded_compressed,
        );
        progress.record_bytes(0)?;

        let uploader = ChunkUploader::new(
            api_client.transfer_client().clone(),
            reporter.clone(),
            session_id.clone(),
            upload_step_number,
        );

        let upload_started = Instant::now();
        let upload_urls_by_key: HashMap<String, String> = save_response
            .chunk_upload_urls
            .iter()
            .filter_map(|(digest, url)| {
                unique_map
                    .get(digest.as_str())
                    .map(|chunk| (chunk.key.clone(), url.clone()))
            })
            .collect();

        if upload_urls_by_key.len() != chunk_upload_count {
            step6.complete()?;
            session.error(format!(
                "Server missing upload URLs for some chunks (expected {}, got {})",
                chunk_upload_count,
                upload_urls_by_key.len()
            ))?;
            drop(reporter);
            progress_system.shutdown()?;
            return Err(anyhow!("Missing upload URLs for some chunks"));
        }

        uploader
            .upload_chunk_refs(
                chunks_to_upload,
                upload_urls_by_key,
                Some(progress),
                verbose,
            )
            .await
            .with_context(|| format!("Failed to upload chunks for {}", tag))?;
        upload_duration = Some(upload_started.elapsed());

        step6.complete()?;

        let reused = chunk_digests.len() - save_response.missing_chunk_digests.len();
        let compression_ratio_percent = if uploaded_uncompressed > 0 {
            (uploaded_compressed as f64 / uploaded_uncompressed as f64 * 1000.0).round() / 10.0
        } else {
            0.0
        };
        ui::info(&format!(
            "info: Uploaded {} → {} ({}% of original) across {} chunk{}",
            crate::progress::format_bytes(uploaded_uncompressed),
            crate::progress::format_bytes(uploaded_compressed),
            compression_ratio_percent,
            save_response.missing_chunk_digests.len(),
            if save_response.missing_chunk_digests.len() == 1 {
                ""
            } else {
                "s"
            }
        ));
        ui::info(&format!(
            "      Reused {} chunk{} from cache",
            reused,
            if reused == 1 { "" } else { "s" }
        ));
    }

    let manifest_step = session.start_step("Uploading manifest".to_string(), None)?;
    // Reuse the precomputed manifest_bytes to ensure consistency with expected_* sent earlier
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
        chunk_count: chunk_digests.len() as u32,
        size: total_size_bytes,
        uncompressed_size: Some(total_uncompressed_size),
        compressed_size: Some(total_compressed_size),
        file_count: Some(file_count),
        manifest_size: Some(manifest_bytes.len() as u64),
        manifest_digest: Some(compute_manifest_digest(&manifest_bytes)),
        manifest_etag,
    };

    api_client
        .confirm(&workspace, cache_entry_id, &confirm_request)
        .await
        .with_context(|| format!("Failed to confirm upload for {}", tag))?;
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
    let fetch_ms = fetch_manifest_duration.map(|d| d.as_millis()).unwrap_or(0);
    let chunk_ms = chunk_duration.as_millis();
    let upload_ms = upload_duration.map(|d| d.as_millis()).unwrap_or(0);
    log::debug!(
        "save timing tag={} fetch_ms={} chunk_ms={} upload_ms={} total_ms={}",
        tag,
        fetch_ms,
        chunk_ms,
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

    // Extract ETag from response for backend verification
    let etag = headers
        .get("etag")
        .and_then(|e| e.to_str().ok())
        .map(|s| s.trim_matches('"').to_string()); // S3 returns ETags with quotes

    if etag.is_some() {
        log::debug!("Manifest uploaded with ETag: {:?}", etag);
    } else {
        log::warn!("Manifest upload response missing ETag header");
    }

    Ok(etag)
}

fn compute_manifest_digest(manifest_bytes: &[u8]) -> String {
    // Persisted manifest digest uses SHA-256 (raw hex, no prefix)
    let mut hasher = Sha256::new();
    hasher.update(manifest_bytes);
    let digest = hasher.finalize();
    digest
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>()
}

fn serialize_manifest(
    tag: &str,
    root_digest: &str,
    files: &[ManifestFile],
    chunk_metadata: &[crate::manifest::ChunkMeta],
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
        chunks: chunk_metadata.to_vec(),
        packs: vec![],
    };

    let mut buffer = Vec::new();
    ciborium::into_writer(&manifest, &mut buffer).context("Failed to serialize manifest")?;
    Ok(buffer)
}

fn collect_required_chunk_digests(files: &[ManifestFile]) -> Vec<String> {
    let mut digests: Vec<String> = files
        .iter()
        .filter_map(|file| file.spans.as_ref())
        .flat_map(|spans| spans.iter().map(|span| span.digest.clone()))
        .collect();

    digests.sort();
    digests.dedup();
    digests
}

fn chunk_meta_from_ref(chunk: &ChunkRef) -> crate::manifest::ChunkMeta {
    crate::manifest::ChunkMeta {
        digest: chunk.hash.clone(),
        uncompressed_size: chunk.uncompressed_size,
        compressed_size: chunk.compressed_size,
    }
}

fn build_chunk_metadata_for_request(
    metas: &[crate::manifest::ChunkMeta],
) -> Vec<SaveChunkMetadata> {
    metas
        .iter()
        .map(|meta| SaveChunkMetadata {
            digest: meta.digest.clone(),
            uncompressed_size: Some(meta.uncompressed_size),
            compressed_size: Some(meta.compressed_size),
            compression_algorithm: Some("zstd".to_string()),
            size: Some(meta.compressed_size),
            file_path: None,
            offset: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_chunk_metadata_uses_zstd() {
        let metas = vec![
            crate::manifest::ChunkMeta {
                digest: "blake3:aaa".to_string(),
                uncompressed_size: 128,
                compressed_size: 64,
            },
            crate::manifest::ChunkMeta {
                digest: "blake3:bbb".to_string(),
                uncompressed_size: 256,
                compressed_size: 100,
            },
        ];

        let result = build_chunk_metadata_for_request(&metas);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].digest, "blake3:aaa");
        assert_eq!(result[0].compression_algorithm.as_deref(), Some("zstd"));
        assert_eq!(result[0].size, Some(64));
        assert_eq!(result[1].digest, "blake3:bbb");
        assert_eq!(result[1].compressed_size, Some(100));
        assert_eq!(result[1].compression_algorithm.as_deref(), Some("zstd"));
    }
}
