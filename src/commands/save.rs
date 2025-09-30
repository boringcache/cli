use anyhow::Result;
use bytes::Bytes;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

use crate::cache_operations::upload::{UploadOperation, UploadProgressHandle};
use crate::commands::utils::ParsedIdentifier;
use crate::progress::{format_bytes, Summary, System as ProgressSystem};

#[derive(Debug)]
struct SavePreflightCheck {
    valid_pairs: Vec<ParsedIdentifier>,
}

fn run_save_preflight_checks(
    parsed_pairs: &[ParsedIdentifier],
    _verbose: bool,
) -> Result<SavePreflightCheck> {
    // Preflight checks are now silent - progress is shown via the progress system

    let mut valid_pairs = Vec::new();
    let mut issues = Vec::new();

    for parsed in parsed_pairs {
        let path = match parsed.path.as_ref() {
            Some(path) => path,
            None => {
                issues.push("Missing path for save request".to_string());
                continue;
            }
        };

        let tag = match parsed.tag.as_ref() {
            Some(tag) => tag,
            None => {
                issues.push(format!("Missing tag for path '{}'", path));
                continue;
            }
        };

        if let Err(error) = crate::commands::utils::validate_tag_name(tag) {
            issues.push(format!("Invalid tag '{}': {}", tag, error));
            continue;
        }

        let expanded_path = crate::commands::utils::expand_tilde_path(path);
        let path_obj = Path::new(&expanded_path);

        if !path_obj.exists() {
            let description = if path != &expanded_path {
                format!("{} (expanded from '{}')", expanded_path, path)
            } else {
                expanded_path.clone()
            };
            issues.push(format!("Path not found: {}", description));
            continue;
        }

        match std::fs::metadata(&expanded_path) {
            Ok(metadata) => {
                if metadata.is_dir() {
                    if let Err(error) = std::fs::read_dir(&expanded_path) {
                        issues.push(format!(
                            "Cannot read directory '{}': {}",
                            expanded_path, error
                        ));
                        continue;
                    }
                } else if metadata.is_file() {
                    if let Err(error) = std::fs::File::open(&expanded_path) {
                        issues.push(format!("Cannot read file '{}': {}", expanded_path, error));
                        continue;
                    }
                } else {
                    issues.push(format!(
                        "Unsupported filesystem entry for '{}': not a file or directory",
                        expanded_path
                    ));
                    continue;
                }

                valid_pairs.push(parsed.clone());
            }
            Err(error) => {
                issues.push(format!("Cannot access '{}': {}", expanded_path, error));
            }
        }
    }

    if !issues.is_empty() {
        let mut message = String::from("Save preflight failed:\n");
        for issue in &issues {
            message.push_str("  - ");
            message.push_str(issue);
            message.push('\n');
        }

        return Err(anyhow::anyhow!(message.trim_end().to_string()));
    }

    Ok(SavePreflightCheck { valid_pairs })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::utils::ParsedIdentifier;

    #[test]
    fn preflight_rejects_missing_path() {
        let parsed = ParsedIdentifier {
            key: String::new(),
            path: Some("/path/does/not/exist".to_string()),
            tag: Some("valid-tag".to_string()),
        };

        let result = run_save_preflight_checks(&[parsed], false);
        assert!(result.is_err());
        let message = format!("{}", result.unwrap_err());
        assert!(message.contains("Path not found"));
    }

    #[test]
    fn preflight_rejects_invalid_tag() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_string_lossy().to_string();
        let parsed = ParsedIdentifier {
            key: String::new(),
            path: Some(path),
            tag: Some("invalid tag".to_string()),
        };

        let result = run_save_preflight_checks(&[parsed], false);
        assert!(result.is_err());
        let message = format!("{}", result.unwrap_err());
        assert!(message.contains("Invalid tag"));
    }

    #[test]
    fn preflight_accepts_existing_directory() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().to_string_lossy().to_string();
        let parsed = ParsedIdentifier {
            key: String::new(),
            path: Some(path),
            tag: Some("valid-tag".to_string()),
        };

        let result = run_save_preflight_checks(&[parsed], false).unwrap();
        assert_eq!(result.valid_pairs.len(), 1);
    }
}

pub async fn execute_batch_save(
    workspace_option: Option<String>,
    tag_path_pairs: Vec<String>,
    compression_choice: Option<crate::cli::CompressionChoice>,
    description: Option<String>,
    verbose: bool,
    no_platform: bool,
    force: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;

    let parsed_pairs: Vec<_> = tag_path_pairs
        .iter()
        .map(|pair| crate::commands::utils::parse_save_format(pair))
        .collect();

    // Run preflight checks
    let preflight_result = run_save_preflight_checks(&parsed_pairs, verbose)?;

    // Detect platform for tag suffix
    let platform = if !no_platform {
        Some(crate::platform::Platform::detect()?)
    } else {
        None
    };

    // Set up progress system
    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();

    if preflight_result.valid_pairs.is_empty() {
        reporter.warning("No valid paths found to save".to_string())?;
        progress_system.shutdown()?;
        return Ok(());
    }

    // Prepare entry metadata and run a batch existence check to skip
    // uploads that the server already has.
    #[derive(Clone)]
    struct EntryCandidate {
        tag: String,
        raw_path: String,
        expanded_path: String,
    }

    let candidates: Vec<EntryCandidate> = preflight_result
        .valid_pairs
        .iter()
        .map(|parsed| {
            let original_tag = parsed.tag.as_ref().unwrap().clone();
            let tag = crate::tag_utils::apply_platform_to_tag_with_instance(
                &original_tag,
                platform.as_ref(),
            );
            let raw_path = parsed.path.as_ref().unwrap().clone();
            EntryCandidate {
                tag,
                raw_path,
                expanded_path: crate::commands::utils::expand_tilde_path(
                    parsed.path.as_ref().unwrap(),
                ),
            }
        })
        .collect();

    #[derive(Clone)]
    struct EntryWork {
        tag: String,
        raw_path: String,
        expanded_path: String,
        fingerprint: String,
    }

    let total_entries = candidates.len();

    let cache_ops = crate::cache_operations::CacheOperation::new(workspace.clone(), verbose)?;

    let mut entries_to_save = Vec::new();
    let mut reused_tags = Vec::new();

    for candidate in candidates {
        let fingerprint = compute_content_fingerprint(Path::new(&candidate.expanded_path))?;

        let mut should_save = true;
        if !force {
            match cache_ops
                .api_client
                .check_content_identifier(&workspace, None, Some(&fingerprint))
                .await
            {
                Ok(response) => {
                    if response.exists {
                        reporter.info(format!(
                            "Cache hit for '{}' (fingerprint {}) — skipping upload",
                            candidate.tag,
                            &fingerprint[..std::cmp::min(12, fingerprint.len())]
                        ))?;
                        reused_tags.push(candidate.tag.clone());
                        should_save = false;
                    }
                }
                Err(err) => {
                    reporter.warning(format!(
                        "Preflight cache check failed for '{}': {} (continuing with upload)",
                        candidate.tag, err
                    ))?;
                }
            }
        }

        if should_save {
            entries_to_save.push(EntryWork {
                tag: candidate.tag,
                raw_path: candidate.raw_path,
                expanded_path: candidate.expanded_path,
                fingerprint,
            });
        }
    }

    // Process each entry with progress tracking
    let mut handles = Vec::new();

    for entry in entries_to_save.iter().cloned() {
        let session_id = format!("{}:{}", workspace.as_str(), entry.tag);
        let title = format!("Saving cache [{}: {}]", workspace.as_str(), entry.tag);

        let reporter_clone = reporter.clone();
        let workspace_clone = workspace.clone();
        let compression_choice_clone = compression_choice;
        let description_clone = description.clone();
        let tag_clone = entry.tag.clone();
        let raw_path_clone = entry.raw_path.clone();
        let expanded_path_clone = entry.expanded_path.clone();
        let fingerprint_clone = entry.fingerprint.clone();
        let cache_ops_clone = cache_ops.clone();

        let handle = tokio::spawn(async move {
            process_single_save(
                cache_ops_clone,
                reporter_clone,
                session_id,
                title,
                workspace_clone,
                tag_clone,
                raw_path_clone,
                expanded_path_clone,
                fingerprint_clone,
                compression_choice_clone,
                description_clone,
                verbose,
            )
            .await
        });

        handles.push(handle);
    }

    // Wait for all saves to complete
    let mut successful = 0;
    for handle in handles {
        if handle.await?? {
            successful += 1;
        }
    }

    if verbose {
        if !reused_tags.is_empty() {
            reporter.info(format!(
                "Reused existing caches for {} entries: {}",
                reused_tags.len(),
                reused_tags.join(", ")
            ))?;
        }
        reporter.info(format!(
            "Successfully saved {}/{} entries",
            successful, total_entries
        ))?;
    }

    progress_system.shutdown()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_single_save(
    cache_ops: crate::cache_operations::CacheOperation,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    tag: String,
    original_path: String,
    expanded_path: String,
    fingerprint: String,
    compression_choice: Option<crate::cli::CompressionChoice>,
    description: Option<String>,
    verbose: bool,
) -> Result<bool> {
    let session_start = Instant::now();

    crate::tag_utils::validate_tag_basic(&tag)?;

    use crate::archive;
    use crate::compression::CompressionBackend;

    let compression = compression_choice.map(|choice| match choice {
        crate::cli::CompressionChoice::Lz4 => CompressionBackend::Lz4,
        crate::cli::CompressionChoice::Zstd => CompressionBackend::Zstd,
    });

    reporter.session_start(session_id.clone(), title, 4)?;

    // Step 1: Creating archive
    reporter.step_start(
        session_id.clone(),
        1,
        "Creating archive".to_string(),
        Some(format!("from {}", expanded_path)),
    )?;
    let arch_start = Instant::now();

    let (archive_progress_tx, mut archive_progress_rx) =
        tokio::sync::mpsc::unbounded_channel::<crate::archive::ArchiveProgressUpdate>();

    let progress_reporter = reporter.clone();
    let progress_session = session_id.clone();
    let progress_task = tokio::spawn(async move {
        while let Some(update) = archive_progress_rx.recv().await {
            let mut detail = format!("{} files", update.files_processed);
            if update.bytes_processed > 0 {
                detail.push_str(&format!(" • {}", format_bytes(update.bytes_processed)));
            }
            if let Some(path) = update.current_path {
                if !path.is_empty() {
                    detail.push_str(&format!(" • {}", path));
                }
            }

            let _ = progress_reporter.step_progress(
                progress_session.clone(),
                1,
                update.percent_complete,
                Some(detail),
            );
        }
    });

    let paths = vec![expanded_path.clone()];
    let archive_result = archive::create_archive_with_progress(
        &paths,
        compression,
        verbose,
        Some(archive_progress_tx.clone()),
    )
    .await;

    drop(archive_progress_tx);
    let _ = progress_task.await;

    let (archive_bytes, archive_info) = archive_result?;

    reporter.step_complete(session_id.clone(), 1, arch_start.elapsed())?;

    // Step 2: Compressing (explicit for clarity)
    let compression_name = archive_info.compression_backend.name();
    reporter.step_start(
        session_id.clone(),
        2,
        "Compressing".to_string(),
        Some(format!("({})", compression_name)),
    )?;
    let compress_start = Instant::now();
    reporter.step_progress(
        session_id.clone(),
        2,
        95.0,
        Some(format!(
            "{} compressed",
            format_bytes(archive_info.compressed_size)
        )),
    )?;
    reporter.step_complete(session_id.clone(), 2, compress_start.elapsed())?;

    // Prepare metadata for upload
    let mut metadata = serde_json::json!({
        "content_hash": archive_info.content_sha256,
        "compression_algorithm": archive_info.compression_backend.name(),
        "size": archive_info.compressed_size,
        "uncompressed_size": archive_info.uncompressed_size,
        "file_count": archive_info.file_count,
        "path": expanded_path,
    });
    metadata["content_fingerprint"] = serde_json::Value::String(fingerprint.clone());
    metadata["source_path"] = serde_json::Value::String(original_path.clone());

    let sbom_data = detect_sbom_in_path(&expanded_path, verbose).await;
    if let Some(sbom) = sbom_data {
        metadata["sbom"] = sbom;
    }

    let compression_str = compression_choice.map(|c| match c {
        crate::cli::CompressionChoice::Lz4 => "lz4",
        crate::cli::CompressionChoice::Zstd => "zstd",
    });

    let entry_tags = vec![tag.clone()];

    let response = cache_ops
        .api_client
        .batch_save_with_metadata(
            &workspace,
            &entry_tags,
            vec![metadata],
            compression_str,
            description.as_deref(),
        )
        .await?;

    let results = response["results"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid API response: missing results array"))?;

    if results.is_empty() {
        return Err(anyhow::anyhow!("No results returned from server"));
    }

    let result = &results[0];

    if let Some(error) = result.get("error") {
        reporter.session_error(
            session_id,
            error.as_str().unwrap_or("server error").to_string(),
        )?;
        return Ok(false);
    }

    let already_uploaded = result
        .get("exists")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let save_response = crate::api::SaveCacheResponse {
        cache_entry_id: result
            .get("cache_entry_id")
            .and_then(|id| id.as_str())
            .unwrap_or_default()
            .to_string(),
        storage_key: result
            .get("storage_key")
            .and_then(|k| k.as_str())
            .unwrap_or_default()
            .to_string(),
        upload_url: result
            .get("upload_url")
            .and_then(|u| u.as_str())
            .map(|s| s.to_string()),
        multipart: result
            .get("multipart")
            .and_then(|m| m.as_bool())
            .unwrap_or(false),
        upload_id: result
            .get("upload_id")
            .and_then(|id| id.as_str())
            .map(|s| s.to_string()),
        part_urls: result
            .get("part_urls")
            .and_then(|p| p.as_array())
            .map(|urls| {
                urls.iter()
                    .filter_map(|url_obj| {
                        let upload_url = url_obj.get("upload_url")?.as_str()?.to_string();
                        let part_number = url_obj.get("part_number")?.as_u64()? as u32;
                        Some(crate::api::PartUpload {
                            upload_url,
                            part_number,
                        })
                    })
                    .collect()
            }),
        tag: None, // Tag response is optional and may not be included in all server responses
    };

    // If the server signals the cache already exists after metadata submission, finish gracefully
    // Step 3: Uploading data to remote storage
    let upload_detail = if save_response.multipart {
        if let Some(part_urls) = &save_response.part_urls {
            format!(
                "[{} parts, {}]",
                part_urls.len(),
                crate::progress::format_bytes(archive_info.compressed_size)
            )
        } else {
            format!(
                "[{}]",
                crate::progress::format_bytes(archive_info.compressed_size)
            )
        }
    } else {
        format!(
            "[{}]",
            crate::progress::format_bytes(archive_info.compressed_size)
        )
    };

    reporter.step_start(
        session_id.clone(),
        3,
        "Uploading".to_string(),
        Some(upload_detail.clone()),
    )?;

    if already_uploaded || (save_response.upload_url.is_none() && !save_response.multipart) {
        reporter.step_complete(session_id.clone(), 3, Duration::from_millis(0))?;
        reporter.step_start(session_id.clone(), 4, "Finalizing upload".to_string(), None)?;
        reporter.step_complete(session_id.clone(), 4, Duration::from_millis(0))?;

        let summary = Summary {
            size_bytes: archive_info.compressed_size,
            file_count: archive_info.file_count,
            digest: Some(archive_info.content_sha256.clone()),
            path: Some(expanded_path),
        };

        reporter.session_complete(session_id, session_start.elapsed(), summary)?;
        return Ok(true);
    }

    let upload_start = Instant::now();
    let data = Bytes::from(archive_bytes);
    let upload_op = UploadOperation::new(cache_ops.api_client.clone(), workspace, verbose);
    let part_count = if save_response.multipart {
        save_response
            .part_urls
            .as_ref()
            .map(|p| p.len() as u32)
            .unwrap_or(1)
    } else {
        1
    };

    let progress_handle = Arc::new(UploadProgressHandle::new(
        reporter.clone(),
        session_id.clone(),
        archive_info.compressed_size,
        part_count,
    ));

    let upload_result = if save_response.multipart {
        upload_op
            .upload_multipart(
                &save_response,
                &data,
                &archive_info,
                Some(&tag),
                Some(progress_handle.clone()),
            )
            .await
    } else {
        upload_op
            .upload_single(
                &save_response,
                &data,
                &archive_info,
                Some(&tag),
                Some(progress_handle.clone()),
            )
            .await
    };

    match upload_result {
        Ok(()) => {
            reporter.step_complete(session_id.clone(), 3, upload_start.elapsed())?;

            // Step 4: Finalizing upload (confirm + metadata update)
            reporter.step_start(session_id.clone(), 4, "Finalizing upload".to_string(), None)?;
            let finalize_start = Instant::now();
            reporter.step_complete(session_id.clone(), 4, finalize_start.elapsed())?;

            let summary = Summary {
                size_bytes: archive_info.compressed_size,
                file_count: archive_info.file_count,
                digest: Some(archive_info.content_sha256.clone()),
                path: Some(expanded_path),
            };

            reporter.session_complete(session_id, session_start.elapsed(), summary)?;
            Ok(true)
        }
        Err(e) => {
            reporter.session_error(session_id, e.to_string())?;
            Ok(false)
        }
    }
}

fn compute_content_fingerprint(path: &Path) -> Result<String> {
    let mut hasher = Sha256::new();

    if path.is_file() {
        let parent = path.parent().unwrap_or(Path::new(""));
        hash_file_entry(&mut hasher, parent, path)?;
    } else if path.is_dir() {
        for entry in WalkDir::new(path).sort_by(|a, b| a.path().cmp(b.path())) {
            let entry = entry?;
            let rel = entry.path().strip_prefix(path).unwrap_or(Path::new(""));
            let rel_str = if rel.as_os_str().is_empty() {
                ".".to_string()
            } else {
                rel.to_string_lossy().replace('\\', "/")
            };

            if crate::archive::should_skip_path_for_fingerprint(&rel_str) {
                continue;
            }

            if entry.file_type().is_dir() {
                hasher.update(b"D");
                hasher.update(rel_str.as_bytes());
            } else if entry.file_type().is_file() {
                hasher.update(b"F");
                hasher.update(rel_str.as_bytes());
                let metadata = entry.metadata()?;
                hasher.update(metadata.len().to_le_bytes());
                hash_file_contents(&mut hasher, entry.path())?;
            } else if entry.file_type().is_symlink() {
                hasher.update(b"L");
                hasher.update(rel_str.as_bytes());
                if let Ok(target) = std::fs::read_link(entry.path()) {
                    hasher.update(target.to_string_lossy().replace('\\', "/").as_bytes());
                }
            }
        }
    } else {
        anyhow::bail!("Unsupported path type for fingerprint: {}", path.display());
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn hash_file_entry(hasher: &mut Sha256, root: &Path, file_path: &Path) -> Result<()> {
    let rel_path = file_path
        .strip_prefix(root)
        .ok()
        .filter(|p| !p.as_os_str().is_empty())
        .map(PathBuf::from)
        .or_else(|| file_path.file_name().map(PathBuf::from))
        .unwrap_or_else(|| file_path.to_path_buf());

    let rel = rel_path.to_string_lossy().replace('\\', "/");
    hasher.update(b"F");
    hasher.update(rel.as_bytes());
    let metadata = file_path.metadata()?;
    hasher.update(metadata.len().to_le_bytes());
    hash_file_contents(hasher, file_path)
}

fn hash_file_contents(hasher: &mut Sha256, path: &Path) -> Result<()> {
    let mut file = File::open(path)?;
    let mut buffer = [0u8; 8192];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(())
}

async fn detect_sbom_in_path(path: &str, verbose: bool) -> Option<serde_json::Value> {
    use std::path::Path;

    let base_dir = if Path::new(path).is_file() {
        Path::new(path).parent()?.to_str()?
    } else {
        path
    };

    // Common SBOM file names
    let sbom_candidates = [
        "sbom.json",
        "bom.json",
        "sbom.spdx.json",
        "sbom.cyclonedx.json",
        ".sbom.json",
        "software-bill-of-materials.json",
    ];

    for candidate in &sbom_candidates {
        let sbom_path = Path::new(base_dir).join(candidate);
        if sbom_path.exists() {
            if let Ok(sbom_content) = tokio::fs::read_to_string(&sbom_path).await {
                // Check SBOM file size to avoid oversized metadata
                const MAX_SBOM_SIZE: usize = 1024 * 1024; // 1MB limit
                if sbom_content.len() > MAX_SBOM_SIZE {
                    // SBOM file is too large - including summary only
                    let _ = verbose; // Suppress unused variable warning
                    if let Ok(sbom_json) = serde_json::from_str::<serde_json::Value>(&sbom_content)
                    {
                        return Some(create_sbom_summary(&sbom_json, candidate));
                    }
                    continue;
                }

                if let Ok(sbom_json) = serde_json::from_str::<serde_json::Value>(&sbom_content) {
                    return Some(serde_json::json!({
                        "file": candidate,
                        "format": detect_sbom_format(&sbom_json),
                        "content": sbom_json
                    }));
                }
            }
        }
    }

    None
}

fn create_sbom_summary(sbom: &serde_json::Value, filename: &str) -> serde_json::Value {
    let format = detect_sbom_format(sbom);
    let mut summary = serde_json::json!({
        "file": filename,
        "format": format,
        "size": "large",
        "summary": true
    });

    // Extract key metadata without the full content
    match format {
        "spdx" => {
            if let Some(name) = sbom.get("name") {
                summary["name"] = name.clone();
            }
            if let Some(version) = sbom.get("spdxVersion") {
                summary["version"] = version.clone();
            }
            if let Some(packages) = sbom.get("packages") {
                if let Some(array) = packages.as_array() {
                    summary["package_count"] =
                        serde_json::Value::Number(serde_json::Number::from(array.len()));
                }
            }
        }
        "cyclonedx" => {
            if let Some(metadata) = sbom.get("metadata") {
                if let Some(component) = metadata.get("component") {
                    if let Some(name) = component.get("name") {
                        summary["name"] = name.clone();
                    }
                    if let Some(version) = component.get("version") {
                        summary["version"] = version.clone();
                    }
                }
            }
            if let Some(components) = sbom.get("components") {
                if let Some(array) = components.as_array() {
                    summary["component_count"] =
                        serde_json::Value::Number(serde_json::Number::from(array.len()));
                }
            }
        }
        _ => {}
    }

    summary
}

fn detect_sbom_format(sbom: &serde_json::Value) -> &'static str {
    if sbom.get("spdxVersion").is_some() {
        "spdx"
    } else if sbom.get("bomFormat").is_some() || sbom.get("specVersion").is_some() {
        "cyclonedx"
    } else {
        "unknown"
    }
}
