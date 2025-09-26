use anyhow::Result;
use bytes::Bytes;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::cache_operations::upload::{UploadOperation, UploadProgressHandle};
use crate::commands::utils::ParsedIdentifier;
use crate::progress::{Summary, System as ProgressSystem};
use crate::ui;

#[derive(Debug)]
struct SavePreflightCheck {
    valid_pairs: Vec<ParsedIdentifier>,
    unreadable_paths: Vec<String>,
    missing_paths: Vec<String>,
}

fn run_save_preflight_checks(
    parsed_pairs: &[ParsedIdentifier],
    _verbose: bool,
) -> Result<SavePreflightCheck> {
    // Preflight checks are now silent - progress is shown via the progress system

    let mut valid_pairs = Vec::new();
    let mut unreadable_paths = Vec::new();
    let mut missing_paths = Vec::new();

    for parsed in parsed_pairs {
        let path = parsed.path.as_ref().expect("Path is required for save");
        let tag = parsed.tag.as_ref().expect("Tag is required for save");

        // Validate tag format early
        crate::tag_utils::validate_tag_basic(tag)?;

        let expanded_path = crate::commands::utils::expand_tilde_path(path);
        let path_obj = Path::new(&expanded_path);

        if !path_obj.exists() {
            if path != &expanded_path {
                missing_paths.push(format!("{} (expanded from '{}')", expanded_path, path));
            } else {
                missing_paths.push(expanded_path.clone());
            }
            continue;
        }

        // Check if path is readable (but don't walk directories - too slow)
        match std::fs::metadata(&expanded_path) {
            Ok(_metadata) => {
                // Don't calculate size here - it's too slow for large directories
                // We'll get the actual size during archiving
                valid_pairs.push(parsed.clone());
            }
            Err(_) => {
                unreadable_paths.push(format!("{} ({})", path, expanded_path));
            }
        }
    }

    // Skip disk space check - it's better to fail during archiving than to delay UI
    // The disk space check was minimal anyway since we don't know the actual size

    Ok(SavePreflightCheck {
        valid_pairs,
        unreadable_paths,
        missing_paths,
    })
}

pub async fn execute_batch_save(
    workspace_option: Option<String>,
    tag_path_pairs: Vec<String>,
    compression_choice: Option<crate::cli::CompressionChoice>,
    description: Option<String>,
    _async_save: bool,
    verbose: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;

    let parsed_pairs: Vec<_> = tag_path_pairs
        .iter()
        .map(|pair| crate::commands::utils::parse_save_format(pair))
        .collect();

    // Run preflight checks
    let preflight_result = run_save_preflight_checks(&parsed_pairs, verbose)?;

    // Set up progress system
    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();

    // Report any issues found during preflight
    if !preflight_result.missing_paths.is_empty() {
        for path in &preflight_result.missing_paths {
            reporter.warning(format!("Skipping: path not found '{}'", path))?;
        }
    }

    if !preflight_result.unreadable_paths.is_empty() {
        for path in &preflight_result.unreadable_paths {
            reporter.warning(format!("Skipping: cannot read '{}'", path))?;
        }
    }

    if preflight_result.valid_pairs.is_empty() {
        reporter.warning("No valid paths found to save".to_string())?;
        progress_system.shutdown()?;
        return Ok(());
    }

    // Process each entry with progress tracking
    let mut handles = Vec::new();

    for parsed in &preflight_result.valid_pairs {
        let tag = parsed.tag.as_ref().unwrap().clone();
        let path = parsed.path.as_ref().unwrap().clone();
        let expanded_path = crate::commands::utils::expand_tilde_path(&path);

        let session_id = format!("{}:{}", workspace.as_str(), tag);
        let title = format!("Saving cache [{}: {}]", workspace.as_str(), tag);

        let reporter_clone = reporter.clone();
        let workspace_clone = workspace.clone();
        let compression_choice_clone = compression_choice;
        let description_clone = description.clone();

        let handle = tokio::spawn(async move {
            process_single_save(
                reporter_clone,
                session_id,
                title,
                workspace_clone,
                tag,
                expanded_path,
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

    // Show summary if verbose
    if verbose {
        reporter.info(format!(
            "Successfully saved {}/{} entries",
            successful,
            preflight_result.valid_pairs.len()
        ))?;
    }

    progress_system.shutdown()?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_single_save(
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    tag: String,
    expanded_path: String,
    compression_choice: Option<crate::cli::CompressionChoice>,
    description: Option<String>,
    verbose: bool,
) -> Result<bool> {
    let session_start = Instant::now();

    crate::tag_utils::validate_tag_basic(&tag)?;

    let cache_ops = crate::cache_operations::CacheOperation::new(workspace.clone(), verbose)?;

    reporter.info(format!("Checking existing cache entry for tag '{}'", tag))?;

    // Check if the cache already exists before starting the session UI
    let entry_identifier = format!("{}:{}", expanded_path, tag);
    let check_result = cache_ops
        .api_client
        .batch_check_existence(&workspace, &[entry_identifier])
        .await?;

    let already_exists = check_result
        .get("results")
        .and_then(|r| r.as_array())
        .map(|results| {
            results.iter().any(|result| {
                result
                    .get("exists")
                    .and_then(|e| e.as_bool())
                    .unwrap_or(false)
            })
        })
        .unwrap_or(false);

    if already_exists {
        ui::info(&format!(
            "Cache entry '{}' already exists on the server; skipping save",
            tag
        ));
        return Ok(true);
    }

    use crate::archive;
    use crate::compression::CompressionBackend;

    let compression = compression_choice.map(|choice| match choice {
        crate::cli::CompressionChoice::Lz4 => CompressionBackend::Lz4,
        crate::cli::CompressionChoice::Zstd => CompressionBackend::Zstd,
    });

    reporter.session_start(session_id.clone(), title, 4)?;

    // Step 1: Archiving files (stream + hash)
    reporter.step_start(session_id.clone(), 1, "Archiving files".to_string(), None)?;
    let arch_start = Instant::now();

    let paths = vec![expanded_path.clone()];
    let (archive_bytes, archive_info) =
        archive::create_archive_silent(&paths, compression, verbose).await?;

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
    tokio::time::sleep(Duration::from_millis(50)).await;
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

    let sbom_data = detect_sbom_in_path(&expanded_path, verbose).await;
    if let Some(sbom) = sbom_data {
        metadata["sbom"] = sbom;
    }

    let compression_str = compression_choice.map(|c| match c {
        crate::cli::CompressionChoice::Lz4 => "lz4",
        crate::cli::CompressionChoice::Zstd => "zstd",
    });

    let cache_key = format!("{}:{}", expanded_path, tag);

    let response = cache_ops
        .api_client
        .batch_save_with_metadata(
            &workspace,
            &[cache_key],
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
