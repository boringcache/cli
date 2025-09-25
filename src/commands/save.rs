use anyhow::Result;
use std::path::Path;

use crate::commands::utils::ParsedIdentifier;
use crate::ui::CleanUI;

#[derive(Debug)]
struct SavePreflightCheck {
    valid_pairs: Vec<ParsedIdentifier>,
    total_size_bytes: u64,
    unreadable_paths: Vec<String>,
    missing_paths: Vec<String>,
}

fn run_save_preflight_checks(
    parsed_pairs: &[ParsedIdentifier],
    verbose: bool,
) -> Result<SavePreflightCheck> {
    if verbose {
        CleanUI::info("Running preflight checks...");
    }

    let mut valid_pairs = Vec::new();
    let mut total_size_bytes = 0u64;
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

        // Check if path is readable
        match std::fs::metadata(&expanded_path) {
            Ok(metadata) => {
                let size = if metadata.is_file() {
                    metadata.len()
                } else {
                    // For directories, estimate size by walking
                    walkdir::WalkDir::new(&expanded_path)
                        .into_iter()
                        .filter_map(|entry| entry.ok())
                        .filter_map(|entry| entry.metadata().ok())
                        .filter(|metadata| metadata.is_file())
                        .map(|metadata| metadata.len())
                        .sum::<u64>()
                };

                total_size_bytes += size;
                valid_pairs.push(parsed.clone());
            }
            Err(_) => {
                unreadable_paths.push(format!("{} ({})", path, expanded_path));
            }
        }
    }

    // Check available disk space for compression workspace
    let temp_dir = std::env::temp_dir();
    let estimated_compression_workspace = total_size_bytes + (total_size_bytes / 2); // Rough estimate

    // Check available disk space for compression workspace
    #[cfg(unix)]
    let available_space: Option<u64> = {
        use std::ffi::CString;
        use std::mem;

        let path_cstring = CString::new(temp_dir.to_string_lossy().as_bytes()).unwrap();
        let mut statfs: libc::statvfs = unsafe { mem::zeroed() };

        if unsafe { libc::statvfs(path_cstring.as_ptr(), &mut statfs) } == 0 {
            let blocks = u128::from(statfs.f_bavail);
            let block_size = u128::from(statfs.f_frsize);
            let available = blocks * block_size;
            Some(std::cmp::min(available, u128::from(u64::MAX)) as u64)
        } else {
            None
        }
    };

    #[cfg(windows)]
    let available_space: Option<u64> = {
        use std::os::windows::ffi::OsStrExt;
        use winapi::um::fileapi::GetDiskFreeSpaceExW;
        use winapi::um::winnt::ULARGE_INTEGER;

        let path: Vec<u16> = temp_dir.as_os_str().encode_wide().chain(Some(0)).collect();

        let mut free_bytes: u64 = 0;

        let success = unsafe {
            GetDiskFreeSpaceExW(
                path.as_ptr(),
                &mut free_bytes as *mut u64 as *mut ULARGE_INTEGER,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };

        if success != 0 {
            Some(free_bytes)
        } else {
            None
        }
    };

    if let Some(available_space) = available_space {
        if available_space < estimated_compression_workspace {
            anyhow::bail!(
                "Insufficient disk space for compression:\n  \
                Need: ~{} for workspace\n  \
                Available: {} in {}\n\n  \
                Solutions:\n  \
                1. Free up disk space\n  \
                2. Set TMPDIR to a location with more space",
                crate::progress::format_bytes(estimated_compression_workspace),
                crate::progress::format_bytes(available_space),
                temp_dir.display()
            );
        }
    }

    Ok(SavePreflightCheck {
        valid_pairs,
        total_size_bytes,
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

    // Run preflight checks early
    let preflight_result = run_save_preflight_checks(&parsed_pairs, verbose)?;

    // Report any issues found during preflight
    if !preflight_result.missing_paths.is_empty() {
        for path in &preflight_result.missing_paths {
            CleanUI::warning(&format!("Skipping: path not found '{}'", path));
        }
    }

    if !preflight_result.unreadable_paths.is_empty() {
        for path in &preflight_result.unreadable_paths {
            CleanUI::warning(&format!("Skipping: cannot read '{}'", path));
        }
    }

    if preflight_result.valid_pairs.is_empty() {
        CleanUI::warning("No valid paths found to save");
        return Ok(());
    }

    if verbose && preflight_result.total_size_bytes > 0 {
        CleanUI::info(&format!(
            "Preflight complete: {} paths, ~{} total",
            preflight_result.valid_pairs.len(),
            crate::progress::format_bytes(preflight_result.total_size_bytes)
        ));
    }

    // Show tags immediately to provide instant feedback before API client creation
    if !preflight_result.valid_pairs.is_empty() {
        for parsed in &preflight_result.valid_pairs {
            let tag = parsed.tag.as_ref().unwrap();
            CleanUI::item_start(tag);
        }
    }

    // Now create cache operations after showing UI feedback
    let cache_ops = crate::cache_operations::CacheOperation::new(workspace.clone(), verbose)?;

    // Early cache hit detection - check which entries already exist
    // Skip this optimization if authentication isn't available (e.g., in tests)
    // Prepare entries for existence check
    let mut path_tag_pairs = Vec::new();

    for parsed in &preflight_result.valid_pairs {
        let tag = parsed.tag.as_ref().unwrap();
        let path = parsed.path.as_ref().unwrap();
        // Use same format as we'll use in actual save
        path_tag_pairs.push(format!("{}:{}", path, tag));
    }

    // Check which entries already exist using the new /caches/check endpoint
    let mut existing_tags = std::collections::HashSet::new();

    if !path_tag_pairs.is_empty() {
        // Use the new batch_check_existence endpoint
        match cache_ops
            .api_client
            .batch_check_existence(&workspace, &path_tag_pairs)
            .await
        {
            Ok(response) => {
                // Handle both single and batch response formats
                let results = if let Some(results_array) = response["results"].as_array() {
                    results_array.clone()
                } else if response.get("exists").is_some() {
                    // Single entry response
                    vec![response.clone()]
                } else {
                    vec![]
                };

                for (idx, result) in results.iter().enumerate() {
                    if result
                        .get("exists")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        if let Some(parsed) = preflight_result.valid_pairs.get(idx) {
                            if let Some(tag) = &parsed.tag {
                                existing_tags.insert(tag.clone());
                                CleanUI::item_exists_with_timing(tag, 1);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                // Silently fall back if the endpoint doesn't exist (older servers)
                if verbose {
                    CleanUI::info("Cache existence check unavailable, processing all entries");
                }
            }
        }
    }

    // Filter out entries that already exist
    let mut entries_to_process = Vec::new();

    for parsed in &preflight_result.valid_pairs {
        let tag = parsed.tag.as_ref().unwrap();
        if !existing_tags.contains(tag) {
            entries_to_process.push(parsed.clone());
        }
    }

    if entries_to_process.is_empty() {
        if verbose {
            CleanUI::info("All cache entries already exist, skipping archiving");
        }
        CleanUI::batch_summary(
            "Saved",
            existing_tags.len(),
            preflight_result.valid_pairs.len(),
            &workspace,
        );
        return Ok(());
    }

    if verbose && !existing_tags.is_empty() {
        CleanUI::info(&format!(
            "Found {} existing entries, processing {} new entries",
            existing_tags.len(),
            entries_to_process.len()
        ));
    }

    CleanUI::batch_start("Saving", entries_to_process.len(), &workspace);

    use crate::archive;
    use crate::compression::CompressionBackend;
    use futures_util::future::join_all;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let archive_semaphore = Arc::new(Semaphore::new(1));
    let mut archive_tasks = Vec::new();

    for parsed in &entries_to_process {
        let user_tag = parsed
            .tag
            .as_ref()
            .expect("Tag is required for save")
            .clone();
        let path = parsed
            .path
            .as_ref()
            .expect("Path is required for save")
            .clone();
        let expanded_path = crate::commands::utils::expand_tilde_path(&path);
        let paths = vec![expanded_path.clone()];

        // Transform tag to platform-aware version
        crate::tag_utils::validate_tag_basic(&user_tag)?;
        let platform_tag = user_tag.clone();
        let sem = Arc::clone(&archive_semaphore);
        let display_tag = user_tag.clone();

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            CleanUI::item_start(&display_tag);

            let compression = compression_choice.map(|choice| match choice {
                crate::cli::CompressionChoice::Lz4 => CompressionBackend::Lz4,
                crate::cli::CompressionChoice::Zstd => CompressionBackend::Zstd,
            });

            let archive_start = std::time::Instant::now();
            let (archive_data, archive_info) =
                archive::create_archive(&paths, compression, false).await?;

            CleanUI::item_archiving(
                archive_info.file_count as usize,
                archive_info.uncompressed_size as f64,
            );

            let algorithm_name = archive_info.compression_backend.name();
            CleanUI::item_compressing(algorithm_name);
            let compression_duration = archive_start.elapsed().as_millis() as u64;
            CleanUI::item_compression_complete(compression_duration);

            // Check for SBOM files in the directory
            let sbom_data = detect_sbom_in_path(&expanded_path).await;
            if sbom_data.is_some() {
                CleanUI::info(&format!("Found SBOM file for {}", user_tag));
            }

            let mut metadata = serde_json::json!({
                "content_hash": archive_info.content_sha256,
                "compression_algorithm": archive_info.compression_backend.name(),
                "size": archive_info.compressed_size,
                "uncompressed_size": archive_info.uncompressed_size,
                "file_count": archive_info.file_count,
                "path": expanded_path,
            });

            // Add SBOM data if found
            if let Some(sbom) = sbom_data {
                metadata["sbom"] = sbom;
                CleanUI::info(&format!("Including SBOM in metadata for {}", user_tag));
            }

            Ok::<
                (
                    serde_json::Value,
                    String,
                    Vec<u8>,
                    crate::archive::ArchiveInfo,
                ),
                anyhow::Error,
            >((metadata, platform_tag, archive_data, archive_info))
        });

        archive_tasks.push(task);
    }

    let results = join_all(archive_tasks).await;

    let mut entries_metadata = Vec::new();
    let mut archives = Vec::new();

    for (index, result) in results.into_iter().enumerate() {
        match result {
            Ok(Ok((metadata, tag, archive_data, archive_info))) => {
                entries_metadata.push(metadata);
                archives.push((tag, archive_data, archive_info));
            }
            Ok(Err(e)) => {
                anyhow::bail!("Failed to process file {}: {}", index + 1, e);
            }
            Err(e) => {
                anyhow::bail!("Task failed for file {}: {}", index + 1, e);
            }
        }
    }

    let compression_str = compression_choice.as_ref().map(|c| match c {
        crate::cli::CompressionChoice::Lz4 => "lz4",
        crate::cli::CompressionChoice::Zstd => "zstd",
    });

    // Reuse cached platform info
    let mut valid_path_tag_pairs = Vec::new();
    for parsed in &entries_to_process {
        let path = parsed.path.as_ref().expect("Path is required");
        let tag = parsed.tag.as_ref().expect("Tag is required");
        crate::tag_utils::validate_tag_basic(tag)?;
        let platform_tag = tag.clone();
        valid_path_tag_pairs.push(format!("{}:{}", path, platform_tag));
    }

    let response = cache_ops
        .api_client
        .batch_save_with_metadata(
            &workspace,
            &valid_path_tag_pairs,
            entries_metadata,
            compression_str,
            description.as_deref(),
        )
        .await?;

    let results = response["results"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("Invalid API response: missing results array"))?;

    if results.len() != archives.len() {
        anyhow::bail!(
            "Response mismatch: got {} results, expected {}",
            results.len(),
            archives.len()
        );
    }

    use crate::cache_operations::upload::UploadOperation;

    let upload_semaphore = Arc::new(Semaphore::new(1));
    let mut upload_tasks = Vec::new();

    for (result, (tag, archive_data, archive_info)) in results.iter().zip(archives.into_iter()) {
        if let Some(error) = result.get("error") {
            CleanUI::item_error(&tag, error.as_str().unwrap_or("server error"));
            continue;
        }

        if result
            .get("exists")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            CleanUI::item_exists_with_timing(&tag, 1);
            continue;
        }

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

        let upload_sem = Arc::clone(&upload_semaphore);
        let api_client = cache_ops.api_client.clone();
        let workspace_clone = workspace.clone();
        let tag_clone = tag.clone();

        let upload_task = tokio::spawn(async move {
            let _permit = upload_sem.acquire().await.unwrap();

            let upload_spinner = CleanUI::item_uploading_start(archive_info.compressed_size as f64);
            let upload_start = std::time::Instant::now();

            let upload_op_silent =
                UploadOperation::new_silent(api_client.clone(), workspace_clone.clone(), false);

            if save_response.multipart {
                upload_op_silent
                    .upload_multipart(
                        &save_response,
                        &archive_data,
                        &archive_info,
                        Some(&tag_clone),
                    )
                    .await?;
            } else {
                upload_op_silent
                    .upload_single(
                        &save_response,
                        &archive_data,
                        &archive_info,
                        Some(&tag_clone),
                    )
                    .await?;
            }

            let upload_duration = upload_start.elapsed().as_millis() as u64;
            CleanUI::item_uploading_complete(upload_spinner, upload_duration);

            Ok::<String, anyhow::Error>(tag_clone)
        });

        upload_tasks.push(upload_task);
    }

    let upload_results = join_all(upload_tasks).await;

    let mut successful_uploads = 0;
    for result in upload_results {
        match result {
            Ok(Ok(_tag)) => {
                successful_uploads += 1;
            }
            Ok(Err(e)) => {
                CleanUI::item_error("upload", &e.to_string());
            }
            Err(e) => {
                CleanUI::item_error("task", &e.to_string());
            }
        }
    }

    let total_saved = successful_uploads + existing_tags.len();
    let total_requested = existing_tags.len() + entries_to_process.len();
    CleanUI::batch_summary("saved", total_saved, total_requested, &workspace);

    Ok(())
}

async fn detect_sbom_in_path(path: &str) -> Option<serde_json::Value> {
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

fn detect_sbom_format(sbom: &serde_json::Value) -> &'static str {
    if sbom.get("spdxVersion").is_some() {
        "spdx"
    } else if sbom.get("bomFormat").is_some() || sbom.get("specVersion").is_some() {
        "cyclonedx"
    } else {
        "unknown"
    }
}
