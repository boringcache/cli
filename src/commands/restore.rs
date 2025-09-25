use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::commands::utils::ParsedIdentifier;
use crate::ui::CleanUI;

#[derive(Debug)]
struct RestorePreflightCheck {
    valid_pairs: Vec<ParsedIdentifier>,
    unwritable_targets: Vec<String>,
    invalid_targets: Vec<String>,
}

fn run_restore_preflight_checks(
    parsed_pairs: &[ParsedIdentifier],
    verbose: bool,
) -> Result<RestorePreflightCheck> {
    if verbose {
        CleanUI::info("Running preflight checks...");
    }

    let mut valid_pairs = Vec::new();
    let mut unwritable_targets = Vec::new();
    let mut invalid_targets = Vec::new();

    for parsed in parsed_pairs {
        let tag = parsed.tag.as_ref().expect("Tag is required for restore");

        // Validate tag format early
        crate::tag_utils::validate_tag_basic(tag)?;

        let default_path = ".".to_string();
        let path = parsed.path.as_ref().unwrap_or(&default_path);
        let expanded_path = crate::commands::utils::expand_tilde_path(path);
        let target_path = Path::new(&expanded_path);

        // Check if target path or its parent directory is writable
        let target_to_check = if target_path.exists() {
            target_path
        } else if let Some(parent) = target_path.parent() {
            parent
        } else {
            invalid_targets.push(format!("{} ({})", path, expanded_path));
            continue;
        };

        // Test writability by trying to create a temp file
        match test_path_writability(target_to_check) {
            Ok(true) => {
                valid_pairs.push(parsed.clone());
            }
            Ok(false) => {
                unwritable_targets.push(format!("{} ({})", path, expanded_path));
            }
            Err(_) => {
                invalid_targets.push(format!("{} ({})", path, expanded_path));
            }
        }
    }

    Ok(RestorePreflightCheck {
        valid_pairs,
        unwritable_targets,
        invalid_targets,
    })
}

fn test_path_writability(path: &Path) -> Result<bool> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let test_file = path.join(format!(".boringcache_write_test_{}", std::process::id()));

    match OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&test_file)
    {
        Ok(mut file) => {
            let write_result = file.write_all(b"test");
            let _ = std::fs::remove_file(&test_file); // Clean up
            Ok(write_result.is_ok())
        }
        Err(_) => Ok(false),
    }
}

pub async fn execute_batch_restore(
    workspace_option: Option<String>,
    tag_path_pairs: Vec<String>, // Raw "tag:path" strings
    verbose: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;

    if tag_path_pairs.is_empty() {
        CleanUI::info("No tag:path pairs specified for restore");
        return Ok(());
    }

    let parsed_identifiers: Vec<ParsedIdentifier> = tag_path_pairs
        .iter()
        .map(|tag_path| crate::commands::utils::parse_restore_format(tag_path))
        .collect();

    // Run preflight checks early
    let preflight_result = run_restore_preflight_checks(&parsed_identifiers, verbose)?;

    // Report any issues found during preflight
    if !preflight_result.invalid_targets.is_empty() {
        for target in &preflight_result.invalid_targets {
            CleanUI::warning(&format!("Skipping: invalid target path '{}'", target));
        }
    }

    if !preflight_result.unwritable_targets.is_empty() {
        for target in &preflight_result.unwritable_targets {
            CleanUI::warning(&format!("Permission issue: cannot write to '{}'", target));
            CleanUI::info("Run with sudo or choose a writable location");
        }
    }

    if preflight_result.valid_pairs.is_empty() {
        CleanUI::warning("No valid restore targets found");
        return Ok(());
    }

    if verbose && !preflight_result.valid_pairs.is_empty() {
        CleanUI::info(&format!(
            "Preflight complete: {} valid targets",
            preflight_result.valid_pairs.len()
        ));
    }

    let tags: Vec<String> = preflight_result
        .valid_pairs
        .iter()
        .filter_map(|parsed| parsed.tag.clone())
        .collect();

    CleanUI::batch_start("Resolving", tags.len(), &workspace);

    // Now create cache operations after showing UI feedback
    let cache_ops = crate::cache_operations::CacheOperation::new(workspace.clone(), verbose)?;
    let _platform_info = crate::platform::Platform::detect()?;

    // Transform tags to platform-aware versions using validated pairs
    let mut platform_aware_tag_paths = Vec::new();
    for parsed in &preflight_result.valid_pairs {
        if let Some(tag) = &parsed.tag {
            let platform_tag = tag.clone();
            if let Some(path) = &parsed.path {
                platform_aware_tag_paths.push(format!("{}:{}", platform_tag, path));
            } else {
                platform_aware_tag_paths.push(format!("{}:.", platform_tag));
            }
        }
    }

    let resolved_entries = match cache_ops
        .api_client
        .batch_restore_caches(&workspace, &platform_aware_tag_paths)
        .await
    {
        Ok(entries) => entries,
        Err(e) => {
            CleanUI::section_break();
            CleanUI::batch_summary("found", 0, tags.len(), &workspace);
            return Err(e);
        }
    };

    let mut hits = Vec::new();
    let mut misses = Vec::new();

    for resolved in resolved_entries.iter() {
        if resolved.status == "hit" {
            hits.push((&resolved.identifier, resolved));
        } else {
            misses.push(&resolved.identifier);
        }
    }

    for (identifier, resolved) in hits.iter() {
        let size_bytes = resolved.size.unwrap_or(0) as f64;
        println!(
            "{}: found ({})",
            identifier,
            crate::ui::format_size(size_bytes)
        );
    }

    for tag in &misses {
        CleanUI::item_not_found(tag);
    }

    if hits.is_empty() {
        CleanUI::section_break();
        CleanUI::batch_summary("found", 0, tags.len(), &workspace);
        return Ok(());
    }

    let semaphore = Arc::new(Semaphore::new(1));

    let mut restore_tasks = Vec::new();

    for resolved in resolved_entries.iter() {
        if resolved.status != "hit" {
            continue;
        }

        let parsed = parsed_identifiers
            .iter()
            .find(|p| {
                p.tag
                    .as_ref()
                    .map(|t| t == &resolved.identifier)
                    .unwrap_or(false)
            })
            .unwrap_or(&parsed_identifiers[0]); // Fallback to first if not found

        let target_path = if let Some(path) = &parsed.path {
            path.clone()
        } else {
            anyhow::bail!(
                "Missing path for tag '{}'. Use format: tag:path (e.g., 'node-deps:node_modules')",
                resolved.identifier
            );
        };

        if let Some(download_url) = &resolved.url {
            let size_bytes = resolved.size.unwrap_or(0) as f64;
            println!(
                "=> Restoring '{}' ({}) → {}",
                resolved.identifier,
                crate::ui::format_size(size_bytes),
                target_path
            );

            let tag_name = resolved.identifier.clone();
            let download_url = download_url.clone();
            let target_path = target_path.clone();
            let api_client = cache_ops.api_client.clone();
            let workspace = workspace.clone();
            let size = resolved.size.unwrap_or(0);
            let compression = resolved.compression_algorithm.clone();
            let content_hash = resolved.content_hash.clone();
            let semaphore = semaphore.clone();

            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();

                let download_spinner = CleanUI::item_downloading_start(size as f64);
                let download_start = std::time::Instant::now();

                let download_op = crate::cache_operations::DownloadOperation::new_silent(
                    api_client.clone(),
                    workspace.clone(),
                    false,
                );

                let download_result = download_op
                    .download_and_extract(
                        &download_url,
                        &target_path,
                        size,
                        compression.as_deref(),
                        content_hash.as_deref(),
                    )
                    .await;

                let download_duration = download_start.elapsed().as_millis() as u64;

                match download_result {
                    Ok(_) => {
                        CleanUI::item_downloading_complete(download_spinner, download_duration);

                        Ok(tag_name)
                    }
                    Err(e) => {
                        download_spinner.stop();
                        CleanUI::item_error(&tag_name, &format!("download failed - {e}"));
                        Err(e)
                    }
                }
            });

            restore_tasks.push(task);
        }
    }

    let mut successfully_restored = Vec::new();

    for task in restore_tasks {
        match task.await {
            Ok(Ok(tag)) => {
                successfully_restored.push(tag);
            }
            Ok(Err(_)) => { /* handled in task already */ }
            Err(e) => {
                CleanUI::item_error("task", &e.to_string());
            }
        }
    }

    if !successfully_restored.is_empty() {
        let restored_list = successfully_restored.join(",");
        CleanUI::batch_summary_restore(&restored_list, &workspace);
    }

    Ok(())
}
