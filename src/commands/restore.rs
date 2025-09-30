use crate::api::CacheResolutionEntry;
use crate::commands::utils::ParsedIdentifier;
use crate::progress::{Summary, System as ProgressSystem};
use crate::ui; // Keep for static table/summary operations only
use anyhow::Result;
use std::io::Write;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug)]
struct RestorePreflightCheck {
    valid_pairs: Vec<ParsedIdentifier>,
}

fn run_restore_preflight_checks(
    parsed_pairs: &[ParsedIdentifier],
) -> Result<RestorePreflightCheck> {
    let mut valid_pairs = Vec::new();
    let mut issues = Vec::new();

    for parsed in parsed_pairs {
        let tag = match parsed.tag.as_ref() {
            Some(tag) => tag,
            None => {
                issues.push("Missing tag for restore request".to_string());
                continue;
            }
        };

        if let Err(error) = crate::commands::utils::validate_tag_name(tag) {
            issues.push(format!("Invalid tag '{}': {}", tag, error));
            continue;
        }

        let default_path = ".".to_string();
        let path = parsed.path.as_ref().unwrap_or(&default_path);
        let expanded_path = crate::commands::utils::expand_tilde_path(path);
        let target_path = Path::new(&expanded_path);

        if target_path.exists() {
            match std::fs::metadata(target_path) {
                Ok(metadata) => {
                    if !metadata.is_dir() {
                        issues.push(format!(
                            "Target '{}' exists but is not a directory",
                            expanded_path
                        ));
                        continue;
                    }
                }
                Err(error) => {
                    issues.push(format!(
                        "Cannot inspect existing target '{}': {}",
                        expanded_path, error
                    ));
                    continue;
                }
            }
        }

        match ensure_restore_target_write_ready(target_path) {
            Ok(()) => {
                valid_pairs.push(parsed.clone());
            }
            Err(error) => {
                issues.push(format!(
                    "Cannot prepare target '{}': {}",
                    expanded_path, error
                ));
            }
        }
    }

    if !issues.is_empty() {
        let mut message = String::from("Restore preflight failed:\n");
        for issue in &issues {
            message.push_str("  - ");
            message.push_str(issue);
            message.push('\n');
        }

        return Err(anyhow::anyhow!(message.trim_end().to_string()));
    }

    Ok(RestorePreflightCheck { valid_pairs })
}

fn ensure_restore_target_write_ready(target_path: &Path) -> Result<()> {
    use std::path::PathBuf;

    let directory_to_check = if target_path.exists() {
        PathBuf::from(target_path)
    } else if let Some(parent) = target_path.parent() {
        if parent.as_os_str().is_empty() {
            std::env::current_dir()?
        } else if parent.exists() {
            parent.to_path_buf()
        } else {
            find_existing_parent(parent)?
        }
    } else {
        std::env::current_dir()?
    };

    if !directory_to_check.exists() {
        anyhow::bail!("No existing parent directory for {}", target_path.display());
    }

    let metadata = std::fs::metadata(&directory_to_check)?;
    if !metadata.is_dir() {
        anyhow::bail!("{} is not a directory", directory_to_check.display());
    }

    assert_directory_writable(&directory_to_check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::utils::ParsedIdentifier;

    #[test]
    fn preflight_rejects_file_target() {
        let temp = tempfile::tempdir().unwrap();
        let file_path = temp.path().join("existing_file");
        std::fs::write(&file_path, b"data").unwrap();

        let parsed = ParsedIdentifier {
            key: String::new(),
            path: Some(file_path.to_string_lossy().to_string()),
            tag: Some("valid-tag".to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]);
        assert!(result.is_err());
        let message = format!("{}", result.unwrap_err());
        assert!(message.contains("not a directory"));
    }

    #[test]
    fn preflight_accepts_new_directory() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("new-directory");
        let parsed = ParsedIdentifier {
            key: String::new(),
            path: Some(target.to_string_lossy().to_string()),
            tag: Some("valid-tag".to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]).unwrap();
        assert_eq!(result.valid_pairs.len(), 1);
    }

    #[test]
    fn preflight_rejects_invalid_tag() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("dir");
        let parsed = ParsedIdentifier {
            key: String::new(),
            path: Some(target.to_string_lossy().to_string()),
            tag: Some("invalid tag".to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]);
        assert!(result.is_err());
        let message = format!("{}", result.unwrap_err());
        assert!(message.contains("Invalid tag"));
    }
}

fn find_existing_parent(path: &Path) -> Result<std::path::PathBuf> {
    let mut current = path;

    while let Some(parent) = current.parent() {
        if parent.as_os_str().is_empty() {
            return Ok(std::env::current_dir()?);
        }

        if parent.exists() {
            return Ok(parent.to_path_buf());
        }

        current = parent;
    }

    Ok(std::env::current_dir()?)
}

fn assert_directory_writable(path: &Path) -> Result<()> {
    use std::fs::OpenOptions;
    use uuid::Uuid;

    let metadata = std::fs::metadata(path)?;
    if !metadata.is_dir() {
        anyhow::bail!("{} is not a directory", path.display());
    }

    let test_file_name = format!(".boringcache_test_{}", Uuid::new_v4());
    let test_file = path.join(&test_file_name);

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&test_file)
        .map_err(|error| {
            anyhow::anyhow!(
                "Failed to create temporary file in {}: {}",
                path.display(),
                error
            )
        })?;

    file.write_all(b"test")
        .map_err(|error| anyhow::anyhow!("Failed to write to {}: {}", path.display(), error))?;

    std::fs::remove_file(&test_file).map_err(|error| {
        anyhow::anyhow!(
            "Failed to clean up temporary file in {}: {}",
            path.display(),
            error
        )
    })?;

    Ok(())
}

pub async fn execute_batch_restore(
    workspace_option: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;

    if tag_path_pairs.is_empty() {
        eprintln!("info: No tag:path pairs specified for restore");
        return Ok(());
    }

    let parsed_identifiers: Vec<ParsedIdentifier> = tag_path_pairs
        .iter()
        .map(|tag_path| crate::commands::utils::parse_restore_format(tag_path))
        .collect();

    // Run preflight checks
    let preflight_result = run_restore_preflight_checks(&parsed_identifiers)?;

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
        reporter.warning("No valid restore targets found".to_string())?;
        progress_system.shutdown()?;
        return Ok(());
    }

    // For restore, construct TAG:PATH entries as expected by the API
    let entries: Vec<String> = preflight_result
        .valid_pairs
        .iter()
        .map(|p| {
            let original_tag = p.tag.as_ref().unwrap();
            crate::tag_utils::apply_platform_to_tag_with_instance(original_tag, platform.as_ref())
        })
        .collect();

    // Create cache operations
    let cache_ops = crate::cache_operations::CacheOperation::new(workspace.clone(), verbose)?;

    // Resolve tags to cache entries
    let session_id = format!("resolve:{}", workspace);
    let tags_display: Vec<String> = preflight_result
        .valid_pairs
        .iter()
        .map(|p| p.tag.as_ref().unwrap().clone())
        .collect();

    reporter.session_start(
        session_id.clone(),
        format!("Resolving cache [{}]", tags_display.join(", ")),
        1,
    )?;

    let step_start = Instant::now();
    reporter.step_start(session_id.clone(), 1, "Resolving entries".to_string(), None)?;

    let resolution_result = cache_ops
        .api_client
        .batch_restore_caches(&workspace, &entries)
        .await?;

    let mut hits: Vec<CacheResolutionEntry> = Vec::new();
    let mut misses: Vec<String> = Vec::new();

    for entry in resolution_result.into_iter() {
        match entry.status.as_deref() {
            Some("hit") => hits.push(entry),
            _ => {
                let identifier = entry
                    .identifier
                    .clone()
                    .or(entry.tag.clone())
                    .unwrap_or_else(|| "unknown".to_string());
                reporter.warning(format!("Cache miss for {}", identifier))?;
                misses.push(identifier);
            }
        }
    }

    reporter.step_complete(session_id.clone(), 1, step_start.elapsed())?;

    if hits.is_empty() {
        reporter.session_error(
            session_id,
            "No cache entries found for the specified tags".to_string(),
        )?;
        progress_system.shutdown()?;

        // Show static summary table
        ui::blank_line();
        ui::workflow_summary("found", 0, tags_display.len(), &workspace);
        if !misses.is_empty() {
            ui::warn(&format!("Not found: {}", misses.join(", ")));
        }
        return Ok(());
    }

    let summary = Summary {
        size_bytes: hits.iter().map(|h| h.size.unwrap_or(0)).sum(),
        file_count: hits.len() as u32,
        digest: None,
        path: None,
    };
    reporter.session_complete(session_id, step_start.elapsed(), summary)?;

    // Process each restore with progress tracking
    let mut handles = Vec::new();

    for hit in &hits {
        // Find the corresponding parsed identifier for target path
        let parsed = preflight_result
            .valid_pairs
            .iter()
            .find(|p| {
                if let (Some(p_tag), Some(hit_tag)) = (p.tag.as_ref(), hit.tag.as_ref()) {
                    // Apply platform suffix to original tag for comparison (like we did earlier)
                    let platform_aware_tag = crate::tag_utils::apply_platform_to_tag_with_instance(
                        p_tag,
                        platform.as_ref(),
                    );
                    platform_aware_tag == *hit_tag
                } else {
                    false
                }
            })
            .expect("Should find matching parsed identifier");

        let default_path = ".".to_string();
        let path = parsed.path.as_ref().unwrap_or(&default_path);
        let expanded_target_path = crate::commands::utils::expand_tilde_path(path);

        let session_id = format!(
            "restore:{}:{}",
            workspace,
            hit.tag.as_ref().unwrap_or(&"unknown".to_string())
        );
        let title = format!(
            "Restoring cache [{}]",
            hit.tag.as_ref().unwrap_or(&"unknown".to_string())
        );

        let reporter_clone = reporter.clone();
        let workspace_clone = workspace.clone();
        let cache_ops_clone = cache_ops.clone();
        let hit_clone = hit.clone();

        let handle = tokio::spawn(async move {
            process_single_restore(
                reporter_clone,
                session_id,
                title,
                workspace_clone,
                cache_ops_clone,
                hit_clone,
                expanded_target_path,
                verbose,
            )
            .await
        });

        handles.push(handle);
    }

    // Wait for all restores to complete
    let mut restored_tags = Vec::new();

    for handle in handles {
        if let Ok(tag) = handle.await? {
            restored_tags.push(tag);
        }
    }

    progress_system.shutdown()?;

    // Show final summary using static UI
    ui::blank_line();
    ui::workflow_summary(
        "restored",
        restored_tags.len(),
        tags_display.len(),
        &workspace,
    );

    if !restored_tags.is_empty() {
        ui::restore_summary(&restored_tags, &workspace);
    }

    if !misses.is_empty() {
        ui::warn(&format!("Missing cache entries: {}", misses.join(", ")));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn process_single_restore(
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    cache_ops: crate::cache_operations::CacheOperation,
    hit: CacheResolutionEntry,
    target_path: String,
    _verbose: bool,
) -> Result<String> {
    let session_start = Instant::now();

    // Start session with 4 steps: [1/4] Resolving, [2/4] Downloading, [3/4] Extracting, [4/4] Finalizing
    reporter.session_start(session_id.clone(), title, 4)?;

    // Step 1: Resolving entry (already done, show briefly)
    let step_start = Instant::now();
    reporter.step_start(session_id.clone(), 1, "Resolving entry".to_string(), None)?;
    tokio::time::sleep(Duration::from_millis(50)).await;
    reporter.step_complete(session_id.clone(), 1, step_start.elapsed())?;

    // Step 2: Downloading
    let download_detail = if let Some(size) = hit.size {
        format!("[{}]", crate::progress::format_bytes(size))
    } else {
        String::new()
    };

    reporter.step_start(
        session_id.clone(),
        2,
        "Downloading".to_string(),
        if download_detail.is_empty() {
            None
        } else {
            Some(download_detail)
        },
    )?;

    let mut attempts = 0;
    let mut current_hit = hit.clone();

    // Create progress tracker for download
    let download_size = current_hit.size.unwrap_or(0);
    let progress = if download_size > 0 {
        Some(std::sync::Arc::new(
            crate::commands::utils::TransferProgress::new(
                reporter.clone(),
                session_id.clone(),
                2, // Step 2 is downloading
                download_size,
            ),
        ))
    } else {
        None
    };

    // Download phase - separate from extraction for proper UI updates
    let download_result = loop {
        attempts += 1;

        let download_url = current_hit
            .url
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("Cache entry missing download URL"))?;

        let download_res = cache_ops
            .download(
                download_url,
                current_hit.size.unwrap_or(0),
                current_hit.content_hash.as_deref(),
                Some(&target_path),
                progress.clone(),
            )
            .await;

        match download_res {
            Ok(archive) => break Ok(archive),
            Err(e) => {
                let message = e.to_string();
                if attempts == 1 && message.contains("HTTP 404") {
                    reporter.warning(
                        "Download link returned 404, refreshing cache metadata and retrying"
                            .to_string(),
                    )?;
                    if let Some(refreshed) =
                        refresh_cache_entry(&cache_ops, &workspace, &current_hit).await?
                    {
                        current_hit = refreshed;
                        continue;
                    }
                }
                break Err(e);
            }
        }
    };

    match download_result {
        Ok(archive) => {
            // Complete the download step with actual duration
            reporter.step_progress(session_id.clone(), 2, 100.0, Some(String::new()))?;
            reporter.step_complete(session_id.clone(), 2, archive.duration)?;

            // Step 3: Extracting files - now separate from download
            reporter.step_start(session_id.clone(), 3, "Extracting files".to_string(), None)?;

            let extraction_duration = cache_ops
                .extract(
                    archive.data,
                    &target_path,
                    current_hit.compression_algorithm.as_deref(),
                )
                .await?;

            reporter.step_complete(session_id.clone(), 3, extraction_duration)?;

            // Step 4: Finalizing
            let step_start = Instant::now();
            reporter.step_start(
                session_id.clone(),
                4,
                "Finalizing restore".to_string(),
                None,
            )?;
            tokio::time::sleep(Duration::from_millis(50)).await;
            reporter.step_complete(session_id.clone(), 4, step_start.elapsed())?;

            let summary = Summary {
                size_bytes: hit.size.unwrap_or(0),
                file_count: 1, // We don't track individual file count in cache entries
                digest: hit.content_hash.clone(),
                path: Some(target_path),
            };

            reporter.session_complete(session_id, session_start.elapsed(), summary)?;
            Ok(hit.tag.clone().unwrap_or_else(|| "unknown".to_string()))
        }
        Err(e) => {
            reporter.session_error(session_id, e.to_string())?;
            Err(e)
        }
    }
}

async fn refresh_cache_entry(
    cache_ops: &crate::cache_operations::CacheOperation,
    workspace: &str,
    current_hit: &CacheResolutionEntry,
) -> Result<Option<CacheResolutionEntry>> {
    let tag = current_hit
        .tag
        .as_ref()
        .or(current_hit.identifier.as_ref())
        .ok_or_else(|| anyhow::anyhow!("Cache entry missing tag"))?;

    let refreshed = cache_ops
        .api_client
        .batch_restore_caches(workspace, &[tag.to_string()])
        .await?;

    Ok(refreshed
        .into_iter()
        .find(|entry| entry.status.as_deref() == Some("hit") && entry.tag == current_hit.tag))
}
