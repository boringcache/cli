use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Semaphore;

use crate::ui::CleanUI;

pub async fn execute_batch_restore(
    workspace_option: Option<String>,
    tag_path_pairs: Vec<String>, // Raw "tag:path" strings
    verbose: bool,
    no_platform: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let cache_ops = crate::cache_operations::CacheOperation::new(workspace.clone(), verbose)?;

    if tag_path_pairs.is_empty() {
        CleanUI::info("No tag:path pairs specified for restore");
        return Ok(());
    }

    let platform_info = crate::platform::Platform::detect()?;

    let parsed_identifiers: Vec<crate::commands::utils::ParsedIdentifier> = tag_path_pairs
        .iter()
        .map(|tag_path| crate::commands::utils::parse_restore_format(tag_path))
        .collect();

    // Transform tags to platform-aware versions
    let mut platform_aware_tag_paths = Vec::new();
    for parsed in &parsed_identifiers {
        if let Some(tag) = &parsed.tag {
            let platform_tag =
                crate::tag_utils::resolve_tag_for_restore(tag, &platform_info, no_platform)?;
            if let Some(path) = &parsed.path {
                platform_aware_tag_paths.push(format!("{}:{}", platform_tag, path));
            } else {
                platform_aware_tag_paths.push(format!("{}:.", platform_tag));
            }
        }
    }

    let tags: Vec<String> = parsed_identifiers
        .iter()
        .filter_map(|parsed| parsed.tag.clone())
        .collect();

    CleanUI::batch_start("Resolving", tags.len(), &workspace);
    if no_platform {
        CleanUI::info("⚠️  Using --no-platform: will look for exact tag matches");
    } else {
        CleanUI::info(&format!(
            "🏷️  Will resolve tags for platform: {}",
            platform_info.to_tag_suffix()
        ));
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
                    .download_and_extract(&download_url, &target_path, size, compression.as_deref())
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
