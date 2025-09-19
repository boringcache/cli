use anyhow::Result;

use crate::commands::utils::ParsedIdentifier;
use crate::ui::CleanUI;

fn validate_and_filter_paths(parsed_pairs: &[ParsedIdentifier]) -> Vec<ParsedIdentifier> {
    let mut valid_parsed_pairs = Vec::new();

    for parsed in parsed_pairs {
        let path = parsed.path.as_ref().expect("Path is required for save");
        let expanded_path = crate::commands::utils::expand_tilde_path(path);

        let path_obj = std::path::Path::new(&expanded_path);
        if !path_obj.exists() {
            CleanUI::warning(&format!(
                "Skipping: path not found '{}' (expanded from '{}')",
                expanded_path, path
            ));
            continue;
        }
        valid_parsed_pairs.push(parsed.clone());
    }

    valid_parsed_pairs
}

pub async fn execute_batch_save(
    workspace_option: Option<String>,
    path_tag_pairs: Vec<String>,
    compression_choice: Option<crate::cli::CompressionChoice>,
    description: Option<String>,
    _async_save: bool,
    verbose: bool,
    no_platform: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;
    let cache_ops = crate::cache_operations::CacheOperation::new(workspace.clone(), verbose)?;

    let parsed_pairs: Vec<_> = path_tag_pairs
        .iter()
        .map(|pair| crate::commands::utils::parse_save_format(pair))
        .collect();

    let valid_parsed_pairs = validate_and_filter_paths(&parsed_pairs);

    if valid_parsed_pairs.is_empty() {
        CleanUI::warning("No valid paths found to save");
        return Ok(());
    }

    if no_platform {
        CleanUI::batch_start("Saving", valid_parsed_pairs.len(), &workspace);
        CleanUI::info("⚠️  Using --no-platform: tags will not include platform suffixes");
    } else {
        CleanUI::batch_start("Saving", valid_parsed_pairs.len(), &workspace);
        let platform = crate::platform::Platform::detect()?;
        CleanUI::info(&format!(
            "🏷️  Tags will include platform suffix: {}",
            platform.to_tag_suffix()
        ));
    }

    use crate::archive;
    use crate::compression::CompressionBackend;
    use futures_util::future::join_all;
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let archive_semaphore = Arc::new(Semaphore::new(1));
    let mut archive_tasks = Vec::new();

    let platform_info = crate::platform::Platform::detect()?;

    for parsed in &valid_parsed_pairs {
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
        let platform_tag =
            crate::tag_utils::ensure_platform_aware_tag(&user_tag, &platform_info, no_platform)?;
        let platform_info_clone = platform_info.clone();
        let sem = Arc::clone(&archive_semaphore);
        let display_tag = if no_platform {
            user_tag.clone()
        } else {
            format!("{} ({})", user_tag, platform_info_clone.to_tag_suffix())
        };

        let task = tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();

            CleanUI::item_start(&display_tag);

            let compression = compression_choice.map(|choice| match choice {
                crate::cli::CompressionChoice::Lz4 => CompressionBackend::Lz4,
                crate::cli::CompressionChoice::Zstd => CompressionBackend::Zstd,
            });

            let platform_fingerprint = if !no_platform {
                Some(platform_info_clone.fingerprint())
            } else {
                None
            };

            let archive_start = std::time::Instant::now();
            let (archive_data, archive_info) =
                archive::create_archive(&paths, compression, false, platform_fingerprint).await?;

            CleanUI::item_archiving(
                archive_info.file_count as usize,
                archive_info.uncompressed_size as f64,
            );

            let algorithm_name = archive_info.compression_backend.name();
            CleanUI::item_compressing(algorithm_name);
            let compression_duration = archive_start.elapsed().as_millis() as u64;
            CleanUI::item_compression_complete(compression_duration);

            let metadata = serde_json::json!({
                "content_hash": archive_info.content_sha256,
                "compression_algorithm": archive_info.compression_backend.name(),
                "size": archive_info.compressed_size,
                "uncompressed_size": archive_info.uncompressed_size,
                "file_count": archive_info.file_count,
                "path": expanded_path,
            });

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

    let platform_info_for_pairs = crate::platform::Platform::detect()?;
    let mut valid_path_tag_pairs = Vec::new();
    for parsed in &valid_parsed_pairs {
        let path = parsed.path.as_ref().expect("Path is required");
        let tag = parsed.tag.as_ref().expect("Tag is required");
        let platform_tag = crate::tag_utils::ensure_platform_aware_tag(
            tag,
            &platform_info_for_pairs,
            no_platform,
        )?;
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

    CleanUI::batch_summary("saved", successful_uploads, parsed_pairs.len(), &workspace);

    Ok(())
}
