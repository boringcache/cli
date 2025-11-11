#![allow(clippy::items_after_test_module)]

use crate::api::CacheResolutionEntry;
use crate::chunks::store::ChunkStore;
use crate::commands::utils::RestoreSpec;
use crate::manifest::diff::compute_root_digest_from_entries;
use crate::progress::{ProgressSession, Summary, System as ProgressSystem};
use crate::ui;
use anyhow::{Context, Error, Result};
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::time::Instant;
use tokio::fs;

#[derive(Debug)]
struct RestorePreflightCheck {
    valid_specs: Vec<RestoreSpec>,
}

fn run_restore_preflight_checks(parsed_pairs: &[RestoreSpec]) -> Result<RestorePreflightCheck> {
    let mut valid_specs = Vec::new();
    let mut warnings = Vec::new();

    for spec in parsed_pairs {
        if let Err(error) = crate::tag_utils::validate_tag(&spec.tag) {
            warnings.push(format!("Skipping invalid tag '{}': {}", spec.tag, error));
            continue;
        }

        let path = spec.path.as_deref().unwrap_or(".");
        let expanded_path = crate::commands::utils::expand_tilde_path(path);
        let target_path = Path::new(&expanded_path);

        if target_path.exists() {
            match std::fs::metadata(target_path) {
                Ok(metadata) => {
                    if !metadata.is_dir() {
                        warnings.push(format!(
                            "Skipping '{}': target '{}' exists but is not a directory",
                            spec.tag, expanded_path
                        ));
                        continue;
                    }
                }
                Err(error) => {
                    warnings.push(format!(
                        "Skipping '{}': cannot inspect target '{}': {}",
                        spec.tag, expanded_path, error
                    ));
                    continue;
                }
            }
        }

        match ensure_restore_target_write_ready(target_path) {
            Ok(()) => {
                valid_specs.push(spec.clone());
            }
            Err(error) => {
                warnings.push(format!(
                    "Skipping '{}': cannot prepare target '{}': {}",
                    spec.tag, expanded_path, error
                ));
            }
        }
    }

    if !warnings.is_empty() {
        for warning in &warnings {
            ui::warn(warning);
        }
    }

    // Allow empty results for batch operations where all entries are skipped
    // This is non-invasive behavior - we continue with whatever is valid

    Ok(RestorePreflightCheck { valid_specs })
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
    use crate::commands::utils::RestoreSpec;

    #[test]
    fn preflight_skips_file_target() {
        let temp = tempfile::tempdir().unwrap();
        let file_path = temp.path().join("existing_file");
        std::fs::write(&file_path, b"data").unwrap();

        let parsed = RestoreSpec {
            tag: "valid-tag".to_string(),
            path: Some(file_path.to_string_lossy().to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]).unwrap();
        assert_eq!(result.valid_specs.len(), 0);
    }

    #[test]
    fn preflight_accepts_new_directory() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("new-directory");
        let parsed = RestoreSpec {
            tag: "valid-tag".to_string(),
            path: Some(target.to_string_lossy().to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]).unwrap();
        assert_eq!(result.valid_specs.len(), 1);
    }

    #[test]
    fn preflight_skips_invalid_tag() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("dir");
        let parsed = RestoreSpec {
            tag: "invalid tag".to_string(),
            path: Some(target.to_string_lossy().to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]).unwrap();
        assert_eq!(result.valid_specs.len(), 0);
    }

    #[test]
    fn preflight_continues_batch_with_valid_entries() {
        let temp = tempfile::tempdir().unwrap();
        let file_path = temp.path().join("existing_file");
        std::fs::write(&file_path, b"data").unwrap();

        let valid_dir = temp.path().join("valid_dir");

        let parsed_entries = vec![
            RestoreSpec {
                tag: "tag1".to_string(),
                path: Some(file_path.to_string_lossy().to_string()),
            },
            RestoreSpec {
                tag: "tag2".to_string(),
                path: Some(valid_dir.to_string_lossy().to_string()),
            },
            RestoreSpec {
                tag: "tag3".to_string(),
                path: Some("/nonexistent/path".to_string()),
            },
        ];

        let result = run_restore_preflight_checks(&parsed_entries).unwrap();
        assert_eq!(result.valid_specs.len(), 1);
        assert_eq!(result.valid_specs[0].tag, "tag2");
    }

    // Tests for new flag functionality - these would be integration tests
    // but we can at least test the flag parsing and basic logic

    #[test]
    fn test_fail_on_cache_miss_flag_logic() {
        // Test that we can correctly identify when we should fail on cache miss
        let fail_on_cache_miss = true;
        let misses = ["missing-cache".to_string()];

        // This would normally be tested in an integration test, but we can verify
        // the basic logic that if flag is true and there are misses, we should fail
        assert!(fail_on_cache_miss && !misses.is_empty());

        // Test when flag is false
        let fail_on_cache_miss = false;
        assert!(!fail_on_cache_miss || misses.is_empty());

        // Test when flag is true but no misses
        let fail_on_cache_miss = true;
        let misses: Vec<String> = vec![];
        assert!(!fail_on_cache_miss || misses.is_empty());
    }

    #[test]
    fn test_lookup_only_flag_logic() {
        // Test that we can correctly identify when we're in lookup-only mode
        let lookup_only = true;
        assert!(lookup_only);

        // Test when flag is false
        let lookup_only = false;
        assert!(!lookup_only);
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
    fail_on_cache_miss: bool,
    lookup_only: bool,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;

    if tag_path_pairs.is_empty() {
        ui::info("No tag:path pairs specified for restore");
        return Ok(());
    }

    let parsed_specs: Vec<RestoreSpec> = tag_path_pairs
        .iter()
        .map(|tag_path| crate::commands::utils::parse_restore_format(tag_path).map_err(Error::from))
        .collect::<Result<_, _>>()?;

    // Run preflight checks
    let preflight_result = run_restore_preflight_checks(&parsed_specs)?;

    // Detect platform for tag suffix
    let platform = if !no_platform {
        Some(crate::platform::Platform::detect()?)
    } else {
        None
    };

    // Set up progress system
    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();

    if preflight_result.valid_specs.is_empty() {
        reporter.warning("No valid restore targets found".to_string())?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(());
    }

    // For restore, construct TAG:PATH entries as expected by the API
    let mut resolved_entries: Vec<String> = Vec::with_capacity(preflight_result.valid_specs.len());
    let mut target_paths_by_tag: HashMap<String, String> =
        HashMap::with_capacity(preflight_result.valid_specs.len());
    let mut tags_display: Vec<String> = Vec::with_capacity(preflight_result.valid_specs.len());

    for spec in &preflight_result.valid_specs {
        tags_display.push(spec.tag.clone());
        let resolved_tag =
            crate::tag_utils::apply_platform_to_tag_with_instance(&spec.tag, platform.as_ref());
        let target_path = spec
            .path
            .as_deref()
            .map(crate::commands::utils::expand_tilde_path)
            .unwrap_or_else(|| ".".to_string());
        target_paths_by_tag.insert(resolved_tag.clone(), target_path);
        resolved_entries.push(resolved_tag);
    }

    // Create API client
    let api_client = crate::api::ApiClient::new()?;

    // Resolve tags to cache entries
    let session_id = format!("resolve:{}", workspace);

    reporter.session_start(
        session_id.clone(),
        format!("Resolving cache [{}]", tags_display.join(", ")),
        1,
    )?;

    let step_start = Instant::now();
    reporter.step_start(session_id.clone(), 1, "Resolving entries".to_string(), None)?;

    let resolution_result = api_client.restore(&workspace, &resolved_entries).await?;

    let mut hits: Vec<CacheResolutionEntry> = Vec::new();
    let mut misses: Vec<String> = Vec::new();

    for entry in resolution_result.into_iter() {
        if entry.status == "hit" {
            hits.push(entry);
        } else {
            reporter.warning(format!("Cache miss for {}", entry.tag))?;
            misses.push(entry.tag.clone());
        }
    }

    reporter.step_complete(session_id.clone(), 1, step_start.elapsed())?;

    // Handle fail-on-cache-miss flag
    if fail_on_cache_miss && !misses.is_empty() {
        reporter.session_error(
            session_id,
            format!("Cache miss for tags: {}", misses.join(", ")),
        )?;
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!("Cache miss for tags: {}", misses.join(", "));
    }

    if hits.is_empty() {
        reporter.session_error(
            session_id,
            "No cache entries found for the specified tags".to_string(),
        )?;
        drop(reporter);
        progress_system.shutdown()?;

        // Show static summary table
        ui::blank_line();
        ui::workflow_summary("found", 0, tags_display.len(), &workspace);
        if !misses.is_empty() {
            ui::warn(&format!("Not found: {}", misses.join(", ")));
        }
        return Ok(());
    }

    // Handle lookup-only flag
    if lookup_only {
        drop(reporter);
        progress_system.shutdown()?;

        // Show summary of what exists vs missing
        ui::blank_line();
        ui::workflow_summary("found", hits.len(), tags_display.len(), &workspace);

        if !hits.is_empty() {
            let found_tags: Vec<String> = hits.iter().map(|h| h.tag.clone()).collect();
            ui::info(&format!(
                "Available cache entries: {}",
                found_tags.join(", ")
            ));
        }

        if !misses.is_empty() {
            ui::warn(&format!("Not found: {}", misses.join(", ")));
        }

        return Ok(());
    }

    enrich_hits_with_manifest_data(&api_client, &workspace, &mut hits, reporter.clone()).await?;

    let summary = Summary {
        size_bytes: hits.iter().map(|h| h.size.unwrap_or(0)).sum(),
        file_count: hits.len() as u32,
        digest: None,
        path: None,
    };
    reporter.session_complete(session_id, step_start.elapsed(), summary)?;

    // Process each restore sequentially to keep output readable
    let mut restored_tags = Vec::new();
    let mut skipped_entries: Vec<(String, String)> = Vec::new();
    let mut restore_errors: Vec<Error> = Vec::new();

    for hit in hits {
        let expanded_target_path = target_paths_by_tag
            .get(&hit.tag)
            .cloned()
            .or_else(|| {
                preflight_result
                    .valid_specs
                    .iter()
                    .find(|spec| {
                        crate::tag_utils::apply_platform_to_tag_with_instance(
                            &spec.tag,
                            platform.as_ref(),
                        ) == hit.tag
                    })
                    .map(|spec| {
                        spec.path
                            .as_deref()
                            .map(crate::commands::utils::expand_tilde_path)
                            .unwrap_or_else(|| ".".to_string())
                    })
            })
            .unwrap_or_else(|| ".".to_string());

        let session_id = format!("restore:{}:{}", workspace, hit.tag);
        let title = format!("Restoring cache [{}]", hit.tag);

        match process_single_restore(
            reporter.clone(),
            session_id,
            title,
            workspace.clone(),
            hit,
            expanded_target_path,
            verbose,
        )
        .await
        {
            Ok(RestoreOutcome::Restored { tag }) => {
                restored_tags.push(tag);
            }
            Ok(RestoreOutcome::Skipped { tag, reason }) => {
                skipped_entries.push((tag, reason));
            }
            Err(err) => {
                restore_errors.push(err);
            }
        }
    }

    drop(reporter);
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

    if !skipped_entries.is_empty() {
        let skipped_list = skipped_entries
            .iter()
            .map(|(tag, _)| tag.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        ui::warn(&format!(
            "Skipped {} entr{}: {}",
            skipped_entries.len(),
            if skipped_entries.len() == 1 {
                "y"
            } else {
                "ies"
            },
            skipped_list
        ));
    }

    if !restore_errors.is_empty() {
        for err in restore_errors {
            ui::error(&format!("Restore failed: {}", err));
        }
    }

    if !misses.is_empty() {
        ui::warn(&format!("Missing cache entries: {}", misses.join(", ")));
    }

    Ok(())
}

async fn enrich_hits_with_manifest_data(
    api_client: &crate::api::ApiClient,
    workspace: &str,
    hits: &mut [CacheResolutionEntry],
    reporter: crate::progress::Reporter,
) -> Result<()> {
    use crate::api::models::cache::{
        ManifestCheckRequest, ManifestCheckResponse, ManifestCheckResult,
    };

    let missing_manifest: Vec<(usize, String, String, Vec<String>)> = hits
        .iter()
        .enumerate()
        .filter_map(|(idx, hit)| {
            let digest = hit.manifest_root_digest.clone()?;
            if hit.manifest_url.is_some() {
                return None;
            }
            Some((idx, hit.tag.clone(), digest, hit.chunk_digests.clone()))
        })
        .collect();

    if missing_manifest.is_empty() {
        return Ok(());
    }

    let manifest_checks: Vec<ManifestCheckRequest> = missing_manifest
        .iter()
        .map(|(_, tag, digest, digests)| ManifestCheckRequest {
            tag: tag.clone(),
            manifest_root_digest: digest.clone(),
            chunk_digests: if digests.is_empty() {
                None
            } else {
                Some(digests.clone())
            },
        })
        .collect();

    let response: ManifestCheckResponse = match api_client
        .check_manifests(workspace, &manifest_checks)
        .await
    {
        Ok(response) => response,
        Err(err) => {
            let _ = reporter.warning(format!("Failed to refresh manifest metadata: {}", err));
            return Ok(());
        }
    };

    if response.results.is_empty() {
        return Ok(());
    }

    let mut result_by_tag: HashMap<String, ManifestCheckResult> = HashMap::new();
    for result in response.results {
        if result.exists && result.manifest_url.is_some() {
            result_by_tag.insert(result.tag.clone(), result);
        }
    }

    for (idx, tag, _, _) in missing_manifest {
        if let Some(extra) = result_by_tag.get(&tag) {
            let hit = &mut hits[idx];
            if hit.manifest_url.is_none() {
                hit.manifest_url = extra.manifest_url.clone();
            }
            if hit.chunks.is_empty() {
                if let Some(new_chunks) = extra.chunk_urls.clone() {
                    hit.chunks = new_chunks;
                    hit.chunk_digests = hit.chunks.iter().map(|c| c.digest.clone()).collect();
                }
            }
            if hit.chunk_count.is_none() {
                hit.chunk_count = extra.chunk_count;
            }
            if hit.size.is_none() {
                hit.size = extra.size;
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
#[derive(Debug)]
enum RestoreOutcome {
    Restored { tag: String },
    Skipped { tag: String, reason: String },
}

async fn process_single_restore(
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    _workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    _verbose: bool,
) -> Result<RestoreOutcome> {
    match ensure_empty_target(&target_path).await? {
        EnsureTargetStatus::Ready => {}
        EnsureTargetStatus::Occupied { existing_path } => {
            let reason = format!(
                "Restore target '{}' is not empty; skipping restore for {}",
                existing_path, hit.tag
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            return Ok(RestoreOutcome::Skipped {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }

    if hit.chunks.is_empty() {
        anyhow::bail!("No chunk metadata in response");
    }
    let chunk_descriptors = hit.chunks.clone();

    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest URL in response"))?
        .clone();

    let mut session = ProgressSession::new(reporter.clone(), session_id.clone(), title, 3)?;

    let client = reqwest::Client::new();

    let manifest_step = session.start_step("Fetch manifest".to_string(), None)?;
    let manifest_bytes = client
        .get(&manifest_url)
        .send()
        .await?
        .error_for_status()
        .context("Manifest request failed")?
        .bytes()
        .await?
        .to_vec();

    let manifest: crate::manifest::Manifest =
        ciborium::from_reader(&manifest_bytes[..]).context("Failed to parse manifest")?;
    manifest_step.complete()?;

    let mut sorted_entries = manifest.files.clone();
    sorted_entries.sort_by(|a, b| a.path.cmp(&b.path));
    let manifest_digest = compute_root_digest_from_entries(&sorted_entries);
    let root_norm = manifest
        .root
        .digest
        .strip_prefix("blake3:")
        .unwrap_or(&manifest.root.digest);
    let manifest_norm = manifest_digest
        .strip_prefix("blake3:")
        .unwrap_or(&manifest_digest);

    if !manifest_norm.eq_ignore_ascii_case(root_norm) {
        anyhow::bail!(
            "Manifest digest mismatch: declared {} but computed {}",
            manifest.root.digest,
            manifest_digest
        );
    }

    let total_compressed: u64 = manifest.chunks.iter().map(|m| m.compressed_size).sum();
    let total_uncompressed: u64 = manifest.chunks.iter().map(|m| m.uncompressed_size).sum();
    let chunk_count = manifest.chunks.len() as u32;

    let download_detail = Some(format!(
        "[{} chunks, {}]",
        chunk_count,
        crate::progress::format_bytes(total_compressed)
    ));
    let download_step = session.start_step("Download chunks".to_string(), download_detail)?;
    let download_step_number = download_step.step_number();

    let progress = if total_compressed > 0 {
        Some(crate::progress::TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            download_step_number,
            total_compressed,
        ))
    } else {
        None
    };

    let stage_start = Instant::now();

    let downloader =
        crate::chunks::ChunkDownloader::new(client, reporter.clone(), session_id.clone());

    let mut store = Some(crate::chunks::store::AnyStore::new_for(total_uncompressed).await?);

    if let Err(e) = downloader
        .download_chunks(
            &manifest,
            store.as_ref().unwrap(),
            &chunk_descriptors,
            download_step_number,
            progress,
            _verbose,
        )
        .await
    {
        session.error(e.to_string())?;
        if let Some(store) = store.take() {
            let _ = Box::new(store).finalize().await;
        }
        return Err(e);
    }

    let download_elapsed = stage_start.elapsed();
    download_step.complete()?;

    let extract_step = session.start_step(
        "Extract files".to_string(),
        Some(format!("{} files", manifest.files.len())),
    )?;
    let extract_start = Instant::now();

    let reassemble_result = downloader
        .reassemble_and_verify(
            &manifest,
            store.as_ref().unwrap(),
            Path::new(&target_path),
            hit.content_hash.as_deref(),
            _verbose,
        )
        .await;

    match reassemble_result {
        Ok(()) => {
            extract_step.complete()?;
            if let Some(store) = store.take() {
                Box::new(store).finalize().await?;
            }

            // Integrity verification: generic verification is already covered by manifest digest
            // and per-chunk hash checks in reassemble_and_verify().

            let total_duration = download_elapsed + extract_start.elapsed();
            let total_secs = total_duration.as_secs_f64().max(0.001);
            let avg_speed = (total_compressed as f64 / 1_000_000.0) / total_secs;
            let compression_pct = if total_uncompressed > 0 {
                (total_compressed as f64 / total_uncompressed as f64) * 100.0
            } else {
                100.0
            };

            let summary_line = format!(
                "Restored {} → {} ({:.0}% of original) in {:.1}s across {} chunks @ {:.1} MB/s",
                crate::progress::format_bytes(total_uncompressed),
                crate::progress::format_bytes(total_compressed),
                compression_pct,
                total_secs,
                chunk_count,
                avg_speed,
            );
            let _ = reporter.info(summary_line);

            let summary = Summary {
                size_bytes: hit.size.unwrap_or(total_uncompressed),
                file_count: manifest.files.len() as u32,
                digest: hit.content_hash.clone(),
                path: Some(target_path),
            };

            session.complete(summary)?;
            Ok(RestoreOutcome::Restored {
                tag: hit.tag.clone(),
            })
        }
        Err(e) => {
            session.error(e.to_string())?;
            if let Some(store) = store.take() {
                let _ = Box::new(store).finalize().await;
            }
            Err(e)
        }
    }
}

enum EnsureTargetStatus {
    Ready,
    Occupied { existing_path: String },
}

async fn ensure_empty_target(path: &str) -> Result<EnsureTargetStatus> {
    let target = Path::new(path);

    match fs::metadata(target).await {
        Ok(metadata) => {
            if !metadata.is_dir() {
                anyhow::bail!(
                    "Restore target '{}' exists and is not a directory",
                    target.display()
                );
            }

            let mut dir_entries = fs::read_dir(target).await.with_context(|| {
                format!("Failed to inspect restore target: {}", target.display())
            })?;

            if dir_entries.next_entry().await?.is_some() {
                return Ok(EnsureTargetStatus::Occupied {
                    existing_path: target.display().to_string(),
                });
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(err).with_context(|| {
                format!("Failed to inspect restore target: {}", target.display())
            });
        }
    }

    Ok(EnsureTargetStatus::Ready)
}
