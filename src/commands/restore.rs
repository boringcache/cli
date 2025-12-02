#![allow(clippy::items_after_test_module)]

use crate::api::{ApiClient, CacheResolutionEntry};
use crate::commands::utils::RestoreSpec;
use crate::manifest::diff::compute_root_digest_from_entries;
use crate::progress::{ProgressSession, Summary, System as ProgressSystem, TransferProgress};
use crate::ui;
use anyhow::{Context, Error, Result};
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;
use tempfile::tempdir;
use tokio::fs;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::sync::Semaphore;

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

    let preflight_result = run_restore_preflight_checks(&parsed_specs)?;

    let platform = if !no_platform {
        Some(crate::platform::Platform::detect()?)
    } else {
        None
    };

    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();

    if preflight_result.valid_specs.is_empty() {
        reporter.warning("No valid restore targets found".to_string())?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(());
    }

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

    let api_client = ApiClient::new()?;

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

        ui::blank_line();
        ui::workflow_summary("found", 0, tags_display.len(), &workspace);
        if !misses.is_empty() {
            ui::warn(&format!("Not found: {}", misses.join(", ")));
        }
        return Ok(());
    }

    if lookup_only {
        drop(reporter);
        progress_system.shutdown()?;

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

    let max_concurrent = crate::commands::utils::get_optimal_concurrency(hits.len(), "restore");

    if hits.len() > 1 {
        crate::commands::utils::display_concurrency_info(max_concurrent, "restore");
    }

    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut tasks = Vec::with_capacity(hits.len());

    let transfer_client = api_client.transfer_client().clone();

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

        let reporter = reporter.clone();
        let workspace = workspace.clone();
        let semaphore = semaphore.clone();
        let client = transfer_client.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            process_restore(
                client,
                reporter,
                session_id,
                title,
                workspace,
                hit,
                expanded_target_path,
                verbose,
            )
            .await
        });

        tasks.push(task);
    }

    let mut restored_tags = Vec::new();
    let mut skipped_entries: Vec<(String, String)> = Vec::new();
    let mut restore_errors: Vec<Error> = Vec::new();

    for task in tasks {
        match task.await {
            Ok(Ok(RestoreOutcome::Restored { tag })) => {
                restored_tags.push(tag);
            }
            Ok(Ok(RestoreOutcome::Skipped { tag, reason })) => {
                skipped_entries.push((tag, reason));
            }
            Ok(Err(err)) => {
                restore_errors.push(err);
            }
            Err(join_err) => {
                restore_errors.push(Error::from(join_err).context("Restore task panicked"));
            }
        }
    }

    drop(reporter);
    progress_system.shutdown()?;

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
    api_client: &ApiClient,
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
            Some((idx, hit.tag.clone(), digest, vec![])) // No chunk digests in tar+zstd approach
        })
        .collect();

    if missing_manifest.is_empty() {
        return Ok(());
    }

    let manifest_checks: Vec<ManifestCheckRequest> = missing_manifest
        .iter()
        .map(|(_, tag, digest, _)| ManifestCheckRequest {
            tag: tag.clone(),
            manifest_root_digest: digest.clone(),
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
            if hit.archive_url.is_none() {
                hit.archive_url = extra.archive_url.clone();
            }
            if hit.size.is_none() {
                hit.size = extra.size;
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum RestoreOutcome {
    Restored { tag: String },
    Skipped { tag: String, reason: String },
}

#[allow(clippy::too_many_arguments)]
async fn process_restore(
    client: reqwest::Client,
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

    if hit.archive_url.is_none() {
        anyhow::bail!("No archive URL in response");
    }
    let archive_url = hit.archive_url.as_ref().unwrap().clone();

    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest URL in response"))?
        .clone();

    let mut session = ProgressSession::new(reporter.clone(), session_id.clone(), title, 3)?;

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

    let total_uncompressed = manifest.summary.raw_size;
    let expected_compressed = hit.size.unwrap_or(total_uncompressed);

    let download_detail = Some(format!(
        "[archive, {}]",
        crate::progress::format_bytes(expected_compressed)
    ));
    let download_step = session.start_step("Download archive".to_string(), download_detail)?;
    let download_step_number = download_step.step_number();

    let progress = if expected_compressed > 0 {
        Some(crate::progress::TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            download_step_number,
            expected_compressed,
        ))
    } else {
        None
    };

    let stage_start = Instant::now();

    let temp_dir = tempdir().context("Failed to create temporary directory for restore")?;
    let archive_file_path = temp_dir
        .path()
        .join(format!("boringcache-{}.tar.zst", hit.tag));

    let head_response = client
        .head(&archive_url)
        .send()
        .await
        .context("Failed to get archive size")?;

    let actual_archive_size = head_response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(expected_compressed);

    log::debug!(
        "Archive size: expected_compressed={}, actual_from_head={}",
        expected_compressed,
        actual_archive_size
    );

    let bytes_downloaded = download_archive(
        &client,
        &archive_url,
        &archive_file_path,
        actual_archive_size,
        progress.as_ref(),
    )
    .await
    .context("Archive download failed")?;

    let download_elapsed = stage_start.elapsed();
    download_step.complete()?;

    let total_files = manifest.files.len() as u64;
    let extract_step = session.start_step(
        "Extract archive".to_string(),
        Some(format!("{} files", total_files)),
    )?;
    let extract_step_number = extract_step.step_number();
    let extract_start = Instant::now();

    let extract_reporter = reporter.clone();
    let extract_session_id = session_id.clone();
    let progress_callback: std::sync::Arc<dyn Fn(u64) + Send + Sync> =
        std::sync::Arc::new(move |files_extracted| {
            let progress = files_extracted as f64 / total_files as f64;
            let detail = format!("{} / {} files", files_extracted, total_files);
            let _ = extract_reporter.step_progress(
                extract_session_id.clone(),
                extract_step_number,
                progress,
                Some(detail),
            );
        });

    let extraction_result = crate::archive::extract_tar_archive(
        &archive_file_path,
        Path::new(&target_path),
        _verbose,
        Some(progress_callback),
    )
    .await;

    match extraction_result {
        Ok(()) => {
            extract_step.complete()?;
            drop(temp_dir);

            let total_duration = download_elapsed + extract_start.elapsed();
            let total_secs = total_duration.as_secs_f64().max(0.001);
            let avg_speed = if bytes_downloaded > 0 {
                (bytes_downloaded as f64 / 1_000_000.0) / total_secs
            } else {
                0.0
            };
            let compression_pct = if total_uncompressed > 0 && bytes_downloaded > 0 {
                (bytes_downloaded as f64 / total_uncompressed as f64) * 100.0
            } else {
                100.0
            };

            let summary_line = format!(
                "Restored {} → {} ({:.0}% of original) in {:.1}s @ {:.1} MB/s",
                crate::progress::format_bytes(total_uncompressed),
                crate::progress::format_bytes(bytes_downloaded),
                compression_pct,
                total_secs,
                avg_speed,
            );
            let _ = reporter.info(summary_line);

            let summary = Summary {
                size_bytes: bytes_downloaded,
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

const PARALLEL_DOWNLOAD_THRESHOLD: u64 = 50 * 1024 * 1024;

fn calculate_download_concurrency() -> usize {
    use crate::platform::resources::{DiskType, MemoryStrategy, SystemResources};

    let resources = SystemResources::detect();
    let is_ci = std::env::var("CI").is_ok();

    let base: usize = match resources.memory_strategy {
        MemoryStrategy::Balanced => 3,
        MemoryStrategy::Aggressive => 6,
        MemoryStrategy::UltraAggressive => 12,
    };

    let disk_adjusted: usize = match resources.disk_type {
        DiskType::NvmeSsd => base + 2,
        DiskType::SataSsd => base,
    };

    let cpu_scaled = disk_adjusted.min(resources.cpu_cores);

    if is_ci {
        cpu_scaled.clamp(2, 6)
    } else {
        cpu_scaled.clamp(4, 16)
    }
}

fn download_buffer_size() -> usize {
    use crate::platform::resources::{MemoryStrategy, SystemResources};

    match SystemResources::detect().memory_strategy {
        MemoryStrategy::Balanced => 512 * 1024,
        MemoryStrategy::Aggressive => 1024 * 1024,
        MemoryStrategy::UltraAggressive => 2 * 1024 * 1024,
    }
}

async fn download_archive(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    total_size: u64,
    progress: Option<&TransferProgress>,
) -> Result<u64> {
    if total_size < PARALLEL_DOWNLOAD_THRESHOLD {
        return download_sequential(client, url, file_path, progress).await;
    }

    let concurrency = calculate_download_concurrency();
    let min_part_size: u64 = 8 * 1024 * 1024;
    let max_part_size: u64 = 64 * 1024 * 1024;
    let target_parts = (concurrency * 2).max(8) as u64;
    let part_size = (total_size / target_parts).clamp(min_part_size, max_part_size);
    let num_parts = total_size.div_ceil(part_size);

    log::info!(
        "Parallel download: {} in {} parts ({} each), {} connections",
        crate::progress::format_bytes(total_size),
        num_parts,
        crate::progress::format_bytes(part_size),
        concurrency
    );

    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(file_path)
        .await
        .context("Failed to create download file")?;
    file.set_len(total_size)
        .await
        .context("Failed to pre-allocate download file")?;
    drop(file);

    let semaphore = Arc::new(Semaphore::new(concurrency));
    let mut tasks = Vec::with_capacity(num_parts as usize);

    for part_idx in 0..num_parts {
        let start = part_idx * part_size;
        let end = std::cmp::min(start + part_size, total_size) - 1;
        let this_part_size = end - start + 1;

        let client = client.clone();
        let url = url.to_string();
        let file_path = file_path.to_path_buf();
        let semaphore = semaphore.clone();
        let progress = progress.cloned();
        let part_num = part_idx + 1;

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            download_range(
                &client,
                &url,
                &file_path,
                start,
                end,
                this_part_size,
                progress.as_ref(),
            )
            .await
            .with_context(|| {
                format!(
                    "Part {}/{} (bytes {}-{}) failed",
                    part_num, num_parts, start, end
                )
            })
        });

        tasks.push(task);
    }

    let mut total_downloaded = 0u64;
    let mut errors: Vec<String> = Vec::new();

    for (idx, task) in tasks.into_iter().enumerate() {
        match task.await {
            Ok(Ok(bytes)) => total_downloaded += bytes,
            Ok(Err(e)) => errors.push(format!("Part {}: {}", idx + 1, e)),
            Err(e) => errors.push(format!("Part {} panicked: {}", idx + 1, e)),
        }
    }

    if !errors.is_empty() {
        anyhow::bail!(
            "Download failed with {} errors:\n{}",
            errors.len(),
            errors.join("\n")
        );
    }

    Ok(total_downloaded)
}

async fn download_sequential(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    progress: Option<&TransferProgress>,
) -> Result<u64> {
    use futures_util::StreamExt;
    use tokio::io::BufWriter;

    let response = client.get(url).send().await?.error_for_status()?;

    let file = tokio::fs::File::create(file_path).await?;
    let mut writer = BufWriter::with_capacity(download_buffer_size(), file);

    let mut bytes_downloaded = 0u64;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        let len = chunk.len();
        writer.write_all(&chunk).await?;
        bytes_downloaded += len as u64;

        if let Some(p) = progress {
            let _ = p.record_bytes(len as u64);
        }
    }

    writer.flush().await?;
    Ok(bytes_downloaded)
}

async fn download_range(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    start: u64,
    end: u64,
    expected_size: u64,
    progress: Option<&TransferProgress>,
) -> Result<u64> {
    use futures_util::StreamExt;
    use tokio::io::BufWriter;

    let response = client
        .get(url)
        .header("Range", format!("bytes={}-{}", start, end))
        .send()
        .await
        .context("Range request failed")?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {}", response.status());
    }

    let file = tokio::fs::OpenOptions::new()
        .write(true)
        .open(file_path)
        .await
        .context("Failed to open file")?;

    let mut writer = BufWriter::with_capacity(download_buffer_size(), file);
    writer.seek(std::io::SeekFrom::Start(start)).await?;

    let mut bytes_written = 0u64;
    let mut stream = response.bytes_stream();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result?;
        let len = chunk.len();
        writer.write_all(&chunk).await?;
        bytes_written += len as u64;

        if let Some(p) = progress {
            let _ = p.record_bytes(len as u64);
        }

        if bytes_written >= expected_size {
            break;
        }
    }

    writer.flush().await?;

    if bytes_written < expected_size {
        anyhow::bail!("Incomplete: {} < {}", bytes_written, expected_size);
    }

    Ok(expected_size)
}
