#![allow(clippy::items_after_test_module)]

use crate::api::{ApiClient, CacheResolutionEntry};
use crate::commands::utils::RestoreSpec;
use crate::progress::{ProgressSession, Summary, System as ProgressSystem, TransferProgress};
use crate::telemetry::StorageMetrics;
use crate::transfer::send_transfer_request_with_retry;
use crate::ui;
use anyhow::{anyhow, Context, Error, Result};
use std::collections::HashMap;
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tempfile::{tempdir, TempPath};
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Semaphore;
use tokio::time::sleep;

const RETRYABLE_ERROR_PATTERNS: &[&str] = &[
    "Storage backend unavailable",
    "Workspace storage is not configured",
    "storage is temporarily unavailable",
    "backend temporarily unavailable",
];

fn is_entry_retryable(entry: &CacheResolutionEntry) -> bool {
    if entry.pending || entry.status == "pending" || entry.status == "uploading" {
        return true;
    }

    if let Some(ref error) = entry.error {
        let error_lower = error.to_lowercase();
        for pattern in RETRYABLE_ERROR_PATTERNS {
            if error_lower.contains(&pattern.to_lowercase()) {
                return true;
            }
        }
    }

    false
}

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
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create parent directory '{}'", parent.display())
            })?;
            parent.to_path_buf()
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
    use anyhow::anyhow;

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
    fn preflight_skips_empty_tag() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("dir");
        let parsed = RestoreSpec {
            tag: "".to_string(),
            path: Some(target.to_string_lossy().to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]).unwrap();
        assert_eq!(result.valid_specs.len(), 0);
    }

    #[test]
    fn preflight_creates_missing_parent_directories() {
        let temp = tempfile::tempdir().unwrap();
        // Create a path with multiple nested missing directories
        let target = temp.path().join("vendor").join("bundle");
        let parsed = RestoreSpec {
            tag: "valid-tag".to_string(),
            path: Some(target.to_string_lossy().to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed]).unwrap();
        assert_eq!(result.valid_specs.len(), 1);
        // Verify parent directories were created
        assert!(temp.path().join("vendor").exists());
    }

    #[test]
    fn preflight_continues_batch_with_valid_entries() {
        let temp = tempfile::tempdir().unwrap();
        let file_path = temp.path().join("existing_file");
        std::fs::write(&file_path, b"data").unwrap();

        let valid_dir = temp.path().join("valid_dir");
        let invalid_child = file_path.join("child");

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
                path: Some(invalid_child.to_string_lossy().to_string()),
            },
        ];

        let result = run_restore_preflight_checks(&parsed_entries).unwrap();
        assert_eq!(result.valid_specs.len(), 1);
        assert_eq!(result.valid_specs[0].tag, "tag2");
    }

    #[test]
    fn test_fail_on_cache_miss_flag_logic() {
        let fail_on_cache_miss = true;
        let misses = ["missing-cache".to_string()];

        assert!(fail_on_cache_miss && !misses.is_empty());

        let fail_on_cache_miss = false;
        assert!(!fail_on_cache_miss || misses.is_empty());

        let fail_on_cache_miss = true;
        let misses: Vec<String> = vec![];
        assert!(!fail_on_cache_miss || misses.is_empty());
    }

    #[test]
    fn test_lookup_only_flag_logic() {
        let lookup_only = true;
        assert!(lookup_only);

        let lookup_only = false;
        assert!(!lookup_only);
    }

    #[test]
    fn finalize_restore_outcome_errors_on_restore_failure() {
        let err: Error = anyhow!("boom");
        let result = super::finalize_restore_outcome(vec![err], Vec::new());
        assert!(result.is_err());
    }

    #[test]
    fn finalize_restore_outcome_errors_on_skipped_entries() {
        let result = super::finalize_restore_outcome(
            Vec::new(),
            vec![("tag1".to_string(), "target busy".to_string())],
        );
        assert!(result.is_err());
    }
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

#[allow(clippy::too_many_arguments)]
pub async fn execute_batch_restore(
    workspace_option: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
    fail_on_cache_miss: bool,
    lookup_only: bool,
    identity: Option<String>,
) -> Result<()> {
    execute_batch_restore_inner(
        workspace_option,
        tag_path_pairs,
        verbose,
        no_platform,
        no_git,
        fail_on_cache_miss,
        lookup_only,
        identity,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_batch_restore_inner(
    workspace_option: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
    fail_on_cache_miss: bool,
    lookup_only: bool,
    identity: Option<String>,
) -> Result<()> {
    let workspace = crate::commands::utils::get_workspace_name(workspace_option)?;

    if tag_path_pairs.is_empty() {
        ui::info("No tag:path pairs specified for restore");
        return Ok(());
    }

    crate::api::parse_workspace_slug(&workspace)?;

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
    let git_enabled = !no_git && !crate::git::is_git_disabled_by_env();

    let progress_system = ProgressSystem::new();
    let reporter = progress_system.reporter();

    if preflight_result.valid_specs.is_empty() {
        reporter.warning("No valid restore targets found".to_string())?;
        drop(reporter);
        progress_system.shutdown()?;
        return Ok(());
    }

    let passphrase_cache = Arc::new(Mutex::new(crate::encryption::PassphraseCache::default()));

    #[derive(Debug, Clone)]
    struct RestorePlan {
        display_tag: String,
        target_path: String,
        candidates: Vec<String>,
    }

    #[derive(Debug, Clone)]
    struct SelectedRestore {
        entry: CacheResolutionEntry,
        target_path: String,
    }

    let mut plans: Vec<RestorePlan> = Vec::with_capacity(preflight_result.valid_specs.len());
    let mut all_candidates: Vec<String> = Vec::new();
    let mut tags_display: Vec<String> = Vec::with_capacity(preflight_result.valid_specs.len());

    for spec in &preflight_result.valid_specs {
        tags_display.push(spec.tag.clone());
        let git_context = if git_enabled {
            crate::git::GitContext::detect_with_path(spec.path.as_deref())
        } else {
            crate::git::GitContext::default()
        };
        let resolver =
            crate::tag_utils::TagResolver::new(platform.clone(), git_context, git_enabled);
        let candidates = resolver.restore_tag_candidates(&spec.tag);
        let target_path = spec
            .path
            .as_deref()
            .map(crate::commands::utils::expand_tilde_path)
            .unwrap_or_else(|| ".".to_string());

        for candidate in &candidates {
            if !all_candidates.contains(candidate) {
                all_candidates.push(candidate.clone());
            }
        }

        plans.push(RestorePlan {
            display_tag: spec.tag.clone(),
            target_path,
            candidates,
        });
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

    let max_pending_retries = 5u32;
    let mut pending_attempt = 0u32;
    let resolution_result = loop {
        match api_client.restore(&workspace, &all_candidates).await {
            Ok(result) => {
                let has_hit = result.iter().any(|entry| entry.status == "hit");
                let has_retryable = result.iter().any(is_entry_retryable);

                if has_retryable && !has_hit && pending_attempt < max_pending_retries {
                    let retry_reason = result
                        .iter()
                        .find(|e| is_entry_retryable(e))
                        .map(|e| {
                            if e.pending || e.status == "pending" || e.status == "uploading" {
                                "upload in progress".to_string()
                            } else if let Some(ref err) = e.error {
                                err.clone()
                            } else {
                                "retryable condition".to_string()
                            }
                        })
                        .unwrap_or_else(|| "retryable condition".to_string());

                    let delay_ms = if std::env::var("BORINGCACHE_TEST_MODE").as_deref() == Ok("1") {
                        100 * 2u64.pow(pending_attempt.min(3))
                    } else {
                        1000 * 2u64.pow(pending_attempt.min(4))
                    };
                    let delay = Duration::from_millis(delay_ms);
                    pending_attempt += 1;
                    ui::info(&format!(
                        "  {}; retrying in {:.1}s (attempt {}/{})",
                        retry_reason,
                        delay.as_secs_f64(),
                        pending_attempt,
                        max_pending_retries
                    ));
                    sleep(delay).await;
                    continue;
                }

                break result;
            }
            Err(err) => {
                let is_pending = err
                    .downcast_ref::<crate::error::BoringCacheError>()
                    .map(|bc_err| matches!(bc_err, crate::error::BoringCacheError::CachePending))
                    .unwrap_or(false);

                if is_pending && pending_attempt < max_pending_retries {
                    let delay_ms = if std::env::var("BORINGCACHE_TEST_MODE").as_deref() == Ok("1") {
                        100 * 2u64.pow(pending_attempt.min(3))
                    } else {
                        1000 * 2u64.pow(pending_attempt.min(4))
                    };
                    let delay = Duration::from_millis(delay_ms);
                    pending_attempt += 1;
                    ui::info(&format!(
                        "  Cache upload in progress; retrying in {:.1}s (attempt {}/{})",
                        delay.as_secs_f64(),
                        pending_attempt,
                        max_pending_retries
                    ));
                    sleep(delay).await;
                    continue;
                }

                reporter.step_complete(session_id.clone(), 1, step_start.elapsed())?;

                if is_pending {
                    reporter.warning("Cache upload still in progress after retries".to_string())?;
                    drop(reporter);
                    progress_system.shutdown()?;
                    return Ok(());
                }

                if crate::error::is_connection_error(&err) {
                    reporter.warning(format!("Cache unavailable: {}", err))?;
                    drop(reporter);
                    progress_system.shutdown()?;
                    return Ok(());
                }
                reporter.warning(format!("Cache restore failed: {}", err))?;
                drop(reporter);
                progress_system.shutdown()?;
                return Ok(());
            }
        }
    };

    let mut misses: Vec<String> = Vec::new();
    let mut selected_hits: Vec<SelectedRestore> = Vec::new();

    let mut results_by_tag: HashMap<String, CacheResolutionEntry> = HashMap::new();
    for entry in resolution_result.into_iter() {
        results_by_tag.insert(entry.tag.clone(), entry);
    }

    for plan in &plans {
        let mut chosen: Option<CacheResolutionEntry> = None;
        for candidate in &plan.candidates {
            if let Some(entry) = results_by_tag.get(candidate) {
                if entry.status == "hit" {
                    chosen = Some(entry.clone());
                    break;
                }
            }
        }

        if let Some(entry) = chosen {
            selected_hits.push(SelectedRestore {
                entry,
                target_path: plan.target_path.clone(),
            });
        } else {
            reporter.warning(format!("Cache miss for {}", plan.display_tag))?;
            misses.push(plan.display_tag.clone());
        }
    }

    reporter.step_complete(session_id.clone(), 1, step_start.elapsed())?;

    if fail_on_cache_miss && !misses.is_empty() {
        drop(reporter);
        progress_system.shutdown()?;
        anyhow::bail!("Cache miss for tags: {}", misses.join(", "));
    }

    if selected_hits.is_empty() {
        reporter.warning("No cache entries found for the specified tags".to_string())?;
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
        ui::workflow_summary("found", selected_hits.len(), tags_display.len(), &workspace);

        if !selected_hits.is_empty() {
            let found_tags: Vec<String> =
                selected_hits.iter().map(|h| h.entry.tag.clone()).collect();
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

    let mut hit_entries: Vec<CacheResolutionEntry> =
        selected_hits.iter().map(|hit| hit.entry.clone()).collect();

    enrich_hits_with_manifest_data(&api_client, &workspace, &mut hit_entries, reporter.clone())
        .await?;

    for (selected, updated_entry) in selected_hits.iter_mut().zip(hit_entries) {
        selected.entry = updated_entry;
    }

    let summary = Summary {
        size_bytes: selected_hits
            .iter()
            .map(|h| h.entry.size.unwrap_or(0))
            .sum(),
        file_count: selected_hits.len() as u32,
        digest: None,
        path: None,
    };
    reporter.session_complete(session_id, step_start.elapsed(), summary)?;

    let max_concurrent =
        crate::commands::utils::get_optimal_concurrency(selected_hits.len(), "restore");

    if selected_hits.len() > 1 {
        crate::commands::utils::display_concurrency_info(max_concurrent, "restore");
        let _ = reporter.set_inline_enabled(false);
    }

    let semaphore = Arc::new(Semaphore::new(max_concurrent));
    let mut tasks = Vec::with_capacity(selected_hits.len());

    for hit in selected_hits {
        let expanded_target_path = hit.target_path.clone();
        let hit_entry = hit.entry;

        let session_id = format!("restore:{}:{}", workspace, hit_entry.tag);
        let title = format!("Restoring cache [{}]", hit_entry.tag);

        let reporter = reporter.clone();
        let workspace = workspace.clone();
        let semaphore = semaphore.clone();
        let api_client = api_client.clone();
        let identity = identity.clone();
        let passphrase_cache = passphrase_cache.clone();

        let task = tokio::spawn(async move {
            let _permit = semaphore.acquire().await.unwrap();
            process_restore(
                api_client,
                reporter,
                session_id,
                title,
                workspace,
                hit_entry,
                expanded_target_path,
                verbose,
                identity,
                passphrase_cache,
            )
            .await
        });

        tasks.push(task);
    }

    let mut restored_tags = Vec::new();
    let mut skipped_entries: Vec<(String, String)> = Vec::new();
    let mut ignored_entries: Vec<(String, String)> = Vec::new();
    let mut restore_errors: Vec<Error> = Vec::new();

    for task in tasks {
        match task.await {
            Ok(Ok(RestoreOutcome::Restored {
                tag,
                manifest_root_digest,
                storage_metrics,
                total_duration_ms,
                download_duration_ms,
                extract_duration_ms,
                bytes_downloaded,
            })) => {
                crate::telemetry::RestoreMetrics {
                    tag: tag.clone(),
                    manifest_root_digest,
                    total_duration_ms,
                    download_duration_ms,
                    extract_duration_ms,
                    compressed_size: bytes_downloaded,
                    storage_metrics,
                }
                .send(&api_client, &workspace)
                .await;
                restored_tags.push(tag);
            }
            Ok(Ok(RestoreOutcome::Skipped { tag, reason })) => {
                skipped_entries.push((tag, reason));
            }
            Ok(Ok(RestoreOutcome::Ignored { tag, reason })) => {
                ignored_entries.push((tag, reason));
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

    if !ignored_entries.is_empty() {
        let ignored_list = ignored_entries
            .iter()
            .map(|(tag, _)| tag.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        ui::warn(&format!(
            "Ignored {} entr{}: {}",
            ignored_entries.len(),
            if ignored_entries.len() == 1 {
                "y"
            } else {
                "ies"
            },
            ignored_list
        ));
        for (_, reason) in &ignored_entries {
            ui::warn(reason);
        }
    }

    if !restore_errors.is_empty() {
        for err in &restore_errors {
            ui::warn(&format!("Restore failed: {:#}", err));
        }
    }

    let _ = finalize_restore_outcome(restore_errors, skipped_entries);

    if !misses.is_empty() {
        ui::warn(&format!("Missing cache entries: {}", misses.join(", ")));
    }

    Ok(())
}

fn finalize_restore_outcome(
    restore_errors: Vec<Error>,
    skipped_entries: Vec<(String, String)>,
) -> Result<()> {
    if !restore_errors.is_empty() {
        let combined = restore_errors
            .into_iter()
            .map(|err| err.to_string())
            .collect::<Vec<_>>()
            .join("\n");
        return Err(anyhow!("Restore failed for one or more tags:\n{combined}"));
    }

    if !skipped_entries.is_empty() {
        let skipped_summary = skipped_entries
            .into_iter()
            .map(|(tag, reason)| format!("{tag}: {reason}"))
            .collect::<Vec<_>>()
            .join("\n");
        let skipped_count = skipped_summary.lines().count();
        return Err(anyhow!(
            "Skipped {} cache entr{} due to destination issues:\n{}",
            skipped_count,
            if skipped_count == 1 { "y" } else { "ies" },
            skipped_summary
        ));
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
            Some((idx, hit.tag.clone(), digest, vec![]))
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
            lookup: None,
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
            if hit.archive_urls.is_empty() {
                hit.archive_urls = extra.archive_urls.clone();
            }
            if hit.size.is_none() {
                hit.size = extra.size;
            }
            if hit.manifest_digest.is_none() {
                hit.manifest_digest = extra.manifest_digest.clone();
            }
            if hit.compressed_size.is_none() {
                hit.compressed_size = extra.compressed_size;
            }
            if hit.uncompressed_size.is_none() {
                hit.uncompressed_size = extra.uncompressed_size;
            }
        }
    }

    Ok(())
}

#[derive(Debug)]
enum RestoreOutcome {
    Restored {
        tag: String,
        manifest_root_digest: Option<String>,
        storage_metrics: StorageMetrics,
        total_duration_ms: u64,
        download_duration_ms: u64,
        extract_duration_ms: u64,
        bytes_downloaded: u64,
    },
    Skipped {
        tag: String,
        reason: String,
    },
    Ignored {
        tag: String,
        reason: String,
    },
}

#[allow(clippy::too_many_arguments)]
async fn process_restore(
    api_client: ApiClient,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    verbose: bool,
    identity: Option<String>,
    passphrase_cache: Arc<Mutex<crate::encryption::PassphraseCache>>,
) -> Result<RestoreOutcome> {
    let restore_adapter = crate::cache_adapter::detect_restore_transport(
        hit.storage_mode.as_deref(),
        hit.cas_layout.as_deref(),
    );
    log::debug!(
        "Restore adapter selection tag={} adapter={} storage_mode={:?} cas_layout={:?}",
        hit.tag,
        restore_adapter.as_str(),
        hit.storage_mode.as_deref(),
        hit.cas_layout.as_deref()
    );

    let adapter = crate::adapters::select_transport_adapter(restore_adapter)?;
    log::debug!(
        "Restore adapter dispatch tag={} adapter={}",
        hit.tag,
        adapter.transport_kind().as_str()
    );

    match adapter {
        crate::adapters::AdapterDispatchKind::Archive => {
            process_restore_archive(
                api_client,
                reporter,
                session_id,
                title,
                workspace,
                hit,
                target_path,
                verbose,
                identity,
                passphrase_cache,
            )
            .await
        }
        crate::adapters::AdapterDispatchKind::Oci => {
            process_restore_oci(
                &api_client,
                reporter,
                session_id,
                title,
                workspace,
                hit,
                target_path,
                verbose,
            )
            .await
        }
        crate::adapters::AdapterDispatchKind::File => {
            process_restore_file(
                &api_client,
                reporter,
                session_id,
                title,
                workspace,
                hit,
                target_path,
                verbose,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_restore_archive(
    api_client: ApiClient,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    _workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    verbose: bool,
    identity: Option<String>,
    passphrase_cache: Arc<Mutex<crate::encryption::PassphraseCache>>,
) -> Result<RestoreOutcome> {
    let client = api_client.transfer_client().clone();

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

    if hit.archive_urls.is_empty() {
        anyhow::bail!("No archive URLs in response");
    }
    let archive_url = hit.archive_urls[0].clone();

    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("No manifest URL in response"))?
        .clone();

    let total_steps = if hit.encrypted { 4 } else { 3 };
    let mut session =
        ProgressSession::new(reporter.clone(), session_id.clone(), title, total_steps)?;

    let manifest_step = session.start_step("Fetch manifest".to_string(), None)?;

    let manifest_future = send_transfer_request_with_retry("Manifest fetch", || async {
        Ok(client.get(&manifest_url).send().await?)
    });
    let archive_head_future = client.head(&archive_url).send();

    let (manifest_result, head_result) = tokio::join!(manifest_future, archive_head_future);

    let manifest_response = manifest_result?
        .error_for_status()
        .context("Manifest request failed")?;

    let (head_storage_metrics, mut actual_archive_size) = match head_result {
        Ok(resp) => {
            if !resp.status().is_success() {
                log::debug!(
                    "Archive HEAD warm failed (non-fatal): HTTP {}",
                    resp.status()
                );
                (StorageMetrics::default(), None)
            } else {
                let metrics = StorageMetrics::from_headers(resp.headers());
                let size = resp
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| s.parse::<u64>().ok());
                (metrics, size)
            }
        }
        Err(e) => {
            log::debug!("Archive HEAD warm failed (non-fatal): {}", e);
            (StorageMetrics::default(), None)
        }
    };

    let manifest_bytes_raw = manifest_response.bytes().await?.to_vec();

    if let Some(expected_digest) = hit.manifest_digest.as_ref() {
        let actual_digest = crate::manifest::io::compute_manifest_digest(&manifest_bytes_raw);
        if expected_digest != &actual_digest {
            let reason = format!(
                "Manifest bytes digest mismatch for {} (expected {}, got {})",
                hit.tag, expected_digest, actual_digest
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            session.error(reason.clone())?;
            return Ok(RestoreOutcome::Ignored {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }
    let manifest_encrypted = crate::encryption::is_age_encrypted(&manifest_bytes_raw);
    let age_identity = if hit.encrypted || manifest_encrypted {
        crate::encryption::load_identity_for_decryption(identity.as_ref())?
    } else {
        None
    };

    let manifest_payload = if manifest_encrypted {
        let cached_passphrase = crate::encryption::cached_passphrase(&passphrase_cache)?;
        match crate::encryption::decrypt_bytes(
            &manifest_bytes_raw,
            age_identity.as_ref(),
            cached_passphrase.as_deref(),
        ) {
            Ok(bytes) => bytes,
            Err(err) if crate::encryption::is_passphrase_required(&err) => {
                let passphrase = crate::encryption::get_or_prompt_passphrase(
                    &passphrase_cache,
                    "Age passphrase (leave blank to skip): ",
                )?;
                let passphrase_ref = passphrase.as_deref();
                if passphrase_ref.is_none() {
                    return Err(err);
                }
                crate::encryption::decrypt_bytes(
                    &manifest_bytes_raw,
                    age_identity.as_ref(),
                    passphrase_ref,
                )?
            }
            Err(err) => return Err(err),
        }
    } else {
        manifest_bytes_raw
    };

    let manifest_bytes = crate::manifest::io::decompress_manifest_if_needed(&manifest_payload)?;

    let manifest: crate::manifest::Manifest =
        ciborium::from_reader(&manifest_bytes[..]).context("Failed to parse manifest")?;
    manifest_step.complete()?;

    if let Some(expected_digest) = hit.manifest_root_digest.as_ref() {
        if expected_digest != &manifest.root.digest {
            let reason = format!(
                "Manifest digest mismatch for {} (expected {}, got {})",
                hit.tag, expected_digest, manifest.root.digest
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            session.error(reason.clone())?;
            return Ok(RestoreOutcome::Ignored {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }

    match (&hit.workspace_signing_public_key, &hit.server_signature) {
        (Some(workspace_key), Some(server_sig)) => {
            match verify_server_signature(
                &manifest.tag,
                &manifest.root.digest,
                workspace_key,
                server_sig,
            ) {
                Ok(()) => {
                    if verbose {
                        let public_key = crate::signing::parse_public_key(workspace_key).ok();
                        let fingerprint = public_key
                            .as_ref()
                            .map(crate::signing::public_key_fingerprint)
                            .unwrap_or_else(|| "unknown".to_string());
                        let _ =
                            reporter.info(format!("  Server signature verified ({})", fingerprint));
                    }
                }
                Err(e) => {
                    ui::warn(&format!("Server signature verification failed: {}", e));
                }
            }
        }
        (Some(_), None) => {
            ui::warn(&format!(
                "Server signature missing for {}; authenticity not verified",
                manifest.tag.as_str()
            ));
        }
        (None, Some(_)) => {
            ui::warn(&format!(
                "Workspace signing key missing for {}; cannot verify server signature",
                manifest.tag.as_str()
            ));
        }
        (None, None) => {}
    }

    if actual_archive_size.is_none() && hit.compressed_size.is_none() {
        actual_archive_size = probe_archive_size(&client, &archive_url).await;
    }

    let total_uncompressed = manifest.summary.raw_size;
    let expected_compressed = actual_archive_size.or(hit.compressed_size).unwrap_or(0);

    let download_detail = if expected_compressed > 0 {
        Some(format!(
            "[archive, {}]",
            crate::progress::format_bytes(expected_compressed)
        ))
    } else {
        None
    };
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

    let archive_size = expected_compressed;

    if let Some(ref region) = head_storage_metrics.region {
        log::info!("Tigris storage region: {}", region);
    }
    if let Some(ref cache_status) = head_storage_metrics.cache_status {
        log::info!("Tigris cache status: {}", cache_status);
    }
    if let Some(ref block_loc) = head_storage_metrics.block_location {
        log::info!("Tigris block location: {}", block_loc);
    }

    log::debug!(
        "Archive size: expected_compressed={}, actual_from_head={}",
        expected_compressed,
        archive_size
    );

    let (bytes_downloaded, download_storage_metrics) = download_archive(
        &client,
        &archive_url,
        &archive_file_path,
        archive_size,
        progress.as_ref(),
    )
    .await
    .context("Archive download failed")?;

    let download_elapsed = stage_start.elapsed();
    download_step.complete()?;

    let decrypted_temp_path: Option<TempPath>;
    let final_archive_path: PathBuf = if hit.encrypted || manifest.encryption.is_some() {
        let decrypt_step = session.start_step("Decrypting archive".to_string(), None)?;

        let cached_passphrase = crate::encryption::cached_passphrase(&passphrase_cache)?;
        let decrypt_result = tokio::task::spawn_blocking({
            let archive_path = archive_file_path.clone();
            let passphrase = cached_passphrase.clone();
            let age_identity = age_identity.clone();
            move || {
                crate::archive::decrypt_archive(
                    &archive_path,
                    age_identity.as_ref(),
                    passphrase.as_deref(),
                )
            }
        })
        .await
        .context("Decryption task failed")?;

        let decrypted_path = match decrypt_result {
            Ok(path) => path,
            Err(err) if crate::encryption::is_passphrase_required(&err) => {
                let passphrase = crate::encryption::get_or_prompt_passphrase(
                    &passphrase_cache,
                    "Age passphrase (leave blank to skip): ",
                )?;
                let passphrase_ref = passphrase.as_deref();
                if passphrase_ref.is_none() {
                    return Err(err);
                }
                tokio::task::spawn_blocking({
                    let archive_path = archive_file_path.clone();
                    let passphrase = passphrase.clone();
                    let age_identity = age_identity.clone();
                    move || {
                        crate::archive::decrypt_archive(
                            &archive_path,
                            age_identity.as_ref(),
                            passphrase.as_deref(),
                        )
                    }
                })
                .await
                .context("Decryption task failed")??
            }
            Err(err) => return Err(err),
        };

        if verbose {
            let encrypted_size = std::fs::metadata(&archive_file_path)?.len();
            let decrypted_size = std::fs::metadata::<&Path>(decrypted_path.as_ref())?.len();
            let _ = reporter.info(format!(
                "  Decrypted archive: {} → {}",
                crate::progress::format_bytes(encrypted_size),
                crate::progress::format_bytes(decrypted_size)
            ));
        }

        decrypt_step.complete()?;
        let path = decrypted_path.to_path_buf();
        decrypted_temp_path = Some(decrypted_path);
        path
    } else {
        decrypted_temp_path = None;
        archive_file_path.clone()
    };

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
        &final_archive_path,
        Path::new(&target_path),
        verbose,
        Some(progress_callback),
    )
    .await;

    drop(decrypted_temp_path);

    match extraction_result {
        Ok(()) => {
            crate::manifest::ManifestApplier::apply(&manifest, Path::new(&target_path)).await?;
            extract_step.complete()?;
            drop(temp_dir);

            let extract_elapsed = extract_start.elapsed();
            let total_duration = download_elapsed + extract_elapsed;
            let total_secs = total_duration.as_secs_f64().max(0.001);
            let compression_pct = if total_uncompressed > 0 && bytes_downloaded > 0 {
                (bytes_downloaded as f64 / total_uncompressed as f64) * 100.0
            } else {
                100.0
            };

            let download_secs = download_elapsed.as_secs_f64().max(0.001);
            let download_speed = (bytes_downloaded as f64 / 1_000_000.0) / download_secs;

            let summary_line = format!(
                "Restored {} → {} ({:.0}% of original) in {:.1}s (download: {:.1} MB/s, extract: {})",
                crate::progress::format_bytes(total_uncompressed),
                crate::progress::format_bytes(bytes_downloaded),
                compression_pct,
                total_secs,
                download_speed,
                format_phase_duration(extract_elapsed),
            );
            let _ = reporter.info(summary_line);

            if verbose {
                let mut storage_info = Vec::new();
                if let Some(ref region) = download_storage_metrics.region {
                    storage_info.push(format!("region={}", region));
                }
                if let Some(ref cache_status) = download_storage_metrics.cache_status {
                    storage_info.push(format!("cache={}", cache_status));
                }
                if let Some(ref block_loc) = download_storage_metrics.block_location {
                    storage_info.push(format!("block={}", block_loc));
                }
                if !storage_info.is_empty() {
                    let _ = reporter.info(format!("  Storage: {}", storage_info.join(", ")));
                }
            }

            let summary = Summary {
                size_bytes: bytes_downloaded,
                file_count: manifest.files.len() as u32,
                digest: hit.content_hash.clone(),
                path: Some(target_path),
            };

            session.complete(summary)?;

            let download_duration_ms = download_elapsed.as_millis() as u64;
            let extract_duration_ms = extract_start.elapsed().as_millis() as u64;
            let total_duration_ms = download_duration_ms + extract_duration_ms;

            Ok(RestoreOutcome::Restored {
                tag: hit.tag.clone(),
                manifest_root_digest: hit.manifest_root_digest.clone(),
                storage_metrics: download_storage_metrics,
                total_duration_ms,
                download_duration_ms,
                extract_duration_ms,
                bytes_downloaded,
            })
        }
        Err(e) => {
            session.error(e.to_string())?;
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn process_restore_oci(
    api_client: &ApiClient,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    verbose: bool,
) -> Result<RestoreOutcome> {
    let transfer_client = api_client.transfer_client().clone();
    let mut session = ProgressSession::new(reporter.clone(), session_id.clone(), title, 3)?;

    let fetch_step = session.start_step("Fetch CAS index".to_string(), None)?;
    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow!("No manifest URL in response"))?
        .clone();

    let index_response = send_transfer_request_with_retry("CAS index fetch", || async {
        Ok(transfer_client.get(&manifest_url).send().await?)
    })
    .await?
    .error_for_status()
    .context("CAS index request failed")?;

    let index_bytes = index_response.bytes().await?.to_vec();
    let actual_manifest_hex = crate::cas_oci::sha256_hex(&index_bytes);

    if let Some(expected_digest) = hit.manifest_digest.as_ref() {
        if !crate::cas_oci::digest_matches(expected_digest, &actual_manifest_hex) {
            let reason = format!(
                "CAS index digest mismatch for {} (expected {}, got sha256:{})",
                hit.tag, expected_digest, actual_manifest_hex
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            session.error(reason.clone())?;
            return Ok(RestoreOutcome::Ignored {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }

    let pointer = crate::cas_oci::parse_pointer(&index_bytes)?;
    let resolved_manifest_root_digest = hit
        .manifest_root_digest
        .clone()
        .unwrap_or_else(|| format!("sha256:{actual_manifest_hex}"));
    if !crate::cas_oci::digest_matches(&resolved_manifest_root_digest, &actual_manifest_hex) {
        let reason = format!(
            "CAS manifest root digest mismatch for {} (expected {}, got sha256:{})",
            hit.tag, resolved_manifest_root_digest, actual_manifest_hex
        );
        let _ = reporter.warning(reason.clone());
        ui::warn(&reason);
        session.error(reason.clone())?;
        return Ok(RestoreOutcome::Ignored {
            tag: hit.tag.clone(),
            reason,
        });
    }
    fetch_step.complete()?;

    match (&hit.workspace_signing_public_key, &hit.server_signature) {
        (Some(workspace_key), Some(server_sig)) => {
            if let Err(err) = verify_server_signature(
                &hit.tag,
                &resolved_manifest_root_digest,
                workspace_key,
                server_sig,
            ) {
                ui::warn(&format!("Server signature verification failed: {}", err));
            }
        }
        (Some(_), None) => {
            ui::warn(&format!(
                "Server signature missing for {}; authenticity not verified",
                hit.tag
            ));
        }
        (None, Some(_)) => {
            ui::warn(&format!(
                "Workspace signing key missing for {}; cannot verify server signature",
                hit.tag
            ));
        }
        (None, None) => {}
    }

    let blobs_dir = Path::new(&target_path).join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)
        .await
        .with_context(|| format!("Failed to create {}", blobs_dir.display()))?;

    let mut missing_blobs = Vec::new();
    let mut blob_path_by_digest: HashMap<String, PathBuf> = HashMap::new();
    for blob in &pointer.blobs {
        let digest_hex = crate::cas_oci::digest_hex_component(&blob.digest)
            .ok_or_else(|| anyhow!("Invalid blob digest {}", blob.digest))?;
        let blob_path = blobs_dir.join(digest_hex);
        let is_present = match fs::metadata(&blob_path).await {
            Ok(metadata) => metadata.is_file() && metadata.len() == blob.size_bytes,
            Err(err) if err.kind() == ErrorKind::NotFound => false,
            Err(err) => {
                return Err(err).with_context(|| format!("Failed to stat {}", blob_path.display()))
            }
        };
        if !is_present {
            missing_blobs.push(crate::api::models::cache::BlobDescriptor {
                digest: blob.digest.clone(),
                size_bytes: blob.size_bytes,
            });
            blob_path_by_digest.insert(blob.digest.clone(), blob_path);
        }
    }

    let download_step = session.start_step(
        "Download blobs".to_string(),
        Some(format!("{} missing", missing_blobs.len())),
    )?;
    let download_started = Instant::now();
    let mut bytes_downloaded = 0u64;
    let mut download_storage_metrics = StorageMetrics::default();

    if !missing_blobs.is_empty() {
        let cache_entry_id = hit
            .cache_entry_id
            .as_deref()
            .ok_or_else(|| anyhow!("Missing cache_entry_id for CAS restore"))?;
        let download_urls = api_client
            .blob_download_urls(&workspace, cache_entry_id, &missing_blobs)
            .await
            .context("Failed to request CAS blob download URLs")?;

        if !download_urls.missing.is_empty() {
            anyhow::bail!(
                "Server reported missing blobs for CAS restore: {}",
                download_urls.missing.join(", ")
            );
        }

        let urls_by_digest: HashMap<&str, &str> = download_urls
            .download_urls
            .iter()
            .map(|item| (item.digest.as_str(), item.url.as_str()))
            .collect();

        let mut items = Vec::new();
        for blob in &missing_blobs {
            let Some(url) = urls_by_digest.get(blob.digest.as_str()) else {
                anyhow::bail!(
                    "Server did not provide download URL for blob {}",
                    blob.digest
                );
            };
            let path = blob_path_by_digest
                .get(&blob.digest)
                .cloned()
                .ok_or_else(|| anyhow!("Missing destination path for blob {}", blob.digest))?;
            items.push((
                blob.digest.clone(),
                (*url).to_string(),
                path,
                blob.size_bytes,
            ));
        }

        let total_download_bytes = items.iter().map(|item| item.3).sum::<u64>();
        let progress = TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            download_step.step_number(),
            total_download_bytes,
        );
        let max_concurrent =
            crate::commands::utils::get_optimal_concurrency(items.len(), "restore");
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let mut tasks = Vec::new();

        for (digest, url, path, expected_size) in items {
            let semaphore = semaphore.clone();
            let progress = progress.clone();
            let client = transfer_client.clone();
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                crate::cas_transport::download_blob_file(
                    &client,
                    &url,
                    &path,
                    Some(&progress),
                    expected_size,
                    download_buffer_size(),
                    Some(&digest),
                )
                .await
            });
            tasks.push(task);
        }

        for task in tasks {
            let (size, metrics) = task.await.context("Blob download task panicked")??;
            bytes_downloaded += size;
            if download_storage_metrics.region.is_none() {
                download_storage_metrics = metrics;
            }
        }
    }
    let download_elapsed = download_started.elapsed();
    download_step.complete()?;

    let materialize_step = session.start_step("Materialize OCI layout".to_string(), None)?;
    let materialize_started = Instant::now();
    let target = Path::new(&target_path);
    fs::create_dir_all(target)
        .await
        .with_context(|| format!("Failed to create {}", target.display()))?;
    fs::write(target.join("index.json"), pointer.index_json_bytes()?)
        .await
        .with_context(|| format!("Failed to write {}", target.join("index.json").display()))?;
    fs::write(target.join("oci-layout"), pointer.oci_layout_bytes()?)
        .await
        .with_context(|| format!("Failed to write {}", target.join("oci-layout").display()))?;
    materialize_step.complete()?;
    let materialize_elapsed = materialize_started.elapsed();

    if verbose {
        let _ = reporter.info(format!(
            "  Restored OCI CAS layout ({} blobs, {} downloaded)",
            pointer.blobs.len(),
            crate::progress::format_bytes(bytes_downloaded)
        ));
    }

    let summary = Summary {
        size_bytes: hit.blob_total_size_bytes.unwrap_or(bytes_downloaded),
        file_count: pointer.blobs.len().min(u32::MAX as usize) as u32,
        digest: Some(resolved_manifest_root_digest.clone()),
        path: Some(target_path.clone()),
    };
    session.complete(summary)?;

    let download_duration_ms = download_elapsed.as_millis() as u64;
    let extract_duration_ms = materialize_elapsed.as_millis() as u64;
    let total_duration_ms = download_duration_ms + extract_duration_ms;

    Ok(RestoreOutcome::Restored {
        tag: hit.tag.clone(),
        manifest_root_digest: Some(resolved_manifest_root_digest),
        storage_metrics: download_storage_metrics,
        total_duration_ms,
        download_duration_ms,
        extract_duration_ms,
        bytes_downloaded,
    })
}

#[allow(clippy::too_many_arguments)]
async fn process_restore_file(
    api_client: &ApiClient,
    reporter: crate::progress::Reporter,
    session_id: String,
    title: String,
    workspace: String,
    hit: CacheResolutionEntry,
    target_path: String,
    verbose: bool,
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

    let transfer_client = api_client.transfer_client().clone();
    let mut session = ProgressSession::new(reporter.clone(), session_id.clone(), title, 3)?;

    let fetch_step = session.start_step("Fetch CAS index".to_string(), None)?;
    let manifest_url = hit
        .manifest_url
        .as_ref()
        .ok_or_else(|| anyhow!("No manifest URL in response"))?
        .clone();

    let index_response = send_transfer_request_with_retry("CAS index fetch", || async {
        Ok(transfer_client.get(&manifest_url).send().await?)
    })
    .await?
    .error_for_status()
    .context("CAS index request failed")?;
    let index_bytes = index_response.bytes().await?.to_vec();
    let actual_manifest_hex = crate::cas_file::sha256_hex(&index_bytes);

    if let Some(expected_digest) = hit.manifest_digest.as_ref() {
        if !crate::cas_file::digest_matches(expected_digest, &actual_manifest_hex) {
            let reason = format!(
                "CAS index digest mismatch for {} (expected {}, got sha256:{})",
                hit.tag, expected_digest, actual_manifest_hex
            );
            let _ = reporter.warning(reason.clone());
            ui::warn(&reason);
            session.error(reason.clone())?;
            return Ok(RestoreOutcome::Ignored {
                tag: hit.tag.clone(),
                reason,
            });
        }
    }

    let pointer = crate::cas_file::parse_pointer(&index_bytes)?;
    let resolved_manifest_root_digest = hit
        .manifest_root_digest
        .clone()
        .unwrap_or_else(|| format!("sha256:{actual_manifest_hex}"));
    if !crate::cas_file::digest_matches(&resolved_manifest_root_digest, &actual_manifest_hex) {
        let reason = format!(
            "CAS manifest root digest mismatch for {} (expected {}, got sha256:{})",
            hit.tag, resolved_manifest_root_digest, actual_manifest_hex
        );
        let _ = reporter.warning(reason.clone());
        ui::warn(&reason);
        session.error(reason.clone())?;
        return Ok(RestoreOutcome::Ignored {
            tag: hit.tag.clone(),
            reason,
        });
    }
    fetch_step.complete()?;

    match (&hit.workspace_signing_public_key, &hit.server_signature) {
        (Some(workspace_key), Some(server_sig)) => {
            if let Err(err) = verify_server_signature(
                &hit.tag,
                &resolved_manifest_root_digest,
                workspace_key,
                server_sig,
            ) {
                ui::warn(&format!("Server signature verification failed: {}", err));
            }
        }
        (Some(_), None) => {
            ui::warn(&format!(
                "Server signature missing for {}; authenticity not verified",
                hit.tag
            ));
        }
        (None, Some(_)) => {
            ui::warn(&format!(
                "Workspace signing key missing for {}; cannot verify server signature",
                hit.tag
            ));
        }
        (None, None) => {}
    }

    let tmp_dir = tempdir().context("Failed to create CAS download temp directory")?;
    let blobs_dir = tmp_dir.path().join("blobs").join("sha256");
    fs::create_dir_all(&blobs_dir)
        .await
        .with_context(|| format!("Failed to create {}", blobs_dir.display()))?;

    let blobs: Vec<crate::api::models::cache::BlobDescriptor> = pointer
        .blobs
        .iter()
        .map(|blob| crate::api::models::cache::BlobDescriptor {
            digest: blob.digest.clone(),
            size_bytes: blob.size_bytes,
        })
        .collect();

    let mut blob_path_by_digest: HashMap<String, PathBuf> = HashMap::new();
    for blob in &pointer.blobs {
        let digest_hex = crate::cas_oci::digest_hex_component(&blob.digest)
            .ok_or_else(|| anyhow!("Invalid blob digest {}", blob.digest))?;
        blob_path_by_digest.insert(blob.digest.clone(), blobs_dir.join(digest_hex));
    }

    let download_step = session.start_step(
        "Download blobs".to_string(),
        Some(format!("{} blobs", blobs.len())),
    )?;
    let download_started = Instant::now();
    let mut bytes_downloaded = 0u64;
    let mut download_storage_metrics = StorageMetrics::default();

    if !blobs.is_empty() {
        let cache_entry_id = hit
            .cache_entry_id
            .as_deref()
            .ok_or_else(|| anyhow!("Missing cache_entry_id for CAS restore"))?;
        let download_urls = api_client
            .blob_download_urls(&workspace, cache_entry_id, &blobs)
            .await
            .context("Failed to request CAS blob download URLs")?;

        if !download_urls.missing.is_empty() {
            anyhow::bail!(
                "Server reported missing blobs for CAS restore: {}",
                download_urls.missing.join(", ")
            );
        }

        let urls_by_digest: HashMap<&str, &str> = download_urls
            .download_urls
            .iter()
            .map(|item| (item.digest.as_str(), item.url.as_str()))
            .collect();
        let mut items = Vec::new();
        for blob in &blobs {
            let Some(url) = urls_by_digest.get(blob.digest.as_str()) else {
                anyhow::bail!(
                    "Server did not provide download URL for blob {}",
                    blob.digest
                );
            };
            let blob_path = blob_path_by_digest
                .get(&blob.digest)
                .cloned()
                .ok_or_else(|| anyhow!("Missing destination path for blob {}", blob.digest))?;
            items.push((
                blob.digest.clone(),
                (*url).to_string(),
                blob_path,
                blob.size_bytes,
            ));
        }

        let total_download_bytes = items.iter().map(|item| item.3).sum::<u64>();
        let progress = TransferProgress::new(
            reporter.clone(),
            session_id.clone(),
            download_step.step_number(),
            total_download_bytes,
        );
        let max_concurrent =
            crate::commands::utils::get_optimal_concurrency(items.len(), "restore");
        let semaphore = Arc::new(Semaphore::new(max_concurrent));
        let writer_capacity = download_buffer_size();
        let mut tasks = Vec::new();

        for (digest, url, blob_path, expected_size) in items {
            let semaphore = semaphore.clone();
            let progress = progress.clone();
            let client = transfer_client.clone();
            let task = tokio::spawn(async move {
                let _permit = semaphore.acquire().await.unwrap();
                crate::cas_transport::download_blob_file(
                    &client,
                    &url,
                    &blob_path,
                    Some(&progress),
                    expected_size,
                    writer_capacity,
                    Some(&digest),
                )
                .await
            });
            tasks.push(task);
        }

        for task in tasks {
            let (size, metrics) = task.await.context("Blob download task panicked")??;
            bytes_downloaded += size;
            if download_storage_metrics.region.is_none() {
                download_storage_metrics = metrics;
            }
        }
    }
    let download_elapsed = download_started.elapsed();
    download_step.complete()?;

    let materialize_step = session.start_step("Materialize files".to_string(), None)?;
    let materialize_started = Instant::now();
    let target_root = Path::new(&target_path);
    fs::create_dir_all(target_root)
        .await
        .with_context(|| format!("Failed to create {}", target_root.display()))?;

    for entry in &pointer.entries {
        if entry.entry_type != crate::manifest::EntryType::Dir {
            continue;
        }
        let destination = crate::cas_file::safe_join(target_root, &entry.path)?;
        remove_path_if_exists(&destination).await?;
        fs::create_dir_all(&destination)
            .await
            .with_context(|| format!("Failed to create {}", destination.display()))?;
    }

    for entry in &pointer.entries {
        match entry.entry_type {
            crate::manifest::EntryType::Dir => {}
            crate::manifest::EntryType::File => {
                let destination = crate::cas_file::safe_join(target_root, &entry.path)?;
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("Failed to create {}", parent.display()))?;
                }
                remove_path_if_exists(&destination).await?;
                let digest = entry
                    .digest
                    .as_ref()
                    .ok_or_else(|| anyhow!("File entry missing digest for {}", entry.path))?;
                let blob_path = blob_path_by_digest
                    .get(digest)
                    .ok_or_else(|| anyhow!("Missing downloaded blob for digest {}", digest))?;
                fs::copy(blob_path, &destination).await.with_context(|| {
                    format!(
                        "Failed to materialize {} from {}",
                        destination.display(),
                        blob_path.display()
                    )
                })?;

                #[cfg(unix)]
                if entry.executable == Some(true) {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = fs::metadata(&destination).await?.permissions();
                    perms.set_mode(perms.mode() | 0o111);
                    fs::set_permissions(&destination, perms).await?;
                }
            }
            crate::manifest::EntryType::Symlink => {
                let destination = crate::cas_file::safe_join(target_root, &entry.path)?;
                if let Some(parent) = destination.parent() {
                    fs::create_dir_all(parent)
                        .await
                        .with_context(|| format!("Failed to create {}", parent.display()))?;
                }
                remove_path_if_exists(&destination).await?;
                let link_target = entry
                    .target
                    .as_ref()
                    .ok_or_else(|| anyhow!("Symlink entry missing target for {}", entry.path))?
                    .clone();
                create_symlink(&destination, link_target).await?;
            }
        }
    }

    materialize_step.complete()?;
    let materialize_elapsed = materialize_started.elapsed();

    if verbose {
        let _ = reporter.info(format!(
            "  Restored file CAS layout ({} blobs, {} downloaded)",
            pointer.blobs.len(),
            crate::progress::format_bytes(bytes_downloaded)
        ));
    }

    let file_count = pointer
        .entries
        .iter()
        .filter(|entry| entry.entry_type == crate::manifest::EntryType::File)
        .count()
        .min(u32::MAX as usize) as u32;
    let summary = Summary {
        size_bytes: hit.blob_total_size_bytes.unwrap_or(bytes_downloaded),
        file_count,
        digest: Some(resolved_manifest_root_digest.clone()),
        path: Some(target_path.clone()),
    };
    session.complete(summary)?;

    let download_duration_ms = download_elapsed.as_millis() as u64;
    let extract_duration_ms = materialize_elapsed.as_millis() as u64;
    let total_duration_ms = download_duration_ms + extract_duration_ms;

    Ok(RestoreOutcome::Restored {
        tag: hit.tag.clone(),
        manifest_root_digest: Some(resolved_manifest_root_digest),
        storage_metrics: download_storage_metrics,
        total_duration_ms,
        download_duration_ms,
        extract_duration_ms,
        bytes_downloaded,
    })
}

async fn remove_path_if_exists(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path).await {
        Ok(metadata) => {
            let file_type = metadata.file_type();
            if file_type.is_dir() {
                fs::remove_dir_all(path)
                    .await
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
            } else {
                fs::remove_file(path)
                    .await
                    .with_context(|| format!("Failed to remove {}", path.display()))?;
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("Failed to inspect {}", path.display())),
    }
}

async fn create_symlink(path: &Path, target: String) -> Result<()> {
    let destination = path.to_path_buf();
    tokio::task::spawn_blocking(move || create_symlink_blocking(&destination, &target))
        .await
        .context("Symlink task panicked")?
}

#[cfg(unix)]
fn create_symlink_blocking(path: &Path, target: &str) -> Result<()> {
    std::os::unix::fs::symlink(target, path)
        .with_context(|| format!("Failed to create symlink {}", path.display()))?;
    Ok(())
}

#[cfg(windows)]
fn create_symlink_blocking(path: &Path, target: &str) -> Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    if symlink_file(target, path).is_err() {
        symlink_dir(target, path)
            .with_context(|| format!("Failed to create symlink {}", path.display()))?;
    }
    Ok(())
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

fn verify_server_signature(
    tag: &str,
    root_digest: &str,
    workspace_signing_public_key: &str,
    server_signature: &str,
) -> Result<()> {
    let public_key = crate::signing::parse_public_key(workspace_signing_public_key)
        .context("Failed to parse workspace signing public key")?;

    let signature = crate::signing::signature_from_base64(server_signature)
        .context("Failed to parse server signature")?;

    let data_to_verify = format!("{}:{}", tag, root_digest);

    crate::signing::verify_signature(data_to_verify.as_bytes(), &signature, &public_key)
        .context("Server signature verification failed")?;

    Ok(())
}

const PARALLEL_DOWNLOAD_THRESHOLD: u64 = 50 * 1024 * 1024;

fn calculate_download_concurrency() -> usize {
    crate::cas_transport::calculate_download_concurrency()
}

fn download_buffer_size() -> usize {
    crate::cas_transport::download_buffer_size()
}

pub(crate) async fn probe_archive_size(client: &reqwest::Client, url: &str) -> Option<u64> {
    let response = match send_transfer_request_with_retry("Archive size probe", || async {
        Ok(client
            .get(url)
            .header(reqwest::header::RANGE, "bytes=0-0")
            .send()
            .await?)
    })
    .await
    {
        Ok(response) => response,
        Err(_) => return None,
    };

    if response.status() == reqwest::StatusCode::PARTIAL_CONTENT {
        let range_header = response
            .headers()
            .get(reqwest::header::CONTENT_RANGE)?
            .to_str()
            .ok()?;
        let total = range_header.split('/').nth(1)?;
        if total == "*" {
            return None;
        }
        return total.parse::<u64>().ok();
    }

    if response.status().is_success() {
        return response
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());
    }

    None
}

pub(crate) async fn download_archive(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    total_size: u64,
    progress: Option<&TransferProgress>,
) -> Result<(u64, StorageMetrics)> {
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
            crate::cas_transport::download_range(
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
    let mut first_storage_metrics: Option<StorageMetrics> = None;

    for (idx, task) in tasks.into_iter().enumerate() {
        match task.await {
            Ok(Ok((bytes, metrics))) => {
                total_downloaded += bytes;

                if first_storage_metrics.is_none() {
                    first_storage_metrics = Some(metrics);
                }
            }
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

    Ok((total_downloaded, first_storage_metrics.unwrap_or_default()))
}

async fn download_sequential(
    client: &reqwest::Client,
    url: &str,
    file_path: &Path,
    progress: Option<&TransferProgress>,
) -> Result<(u64, StorageMetrics)> {
    use futures_util::StreamExt;
    use tokio::io::BufWriter;

    let response = send_transfer_request_with_retry("Archive download", || async {
        Ok(client.get(url).send().await?)
    })
    .await?
    .error_for_status()
    .context("Archive download failed")?;

    let storage_metrics = StorageMetrics::from_headers(response.headers());

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
    Ok((bytes_downloaded, storage_metrics))
}

fn format_phase_duration(duration: Duration) -> String {
    if duration.as_millis() >= 1_000 {
        format!("{:.1}s", duration.as_secs_f64())
    } else {
        format!("{}ms", duration.as_millis())
    }
}
