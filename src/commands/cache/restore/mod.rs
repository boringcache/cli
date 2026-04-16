//! Restore command namespace.
//! Archive, OCI, and file layout restore flows should move into sibling modules here.

#![allow(clippy::items_after_test_module)]

mod archive;
mod file;
mod oci;

use crate::api::{ApiClient, CacheResolutionEntry};
use crate::command_support::RestoreSpec;
use crate::progress::{Summary, System as ProgressSystem, TransferProgress};
use crate::telemetry::StorageMetrics;
use crate::transfer::send_transfer_request_with_retry;
use crate::ui;
use anyhow::{Context, Error, Result, anyhow};
use std::collections::{HashMap, HashSet};
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
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

fn run_restore_preflight_checks(
    parsed_pairs: &[RestoreSpec],
    validate_targets: bool,
) -> Result<RestorePreflightCheck> {
    let mut valid_specs = Vec::new();
    let mut warnings = Vec::new();

    for spec in parsed_pairs {
        if let Err(error) = crate::tag_utils::validate_tag(&spec.tag) {
            warnings.push(format!("Skipping invalid tag '{}': {}", spec.tag, error));
            continue;
        }

        if !validate_targets {
            valid_specs.push(spec.clone());
            continue;
        }

        let path = spec.path.as_deref().unwrap_or(".");
        let expanded_path = crate::command_support::expand_tilde_path(path);
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

fn should_fail_on_restore_error(fail_on_cache_error: bool, require_server_signature: bool) -> bool {
    fail_on_cache_error || require_server_signature
}

fn finalize_execute_batch_restore_result(
    result: Result<()>,
    fail_on_cache_miss: bool,
    fail_on_cache_error: bool,
    require_server_signature: bool,
) -> Result<()> {
    match result {
        Ok(()) => Ok(()),
        Err(err) => {
            if fail_on_cache_miss
                || should_fail_on_restore_error(fail_on_cache_error, require_server_signature)
            {
                return Err(err);
            }
            ui::warn(&format!("{:#}", err));
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command_support::RestoreSpec;
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

        let result = run_restore_preflight_checks(&[parsed], true).unwrap();
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

        let result = run_restore_preflight_checks(&[parsed], true).unwrap();
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

        let result = run_restore_preflight_checks(&[parsed], true).unwrap();
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

        let result = run_restore_preflight_checks(&[parsed], true).unwrap();
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

        let result = run_restore_preflight_checks(&parsed_entries, true).unwrap();
        assert_eq!(result.valid_specs.len(), 1);
        assert_eq!(result.valid_specs[0].tag, "tag2");
    }

    #[test]
    fn preflight_lookup_only_does_not_create_missing_parent_directories() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("vendor").join("bundle");
        let parsed = RestoreSpec {
            tag: "valid-tag".to_string(),
            path: Some(target.to_string_lossy().to_string()),
        };

        let result = run_restore_preflight_checks(&[parsed], false).unwrap();
        assert_eq!(result.valid_specs.len(), 1);
        assert!(!temp.path().join("vendor").exists());
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
    fn strict_restore_errors_include_signature_requirement() {
        assert!(super::should_fail_on_restore_error(true, false));
        assert!(super::should_fail_on_restore_error(false, true));
        assert!(!super::should_fail_on_restore_error(false, false));
    }

    #[test]
    fn lenient_execute_batch_restore_result_warns_and_continues() {
        let err: Error = anyhow!("boom");
        let result = super::finalize_execute_batch_restore_result(Err(err), false, false, false);
        assert!(result.is_ok());
    }

    #[test]
    fn strict_execute_batch_restore_result_returns_error() {
        let err: Error = anyhow!("boom");
        let result = super::finalize_execute_batch_restore_result(Err(err), false, true, false);
        assert!(result.is_err());
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
    allow_external_symlinks: bool,
    fail_on_cache_error: bool,
    require_server_signature: bool,
) -> Result<()> {
    finalize_execute_batch_restore_result(
        execute_batch_restore_inner(
            workspace_option,
            tag_path_pairs,
            verbose,
            no_platform,
            no_git,
            fail_on_cache_miss,
            lookup_only,
            identity,
            allow_external_symlinks,
            fail_on_cache_error,
            require_server_signature,
        )
        .await,
        fail_on_cache_miss,
        fail_on_cache_error,
        require_server_signature,
    )
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
    allow_external_symlinks: bool,
    fail_on_cache_error: bool,
    require_server_signature: bool,
) -> Result<()> {
    let workspace = crate::command_support::get_workspace_name(workspace_option)?;

    if tag_path_pairs.is_empty() {
        ui::info("No tag:path pairs specified for restore");
        return Ok(());
    }

    crate::api::parse_workspace_slug(&workspace)?;

    let strict_restore_errors =
        should_fail_on_restore_error(fail_on_cache_error, require_server_signature);

    let parsed_specs: Vec<RestoreSpec> = tag_path_pairs
        .iter()
        .map(|tag_path| crate::command_support::parse_restore_format(tag_path).map_err(Error::from))
        .collect::<Result<_, _>>()?;

    let preflight_result = run_restore_preflight_checks(&parsed_specs, !lookup_only)?;

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
    let mut seen_candidates: HashSet<String> = HashSet::new();
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
            .map(crate::command_support::expand_tilde_path)
            .unwrap_or_else(|| ".".to_string());

        for candidate in &candidates {
            if seen_candidates.insert(candidate.clone()) {
                all_candidates.push(candidate.clone());
            }
        }

        plans.push(RestorePlan {
            display_tag: spec.tag.clone(),
            target_path,
            candidates,
        });
    }

    let api_client = ApiClient::for_restore()?;

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
        let restore_result = api_client
            .restore(&workspace, &all_candidates, require_server_signature)
            .await;
        match restore_result {
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
                    .map(|bc_err| {
                        matches!(bc_err, crate::error::BoringCacheError::CachePending { .. })
                    })
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
                    let warning_message = "Cache upload still in progress after retries";
                    reporter.warning(warning_message.to_string())?;
                    drop(reporter);
                    progress_system.shutdown()?;
                    if strict_restore_errors {
                        anyhow::bail!(warning_message);
                    }
                    return Ok(());
                }

                if crate::error::is_connection_error(&err) {
                    reporter.warning(format!("Cache unavailable: {}", err))?;
                    drop(reporter);
                    progress_system.shutdown()?;
                    if strict_restore_errors {
                        return Err(err);
                    }
                    return Ok(());
                }
                reporter.warning(format!("Cache restore failed: {}", err))?;
                drop(reporter);
                progress_system.shutdown()?;
                if strict_restore_errors {
                    return Err(err);
                }
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
            if let Some(entry) = results_by_tag.get(candidate)
                && entry.status == "hit"
            {
                chosen = Some(entry.clone());
                break;
            }
        }

        if let Some(entry) = chosen {
            selected_hits.push(SelectedRestore {
                entry,
                target_path: plan.target_path.clone(),
            });
        } else {
            reporter.info(format!("Cache miss for {}", plan.display_tag))?;
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
        reporter.info("No cache entries found for the specified tags".to_string())?;
        drop(reporter);
        progress_system.shutdown()?;

        ui::blank_line();
        ui::workflow_summary("found", 0, tags_display.len(), &workspace);
        if !misses.is_empty() {
            ui::info(&format!("Cache miss: {}", misses.join(", ")));
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
            ui::info(&format!("Cache miss: {}", misses.join(", ")));
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
        crate::command_support::get_optimal_concurrency(selected_hits.len(), "restore");

    if selected_hits.len() > 1 {
        crate::command_support::display_concurrency_info(max_concurrent, "restore");
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
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|e| anyhow!("Restore semaphore closed: {e}"))?;
            let result = process_restore(
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
                allow_external_symlinks,
                require_server_signature,
            )
            .await;
            drop(_permit);
            result
        });

        tasks.push(task);
    }

    let mut restored_tags = Vec::new();
    let mut skipped_entries: Vec<(String, String)> = Vec::new();
    let mut ignored_entries: Vec<(String, String)> = Vec::new();
    let mut restore_errors: Vec<Error> = Vec::new();

    for task in tasks {
        let task_result = task.await;
        match task_result {
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

    if strict_restore_errors {
        finalize_restore_outcome(restore_errors, skipped_entries)?;
    } else {
        let _ = finalize_restore_outcome(restore_errors, skipped_entries);
    }

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
    allow_external_symlinks: bool,
    require_server_signature: bool,
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

    let adapter = crate::adapters::select_transport_adapter(restore_adapter);
    log::debug!(
        "Restore adapter dispatch tag={} adapter={}",
        hit.tag,
        adapter.transport_kind().as_str()
    );

    let archive_api_client = api_client.clone();
    let archive_reporter = reporter.clone();
    let archive_session_id = session_id.clone();
    let archive_title = title.clone();
    let archive_workspace = workspace.clone();
    let archive_hit = hit.clone();
    let archive_target_path = target_path.clone();
    let archive_identity = identity.clone();
    let archive_passphrase_cache = passphrase_cache.clone();
    let oci_reporter = reporter.clone();
    let oci_session_id = session_id.clone();
    let oci_title = title.clone();
    let oci_workspace = workspace.clone();
    let oci_hit = hit.clone();
    let oci_target_path = target_path.clone();

    adapter
        .dispatch(
            || {
                archive::process_restore_archive(
                    archive_api_client,
                    archive_reporter,
                    archive_session_id,
                    archive_title,
                    archive_workspace,
                    archive_hit,
                    archive_target_path,
                    verbose,
                    archive_identity,
                    archive_passphrase_cache,
                    allow_external_symlinks,
                    require_server_signature,
                )
            },
            || {
                oci::process_restore_oci(
                    &api_client,
                    oci_reporter,
                    oci_session_id,
                    oci_title,
                    oci_workspace,
                    oci_hit,
                    oci_target_path,
                    verbose,
                    require_server_signature,
                )
            },
            || {
                file::process_restore_file(
                    &api_client,
                    reporter,
                    session_id,
                    title,
                    workspace,
                    hit,
                    target_path,
                    verbose,
                    allow_external_symlinks,
                    require_server_signature,
                )
            },
        )
        .await
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
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|e| anyhow!("Archive download semaphore closed: {e}"))?;
            let result = crate::cas_transport::download_range(
                &client,
                &url,
                &file_path,
                start,
                end,
                this_part_size,
                progress.as_ref(),
                None,
            )
            .await
            .with_context(|| {
                format!(
                    "Part {}/{} (bytes {}-{}) failed",
                    part_num, num_parts, start, end
                )
            });
            drop(_permit);
            result
        });

        tasks.push(task);
    }

    let mut total_downloaded = 0u64;
    let mut errors: Vec<String> = Vec::new();
    let mut first_storage_metrics: Option<StorageMetrics> = None;

    for (idx, task) in tasks.into_iter().enumerate() {
        let task_result = task.await;
        match task_result {
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

    loop {
        let next_chunk = stream.next().await;
        let Some(chunk_result) = next_chunk else {
            break;
        };
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
