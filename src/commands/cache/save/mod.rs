//! Save command namespace.
//! Layout-specific save flows should be split into sibling modules under this directory.

mod archive;
mod cas;
mod file;
mod oci;

use anyhow::{Context, Error, Result, anyhow};
use std::sync::Arc;
use tokio::sync::OnceCell;

use crate::api::ApiClient;
use crate::ui;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SaveStatus {
    AlreadyExists,
    Uploaded,
    Skipped,
}

async fn shared_save_api_client(shared_client: &OnceCell<ApiClient>) -> Result<ApiClient> {
    let client = shared_client
        .get_or_try_init(|| async { ApiClient::for_save() })
        .await?;
    Ok(client.clone())
}

#[allow(clippy::too_many_arguments)]
pub async fn execute_batch_save(
    workspace: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: Vec<String>,
    recipient: Option<String>,
    fail_on_cache_error: bool,
) -> Result<()> {
    if let Err(err) = execute_batch_save_inner(
        workspace,
        tag_path_pairs,
        verbose,
        no_platform,
        no_git,
        force,
        exclude,
        recipient,
    )
    .await
    {
        if fail_on_cache_error {
            return Err(err);
        }
        ui::warn(&format!("{:#}", err));
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn execute_batch_save_inner(
    workspace: Option<String>,
    tag_path_pairs: Vec<String>,
    verbose: bool,
    no_platform: bool,
    no_git: bool,
    force: bool,
    exclude: Vec<String>,
    recipient: Option<String>,
) -> Result<()> {
    let workspace = crate::command_support::get_workspace_name(workspace)?;
    crate::api::parse_workspace_slug(&workspace)?;

    let (encrypt, recipient) =
        crate::command_support::resolve_encryption_config(&workspace, recipient)?;

    let parsed_pairs: Vec<crate::command_support::SaveSpec> = tag_path_pairs
        .into_iter()
        .map(|pair| crate::command_support::parse_save_format(&pair).map_err(Error::from))
        .collect::<Result<_, _>>()?;

    let mut skipped_paths = 0usize;

    let platform = if no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };
    let git_enabled = !no_git && !crate::git::is_git_disabled_by_env();

    let mut prepared_entries: Vec<(String, String)> = Vec::new();

    for crate::command_support::SaveSpec {
        tag: base_tag,
        path,
    } in parsed_pairs
    {
        let expanded_path = crate::command_support::expand_tilde_path(&path);
        let git_context = if git_enabled {
            crate::git::GitContext::detect_with_path(Some(&expanded_path))
        } else {
            crate::git::GitContext::default()
        };
        let tag_resolver =
            crate::tag_utils::TagResolver::new(platform.clone(), git_context, git_enabled);

        let tag = tag_resolver.effective_save_tag(&base_tag)?;

        let path_obj = std::path::Path::new(&expanded_path);
        if !path_obj.exists() {
            if path != expanded_path {
                ui::warn(&format!(
                    "Skipping {} -> {} (expanded from {}) (path not found)",
                    tag, expanded_path, path
                ));
            } else {
                ui::warn(&format!(
                    "Skipping {} -> {} (path not found)",
                    tag, expanded_path
                ));
            }
            skipped_paths += 1;
            continue;
        }

        prepared_entries.push((tag, expanded_path));
    }

    let attempted_saves = prepared_entries.len();

    if attempted_saves == 0 {
        if skipped_paths > 0 {
            anyhow::bail!("No valid paths found to save");
        } else {
            return Ok(());
        }
    }

    let total_entries = attempted_saves;
    let mut successful_saves = 0usize;
    let mut failed_attempts = 0usize;
    let mut errors: Vec<anyhow::Error> = Vec::new();
    let max_concurrent = crate::command_support::get_optimal_concurrency(total_entries, "save");
    let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent.max(1)));
    let mut tasks = Vec::with_capacity(total_entries);
    let shared_api_client: Arc<OnceCell<ApiClient>> = Arc::new(OnceCell::new());

    for (position, (tag, expanded_path)) in prepared_entries.into_iter().enumerate() {
        let shared_api_client = shared_api_client.clone();
        let workspace = workspace.clone();
        let exclude = exclude.clone();
        let recipient = recipient.clone();
        let semaphore = semaphore.clone();
        let task = tokio::spawn(async move {
            let _permit = semaphore
                .acquire_owned()
                .await
                .map_err(|e| anyhow!("Save worker semaphore closed: {e}"))?;
            let result = save_single_entry(
                shared_api_client,
                workspace,
                tag.clone(),
                expanded_path,
                verbose,
                force,
                position,
                total_entries,
                exclude,
                encrypt,
                recipient,
            )
            .await;
            Ok::<(String, Result<SaveStatus>), anyhow::Error>((tag, result))
        });
        tasks.push(task);
    }

    for task in tasks {
        let (tag, result) = task.await.context("Batch save task panicked")??;
        match result {
            Ok(SaveStatus::AlreadyExists | SaveStatus::Uploaded) => successful_saves += 1,
            Ok(SaveStatus::Skipped) => {}
            Err(err) => {
                failed_attempts += 1;
                errors.push(err.context(format!("Failed to save {}", tag)));
            }
        }
    }

    log::debug!(
        "Completed save command for workspace={} attempted={} succeeded={} skipped_paths={}",
        workspace,
        attempted_saves,
        successful_saves,
        skipped_paths
    );

    if attempted_saves > 0 {
        ui::workflow_summary("saved", successful_saves, attempted_saves, &workspace);
        if skipped_paths > 0 {
            ui::warn(&format!(
                "Skipped {} entr{} due to missing paths",
                skipped_paths,
                if skipped_paths == 1 { "y" } else { "ies" }
            ));
        }
    }

    if !errors.is_empty() {
        let message = errors
            .into_iter()
            .map(|err| format!("{:#}", err))
            .collect::<Vec<_>>()
            .join("\n");
        anyhow::bail!(message);
    }

    if failed_attempts > 0 {
        anyhow::bail!(
            "Failed to save {} of {} cache entr{}",
            failed_attempts,
            attempted_saves,
            if attempted_saves == 1 { "y" } else { "ies" }
        );
    }

    if verbose && successful_saves > 0 {
        ui::info(&format!(
            "Successfully saved {} entr{}",
            successful_saves,
            if successful_saves == 1 { "y" } else { "ies" }
        ));
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn save_single_entry(
    shared_api_client: Arc<OnceCell<ApiClient>>,
    workspace: String,
    tag: String,
    path: String,
    verbose: bool,
    force: bool,
    entry_index: usize,
    total_entries: usize,
    exclude: Vec<String>,
    encrypt: bool,
    recipient: Option<String>,
) -> Result<SaveStatus> {
    ui::info(&format!(
        "\nSaving ({}/{}) {} -> {}",
        entry_index + 1,
        total_entries,
        tag,
        path
    ));

    let adapter_detection = crate::cache_adapter::detect_layout(std::path::Path::new(&path));
    log::debug!(
        "Starting save {} of {} for tag={} path={} workspace={}",
        entry_index + 1,
        total_entries,
        tag,
        path,
        workspace
    );
    log::debug!(
        "Save adapter selection tag={} path={} adapter={} reason={}",
        tag,
        path,
        adapter_detection.kind.as_str(),
        adapter_detection.reason
    );

    let adapter_selection = crate::adapters::select_layout_adapter(adapter_detection.kind, encrypt);
    if adapter_selection.used_encryption_fallback {
        ui::warn(crate::adapters::CONTENT_ADDRESSED_ENCRYPTION_FALLBACK_WARNING);
    }
    let adapter = adapter_selection.adapter;
    log::debug!(
        "Save adapter dispatch tag={} adapter={}",
        tag,
        adapter.transport_kind().as_str()
    );

    let archive_workspace = workspace.clone();
    let archive_tag = tag.clone();
    let archive_path = path.clone();
    let archive_exclude = exclude.clone();
    let archive_recipient = recipient.clone();
    let archive_api_client = shared_api_client.clone();
    let oci_workspace = workspace.clone();
    let oci_tag = tag.clone();
    let oci_path = path.clone();
    let oci_api_client = shared_api_client.clone();
    let file_api_client = shared_api_client;

    adapter
        .dispatch(
            || {
                archive::save_single_archive_entry(
                    archive_api_client,
                    archive_workspace,
                    archive_tag,
                    archive_path,
                    verbose,
                    force,
                    entry_index,
                    total_entries,
                    archive_exclude,
                    encrypt,
                    archive_recipient,
                )
            },
            || async move {
                oci::save_single_oci_entry(
                    oci_api_client,
                    oci_workspace,
                    oci_tag,
                    oci_path,
                    verbose,
                    force,
                    entry_index,
                    total_entries,
                )
                .await
            },
            || async move {
                file::save_single_file_entry(
                    file_api_client,
                    workspace,
                    tag,
                    path,
                    verbose,
                    force,
                    entry_index,
                    total_entries,
                    exclude,
                    adapter_detection.kind,
                )
                .await
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::archive::{
        ArchiveConfirmOutcome, build_archive_manifest_checks,
        digest_existing_cache_entry_id_from_result,
    };
    use crate::api::models::cache::ManifestCheckResult;
    use crate::command_support::save_support::{
        archive_cache_root_digest, conflict_message_from_error, is_cache_pending_error,
        serialize_manifest,
    };

    fn manifest_check_result(
        exists: bool,
        status: Option<&str>,
        cache_entry_id: Option<&str>,
    ) -> ManifestCheckResult {
        ManifestCheckResult {
            tag: "tag".to_string(),
            exists,
            pending: false,
            manifest_root_digest: None,
            cache_entry_id: cache_entry_id.map(str::to_string),
            content_hash: None,
            manifest_digest: None,
            manifest_url: None,
            compression_algorithm: None,
            archive_urls: Vec::new(),
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            status: status.map(str::to_string),
            error: None,
        }
    }

    #[test]
    fn conflict_message_is_extracted_from_boringcache_error() {
        let err: anyhow::Error =
            crate::error::BoringCacheError::cache_conflict("tag already claimed").into();

        assert_eq!(
            conflict_message_from_error(&err),
            Some("tag already claimed".to_string())
        );
    }

    #[test]
    fn cache_pending_errors_are_detected() {
        let err: anyhow::Error = crate::error::BoringCacheError::cache_pending().into();

        assert!(is_cache_pending_error(&err));
        assert_eq!(conflict_message_from_error(&err), None);
    }

    #[test]
    fn non_boringcache_errors_do_not_report_contention() {
        let err = anyhow::anyhow!("boom");

        assert!(!is_cache_pending_error(&err));
        assert_eq!(conflict_message_from_error(&err), None);
    }

    #[test]
    fn archive_manifest_checks_include_digest_lookup_when_not_forced() {
        let checks = build_archive_manifest_checks("ruby-deps", "sha256:abc", false);
        assert_eq!(checks.len(), 2);
        assert_eq!(checks[0].lookup, None);
        assert_eq!(checks[1].lookup.as_deref(), Some("digest"));
    }

    #[test]
    fn archive_manifest_checks_skip_digest_lookup_when_forced() {
        let checks = build_archive_manifest_checks("ruby-deps", "sha256:abc", true);
        assert_eq!(checks.len(), 1);
        let check = &checks[0];
        assert_eq!(check.tag, "ruby-deps");
        assert_eq!(check.manifest_root_digest, "sha256:abc");
        assert_eq!(check.lookup, None);
    }

    #[test]
    fn archive_cache_root_digest_is_plain_for_unencrypted_archives() {
        let digest = "sha256:abc";
        assert_eq!(archive_cache_root_digest(digest, None), digest);
    }

    #[test]
    fn archive_cache_root_digest_is_recipient_scoped_for_encrypted_archives() {
        let digest = "sha256:abc";
        let scoped_a = archive_cache_root_digest(digest, Some("age1recipient-a"));
        let scoped_b = archive_cache_root_digest(digest, Some("age1recipient-b"));

        assert_ne!(scoped_a, digest);
        assert_ne!(scoped_a, scoped_b);
        assert!(scoped_a.starts_with("sha256:"));
        assert_eq!(scoped_a.len(), "sha256:".len() + 64);
    }

    #[test]
    fn digest_lookup_accepts_ready_entry_with_cache_entry_id() {
        let result = manifest_check_result(true, Some("ready"), Some("entry-123"));
        assert_eq!(
            digest_existing_cache_entry_id_from_result(&result),
            Some("entry-123".to_string())
        );
    }

    #[test]
    fn digest_lookup_ignores_pending_entries() {
        let result = manifest_check_result(true, Some("pending"), Some("entry-123"));
        assert_eq!(digest_existing_cache_entry_id_from_result(&result), None);
    }

    #[test]
    fn digest_lookup_ignores_missing_entries() {
        let result = manifest_check_result(false, Some("ready"), Some("entry-123"));
        assert_eq!(digest_existing_cache_entry_id_from_result(&result), None);
    }

    #[test]
    fn serialize_manifest_includes_archive_content_hash() {
        let bytes = serialize_manifest(
            "cache-tag",
            "sha256:1111111111111111111111111111111111111111111111111111111111111111",
            &[],
            "sha256:2222222222222222222222222222222222222222222222222222222222222222",
            None,
            None,
        )
        .unwrap();

        let manifest: crate::manifest::Manifest = ciborium::from_reader(&bytes[..]).unwrap();
        let archive = manifest
            .archive
            .expect("archive metadata should be present");
        assert_eq!(
            archive.content_hash.as_deref(),
            Some("sha256:2222222222222222222222222222222222222222222222222222222222222222")
        );
        assert_eq!(archive.compression, "zstd");
    }

    #[test]
    fn archive_confirm_outcome_reports_existing_winner() {
        let response = crate::api::models::cache::CacheConfirmResponse {
            status: "ready".to_string(),
            cache_entry_id: Some("entry-existing".to_string()),
            manifest_root_digest: None,
            uploaded_at: None,
            tag: None,
            tag_status: None,
            promotion_status: None,
            promotion_reason: None,
            requested_cache_entry_id: None,
            signature: None,
            signing_public_key: None,
            signed_at: None,
        };

        assert_eq!(
            ArchiveConfirmOutcome::from_response("entry-new", response),
            ArchiveConfirmOutcome::Published {
                winner_id: Some("entry-existing".to_string())
            }
        );
    }

    #[test]
    fn archive_confirm_outcome_ignores_same_entry_winner() {
        let response = crate::api::models::cache::CacheConfirmResponse {
            status: "ready".to_string(),
            cache_entry_id: Some("entry-same".to_string()),
            manifest_root_digest: None,
            uploaded_at: None,
            tag: None,
            tag_status: None,
            promotion_status: None,
            promotion_reason: None,
            requested_cache_entry_id: None,
            signature: None,
            signing_public_key: None,
            signed_at: None,
        };

        assert_eq!(
            ArchiveConfirmOutcome::from_response("entry-same", response),
            ArchiveConfirmOutcome::Published { winner_id: None }
        );
    }

    #[test]
    fn resumable_pending_cas_save_requires_pending_cas_upload_metadata() {
        let resumable: crate::api::models::cache::SaveResponse = serde_json::from_value(
            serde_json::json!({
                "tag": "cache-tag",
                "cache_entry_id": "entry-1",
                "upload_session_id": "session-1",
                "upload_state": "uploading",
                "exists": true,
                "storage_mode": "cas",
                "blob_count": 1,
                "blob_total_size_bytes": 128,
                "cas_layout": "oci",
                "manifest_upload_url": "https://example.test/manifest",
                "upload_headers": {},
                "manifest_root_digest": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
                "status": "pending"
            }),
        )
        .unwrap();
        assert!(resumable.is_resumable_pending_cas());
        assert!(resumable.is_resumable_pending_cas_for(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ));
        assert!(
            resumable
                .blocking_pending_cas_reason(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                )
                .is_none()
        );
        assert!(!resumable.should_skip_existing_uploads());
        assert!(!resumable.should_skip_existing_uploads_for(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ));

        assert!(!resumable.is_resumable_pending_cas_for(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        ));
        assert!(
            resumable
                .blocking_pending_cas_reason(
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                )
                .is_some()
        );
        assert!(!resumable.should_skip_existing_uploads_for(
            "sha256:2222222222222222222222222222222222222222222222222222222222222222"
        ));

        let mut missing_manifest = resumable;
        missing_manifest.manifest_upload_url = None;
        assert!(!missing_manifest.is_resumable_pending_cas());
        assert!(missing_manifest.should_skip_existing_uploads());
        assert!(
            missing_manifest
                .blocking_pending_cas_reason(
                    "sha256:1111111111111111111111111111111111111111111111111111111111111111"
                )
                .is_some()
        );
        assert!(!missing_manifest.should_skip_existing_uploads_for(
            "sha256:1111111111111111111111111111111111111111111111111111111111111111"
        ));
    }
}
