//! Mount command namespace.
//! Initial restore and sync flows should be split by layout under this directory.

mod archive;
mod cas;
mod file;
mod oci;

use anyhow::{Context, Result};
use notify_debouncer_mini::{DebounceEventResult, new_debouncer, notify::RecursiveMode};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

use crate::api::models::cache::ManifestCheckResult;
use crate::api::{ApiClient, CacheResolutionEntry};
use crate::ui;

const DEBOUNCE_TIMEOUT_SECS: u64 = 5;
const MIN_CHANGES_TO_SYNC: usize = 50;
const IDLE_SYNC_SECS: u64 = 60;
const CAS_BLOB_WRITER_CAPACITY: usize = 512 * 1024;
const MOUNT_SYNC_VISIBILITY_TIMEOUT_SECS: u64 = 15;
const MOUNT_SYNC_VISIBILITY_POLL_MS: u64 = 250;

enum RestoreAction {
    Downloaded,
    AlreadyInSync,
    LocalDiffers,
    NoRemoteCache,
}

#[derive(Clone, Copy)]
struct MountSyncPublication<'a> {
    cache_entry_id: &'a str,
    manifest_root_digest: &'a str,
}

pub struct MountOptions {
    pub no_platform: bool,
    pub no_git: bool,
    pub verbose: bool,
    pub force: bool,
    pub recipient: Option<String>,
    pub identity: Option<String>,
    pub require_server_signature: bool,
}

fn manifest_check_is_pending(result: &ManifestCheckResult) -> bool {
    result.pending || matches!(result.status.as_deref(), Some("pending" | "uploading"))
}

fn manifest_check_is_ready(result: &ManifestCheckResult) -> bool {
    result.exists && !manifest_check_is_pending(result)
}

async fn wait_for_mount_sync_visibility(
    api_client: &ApiClient,
    workspace: &str,
    tag: &str,
    publication: MountSyncPublication<'_>,
    require_server_signature: bool,
) -> Result<()> {
    let deadline =
        std::time::Instant::now() + Duration::from_secs(MOUNT_SYNC_VISIBILITY_TIMEOUT_SECS);
    loop {
        let hit = api_client
            .fetch_manifest_entry(workspace, tag, require_server_signature)
            .await?;
        if let Some(hit) = hit.as_ref()
            && mount_sync_visible(hit, publication)
        {
            return Ok(());
        }

        let last_observation = describe_mount_sync_visibility(hit.as_ref(), publication);
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "mount sync for {tag} was published but restore did not resolve the updated entry before timeout: {last_observation}"
            );
        }

        tokio::time::sleep(Duration::from_millis(MOUNT_SYNC_VISIBILITY_POLL_MS)).await;
    }
}

fn ensure_mount_sync_won(
    publication: MountSyncPublication<'_>,
    response: &crate::api::models::cache::CacheConfirmResponse,
    tag: &str,
) -> Result<()> {
    if let Some(winner_id) = response.cache_entry_id.as_deref()
        && winner_id != publication.cache_entry_id
    {
        anyhow::bail!(
            "mount sync for {tag} did not publish the updated entry; server kept existing entry {winner_id}"
        );
    }
    if let Some(published_digest) = response.manifest_root_digest.as_deref()
        && published_digest != publication.manifest_root_digest
    {
        anyhow::bail!(
            "mount sync for {tag} published unexpected digest {published_digest}; expected {}",
            publication.manifest_root_digest
        );
    }
    Ok(())
}

fn mount_sync_visible(hit: &CacheResolutionEntry, publication: MountSyncPublication<'_>) -> bool {
    !hit.pending
        && !matches!(hit.status.as_str(), "pending" | "uploading")
        && hit.cache_entry_id.as_deref() == Some(publication.cache_entry_id)
        && hit.manifest_root_digest.as_deref() == Some(publication.manifest_root_digest)
}

fn describe_mount_sync_visibility(
    hit: Option<&CacheResolutionEntry>,
    publication: MountSyncPublication<'_>,
) -> String {
    match hit {
        Some(hit) => format!(
            "saw status={} cache_entry_id={} manifest_root_digest={}",
            hit.status,
            hit.cache_entry_id.as_deref().unwrap_or("<missing>"),
            hit.manifest_root_digest.as_deref().unwrap_or("<missing>")
        ),
        None => format!(
            "tag not visible for cache_entry_id={} manifest_root_digest={}",
            publication.cache_entry_id, publication.manifest_root_digest
        ),
    }
}

pub async fn execute(workspace: String, tag_path: String, options: MountOptions) -> Result<()> {
    let (tag, local_path) = parse_tag_path(&tag_path)?;
    let expanded_path = crate::command_support::expand_tilde_path(&local_path);
    let local_path = PathBuf::from(&expanded_path);

    crate::api::parse_workspace_slug(&workspace)?;
    crate::tag_utils::validate_tag(&tag)?;

    let platform = if options.no_platform {
        None
    } else {
        Some(crate::platform::Platform::detect()?)
    };
    let git_enabled = !options.no_git && !crate::git::is_git_disabled_by_env();
    let git_context = if git_enabled {
        crate::git::GitContext::detect_with_path(Some(&expanded_path))
    } else {
        crate::git::GitContext::default()
    };
    let tag_resolver = crate::tag_utils::TagResolver::new(platform, git_context, git_enabled);
    let resolved_tag = tag_resolver.effective_save_tag(&tag)?;

    let api_client = ApiClient::for_save()?;

    api_client
        .get_token()
        .context("No configuration found. Run 'boringcache auth' to authenticate.")?;

    let (encrypt, recipient) =
        crate::command_support::resolve_encryption_config(&workspace, options.recipient)?;
    let passphrase_cache = Arc::new(Mutex::new(crate::encryption::PassphraseCache::default()));

    ui::info(&format!(
        "Mounting {} -> {}",
        resolved_tag,
        local_path.display()
    ));

    let restore_result = initial_restore(
        &api_client,
        &workspace,
        &resolved_tag,
        &local_path,
        options.verbose,
        options.force,
        recipient.clone(),
        options.identity.clone(),
        passphrase_cache.clone(),
        options.require_server_signature,
    )
    .await?;

    match restore_result {
        RestoreAction::Downloaded => {
            ui::info("  Restored from remote cache");
        }
        RestoreAction::AlreadyInSync => {
            ui::info("  Local content in sync with remote");
        }
        RestoreAction::LocalDiffers => {
            ui::info("  Local content differs, syncing to remote...");
            sync_to_remote(
                &api_client,
                &workspace,
                &tag,
                &resolved_tag,
                &local_path,
                options.verbose,
                encrypt,
                recipient.clone(),
                options.require_server_signature,
            )
            .await?;
        }
        RestoreAction::NoRemoteCache => {
            ui::info("  No remote cache found, using local state");
            ensure_local_directory(&local_path)?;

            if has_content(&local_path)? {
                ui::info("  Performing initial sync of existing content...");
                sync_to_remote(
                    &api_client,
                    &workspace,
                    &tag,
                    &resolved_tag,
                    &local_path,
                    options.verbose,
                    encrypt,
                    recipient.clone(),
                    options.require_server_signature,
                )
                .await?;
            }
        }
    }

    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_clone = shutdown.clone();

    ctrlc::set_handler(move || {
        shutdown_clone.store(true, Ordering::SeqCst);
    })
    .context("Failed to set Ctrl+C handler")?;

    ui::info(&format!(
        "Watching {} for changes (Ctrl+C to stop)...",
        local_path.display()
    ));

    watch_and_sync(
        &api_client,
        &workspace,
        &tag,
        &resolved_tag,
        &local_path,
        options.verbose,
        shutdown,
        encrypt,
        recipient,
        options.require_server_signature,
    )
    .await?;
    Ok(())
}

fn parse_tag_path(tag_path: &str) -> Result<(String, String)> {
    let trimmed = tag_path.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "Invalid tag:path format. Expected 'tag:path', got '{}'",
            tag_path
        );
    }

    let (tag_raw, path_raw) = trimmed.split_once(':').ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid tag:path format. Expected 'tag:path', got '{}'",
            tag_path
        )
    })?;

    let tag = tag_raw.trim();
    if tag.is_empty() {
        anyhow::bail!("Tag is missing in '{}'. Add a tag before ':'.", tag_path);
    }

    let path = path_raw.trim();
    if path.is_empty() {
        anyhow::bail!("Path is missing in '{}'. Add a path after ':'.", tag_path);
    }

    Ok((tag.to_string(), path.to_string()))
}

fn ensure_local_directory(path: &Path) -> Result<()> {
    if !path.exists() {
        std::fs::create_dir_all(path)
            .with_context(|| format!("Failed to create directory: {}", path.display()))?;
    }
    Ok(())
}

fn has_content(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(false);
    }
    let entries = std::fs::read_dir(path)
        .with_context(|| format!("Failed to read directory: {}", path.display()))?;
    Ok(entries.count() > 0)
}

fn unsafe_mount_path_reason(path: &Path) -> Result<Option<&'static str>> {
    let absolute_path = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let canonical_path = absolute_path.canonicalize().unwrap_or(absolute_path);

    let is_root = canonical_path.has_root()
        && !canonical_path
            .components()
            .any(|component| matches!(component, Component::Normal(_)));
    if is_root {
        return Ok(Some("root directory"));
    }

    if let Some(home_dir) = dirs::home_dir() {
        let home_dir = home_dir.canonicalize().unwrap_or(home_dir);
        if canonical_path == home_dir {
            return Ok(Some("home directory"));
        }
    }

    let cwd = std::env::current_dir()?;
    let cwd = cwd.canonicalize().unwrap_or(cwd);
    if canonical_path == cwd {
        return Ok(Some("workspace root"));
    }

    Ok(None)
}

#[allow(clippy::too_many_arguments)]
async fn initial_restore(
    api_client: &ApiClient,
    workspace: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    force: bool,
    recipient: Option<String>,
    identity: Option<String>,
    passphrase_cache: Arc<Mutex<crate::encryption::PassphraseCache>>,
    require_server_signature: bool,
) -> Result<RestoreAction> {
    let resolution_result = api_client
        .restore(
            workspace,
            &[resolved_tag.to_string()],
            require_server_signature,
        )
        .await;

    let hits = match resolution_result {
        Ok(entries) => entries
            .into_iter()
            .filter(|e| e.status == "hit")
            .collect::<Vec<_>>(),
        Err(e) => {
            if verbose {
                ui::warn(&format!("  Failed to check remote cache: {}", e));
            }
            return Ok(RestoreAction::NoRemoteCache);
        }
    };

    if hits.is_empty() {
        return Ok(RestoreAction::NoRemoteCache);
    }

    let hit = &hits[0];
    let restore_adapter = crate::cache_adapter::detect_restore_transport(
        hit.storage_mode.as_deref(),
        hit.cas_layout.as_deref(),
    );
    let adapter = crate::adapters::select_transport_adapter(restore_adapter);
    log::debug!(
        "Mount restore adapter dispatch tag={} adapter={}",
        hit.tag,
        adapter.transport_kind().as_str()
    );
    let archive_identity = identity.clone();
    let archive_recipient = recipient.clone();
    let archive_passphrase_cache = passphrase_cache.clone();
    let restore_action = adapter
        .dispatch(
            || {
                archive::initial_restore_archive(
                    api_client,
                    hit,
                    local_path,
                    verbose,
                    force,
                    archive_recipient,
                    archive_identity,
                    archive_passphrase_cache,
                    require_server_signature,
                )
            },
            || {
                oci::initial_restore_oci(
                    api_client,
                    workspace,
                    hit,
                    local_path,
                    verbose,
                    force,
                    require_server_signature,
                )
            },
            || {
                file::initial_restore_file(
                    api_client,
                    workspace,
                    hit,
                    local_path,
                    verbose,
                    force,
                    require_server_signature,
                )
            },
        )
        .await?;
    Ok(restore_action)
}

#[allow(clippy::too_many_arguments)]
async fn watch_and_sync(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    shutdown: Arc<AtomicBool>,
    encrypt: bool,
    recipient: Option<String>,
    require_server_signature: bool,
) -> Result<()> {
    let (tx, mut rx) = mpsc::channel::<DebounceEventResult>(100);

    let tx_clone = tx.clone();
    let mut debouncer = new_debouncer(
        Duration::from_secs(DEBOUNCE_TIMEOUT_SECS),
        move |res: DebounceEventResult| {
            let _ = tx_clone.blocking_send(res);
        },
    )
    .context("Failed to create file watcher")?;

    debouncer
        .watcher()
        .watch(local_path, RecursiveMode::Recursive)
        .with_context(|| format!("Failed to watch directory: {}", local_path.display()))?;

    let mut pending_changes: usize = 0;
    let mut last_change_time = std::time::Instant::now();
    let mut has_pending = false;

    loop {
        if shutdown.load(Ordering::SeqCst) {
            ui::info("Shutting down...");

            if let Err(e) = sync_to_remote(
                api_client,
                workspace,
                base_tag,
                resolved_tag,
                local_path,
                verbose,
                encrypt,
                recipient.clone(),
                require_server_signature,
            )
            .await
            {
                ui::warn(&format!("  Final sync failed: {}", e));
            }
            break;
        }

        let should_sync = has_pending
            && (pending_changes >= MIN_CHANGES_TO_SYNC
                || last_change_time.elapsed() >= Duration::from_secs(IDLE_SYNC_SECS));

        if should_sync {
            if verbose {
                ui::info(&format!(
                    "  Syncing {} accumulated change(s)...",
                    pending_changes
                ));
            }
            if let Err(e) = sync_to_remote(
                api_client,
                workspace,
                base_tag,
                resolved_tag,
                local_path,
                verbose,
                encrypt,
                recipient.clone(),
                require_server_signature,
            )
            .await
            {
                ui::warn(&format!("  Sync failed: {}", e));
            }
            pending_changes = 0;
            has_pending = false;
        }

        tokio::select! {
            Some(event_result) = rx.recv() => {
                match event_result {
                    Ok(events) => {
                        if !events.is_empty() {
                            pending_changes += events.len();
                            last_change_time = std::time::Instant::now();
                            has_pending = true;


                            while let Ok(more) = rx.try_recv() {
                                if let Ok(more_events) = more {
                                    pending_changes += more_events.len();
                                }
                            }

                            if verbose {
                                ui::info(&format!(
                                    "  Detected changes ({} pending, sync at {} or after {}s idle)",
                                    pending_changes, MIN_CHANGES_TO_SYNC, IDLE_SYNC_SECS
                                ));
                            }
                        }
                    }
                    Err(errors) => {
                        ui::warn(&format!("  Watch error: {:?}", errors));
                    }
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(500)) => {

            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn sync_to_remote(
    api_client: &ApiClient,
    workspace: &str,
    base_tag: &str,
    resolved_tag: &str,
    local_path: &Path,
    verbose: bool,
    encrypt: bool,
    recipient: Option<String>,
    require_server_signature: bool,
) -> Result<()> {
    let adapter_detection = crate::cache_adapter::detect_layout(local_path);
    log::debug!(
        "Mount sync adapter selection tag={} adapter={} reason={}",
        resolved_tag,
        adapter_detection.kind.as_str(),
        adapter_detection.reason
    );
    let adapter_selection = crate::adapters::select_layout_adapter(adapter_detection.kind, encrypt);
    if adapter_selection.used_encryption_fallback {
        ui::warn(crate::adapters::CONTENT_ADDRESSED_ENCRYPTION_FALLBACK_WARNING);
    }
    let adapter = adapter_selection.adapter;
    log::debug!(
        "Mount sync adapter dispatch tag={} adapter={}",
        resolved_tag,
        adapter.transport_kind().as_str()
    );
    adapter
        .dispatch(
            || {
                archive::sync_to_remote_archive(
                    api_client,
                    workspace,
                    base_tag,
                    resolved_tag,
                    local_path,
                    verbose,
                    encrypt,
                    recipient,
                    require_server_signature,
                )
            },
            || {
                oci::sync_to_remote_oci(
                    api_client,
                    workspace,
                    base_tag,
                    resolved_tag,
                    local_path,
                    verbose,
                    require_server_signature,
                )
            },
            || {
                file::sync_to_remote_file(
                    api_client,
                    workspace,
                    base_tag,
                    resolved_tag,
                    local_path,
                    verbose,
                    adapter_detection.kind,
                    require_server_signature,
                )
            },
        )
        .await
}

#[cfg(test)]
mod tests {
    use super::archive::initial_restore_archive;
    use super::oci::local_oci_manifest_digest;
    use super::*;
    use crate::api::models::cache::ManifestCheckResult;
    use crate::command_support::save_support::archive_cache_root_digest;
    use crate::{archive, encryption, manifest, test_env};
    use chrono::Utc;
    use mockito::Server;
    use std::fs;

    #[test]
    fn manifest_check_ready_requires_non_pending_status() {
        let result = ManifestCheckResult {
            tag: "test-tag".to_string(),
            exists: true,
            pending: false,
            manifest_root_digest: None,
            cache_entry_id: None,
            content_hash: None,
            manifest_digest: None,
            manifest_url: None,
            compression_algorithm: None,
            archive_urls: Vec::new(),
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            status: Some("pending".to_string()),
            error: None,
        };

        assert!(!manifest_check_is_ready(&result));
        assert!(manifest_check_is_pending(&result));
    }

    #[test]
    fn manifest_check_pending_flag_blocks_ready_classification() {
        let result = ManifestCheckResult {
            tag: "test-tag".to_string(),
            exists: true,
            pending: true,
            manifest_root_digest: None,
            cache_entry_id: None,
            content_hash: None,
            manifest_digest: None,
            manifest_url: None,
            compression_algorithm: None,
            archive_urls: Vec::new(),
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            status: Some("hit".to_string()),
            error: None,
        };

        assert!(!manifest_check_is_ready(&result));
        assert!(manifest_check_is_pending(&result));
    }

    #[test]
    fn manifest_check_ready_accepts_ready_hit() {
        let result = ManifestCheckResult {
            tag: "test-tag".to_string(),
            exists: true,
            pending: false,
            manifest_root_digest: None,
            cache_entry_id: None,
            content_hash: None,
            manifest_digest: None,
            manifest_url: None,
            compression_algorithm: None,
            archive_urls: Vec::new(),
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            status: Some("hit".to_string()),
            error: None,
        };

        assert!(manifest_check_is_ready(&result));
        assert!(!manifest_check_is_pending(&result));
    }

    #[test]
    fn local_oci_manifest_digest_returns_none_for_non_oci_layout() {
        let temp_dir = tempfile::tempdir().unwrap();
        std::fs::write(temp_dir.path().join("file.txt"), b"hello").unwrap();

        let digest = local_oci_manifest_digest(temp_dir.path()).unwrap();
        assert!(digest.is_none());
    }

    #[test]
    fn local_oci_manifest_digest_matches_pointer_digest() {
        let temp_dir = tempfile::tempdir().unwrap();
        let blobs_dir = temp_dir.path().join("blobs").join("sha256");
        std::fs::create_dir_all(&blobs_dir).unwrap();

        std::fs::write(temp_dir.path().join("index.json"), b"{\"schemaVersion\":2}").unwrap();
        std::fs::write(
            temp_dir.path().join("oci-layout"),
            b"{\"imageLayoutVersion\":\"1.0.0\"}",
        )
        .unwrap();
        std::fs::write(
            blobs_dir.join("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
            b"blob-data",
        )
        .unwrap();

        let digest = local_oci_manifest_digest(temp_dir.path())
            .unwrap()
            .expect("expected digest");

        let scan = crate::cas_oci::scan_layout(temp_dir.path()).unwrap();
        let pointer_bytes = crate::cas_oci::build_pointer(&scan).unwrap();
        let expected = crate::cas_oci::prefixed_sha256_digest(&pointer_bytes);

        assert_eq!(digest, expected);
    }

    #[test]
    fn mount_sync_accepts_confirm_without_winner_switch() {
        let response = crate::api::models::cache::CacheConfirmResponse {
            status: "published".to_string(),
            cache_entry_id: Some("entry-1".to_string()),
            manifest_root_digest: Some("sha256:root".to_string()),
            uploaded_at: None,
            tag: None,
            tag_status: None,
            signature: None,
            signing_public_key: None,
            signed_at: None,
        };

        let publication = MountSyncPublication {
            cache_entry_id: "entry-1",
            manifest_root_digest: "sha256:root",
        };
        ensure_mount_sync_won(publication, &response, "cache-tag").expect("same entry should pass");
    }

    #[test]
    fn mount_sync_rejects_confirm_when_existing_entry_wins() {
        let response = crate::api::models::cache::CacheConfirmResponse {
            status: "published".to_string(),
            cache_entry_id: Some("entry-existing".to_string()),
            manifest_root_digest: Some("sha256:root".to_string()),
            uploaded_at: None,
            tag: None,
            tag_status: None,
            signature: None,
            signing_public_key: None,
            signed_at: None,
        };

        let publication = MountSyncPublication {
            cache_entry_id: "entry-new",
            manifest_root_digest: "sha256:root",
        };
        let error = ensure_mount_sync_won(publication, &response, "cache-tag")
            .expect_err("winner switch should fail");
        assert!(
            error
                .to_string()
                .contains("did not publish the updated entry"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn mount_sync_rejects_confirm_with_unexpected_digest() {
        let response = crate::api::models::cache::CacheConfirmResponse {
            status: "published".to_string(),
            cache_entry_id: Some("entry-new".to_string()),
            manifest_root_digest: Some("sha256:old".to_string()),
            uploaded_at: None,
            tag: None,
            tag_status: None,
            signature: None,
            signing_public_key: None,
            signed_at: None,
        };

        let publication = MountSyncPublication {
            cache_entry_id: "entry-new",
            manifest_root_digest: "sha256:new",
        };
        let error = ensure_mount_sync_won(publication, &response, "cache-tag")
            .expect_err("digest mismatch should fail");
        assert!(
            error.to_string().contains("published unexpected digest"),
            "unexpected error: {error}"
        );
    }

    fn restore_entry_for_mount_visibility(
        status: &str,
        cache_entry_id: Option<&str>,
        manifest_root_digest: Option<&str>,
    ) -> CacheResolutionEntry {
        CacheResolutionEntry {
            tag: "cache-tag".to_string(),
            primary_tag: None,
            signature_tag: None,
            status: status.to_string(),
            cache_entry_id: cache_entry_id.map(str::to_string),
            manifest_url: None,
            manifest_root_digest: manifest_root_digest.map(str::to_string),
            manifest_digest: None,
            compression_algorithm: None,
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            archive_urls: Vec::new(),
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            content_hash: None,
            pending: false,
            error: None,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: false,
        }
    }

    #[test]
    fn mount_sync_visibility_requires_matching_entry_and_digest() {
        let publication = MountSyncPublication {
            cache_entry_id: "entry-new",
            manifest_root_digest: "sha256:new",
        };
        let hit = restore_entry_for_mount_visibility("hit", Some("entry-new"), Some("sha256:new"));

        assert!(mount_sync_visible(&hit, publication));
    }

    #[test]
    fn mount_sync_visibility_rejects_old_restore_result() {
        let publication = MountSyncPublication {
            cache_entry_id: "entry-new",
            manifest_root_digest: "sha256:new",
        };
        let hit = restore_entry_for_mount_visibility("hit", Some("entry-old"), Some("sha256:old"));

        assert!(!mount_sync_visible(&hit, publication));
    }

    #[tokio::test]
    async fn initial_restore_archive_accepts_recipient_scoped_encrypted_local_digest() {
        let _guard = test_env::lock();
        test_env::set_var("BORINGCACHE_API_URL", "https://api.example.com");
        test_env::set_var("BORINGCACHE_API_TOKEN", "test-token-123");

        let temp_dir = tempfile::tempdir().unwrap();
        let source_dir = temp_dir.path().join("data");
        fs::create_dir(&source_dir).unwrap();
        fs::write(source_dir.join("hello.txt"), "hello").unwrap();

        let draft = manifest::ManifestBuilder::new(&source_dir).build().unwrap();
        let content_root_digest = manifest::diff::compute_digest_from_draft(&draft);
        let recipient = "age1recipient-local";
        let scoped_root_digest = archive_cache_root_digest(&content_root_digest, Some(recipient));
        let api_client = crate::api::ApiClient::for_save().unwrap();
        let hit = crate::api::models::cache::CacheResolutionEntry {
            tag: "cache-tag".to_string(),
            primary_tag: None,
            signature_tag: None,
            status: "hit".to_string(),
            cache_entry_id: Some("123".to_string()),
            manifest_url: None,
            manifest_root_digest: Some(scoped_root_digest),
            manifest_digest: None,
            compression_algorithm: Some("zstd".to_string()),
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            archive_urls: Vec::new(),
            size: None,
            uncompressed_size: None,
            compressed_size: None,
            uploaded_at: None,
            content_hash: None,
            pending: false,
            error: None,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: true,
        };

        let result = initial_restore_archive(
            &api_client,
            &hit,
            &source_dir,
            false,
            false,
            Some(recipient.to_string()),
            None,
            Arc::new(Mutex::new(encryption::PassphraseCache::default())),
            false,
        )
        .await
        .unwrap();

        assert!(matches!(result, RestoreAction::AlreadyInSync));

        test_env::remove_var("BORINGCACHE_API_TOKEN");
        test_env::remove_var("BORINGCACHE_API_URL");
    }

    #[tokio::test]
    async fn initial_restore_archive_extracts_encrypted_archive() {
        let _guard = test_env::lock();
        test_env::set_var("BORINGCACHE_TEST_MODE", "1");

        let mut server = Server::new_async().await;
        test_env::set_var("BORINGCACHE_API_URL", server.url());
        test_env::set_var("BORINGCACHE_API_TOKEN", "test-token-123");

        let temp_dir = tempfile::tempdir().unwrap();
        let source_dir = temp_dir.path().join("data");
        fs::create_dir(&source_dir).unwrap();
        fs::write(source_dir.join("hello.txt"), "hello").unwrap();

        let (identity, recipient) = encryption::generate_keypair();
        let identity_path = temp_dir.path().join("age-identity.txt");
        encryption::save_identity(&identity, &identity_path).unwrap();

        let draft = manifest::ManifestBuilder::new(&source_dir).build().unwrap();
        let root_digest = manifest::diff::compute_digest_from_draft(&draft);
        let archive_info =
            archive::create_tar_archive(&draft, source_dir.to_str().unwrap(), false, None)
                .await
                .unwrap();
        let archive_bytes = fs::read(&archive_info.archive_path).unwrap();

        let file_count = archive_info.manifest_files.len() as u64;
        let manifest_doc = manifest::Manifest {
            format_version: 1,
            tag: "cache-tag".to_string(),
            root: manifest::ManifestRoot {
                digest: root_digest.clone(),
                algo: "sha256".to_string(),
            },
            summary: manifest::ManifestSummary {
                file_count,
                raw_size: archive_info.uncompressed_size,
                changed_count: file_count,
                removed_count: 0,
            },
            entry: None,
            archive: None,
            files: archive_info.manifest_files.clone(),
            encryption: Some(manifest::EncryptionMetadata {
                algorithm: encryption::ENCRYPTION_ALGORITHM_AGE_X25519.to_string(),
                recipient_hint: Some(encryption::recipient_hint(&recipient.to_string())),
                encrypted_at: Utc::now(),
            }),
            signature: None,
        };

        let manifest_cbor = manifest::io::encode_manifest(&manifest_doc).unwrap();
        let manifest_bytes = manifest::io::compress_manifest(&manifest_cbor).unwrap();
        let manifest_encrypted = encryption::encrypt_data(&manifest_bytes, &recipient).unwrap();
        let archive_encrypted = encryption::encrypt_data(&archive_bytes, &recipient).unwrap();

        let manifest_url = format!("{}/manifest", server.url());
        let archive_url = format!("{}/archive", server.url());

        let _manifest_mock = server
            .mock("GET", "/manifest")
            .with_status(200)
            .with_header("content-type", "application/octet-stream")
            .with_body(manifest_encrypted)
            .create_async()
            .await;

        let archive_len = archive_encrypted.len().to_string();
        let _archive_head_mock = server
            .mock("HEAD", "/archive")
            .with_status(200)
            .with_header("content-length", archive_len.as_str())
            .create_async()
            .await;

        let archive_encrypted_len = archive_encrypted.len() as u64;
        let _archive_get_mock = server
            .mock("GET", "/archive")
            .with_status(200)
            .with_header("content-length", archive_len.as_str())
            .with_body(archive_encrypted)
            .create_async()
            .await;

        let api_client = crate::api::ApiClient::for_save().unwrap();
        let hit = crate::api::models::cache::CacheResolutionEntry {
            tag: "cache-tag".to_string(),
            primary_tag: None,
            signature_tag: None,
            status: "hit".to_string(),
            cache_entry_id: Some("123".to_string()),
            manifest_url: Some(manifest_url),
            manifest_root_digest: Some(root_digest),
            manifest_digest: None,
            compression_algorithm: Some("zstd".to_string()),
            storage_mode: None,
            blob_count: None,
            blob_total_size_bytes: None,
            cas_layout: None,
            archive_urls: vec![archive_url],
            size: Some(archive_info.compressed_size),
            uncompressed_size: Some(archive_info.uncompressed_size),
            compressed_size: Some(archive_encrypted_len),
            uploaded_at: None,
            content_hash: None,
            pending: false,
            error: None,
            workspace_signing_public_key: None,
            server_signature: None,
            server_signed_at: None,
            encrypted: true,
        };

        let target_dir = temp_dir.path().join("mount-target");
        let result = initial_restore_archive(
            &api_client,
            &hit,
            &target_dir,
            false,
            false,
            Some(recipient.to_string()),
            Some(identity_path.to_string_lossy().into_owned()),
            Arc::new(Mutex::new(encryption::PassphraseCache::default())),
            false,
        )
        .await
        .unwrap();

        assert!(matches!(result, RestoreAction::Downloaded));
        assert_eq!(
            fs::read_to_string(target_dir.join("hello.txt")).unwrap(),
            "hello"
        );

        test_env::remove_var("BORINGCACHE_API_TOKEN");
        test_env::remove_var("BORINGCACHE_API_URL");
        test_env::remove_var("BORINGCACHE_TEST_MODE");
    }
}
