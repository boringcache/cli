use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Result, anyhow};
use tokio::sync::oneshot;

use crate::observability::{self, ObservabilityEvent};
use crate::serve::cache_registry;
use crate::serve::state::{AppState, build_cache_session_summary};

const KV_SHUTDOWN_FLUSH_TIMEOUT_SECS_ENV: &str = "BORINGCACHE_KV_SHUTDOWN_FLUSH_TIMEOUT_SECS";
const DEFAULT_KV_SHUTDOWN_FLUSH_TIMEOUT_SECS: u64 = 180;

fn kv_shutdown_flush_timeout() -> std::time::Duration {
    std::env::var(KV_SHUTDOWN_FLUSH_TIMEOUT_SECS_ENV)
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .map(std::time::Duration::from_secs)
        .unwrap_or_else(|| std::time::Duration::from_secs(DEFAULT_KV_SHUTDOWN_FLUSH_TIMEOUT_SECS))
}

pub(super) fn emit_cache_session_summary(state: &AppState) {
    let summary = build_cache_session_summary(state);

    observability::emit(ObservabilityEvent::cache_session_summary(
        state.workspace.clone(),
        summary.mode,
        summary.adapter,
        summary.duration_ms,
        summary.proxy,
        summary.backend_api,
        summary.rails,
        summary.storage,
        summary.lifecycle,
        summary.oci,
        summary.startup_prefetch,
        summary.kv_upload,
        summary.singleflight,
        summary.kv_lookup,
        summary.local_cache,
        summary.buildkit,
        summary.native_tool,
        summary.classification,
    ));
    observability::flush_for(std::time::Duration::from_secs(2));
    eprintln!(
        "BoringCache proxy summary workspace={} mode={} adapter={} duration={}s",
        summary.workspace,
        summary.mode,
        summary.adapter,
        summary.duration_ms / 1000
    );
}

pub(super) async fn cleanup_runtime_temp_dir(state: &AppState) {
    if let Err(error) = tokio::fs::remove_dir_all(&state.runtime_temp_dir).await
        && error.kind() != std::io::ErrorKind::NotFound
    {
        log::warn!(
            "Failed to clean runtime temp dir {}: {error}",
            state.runtime_temp_dir.display()
        );
    }
}

pub(super) async fn flush_pending_on_shutdown(state: &AppState) -> Result<()> {
    let timeout = kv_shutdown_flush_timeout();
    let deadline = std::time::Instant::now() + timeout;

    loop {
        let pending_entries = {
            let pending = state.kv_pending.read().await;
            pending.entry_count()
        };
        if pending_entries == 0 {
            {
                let _running_flush = state.kv_flush_lock.lock().await;
            }

            let pending_after_flush = {
                let pending = state.kv_pending.read().await;
                pending.entry_count()
            };
            if pending_after_flush == 0 {
                break;
            } else {
                continue;
            }
        }

        let flush_guard = cache_registry::try_schedule_flush(state);
        match flush_guard {
            Some(_flush_guard) => {
                let flush_result = cache_registry::flush_kv_index_on_shutdown(state).await;
                match flush_result {
                    cache_registry::FlushResult::Ok | cache_registry::FlushResult::Permanent => {
                        let mut gate = state.kv_next_flush_at.write().await;
                        *gate = None;
                        if matches!(flush_result, cache_registry::FlushResult::Permanent)
                            && state.fail_on_cache_error
                        {
                            return Err(anyhow!(
                                "Shutdown: cache publish failed permanently; see proxy log for the backend error"
                            ));
                        }
                    }
                    cache_registry::FlushResult::Conflict | cache_registry::FlushResult::Error => {
                        let mut gate = state.kv_next_flush_at.write().await;
                        *gate = None;
                    }
                }
            }
            None => {
                let _running_flush = state.kv_flush_lock.lock().await;
            }
        }

        if pending_entries_empty(state).await {
            break;
        }

        if std::time::Instant::now() >= deadline {
            let pending_entries = {
                let pending = state.kv_pending.read().await;
                pending.entry_count()
            };
            if pending_entries == 0 {
                break;
            }
            let message = format!(
                "Shutdown: flush timeout reached after {}s with {pending_entries} pending entries remaining",
                timeout.as_secs()
            );
            eprintln!("{message}");
            if state.fail_on_cache_error {
                return Err(anyhow!(message));
            }
            break;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    publish_current_kv_version_on_shutdown(state).await;
    super::maintenance::flush_cache_ops_on_shutdown(state).await;
    Ok(())
}

async fn pending_entries_empty(state: &AppState) -> bool {
    let pending_entries = {
        let pending = state.kv_pending.read().await;
        pending.entry_count()
    };
    pending_entries == 0
}

async fn publish_current_kv_version_on_shutdown(state: &AppState) {
    if state.read_only {
        return;
    }

    let entries = state.kv_active_set_snapshot();
    if entries.is_empty() {
        return;
    }

    for tag in cache_registry::kv_visibility_tags(state) {
        match state
            .api_client
            .publish_cache_kv_current_version(&state.workspace, &tag, &entries)
            .await
        {
            Ok(Some(response)) => {
                if crate::serve::state::diagnostics_enabled() {
                    eprintln!(
                        "KV current version: tag={} published version={} marked={} requested={} missing={}",
                        tag,
                        response
                            .current_kv_version
                            .map(|version| version.to_string())
                            .unwrap_or_else(|| "none".to_string()),
                        response.marked_count,
                        response.requested_count,
                        response.missing_count,
                    );
                }
                if response.missing_count > 0 {
                    log::warn!(
                        "KV current version publish for tag {} missed {} active keys",
                        tag,
                        response.missing_count
                    );
                }
            }
            Ok(None) => {}
            Err(error) => {
                log::warn!("KV current version publish for tag {tag} failed: {error}");
            }
        }
    }
}

pub(super) async fn shutdown_signal(shutdown_requested: Arc<AtomicBool>) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            log::warn!("Failed to install Ctrl+C handler: {error}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                log::warn!("Failed to install SIGTERM handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    shutdown_requested.store(true, Ordering::Release);
    eprintln!("\nShutting down...");
}

pub(super) async fn shutdown_signal_with_channel(
    mut shutdown_rx: oneshot::Receiver<()>,
    shutdown_requested: Arc<AtomicBool>,
) {
    let ctrl_c = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            log::warn!("Failed to install Ctrl+C handler: {error}");
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                log::warn!("Failed to install SIGTERM handler: {error}");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
        _ = &mut shutdown_rx => {},
    }

    shutdown_requested.store(true, Ordering::Release);
    eprintln!("\nShutting down...");
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::api::client::ApiClient;
    use crate::api::models::cache::BlobDescriptor;
    use crate::cas_file;
    use crate::git::GitContext;
    use crate::tag_utils::TagResolver;
    use crate::test_env;
    use mockito::{Matcher, Server};
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::ffi::{OsStr, OsString};

    struct EnvVarGuard {
        key: &'static str,
        original: Option<OsString>,
    }

    impl EnvVarGuard {
        fn new(key: &'static str) -> Self {
            Self {
                key,
                original: std::env::var_os(key),
            }
        }

        fn set<V>(&self, value: V)
        where
            V: AsRef<OsStr>,
        {
            test_env::set_var(self.key, value);
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(ref value) = self.original {
                test_env::set_var(self.key, value);
            } else {
                test_env::remove_var(self.key);
            }
        }
    }

    #[tokio::test]
    async fn strict_shutdown_returns_error_on_permanent_kv_flush_failure() {
        let mut server = Server::new_async().await;
        let _guard = test_env::lock();
        let temp_home = tempfile::tempdir().expect("temp home");
        let home_env = EnvVarGuard::new("HOME");
        let api_url_env = EnvVarGuard::new("BORINGCACHE_API_URL");
        let auth_token_env = EnvVarGuard::new("BORINGCACHE_AUTH_TOKEN");
        let test_mode_env = EnvVarGuard::new("BORINGCACHE_TEST_MODE");
        home_env.set(temp_home.path());
        api_url_env.set(server.url());
        auth_token_env.set("test-token");
        test_mode_env.set("1");

        let api_client =
            ApiClient::new_with_token_override(Some("test-token".to_string())).expect("client");
        let (state, _listener, _replication_rx) = super::super::listener::build_server_runtime(
            api_client,
            "org/repo".to_string(),
            "127.0.0.1".to_string(),
            0,
            TagResolver::new(None, GitContext::default(), false),
            Vec::new(),
            "registry".to_string(),
            vec!["registry".to_string()],
            Vec::new(),
            BTreeMap::new(),
            false,
            crate::serve::OciHydrationPolicy::MetadataOnly,
            true,
            false,
        )
        .await
        .expect("server runtime");

        let payload = b"strict-shutdown-permanent-failure";
        let digest = cas_file::prefixed_sha256_digest(payload);
        let blob_path = state.kv_blob_temp_dir.join("strict-shutdown-blob");
        tokio::fs::write(&blob_path, payload)
            .await
            .expect("pending blob");
        {
            let mut pending = state.kv_pending.write().await;
            pending.insert(
                "bazel_cas/strict-shutdown".to_string(),
                BlobDescriptor {
                    digest: digest.clone(),
                    size_bytes: payload.len() as u64,
                },
                blob_path,
            );
        }

        let blob_stage_mock = server
            .mock("POST", "/v2/workspaces/org/repo/caches/blobs/stage")
            .expect(1)
            .match_body(Matcher::PartialJson(json!({
                "blobs": [{ "digest": digest, "size_bytes": payload.len() }]
            })))
            .with_status(422)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "success": false,
                    "error": "blob upload receipt required"
                })
                .to_string(),
            )
            .create_async()
            .await;

        let error = flush_pending_on_shutdown(&state)
            .await
            .expect_err("strict shutdown should fail on permanent flush failure");

        assert!(
            error
                .to_string()
                .contains("cache publish failed permanently"),
            "{error:#}"
        );
        assert_eq!(state.kv_pending.read().await.entry_count(), 1);
        blob_stage_mock.assert_async().await;
        cleanup_runtime_temp_dir(&state).await;
    }

    #[tokio::test]
    async fn shutdown_current_version_publish_uses_active_kv_set() {
        let mut server = Server::new_async().await;
        let _guard = test_env::lock();
        let temp_home = tempfile::tempdir().expect("temp home");
        let home_env = EnvVarGuard::new("HOME");
        let api_url_env = EnvVarGuard::new("BORINGCACHE_API_URL");
        let auth_token_env = EnvVarGuard::new("BORINGCACHE_AUTH_TOKEN");
        let test_mode_env = EnvVarGuard::new("BORINGCACHE_TEST_MODE");
        home_env.set(temp_home.path());
        api_url_env.set(server.url());
        auth_token_env.set("test-token");
        test_mode_env.set("1");

        let api_client =
            ApiClient::new_with_token_override(Some("test-token".to_string())).expect("client");
        let (state, _listener, _replication_rx) = super::super::listener::build_server_runtime(
            api_client,
            "org/repo".to_string(),
            "127.0.0.1".to_string(),
            0,
            TagResolver::new(None, GitContext::default(), false),
            Vec::new(),
            "registry".to_string(),
            vec!["registry".to_string()],
            Vec::new(),
            BTreeMap::new(),
            false,
            crate::serve::OciHydrationPolicy::MetadataOnly,
            true,
            false,
        )
        .await
        .expect("server runtime");

        state.record_kv_active_key("sccache", "sccache/hot");

        let capabilities_mock = server
            .mock("GET", "/v2/capabilities")
            .expect(1)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "api_version": "v2",
                    "features": {
                        "cache_kv_entries_v1": true,
                        "cache_kv_entries_current_version_v1": true
                    }
                })
                .to_string(),
            )
            .create_async()
            .await;
        let publish_mock = server
            .mock(
                "POST",
                "/v2/workspaces/org/repo/cache-kv-entries/current-version",
            )
            .expect(1)
            .match_body(Matcher::PartialJson(json!({
                "tag": "registry",
                "entries": [
                    { "namespace": "sccache", "scoped_key": "sccache/hot" }
                ]
            })))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                json!({
                    "response_type": "current_version",
                    "current_kv_version": 1,
                    "requested_count": 1,
                    "marked_count": 1,
                    "missing_count": 0,
                    "missing": []
                })
                .to_string(),
            )
            .create_async()
            .await;

        publish_current_kv_version_on_shutdown(&state).await;

        capabilities_mock.assert_async().await;
        publish_mock.assert_async().await;
        cleanup_runtime_temp_dir(&state).await;
    }

    #[test]
    fn kv_shutdown_flush_timeout_uses_default_and_env_override() {
        let _guard = test_env::lock();
        test_env::remove_var(KV_SHUTDOWN_FLUSH_TIMEOUT_SECS_ENV);
        assert_eq!(
            kv_shutdown_flush_timeout(),
            std::time::Duration::from_secs(DEFAULT_KV_SHUTDOWN_FLUSH_TIMEOUT_SECS)
        );

        test_env::set_var(KV_SHUTDOWN_FLUSH_TIMEOUT_SECS_ENV, "42");
        assert_eq!(
            kv_shutdown_flush_timeout(),
            std::time::Duration::from_secs(42)
        );

        test_env::remove_var(KV_SHUTDOWN_FLUSH_TIMEOUT_SECS_ENV);
    }
}
