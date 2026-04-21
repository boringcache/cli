mod listener;
mod maintenance;
mod shutdown;

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::{Notify, RwLock, oneshot};

use crate::api::client::ApiClient;
use crate::serve::http::routes;
use crate::serve::state::AppState;
use crate::tag_utils::TagResolver;

pub struct ServeHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<Result<()>>,
    shutdown_requested: Arc<AtomicBool>,
    ready: Arc<AtomicBool>,
    ready_notify: Arc<Notify>,
    prefetch_error: Arc<RwLock<Option<String>>>,
    pub port: u16,
}

impl ServeHandle {
    pub fn is_finished(&self) -> bool {
        self.server_task.is_finished()
    }

    pub(crate) fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub(crate) fn ready_notification(&self) -> tokio::sync::futures::Notified<'_> {
        self.ready_notify.notified()
    }

    pub(crate) async fn prefetch_error_message(&self) -> Option<String> {
        self.prefetch_error.read().await.clone()
    }

    pub async fn shutdown_and_flush(mut self) -> Result<()> {
        self.shutdown_requested.store(true, Ordering::Release);
        if let Some(shutdown_tx) = self.shutdown_tx.take() {
            let _ = shutdown_tx.send(());
        }

        self.server_task
            .await
            .context("Cache registry server task panicked")??;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run_server(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
    registry_root_tag: String,
    oci_alias_promotion_refs: Vec<String>,
    proxy_metadata_hints: BTreeMap<String, String>,
    startup_warm: bool,
    oci_prefetch_refs: Vec<(String, String)>,
    oci_hydration_policy: crate::serve::OciHydrationPolicy,
    fail_on_cache_error: bool,
    read_only: bool,
    ready_file: Option<PathBuf>,
) -> Result<()> {
    let (state, listener, replication_rx) = listener::build_server_runtime(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        oci_alias_promotion_refs,
        proxy_metadata_hints,
        startup_warm,
        oci_hydration_policy,
        fail_on_cache_error,
        read_only,
    )
    .await?;

    maintenance::spawn_maintenance_tasks(&state, replication_rx);
    spawn_startup_prefetch(
        &state,
        startup_warm,
        oci_prefetch_refs,
        oci_hydration_policy,
    );
    spawn_ready_file_marker(
        state.prefetch_complete.clone(),
        state.prefetch_complete_notify.clone(),
        ready_file,
    );

    let router = routes::build_router(state.clone());
    listener::serve_router(
        listener,
        router,
        shutdown::shutdown_signal(state.shutdown_requested.clone()),
    )
    .await?;

    eprintln!("Shutdown: flushing pending KV entries");
    shutdown::flush_pending_on_shutdown(&state).await;
    shutdown::emit_cache_session_summary(&state);
    shutdown::cleanup_runtime_temp_dir(&state).await;

    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn start_server_background(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
    registry_root_tag: String,
    oci_alias_promotion_refs: Vec<String>,
    proxy_metadata_hints: BTreeMap<String, String>,
    startup_warm: bool,
    oci_prefetch_refs: Vec<(String, String)>,
    oci_hydration_policy: crate::serve::OciHydrationPolicy,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<ServeHandle> {
    let (state, listener, replication_rx) = listener::build_server_runtime(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        oci_alias_promotion_refs,
        proxy_metadata_hints,
        startup_warm,
        oci_hydration_policy,
        fail_on_cache_error,
        read_only,
    )
    .await?;

    maintenance::spawn_maintenance_tasks(&state, replication_rx);
    spawn_startup_prefetch(
        &state,
        startup_warm,
        oci_prefetch_refs,
        oci_hydration_policy,
    );

    let router = routes::build_router(state.clone());
    let bound_port = listener
        .local_addr()
        .context("Failed to determine proxy port")?
        .port();

    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let shutdown_requested = state.shutdown_requested.clone();
    let shutdown_handle_flag = state.shutdown_requested.clone();
    let server_state = state.clone();
    let server_task = tokio::spawn(async move {
        listener::serve_router(
            listener,
            router,
            shutdown::shutdown_signal_with_channel(shutdown_rx, shutdown_requested),
        )
        .await?;

        eprintln!("Shutdown: flushing pending KV entries");
        shutdown::flush_pending_on_shutdown(&server_state).await;
        shutdown::emit_cache_session_summary(&server_state);
        shutdown::cleanup_runtime_temp_dir(&server_state).await;
        Ok(())
    });

    Ok(ServeHandle {
        shutdown_tx: Some(shutdown_tx),
        server_task,
        shutdown_requested: shutdown_handle_flag,
        ready: state.prefetch_complete.clone(),
        ready_notify: state.prefetch_complete_notify.clone(),
        prefetch_error: state.prefetch_error.clone(),
        port: bound_port,
    })
}

fn spawn_startup_prefetch(
    state: &AppState,
    startup_warm: bool,
    oci_prefetch_refs: Vec<(String, String)>,
    oci_hydration_policy: crate::serve::OciHydrationPolicy,
) {
    if !startup_warm {
        return;
    }

    let prefetch_state = state.clone();
    tokio::spawn(async move {
        let timeout = crate::serve::cache_registry::KV_PREFETCH_READINESS_TIMEOUT
            .saturating_sub(std::time::Duration::from_secs(5));
        if tokio::time::timeout(
            timeout,
            crate::serve::cache_registry::prefetch_manifest_blobs(
                &prefetch_state,
                startup_warm,
                oci_prefetch_refs,
                oci_hydration_policy,
            ),
        )
        .await
        .is_err()
        {
            let message = format!("Startup warmup timed out after {}s", timeout.as_secs());
            prefetch_state.prefetch_metrics.record_startup_timeout();
            log::warn!("{message}");
            eprintln!("Prefetch: {message}; serving remaining blobs on demand");
        }
        prefetch_state
            .prefetch_complete
            .store(true, Ordering::Release);
        prefetch_state.prefetch_complete_notify.notify_waiters();
    });
}

fn spawn_ready_file_marker(
    ready: Arc<AtomicBool>,
    ready_notify: Arc<Notify>,
    ready_file: Option<PathBuf>,
) {
    let Some(ready_file) = ready_file else {
        return;
    };

    tokio::spawn(async move {
        if let Some(parent) = ready_file.parent()
            && !parent.as_os_str().is_empty()
            && let Err(error) = tokio::fs::create_dir_all(parent).await
        {
            eprintln!(
                "Failed to create cache-registry ready-file directory {}: {error:#}",
                parent.display()
            );
            return;
        }

        match tokio::fs::remove_file(&ready_file).await {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                eprintln!(
                    "Failed to clear cache-registry ready-file {}: {error:#}",
                    ready_file.display()
                );
                return;
            }
        }

        if !ready.load(Ordering::Acquire) {
            let notified = ready_notify.notified();
            if !ready.load(Ordering::Acquire) {
                notified.await;
                if !ready.load(Ordering::Acquire) {
                    return;
                }
            }
        }

        if let Err(error) = tokio::fs::write(&ready_file, b"ready\n").await {
            eprintln!(
                "Failed to write cache-registry ready-file {}: {error:#}",
                ready_file.display()
            );
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ready_file_marker_waits_for_readiness() {
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let ready_file = temp_dir.path().join("proxy-ready");
        let ready = Arc::new(AtomicBool::new(false));
        let ready_notify = Arc::new(Notify::new());

        spawn_ready_file_marker(
            ready.clone(),
            ready_notify.clone(),
            Some(ready_file.clone()),
        );

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(
            tokio::fs::metadata(&ready_file).await.is_err(),
            "ready marker should not be written before readiness"
        );

        ready.store(true, Ordering::Release);
        ready_notify.notify_waiters();

        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if tokio::fs::metadata(&ready_file).await.is_ok() {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("ready marker should be written");

        assert_eq!(
            tokio::fs::read_to_string(&ready_file)
                .await
                .expect("read ready marker"),
            "ready\n"
        );
    }
}
