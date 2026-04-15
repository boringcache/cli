mod listener;
mod maintenance;
mod shutdown;

use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::oneshot;

use crate::api::client::ApiClient;
use crate::serve::http::routes;
use crate::serve::state::AppState;
use crate::tag_utils::TagResolver;

pub struct ServeHandle {
    shutdown_tx: Option<oneshot::Sender<()>>,
    server_task: tokio::task::JoinHandle<Result<()>>,
    shutdown_requested: Arc<AtomicBool>,
    pub port: u16,
}

impl ServeHandle {
    pub fn is_finished(&self) -> bool {
        self.server_task.is_finished()
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
    proxy_metadata_hints: BTreeMap<String, String>,
    startup_warm: bool,
    fail_on_cache_error: bool,
    read_only: bool,
) -> Result<()> {
    let (state, listener, replication_rx) = listener::build_server_runtime(
        api_client,
        workspace,
        host,
        port,
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        proxy_metadata_hints,
        startup_warm,
        fail_on_cache_error,
        read_only,
    )
    .await?;

    maintenance::spawn_maintenance_tasks(&state, replication_rx);
    spawn_startup_prefetch(&state);

    let router = routes::build_router(state.clone());
    listener::serve_router(
        listener,
        router,
        shutdown::shutdown_signal(state.shutdown_requested.clone()),
    )
    .await?;

    eprintln!("Shutdown: flushing pending KV entries");
    shutdown::flush_pending_on_shutdown(&state).await;
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
    proxy_metadata_hints: BTreeMap<String, String>,
    startup_warm: bool,
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
        proxy_metadata_hints,
        startup_warm,
        fail_on_cache_error,
        read_only,
    )
    .await?;

    maintenance::spawn_maintenance_tasks(&state, replication_rx);
    spawn_startup_prefetch(&state);

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
        shutdown::cleanup_runtime_temp_dir(&server_state).await;
        Ok(())
    });

    Ok(ServeHandle {
        shutdown_tx: Some(shutdown_tx),
        server_task,
        shutdown_requested: shutdown_handle_flag,
        port: bound_port,
    })
}

fn spawn_startup_prefetch(state: &AppState) {
    let prefetch_state = state.clone();
    tokio::spawn(async move {
        crate::serve::cache_registry::prefetch_manifest_blobs(&prefetch_state).await;
        prefetch_state
            .prefetch_complete
            .store(true, Ordering::Release);
        prefetch_state.prefetch_complete_notify.notify_waiters();
    });
}
