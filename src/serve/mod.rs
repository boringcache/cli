pub mod cache_registry;
pub mod error;
pub mod handlers;
pub mod routes;
pub mod state;

use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::api::client::ApiClient;
use crate::serve::state::{
    AppState, BlobLocatorCache, KvPendingStore, KvPublishedIndex, UploadSessionStore,
};
use crate::tag_utils::TagResolver;

pub async fn run_server(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
    registry_root_tag: String,
) -> Result<()> {
    let state = AppState {
        api_client,
        workspace: workspace.clone(),
        tag_resolver,
        configured_human_tags,
        registry_root_tag,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
        kv_pending: Arc::new(RwLock::new(KvPendingStore::default())),
        kv_flush_lock: Arc::new(tokio::sync::Mutex::new(())),
        kv_last_put: Arc::new(RwLock::new(None)),
        kv_published_index: Arc::new(RwLock::new(KvPublishedIndex::default())),
    };

    let router = routes::build_router(state.clone());
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await?;

    eprintln!("BoringCache cache registry proxy listening on {addr}");
    eprintln!("  Workspace: {workspace}");
    if !state.configured_human_tags.is_empty() {
        eprintln!(
            "  OCI Human Tag Aliases: {}",
            state.configured_human_tags.join(", ")
        );
    }
    eprintln!("  Registry Root Tag: {}", state.registry_root_tag);
    eprintln!("  OCI: --cache-from/--cache-to type=registry,ref={host}:{port}/CACHE_NAME:TAG");
    eprintln!("  Bazel HTTP: http://{host}:{port}/ac/{{sha256}} and /cas/{{sha256}}");
    eprintln!("  Gradle HTTP: http://{host}:{port}/cache/{{cache-key}}");
    eprintln!("  Turborepo: http://{host}:{port}/v8/artifacts/{{hash}}");
    eprintln!("  sccache WebDAV: http://{host}:{port}/<prefix>/a/b/c/<key>");

    let preload_state = state.clone();
    tokio::spawn(async move {
        cache_registry::preload_kv_index(&preload_state).await;
    });

    let upload_sessions = state.upload_sessions.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            let expired = {
                let mut sessions = upload_sessions.write().await;
                sessions.cleanup_expired(std::time::Duration::from_secs(1800))
            };
            for session in expired {
                let _ = tokio::fs::remove_file(&session.temp_path).await;
            }
        }
    });

    let flush_state = state.clone();
    tokio::spawn(async move {
        use crate::serve::state::{FLUSH_BLOB_THRESHOLD, FLUSH_SIZE_THRESHOLD};
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.tick().await;
        loop {
            interval.tick().await;

            let should_flush = {
                let pending = flush_state.kv_pending.read().await;
                if pending.is_empty() {
                    false
                } else if pending.blob_count() >= FLUSH_BLOB_THRESHOLD
                    || pending.total_spool_bytes() >= FLUSH_SIZE_THRESHOLD
                {
                    true
                } else {
                    let last_put = flush_state.kv_last_put.read().await;
                    last_put
                        .map(|t| t.elapsed() >= std::time::Duration::from_secs(10))
                        .unwrap_or(false)
                }
            };

            if should_flush {
                cache_registry::flush_kv_index(&flush_state).await;
            }
        }
    });

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    cache_registry::flush_kv_index(&state).await;

    Ok(())
}

async fn shutdown_signal() {
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

    eprintln!("\nShutting down...");
}
