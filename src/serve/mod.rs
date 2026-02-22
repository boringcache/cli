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
        kv_lookup_lock: Arc::new(tokio::sync::Mutex::new(())),
        kv_last_put: Arc::new(RwLock::new(None)),
        kv_next_flush_at: Arc::new(RwLock::new(None)),
        kv_flush_scheduled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        kv_published_index: Arc::new(RwLock::new(KvPublishedIndex::default())),
        kv_recent_misses: Arc::new(RwLock::new(std::collections::HashMap::new())),
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

    for dir_name in ["boringcache-kv-blobs", "boringcache-uploads"] {
        let stale_dir = std::env::temp_dir().join(dir_name);
        if stale_dir.exists() {
            let _ = tokio::fs::remove_dir_all(&stale_dir).await;
        }
    }

    cache_registry::preload_kv_index(&state).await;

    let refresh_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
        interval.tick().await;
        loop {
            interval.tick().await;
            cache_registry::refresh_kv_index(&refresh_state).await;
        }
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
        use rand::Rng;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
        interval.tick().await;
        let mut consecutive_failures: u32 = 0;
        loop {
            interval.tick().await;

            {
                let gate = flush_state.kv_next_flush_at.read().await;
                if let Some(next) = *gate {
                    if std::time::Instant::now() < next {
                        continue;
                    }
                }
            }

            if consecutive_failures > 0 {
                let base_secs: u64 = match consecutive_failures {
                    1 => 2,
                    2 => 5,
                    3 => 15,
                    4 => 30,
                    _ => 60,
                };
                let jitter_ms: u64 = rand::thread_rng().gen_range(0..3000);
                tokio::time::sleep(std::time::Duration::from_millis(
                    base_secs * 1000 + jitter_ms,
                ))
                .await;
            }

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
                let Some(_flush_guard) = cache_registry::try_schedule_flush(&flush_state) else {
                    continue;
                };
                match cache_registry::flush_kv_index(&flush_state).await {
                    cache_registry::FlushResult::Ok => {
                        consecutive_failures = 0;
                        let mut gate = flush_state.kv_next_flush_at.write().await;
                        *gate = None;
                    }
                    cache_registry::FlushResult::Conflict => {}
                    cache_registry::FlushResult::Error => {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                    }
                    cache_registry::FlushResult::Permanent => {
                        consecutive_failures = 0;
                        let mut gate = flush_state.kv_next_flush_at.write().await;
                        *gate = None;
                    }
                }
            }
        }
    });

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    if let Some(_flush_guard) = cache_registry::try_schedule_flush(&state) {
        eprintln!("Shutdown: flushing pending KV entries");
        cache_registry::flush_kv_index(&state).await;
    } else {
        eprintln!("Shutdown: waiting for in-flight KV flush");
        let _running_flush = state.kv_flush_lock.lock().await;
        drop(_running_flush);
        if let Some(_flush_guard) = cache_registry::try_schedule_flush(&state) {
            eprintln!("Shutdown: running follow-up KV flush");
            cache_registry::flush_kv_index(&state).await;
        }
    }

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
