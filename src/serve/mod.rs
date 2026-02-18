pub mod error;
pub mod handlers;
pub mod routes;
pub mod state;

use anyhow::Result;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::api::client::ApiClient;
use crate::serve::state::{AppState, BlobLocatorCache, UploadSessionStore};
use crate::tag_utils::TagResolver;

pub async fn run_server(
    api_client: ApiClient,
    workspace: String,
    host: String,
    port: u16,
    tag_resolver: TagResolver,
    configured_human_tags: Vec<String>,
) -> Result<()> {
    let state = AppState {
        api_client,
        workspace: workspace.clone(),
        tag_resolver,
        configured_human_tags,
        blob_locator: Arc::new(RwLock::new(BlobLocatorCache::default())),
        upload_sessions: Arc::new(RwLock::new(UploadSessionStore::default())),
    };

    let router = routes::build_router(state.clone());
    let addr = format!("{host}:{port}");
    let listener = TcpListener::bind(&addr).await?;

    eprintln!("BoringCache OCI registry proxy listening on {addr}");
    eprintln!("  Workspace: {workspace}");
    if !state.configured_human_tags.is_empty() {
        eprintln!(
            "  Human Tag Aliases: {}",
            state.configured_human_tags.join(", ")
        );
    }
    eprintln!("  Use: --cache-from type=registry,ref={host}:{port}/CACHE_NAME:TAG");
    eprintln!("  Use: --cache-to type=registry,ref={host}:{port}/CACHE_NAME:TAG");

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

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    eprintln!("\nShutting down...");
}
