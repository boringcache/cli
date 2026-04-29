use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;

use crate::observability::{self, ObservabilityEvent};
use crate::serve::cache_registry;
use crate::serve::state::{AppState, build_cache_session_summary};

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
        summary.local_cache,
        summary.buildkit,
        summary.classification,
    ));
    observability::flush_for(std::time::Duration::from_secs(2));
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

pub(super) async fn flush_pending_on_shutdown(state: &AppState) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);

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
            }
            continue;
        }

        let flush_guard = cache_registry::try_schedule_flush(state);
        match flush_guard {
            Some(_flush_guard) => {
                let flush_result = cache_registry::flush_kv_index_on_shutdown(state).await;
                match flush_result {
                    cache_registry::FlushResult::Ok
                    | cache_registry::FlushResult::AcceptedContention
                    | cache_registry::FlushResult::Permanent => {
                        let mut gate = state.kv_next_flush_at.write().await;
                        *gate = None;
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

        if std::time::Instant::now() >= deadline {
            let pending_entries = {
                let pending = state.kv_pending.read().await;
                pending.entry_count()
            };
            if pending_entries == 0 {
                break;
            }
            eprintln!(
                "Shutdown: flush timeout reached with {pending_entries} pending entries remaining"
            );
            break;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }

    super::maintenance::flush_cache_ops_on_shutdown(state).await;
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
