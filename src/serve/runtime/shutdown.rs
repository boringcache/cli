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
    use crate::test_env;

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
