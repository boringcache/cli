use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::oneshot;

use crate::api::client::TagPointerPollResult;
use crate::observability::{self, ObservabilityEvent};
use crate::serve::cache_registry;
use crate::serve::state::AppState;

pub(super) fn emit_cache_session_summary(state: &AppState) {
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let oci_body = state.oci_body_metrics.metadata_hints();
    let oci_engine = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    let oci_negative = state.oci_negative_cache.metadata_hints();
    let singleflight = state.singleflight_metrics.metadata_hints();

    let proxy = serde_json::json!({
        "hydration_policy": state.oci_hydration_policy.as_str(),
        "duration_ms": duration_ms,
        "read_only": state.read_only,
        "fail_on_cache_error": state.fail_on_cache_error,
        "blob_download_max_concurrency": state.blob_download_max_concurrency,
        "oci_alias_promotion_refs": &state.oci_alias_promotion_refs,
    });
    let rails = serde_json::json!({
        "request_metrics": "see_jsonl",
    });
    let storage = map_to_json(select_metric_prefixes(
        &oci_engine,
        &[
            "oci_engine_storage_",
            "oci_engine_local_spool_",
            "oci_engine_digest_verify_",
            "oci_engine_cache_promotion_",
        ],
    ));
    let mut oci = merged_maps_to_json(&[oci_body.clone(), oci_engine, oci_negative]);
    if let Some(object) = oci.as_object_mut() {
        object.insert(
            "buildkit_enrichment".to_string(),
            serde_json::Value::String("unknown".to_string()),
        );
    }
    let local_cache = serde_json::json!({
        "blob_read_cache_bytes": state.blob_read_cache.total_bytes(),
        "blob_read_cache_max_bytes": state.blob_read_cache.max_bytes(),
        "oci_body": map_to_json(oci_body),
        "blob_read": map_to_json(state.blob_read_metrics.metadata_hints()),
    });
    let buildkit = serde_json::json!({
        "run_classification": "unknown",
    });

    observability::emit(ObservabilityEvent::cache_session_summary(
        state.workspace.clone(),
        duration_ms,
        proxy,
        rails,
        storage,
        oci,
        map_to_json(singleflight),
        local_cache,
        buildkit,
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
    super::maintenance::flush_cache_ops(state).await;

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(180);
    let mut expected_root_cache_entry_id: Option<String> = None;

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
                if expected_root_cache_entry_id.is_none() {
                    expected_root_cache_entry_id = {
                        let published = state.kv_published_index.read().await;
                        published.cache_entry_id().map(|value| value.to_string())
                    };
                }
                if let Some(cache_entry_id) = expected_root_cache_entry_id.as_deref() {
                    let _ = wait_for_tag_visibility(state, cache_entry_id, deadline).await;
                }
                return;
            }
            continue;
        }

        let flush_guard = cache_registry::try_schedule_flush(state);
        match flush_guard {
            Some(_flush_guard) => {
                let flush_result = cache_registry::flush_kv_index_on_shutdown(state).await;
                match flush_result {
                    cache_registry::FlushResult::Ok => {
                        let published_entry = {
                            let published = state.kv_published_index.read().await;
                            published.cache_entry_id().map(|value| value.to_string())
                        };
                        expected_root_cache_entry_id = published_entry;
                        {
                            let mut gate = state.kv_next_flush_at.write().await;
                            *gate = None;
                        }
                    }
                    cache_registry::FlushResult::Permanent => {
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
            eprintln!(
                "Shutdown: flush timeout reached with {pending_entries} pending entries remaining"
            );
            return;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
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

fn visibility_tags_from_values(
    registry_root_tag: &str,
    configured_human_tags: &[String],
) -> Vec<String> {
    let mut tags = Vec::with_capacity(1 + configured_human_tags.len());

    let root = registry_root_tag.trim();
    if !root.is_empty() {
        tags.push(root.to_string());
    }

    for tag in configured_human_tags {
        let trimmed = tag.trim();
        if trimmed.is_empty() || tags.iter().any(|existing| existing == trimmed) {
            continue;
        }
        tags.push(trimmed.to_string());
    }

    tags
}

fn merged_maps_to_json(maps: &[std::collections::BTreeMap<String, String>]) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for map in maps {
        for (key, value) in map {
            object.insert(key.clone(), json_metric_value(value));
        }
    }
    serde_json::Value::Object(object)
}

fn map_to_json(map: std::collections::BTreeMap<String, String>) -> serde_json::Value {
    let mut object = serde_json::Map::new();
    for (key, value) in map {
        object.insert(key, json_metric_value(&value));
    }
    serde_json::Value::Object(object)
}

fn select_metric_prefixes(
    map: &std::collections::BTreeMap<String, String>,
    prefixes: &[&str],
) -> std::collections::BTreeMap<String, String> {
    map.iter()
        .filter(|(key, _)| prefixes.iter().any(|prefix| key.starts_with(prefix)))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect()
}

fn json_metric_value(value: &str) -> serde_json::Value {
    value
        .parse::<u64>()
        .map(serde_json::Value::from)
        .unwrap_or_else(|_| serde_json::Value::String(value.to_string()))
}

async fn wait_for_tag_visibility(
    state: &AppState,
    expected_cache_entry_id: &str,
    deadline: std::time::Instant,
) -> bool {
    let tags = visibility_tags_from_values(&state.registry_root_tag, &state.configured_human_tags);
    let mut attempts = 0u32;

    loop {
        attempts = attempts.saturating_add(1);
        let mut missing_tags = Vec::new();

        for tag in &tags {
            match state
                .api_client
                .tag_pointer(&state.workspace, tag, None)
                .await
            {
                Ok(TagPointerPollResult::Changed { pointer, .. }) => {
                    if pointer.cache_entry_id.as_deref() != Some(expected_cache_entry_id) {
                        missing_tags.push(tag.clone());
                    }
                }
                Ok(TagPointerPollResult::NotModified) | Ok(TagPointerPollResult::NotFound) => {
                    missing_tags.push(tag.clone());
                }
                Err(error) => {
                    log::warn!(
                        "Shutdown: tag visibility poll failed for {} tag={}: {}",
                        expected_cache_entry_id,
                        tag,
                        error
                    );
                    missing_tags.push(tag.clone());
                }
            }
        }

        if missing_tags.is_empty() {
            eprintln!(
                "Shutdown: registry root and human tags visible for cache_entry_id={} after {} poll(s)",
                expected_cache_entry_id, attempts
            );
            return true;
        }

        if std::time::Instant::now() >= deadline {
            eprintln!(
                "Shutdown: tags did not converge to cache_entry_id={} before timeout (missing: {})",
                expected_cache_entry_id,
                missing_tags.join(", ")
            );
            return false;
        }

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn visibility_tags_include_root_and_human_tags_without_duplicates() {
        let tags = visibility_tags_from_values(
            "bc_registry_root_v2_123",
            &[
                "mode-docker-ubuntu-24-x86_64".to_string(),
                "mode-docker-ubuntu-24-x86_64".to_string(),
                "digest-sha256-abc".to_string(),
                "".to_string(),
            ],
        );

        assert_eq!(
            tags,
            vec![
                "bc_registry_root_v2_123".to_string(),
                "mode-docker-ubuntu-24-x86_64".to_string(),
                "digest-sha256-abc".to_string(),
            ]
        );
    }
}
