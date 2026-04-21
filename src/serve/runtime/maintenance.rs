use std::sync::Arc;
use std::sync::atomic::Ordering;

use tokio::sync::mpsc;

use crate::observability;
use crate::serve::cache_registry;
use crate::serve::state::{
    AppState, KV_REPLICATION_WORK_QUEUE_CAPACITY, KvReplicationWork, diagnostics_enabled,
    unix_time_ms_now,
};

const KV_REFRESH_TASK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const KV_REPLICATION_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
const KV_IDLE_FLUSH_WINDOW_DEFAULT_MS: u64 = 10_000;
const KV_IDLE_FLUSH_WINDOW_SMALL_BATCH_MS: u64 = 2_000;
const KV_SMALL_BATCH_IDLE_FLUSH_MAX_BLOBS: usize = 64;
const KV_SMALL_BATCH_IDLE_FLUSH_MAX_BYTES: u64 = 64 * 1024 * 1024;

pub(super) fn spawn_maintenance_tasks(
    state: &AppState,
    mut replication_rx: mpsc::Receiver<KvReplicationWork>,
) {
    let diagnostics = diagnostics_enabled();
    spawn_runtime_watchdog(state.cache_ops.clone(), diagnostics);

    if diagnostics {
        let heartbeat_state = state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
            interval.tick().await;
            loop {
                interval.tick().await;
                let ts = chrono::Utc::now().format("%H:%M:%S");
                eprintln!("HEARTBEAT ts={ts} phase=tick");
                let (pending_count, pending_bytes, pending_oldest_ms) = {
                    let now_ms = unix_time_ms_now();
                    let p = heartbeat_state.kv_pending.read().await;
                    (
                        p.entry_count(),
                        p.total_spool_bytes(),
                        p.oldest_entry_age_ms(now_ms).unwrap_or(0),
                    )
                };
                let published_count = {
                    let p = heartbeat_state.kv_published_index.read().await;
                    p.entry_count()
                };
                let flush_gate_delay_ms = {
                    let gate = heartbeat_state.kv_next_flush_at.read().await;
                    gate.map(|next| {
                        next.saturating_duration_since(std::time::Instant::now())
                            .as_millis() as u64
                    })
                    .unwrap_or(0)
                };
                let flights = heartbeat_state.kv_lookup_inflight.len();
                let cache_bytes = heartbeat_state.blob_read_cache.total_bytes();
                let breaker_open = heartbeat_state.backend_breaker.is_open();
                let (inflight, total) = cache_registry::request_counters();
                let cache_ops_queue_depth = heartbeat_state.cache_ops.queue_depth();
                let cache_ops_dropped_total = heartbeat_state.cache_ops.dropped_events_total();
                let observability_queue_depth = observability::queue_depth();
                let observability_dropped_total = observability::dropped_events_total();
                let backlog_rejects = heartbeat_state.kv_backlog_rejects.load(Ordering::Acquire);
                let replication_deferred = heartbeat_state
                    .kv_replication_enqueue_deferred
                    .load(Ordering::Acquire);
                let replication_queue_depth = heartbeat_state
                    .kv_replication_queue_depth
                    .load(Ordering::Acquire);
                let replication_flush_ok = heartbeat_state
                    .kv_replication_flush_ok
                    .load(Ordering::Acquire);
                let replication_flush_conflict = heartbeat_state
                    .kv_replication_flush_conflict
                    .load(Ordering::Acquire);
                let replication_flush_error = heartbeat_state
                    .kv_replication_flush_error
                    .load(Ordering::Acquire);
                let replication_flush_permanent = heartbeat_state
                    .kv_replication_flush_permanent
                    .load(Ordering::Acquire);
                eprintln!(
                    "HEARTBEAT ts={ts} reqs={total} inflight={inflight} pending={} pending_bytes={} pending_oldest_ms={} flush_gate_ms={} backlog_rejects={} repl_q={} repl_q_max={} repl_deferred={} repl_ok={} repl_conflict={} repl_error={} repl_permanent={} published={} flights={} cache_bytes={} breaker={} ops_q={} ops_drop={} obs_q={} obs_drop={}",
                    pending_count,
                    pending_bytes,
                    pending_oldest_ms,
                    flush_gate_delay_ms,
                    backlog_rejects,
                    replication_queue_depth,
                    KV_REPLICATION_WORK_QUEUE_CAPACITY,
                    replication_deferred,
                    replication_flush_ok,
                    replication_flush_conflict,
                    replication_flush_error,
                    replication_flush_permanent,
                    published_count,
                    flights,
                    cache_bytes,
                    if breaker_open { "OPEN" } else { "closed" },
                    cache_ops_queue_depth,
                    cache_ops_dropped_total,
                    observability_queue_depth,
                    observability_dropped_total,
                );
            }
        });
    }

    let version_poll_state = state.clone();
    tokio::spawn(async move {
        cache_registry::poll_tag_version_loop(&version_poll_state).await;
    });

    let refresh_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(120));
        interval.tick().await;
        loop {
            interval.tick().await;
            if tokio::time::timeout(
                KV_REFRESH_TASK_TIMEOUT,
                cache_registry::refresh_kv_index(&refresh_state),
            )
            .await
            .is_err()
            {
                log::warn!(
                    "KV index refresh timed out after {}s",
                    KV_REFRESH_TASK_TIMEOUT.as_secs()
                );
            }
        }
    });

    let miss_cleanup_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            cache_registry::cleanup_expired_kv_misses(&miss_cleanup_state);
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
                if session.owns_temp_file() {
                    let _ = tokio::fs::remove_file(&session.temp_path).await;
                }
            }
        }
    });

    let replication_state = state.clone();
    tokio::spawn(async move {
        let mut consecutive_failures: u32 = 0;
        loop {
            let next_work = replication_rx.recv().await;
            let Some(work) = next_work else {
                break;
            };
            decrement_replication_queue_depth(&replication_state);
            let mut urgent = matches!(work, KvReplicationWork::FlushHint { urgent: true });
            while let Ok(extra) = replication_rx.try_recv() {
                decrement_replication_queue_depth(&replication_state);
                if matches!(extra, KvReplicationWork::FlushHint { urgent: true }) {
                    urgent = true;
                }
            }
            if replication_state.shutdown_requested.load(Ordering::Acquire) {
                continue;
            }
            process_replication_work(&replication_state, urgent, &mut consecutive_failures).await;
        }
    });

    let sweep_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(KV_REPLICATION_SWEEP_INTERVAL);
        interval.tick().await;
        loop {
            interval.tick().await;
            if sweep_state.shutdown_requested.load(Ordering::Acquire) {
                continue;
            }
            let pending_count = {
                let pending = sweep_state.kv_pending.read().await;
                pending.entry_count()
            };
            if pending_count == 0 {
                continue;
            }

            if sweep_state
                .kv_replication_queue_depth
                .load(Ordering::Acquire)
                > 0
            {
                continue;
            }

            let _ = cache_registry::enqueue_replication_flush_hint(&sweep_state, false, false);
        }
    });

    let ops_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        interval.tick().await;
        loop {
            interval.tick().await;
            flush_cache_ops(&ops_state).await;
        }
    });
}

pub(super) async fn flush_cache_ops(state: &AppState) {
    let blob_read_hints = state.blob_read_metrics.metadata_hints();
    if !blob_read_hints.is_empty() {
        state
            .cache_ops
            .merge_session_metadata_hints(blob_read_hints);
    }
    let oci_body_hints = state.oci_body_metrics.metadata_hints();
    if !oci_body_hints.is_empty() {
        state.cache_ops.merge_session_metadata_hints(oci_body_hints);
    }
    let oci_engine_hints = state
        .oci_engine_diagnostics
        .metadata_hints(state.oci_hydration_policy.as_str());
    if !oci_engine_hints.is_empty() {
        state
            .cache_ops
            .merge_session_metadata_hints(oci_engine_hints);
    }
    let prefetch_hints = state.prefetch_metrics.metadata_hints();
    if !prefetch_hints.is_empty() {
        state.cache_ops.merge_session_metadata_hints(prefetch_hints);
    }
    if state.cache_ops.is_empty() {
        return;
    }
    let (rollups, missed_keys, sessions) = state.cache_ops.drain();
    if rollups.is_empty() && missed_keys.is_empty() && sessions.is_empty() {
        return;
    }
    let batch = crate::api::models::cache_rollups::BatchParams {
        rollups: rollups
            .iter()
            .map(|r| crate::api::models::cache_rollups::RollupParam {
                bucket_at: chrono::DateTime::from_timestamp(r.bucket_epoch_secs as i64, 0)
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default(),
                session_id: r.session_id.clone(),
                tool: r.tool.clone(),
                operation: r.operation.clone(),
                result: r.result.clone(),
                degraded: r.degraded,
                event_count: r.event_count,
                bytes_total: r.bytes_total,
                latency_sum_ms: r.latency_sum_ms,
                latency_count: r.latency_count,
            })
            .collect(),
        missed_keys: missed_keys
            .iter()
            .map(|mk| crate::api::models::cache_rollups::MissedKeyParam {
                key_hash: mk.key_hash.clone(),
                tool: mk.tool.clone(),
                miss_count: mk.miss_count,
                sampled_key_prefix: mk.sampled_key_prefix.clone(),
            })
            .collect(),
        sessions: sessions
            .iter()
            .map(|session| crate::api::models::cache_rollups::SessionParam {
                session_id: session.session_id.clone(),
                tool: session.tool.clone(),
                session_duration_ms: session.session_duration_ms,
                hit_count: session.hit_count,
                miss_count: session.miss_count,
                error_count: session.error_count,
                bytes_read: session.bytes_read,
                bytes_written: session.bytes_written,
                metadata_hints: session.metadata_hints.clone(),
                top_missed_keys: session
                    .top_missed_keys
                    .iter()
                    .map(
                        |miss| crate::api::models::cache_rollups::SessionMissedKeyParam {
                            key_hash: miss.key_hash.clone(),
                            miss_count: miss.miss_count,
                            sampled_key_prefix: miss.sampled_key_prefix.clone(),
                        },
                    )
                    .collect(),
            })
            .collect(),
    };
    if let Err(error) = state
        .api_client
        .send_cache_rollups(&state.workspace, batch)
        .await
    {
        state.cache_ops.restore(rollups, missed_keys, sessions);
        log::debug!("Cache ops flush failed: {error}");
    }
}

fn spawn_runtime_watchdog(
    cache_ops: Arc<cache_registry::cache_ops::Aggregator>,
    diagnostics: bool,
) {
    let rt_handle = tokio::runtime::Handle::current();
    std::thread::Builder::new()
        .name("watchdog".into())
        .spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(10));
            let mut stuck_count: u32 = 0;
            loop {
                let started_at = std::time::Instant::now();
                let ts = chrono::Utc::now().format("%H:%M:%S%.3f");
                let (tx, rx) = std::sync::mpsc::channel();
                rt_handle.spawn(async move {
                    let _ = tx.send(());
                });
                match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok(()) => {
                        if diagnostics && stuck_count > 0 {
                            eprintln!(
                                "WATCHDOG ts={ts} runtime=recovered after_stuck={stuck_count}"
                            );
                        }
                        cache_ops.record(
                            cache_registry::cache_ops::Tool::Runtime,
                            cache_registry::cache_ops::Op::Query,
                            cache_registry::cache_ops::OpResult::Hit,
                            false,
                            0,
                            started_at.elapsed().as_millis() as u64,
                        );
                        stuck_count = 0;
                    }
                    Err(_) => {
                        stuck_count += 1;
                        if diagnostics {
                            eprintln!("WATCHDOG ts={ts} runtime=STUCK consecutive={stuck_count}");
                            cache_registry::dump_stuck_puts(5, 2_000);
                        }
                        cache_ops.record(
                            cache_registry::cache_ops::Tool::Runtime,
                            cache_registry::cache_ops::Op::Query,
                            cache_registry::cache_ops::OpResult::Error,
                            true,
                            0,
                            started_at.elapsed().as_millis() as u64,
                        );
                    }
                }
                std::thread::sleep(std::time::Duration::from_secs(10));
            }
        })
        .expect("Failed to spawn watchdog thread");
}

fn decrement_replication_queue_depth(state: &AppState) {
    let _ = state.kv_replication_queue_depth.fetch_update(
        Ordering::AcqRel,
        Ordering::Acquire,
        |depth| Some(depth.saturating_sub(1)),
    );
}

async fn should_flush_pending(state: &AppState, urgent: bool) -> bool {
    use crate::serve::state::FLUSH_SIZE_THRESHOLD;

    let pending = state.kv_pending.read().await;
    let pending_blob_count = pending.blob_count();
    let pending_spool_bytes = pending.total_spool_bytes();
    let last_put_ms = state.kv_last_put.load(Ordering::Acquire);
    should_flush_pending_values(
        urgent,
        pending_blob_count,
        pending_spool_bytes,
        last_put_ms,
        unix_time_ms_now(),
        crate::serve::state::flush_blob_threshold(),
        FLUSH_SIZE_THRESHOLD,
    )
}

fn flush_idle_window_ms(pending_blob_count: usize, pending_spool_bytes: u64) -> u64 {
    if pending_blob_count <= KV_SMALL_BATCH_IDLE_FLUSH_MAX_BLOBS
        && pending_spool_bytes <= KV_SMALL_BATCH_IDLE_FLUSH_MAX_BYTES
    {
        return KV_IDLE_FLUSH_WINDOW_SMALL_BATCH_MS;
    }

    KV_IDLE_FLUSH_WINDOW_DEFAULT_MS
}

fn should_flush_pending_values(
    urgent: bool,
    pending_blob_count: usize,
    pending_spool_bytes: u64,
    last_put_ms: u64,
    now_ms: u64,
    flush_blob_threshold: usize,
    flush_size_threshold: u64,
) -> bool {
    if pending_blob_count == 0 {
        return false;
    }
    if urgent {
        return true;
    }
    if pending_blob_count >= flush_blob_threshold || pending_spool_bytes >= flush_size_threshold {
        return true;
    }

    let idle_window_ms = flush_idle_window_ms(pending_blob_count, pending_spool_bytes);
    if idle_window_ms == 0 {
        return true;
    }

    last_put_ms > 0 && now_ms.saturating_sub(last_put_ms) >= idle_window_ms
}

async fn process_replication_work(state: &AppState, urgent: bool, consecutive_failures: &mut u32) {
    {
        let gate = state.kv_next_flush_at.read().await;
        if let Some(next) = *gate
            && std::time::Instant::now() < next
        {
            return;
        }
    }

    if *consecutive_failures > 0 {
        use rand::Rng;

        let base_secs: u64 = match *consecutive_failures {
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

    if !should_flush_pending(state, urgent).await {
        return;
    }

    let Some(_flush_guard) = cache_registry::try_schedule_flush(state) else {
        return;
    };
    let flush_result = cache_registry::flush_kv_index(state).await;
    update_consecutive_failures_on_flush_result(&flush_result, consecutive_failures);
    match flush_result {
        cache_registry::FlushResult::Ok => {
            let mut gate = state.kv_next_flush_at.write().await;
            *gate = None;
            state.kv_replication_flush_ok.fetch_add(1, Ordering::AcqRel);
            let remaining_pending = {
                let pending = state.kv_pending.read().await;
                pending.entry_count()
            };
            if remaining_pending > 0 {
                eprintln!(
                    "KV flush: {remaining_pending} pending entries arrived during flush, scheduling follow-up"
                );
                let _ = cache_registry::enqueue_replication_flush_hint(state, true, false);
            }
        }
        cache_registry::FlushResult::Conflict => {
            state
                .kv_replication_flush_conflict
                .fetch_add(1, Ordering::AcqRel);
        }
        cache_registry::FlushResult::Error => {
            state
                .kv_replication_flush_error
                .fetch_add(1, Ordering::AcqRel);
        }
        cache_registry::FlushResult::Permanent => {
            let mut gate = state.kv_next_flush_at.write().await;
            *gate = None;
            state
                .kv_replication_flush_permanent
                .fetch_add(1, Ordering::AcqRel);
        }
    }
}

fn update_consecutive_failures_on_flush_result(
    result: &cache_registry::FlushResult,
    consecutive_failures: &mut u32,
) {
    match result {
        cache_registry::FlushResult::Error => {
            *consecutive_failures = consecutive_failures.saturating_add(1);
        }
        cache_registry::FlushResult::Ok
        | cache_registry::FlushResult::Conflict
        | cache_registry::FlushResult::Permanent => {
            *consecutive_failures = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_consecutive_failures_resets_on_conflict() {
        let mut consecutive_failures = 3;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Conflict,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 0);
    }

    #[test]
    fn update_consecutive_failures_increments_on_error() {
        let mut consecutive_failures = 2;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Error,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 3);
    }

    #[test]
    fn update_consecutive_failures_resets_on_ok_and_permanent() {
        let mut consecutive_failures = 2;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Ok,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 0);

        consecutive_failures = 5;
        update_consecutive_failures_on_flush_result(
            &cache_registry::FlushResult::Permanent,
            &mut consecutive_failures,
        );
        assert_eq!(consecutive_failures, 0);
    }

    #[test]
    fn should_flush_pending_values_coalesces_tiny_batches_with_short_idle_window() {
        let now_ms = 10_000;
        assert!(!should_flush_pending_values(
            false,
            2,
            1_024,
            now_ms - 1_500,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            2,
            1_024,
            now_ms - 2_000,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_uses_short_idle_window_for_small_batches() {
        let now_ms = 10_000;
        assert!(!should_flush_pending_values(
            false,
            32,
            4 * 1024 * 1024,
            now_ms - 1_500,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            32,
            4 * 1024 * 1024,
            now_ms - 2_000,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_uses_default_idle_window_for_large_batches() {
        let now_ms = 20_000;
        assert!(!should_flush_pending_values(
            false,
            128,
            128 * 1024 * 1024,
            now_ms - 9_500,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            128,
            128 * 1024 * 1024,
            now_ms - 10_000,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_flushes_when_threshold_is_reached() {
        let now_ms = 10_000;
        assert!(should_flush_pending_values(
            false,
            2_000,
            1_024,
            now_ms,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
        assert!(should_flush_pending_values(
            false,
            1,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
            now_ms,
            now_ms,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }

    #[test]
    fn should_flush_pending_values_respects_urgent_signal() {
        assert!(should_flush_pending_values(
            true,
            1,
            1_024,
            0,
            0,
            2_000,
            crate::serve::state::FLUSH_SIZE_THRESHOLD,
        ));
    }
}
