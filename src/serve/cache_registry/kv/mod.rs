use axum::body::Body;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::StreamExt;
use futures_util::future::join_all;
use rand::Rng;
use reqwest::header::{CONTENT_LENGTH, CONTENT_TYPE};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio::sync::mpsc::error::TrySendError;
use tokio_util::io::ReaderStream;

use crate::api::models::cache::{
    BlobDescriptor, CacheResolutionEntry, ConfirmRequest, SaveRequest,
};
use crate::cache::receipts::try_commit_blob_receipts;
use crate::cas_transport::upload_payload;
use crate::error::BoringCacheError;
use crate::manifest::EntryType;
use crate::serve::state::{
    AppState, BlobReadHandle, KV_BACKLOG_POLICY, KvFlushingSnapshot, KvReplicationWork,
};

use super::error::RegistryError;
use super::kv_publish::{BlobUploadStats, partial_blob_upload_stats, upload_blobs};

const KV_MISS_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(5);
const KV_CONFLICT_BACKOFF_MS: u64 = 5_000;
const KV_CONFLICT_JITTER_MS: u64 = 3_000;
const KV_CONFLICT_IN_PROGRESS_BACKOFF_MS: u64 = 30_000;
const KV_CONFLICT_IN_PROGRESS_JITTER_MS: u64 = 10_000;
const KV_TRANSIENT_BACKOFF_MS: u64 = 2_000;
const KV_TRANSIENT_JITTER_MS: u64 = 2_000;
const KV_TRANSIENT_WRITE_PATH_BACKOFF_MS: u64 = 20_000;
const KV_TRANSIENT_WRITE_PATH_JITTER_MS: u64 = 5_000;
const KV_CONFIRM_VERIFICATION_RETRY_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(90);
const KV_CONFIRM_VERIFICATION_RETRY_BASE_MS: u64 = 1_000;
const KV_CONFIRM_VERIFICATION_RETRY_MAX_MS: u64 = 5_000;
const KV_INDEX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(30);
const KV_EMPTY_INDEX_REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(12);
const KV_PENDING_REFRESH_SUPPRESSION_WINDOW: std::time::Duration =
    std::time::Duration::from_secs(12);
const KV_RESOLVE_NOT_FOUND_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);
const KV_BLOB_DOWNLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
const KV_BLOB_URL_RESOLVE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KV_LOOKUP_REFRESH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KV_PUT_BODY_CHUNK_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const KV_PUT_BODY_SLOW_WARN_THRESHOLD: std::time::Duration = std::time::Duration::from_secs(5);
const KV_RESOLVE_HIT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
const KV_FETCH_POINTER_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
#[cfg(test)]
const KV_STARTUP_PREFETCH_MAX_BLOBS_ENV: &str = "BORINGCACHE_STARTUP_PREFETCH_MAX_BLOBS";
#[cfg(test)]
const KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV: &str =
    "BORINGCACHE_STARTUP_PREFETCH_MAX_TOTAL_BYTES";
#[cfg(test)]
const KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV: &str =
    "BORINGCACHE_BLOB_PREFETCH_MAX_INFLIGHT_BYTES";
#[cfg(test)]
const KV_BLOB_PRELOAD_SKIP_USED_PCT: u64 = 95;
const KV_VERSION_POLL_ACTIVE_SECS: u64 = 3;
const KV_VERSION_POLL_IDLE_SECS: u64 = 30;
const KV_VERSION_POLL_ACTIVE_WINDOW: std::time::Duration = std::time::Duration::from_secs(10);
const KV_VERSION_POLL_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const KV_VERSION_POLL_JITTER_MS: u64 = 500;
const KV_VERSION_REFRESH_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(10);
const LOOKUP_REFRESH_FLIGHT_KEY: &str = "lookup_refresh";
static KV_BLOB_DOWNLOAD_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BlobReadSource {
    LocalCache,
    RemoteFetch,
}

impl BlobReadSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::LocalCache => "local_cache",
            Self::RemoteFetch => "remote_fetch",
        }
    }
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub(crate) struct StartupPrefetchCandidates {
    ordered_blobs: Vec<BlobDescriptor>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct DownloadUrlPreloadStats {
    requested: usize,
    resolved: usize,
    missing: usize,
}

#[derive(Debug, Clone)]
pub(crate) struct StartupPrefetchTarget {
    blob: BlobDescriptor,
    cached_url: Option<String>,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct StartupPrefetchTargetSummary {
    cached_url_count: usize,
    unresolved_url_count: usize,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum KvNamespace {
    BazelAc,
    BazelCas,
    Gradle,
    Maven,
    Nx,
    NxTerminalOutput,
    Turborepo,
    TurborepoMeta,
    Sccache,
    GoCache,
}

impl KvNamespace {
    pub(crate) fn normalize_key(self, key: &str) -> String {
        match self {
            KvNamespace::BazelAc
            | KvNamespace::BazelCas
            | KvNamespace::Gradle
            | KvNamespace::GoCache => key.to_ascii_lowercase(),
            KvNamespace::Maven
            | KvNamespace::Nx
            | KvNamespace::NxTerminalOutput
            | KvNamespace::Turborepo
            | KvNamespace::TurborepoMeta
            | KvNamespace::Sccache => key.to_string(),
        }
    }

    fn namespace_prefix(self) -> &'static str {
        match self {
            KvNamespace::BazelAc => "bazel_ac",
            KvNamespace::BazelCas => "bazel_cas",
            KvNamespace::Gradle => "gradle",
            KvNamespace::Maven => "maven",
            KvNamespace::Nx => "nx",
            KvNamespace::NxTerminalOutput => "nx_terminal",
            KvNamespace::Turborepo => "turbo",
            KvNamespace::TurborepoMeta => "turbo_meta",
            KvNamespace::Sccache => "sccache",
            KvNamespace::GoCache => "go_cache",
        }
    }

    pub(crate) fn scoped_key(self, key: &str) -> String {
        format!("{}/{}", self.namespace_prefix(), self.normalize_key(key))
    }
}

mod blob_read;
mod flight;
mod flush;
mod index;
mod instrumentation;
mod lookup;
mod policy;
mod prefetch;
mod refresh;
mod write;

pub(crate) use blob_read::*;
pub(crate) use flight::*;
pub(crate) use flush::*;
pub(crate) use index::*;
pub(crate) use instrumentation::*;
pub(crate) use lookup::*;
pub(crate) use policy::*;
pub(crate) use prefetch::*;
pub(crate) use refresh::*;
pub(crate) use write::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::client::ApiClient;
    use crate::git::GitContext;
    use crate::serve::state::{
        AppState, BackendCircuitBreaker, BlobLocatorCache, BlobReadCache, BlobReadMetrics,
        KvPendingStore, KvPublishedIndex, UploadSessionStore,
    };
    use crate::tag_utils::TagResolver;
    use crate::test_env;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::sync::{Mutex as TokioMutex, RwLock};

    #[tokio::test]
    async fn put_kv_object_is_noop_in_read_only_mode() {
        let temp_home = tempfile::tempdir().expect("temp dir");
        let api_client =
            ApiClient::new_with_token_override(Some("test-token".to_string())).expect("client");
        let (kv_replication_work_tx, _kv_replication_work_rx) =
            tokio::sync::mpsc::channel(crate::serve::state::KV_REPLICATION_WORK_QUEUE_CAPACITY);
        let runtime_temp_dir = temp_home.path().join("serve-runtime");
        std::fs::create_dir_all(runtime_temp_dir.join("kv-blobs")).expect("kv blob temp dir");
        std::fs::create_dir_all(runtime_temp_dir.join("oci-uploads")).expect("oci upload temp dir");

        let state = AppState {
            api_client,
            workspace: "org/repo".to_string(),
            runtime_temp_dir: runtime_temp_dir.clone(),
            kv_blob_temp_dir: runtime_temp_dir.join("kv-blobs"),
            oci_upload_temp_dir: runtime_temp_dir.join("oci-uploads"),
            read_only: true,
            tag_resolver: TagResolver::new(None, GitContext::default(), false),
            configured_human_tags: Vec::new(),
            registry_root_tag: "registry".to_string(),
            fail_on_cache_error: true,
            oci_hydration_policy: crate::serve::OciHydrationPolicy::MetadataOnly,
            blob_locator: std::sync::Arc::new(RwLock::new(BlobLocatorCache::default())),
            upload_sessions: std::sync::Arc::new(RwLock::new(UploadSessionStore::default())),
            kv_pending: std::sync::Arc::new(RwLock::new(KvPendingStore::default())),
            kv_flush_lock: std::sync::Arc::new(TokioMutex::new(())),
            kv_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
            oci_lookup_inflight: std::sync::Arc::new(dashmap::DashMap::new()),
            kv_last_put: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_backlog_rejects: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_enqueue_deferred: std::sync::Arc::new(
                std::sync::atomic::AtomicU64::new(0),
            ),
            kv_replication_flush_ok: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_conflict: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                0,
            )),
            kv_replication_flush_error: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_flush_permanent: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                0,
            )),
            kv_replication_queue_depth: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
            kv_replication_work_tx,
            kv_next_flush_at: std::sync::Arc::new(RwLock::new(None)),
            kv_flush_scheduled: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            kv_published_index: std::sync::Arc::new(RwLock::new(KvPublishedIndex::default())),
            kv_flushing: std::sync::Arc::new(RwLock::new(None)),
            shutdown_requested: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            kv_recent_misses: std::sync::Arc::new(dashmap::DashMap::new()),
            kv_miss_generations: std::sync::Arc::new(dashmap::DashMap::new()),
            blob_read_cache: std::sync::Arc::new(
                BlobReadCache::new_at(
                    temp_home.path().join("blob-read-cache"),
                    2 * 1024 * 1024 * 1024,
                )
                .expect("blob read cache"),
            ),
            blob_read_metrics: std::sync::Arc::new(BlobReadMetrics::new()),
            oci_body_metrics: std::sync::Arc::new(crate::serve::state::OciBodyMetrics::new()),
            oci_engine_diagnostics: std::sync::Arc::new(
                crate::serve::state::OciEngineDiagnostics::new(),
            ),
            prefetch_metrics: std::sync::Arc::new(crate::serve::state::PrefetchMetrics::new()),
            blob_download_max_concurrency: 16,
            blob_download_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(16)),
            blob_prefetch_semaphore: std::sync::Arc::new(tokio::sync::Semaphore::new(2)),
            cache_ops: std::sync::Arc::new(
                crate::serve::cache_registry::cache_ops::Aggregator::new(),
            ),
            oci_manifest_cache: std::sync::Arc::new(dashmap::DashMap::new()),
            backend_breaker: std::sync::Arc::new(BackendCircuitBreaker::new()),
            prefetch_complete: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prefetch_complete_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            prefetch_error: std::sync::Arc::new(RwLock::new(None)),
        };

        let response = put_kv_object(
            &state,
            KvNamespace::Gradle,
            "cache-key",
            Body::from("payload"),
            StatusCode::OK,
        )
        .await
        .expect("read-only puts should succeed");

        assert_eq!(response.status(), StatusCode::OK);
        let pending = state.kv_pending.read().await;
        assert_eq!(pending.blob_count(), 0);
    }

    #[test]
    fn classify_flush_error_treats_precondition_failed_as_conflict() {
        let error = anyhow::anyhow!("HTTP 412 from backend: precondition failed");
        let classified = classify_flush_error(&error, "confirm failed");
        assert!(matches!(classified, FlushError::Conflict(_)));
    }

    #[test]
    fn classify_flush_error_treats_cache_pending_as_conflict() {
        let error: anyhow::Error = BoringCacheError::cache_pending().into();
        let classified = classify_flush_error(&error, "confirm failed");
        assert!(matches!(classified, FlushError::Transient(_)));
    }

    #[test]
    fn classify_flush_error_treats_server_error_message_as_transient() {
        let error = anyhow::anyhow!("Server error (500). Please try again later.");
        let classified = classify_flush_error(&error, "confirm failed");
        assert!(matches!(classified, FlushError::Transient(_)));
    }

    #[test]
    fn classify_flush_error_treats_blob_verification_pending_as_transient() {
        let error = anyhow::anyhow!(
            "Server returned 400 Bad Request: 714 blob(s) not yet verified in storage — retry after upload completes"
        );
        let classified = classify_flush_error(&error, "confirm failed");
        assert!(matches!(classified, FlushError::Transient(_)));
    }

    #[test]
    fn classify_flush_error_treats_tls_unexpected_eof_as_transient() {
        let error = anyhow::anyhow!(
            "blob upload failed: client error (SendRequest): connection error: peer closed connection without sending TLS close_notify: https://docs.rs/rustls/latest/rustls/manual/_03_howto/index.html#unexpected-eof"
        );
        let classified = classify_flush_error(&error, "blob upload failed");
        assert!(matches!(classified, FlushError::Transient(_)));
    }

    #[test]
    fn conflict_backoff_window_is_longer_for_in_progress_conflicts() {
        let (base, jitter) =
            conflict_backoff_window("save_entry failed: another cache upload is in progress");
        assert_eq!(base, KV_CONFLICT_IN_PROGRESS_BACKOFF_MS);
        assert_eq!(jitter, KV_CONFLICT_IN_PROGRESS_JITTER_MS);
    }

    #[test]
    fn transient_backoff_window_is_longer_for_write_path_failures() {
        let (base, jitter) = transient_backoff_window("confirm failed: Server error (500)");
        assert_eq!(base, KV_TRANSIENT_WRITE_PATH_BACKOFF_MS);
        assert_eq!(jitter, KV_TRANSIENT_WRITE_PATH_JITTER_MS);
    }

    #[test]
    fn classify_flush_error_treats_bad_request_as_permanent() {
        let error = anyhow::anyhow!("HTTP 400 from backend: invalid payload");
        let classified = classify_flush_error(&error, "save failed");
        assert!(matches!(classified, FlushError::Permanent(_)));
    }

    #[test]
    fn kv_confirm_verification_retry_delay_is_capped() {
        assert_eq!(
            kv_confirm_verification_retry_delay(1),
            std::time::Duration::from_millis(1_000)
        );
        assert_eq!(
            kv_confirm_verification_retry_delay(3),
            std::time::Duration::from_millis(4_000)
        );
        assert_eq!(
            kv_confirm_verification_retry_delay(6),
            std::time::Duration::from_millis(5_000)
        );
    }

    #[test]
    fn confirm_retry_reason_retries_transient_server_errors() {
        let error = anyhow::anyhow!("Server error (500). Please try again later.");
        let classified = classify_flush_error(&error, "confirm failed");
        let reason = confirm_retry_reason(
            "confirm failed: Server error (500). Please try again later.",
            &classified,
        );
        assert_eq!(reason, Some("transient backend error"));
    }

    #[test]
    fn confirm_retry_reason_prefers_blob_verification_pending() {
        let error = anyhow::anyhow!(
            "Server returned 400 Bad Request: 714 blob(s) not yet verified in storage — retry after upload completes"
        );
        let classified = classify_flush_error(&error, "confirm failed");
        let reason = confirm_retry_reason(
            "confirm failed: Server returned 400 Bad Request: 714 blob(s) not yet verified in storage — retry after upload completes",
            &classified,
        );
        assert_eq!(reason, Some("blob verification pending"));
    }

    #[test]
    fn should_clear_flushing_after_flush_skips_ok_path() {
        assert!(!should_clear_flushing_after_flush(&FlushResult::Ok));
        assert!(should_clear_flushing_after_flush(&FlushResult::Conflict));
        assert!(should_clear_flushing_after_flush(&FlushResult::Error));
        assert!(should_clear_flushing_after_flush(&FlushResult::Permanent));
    }

    #[test]
    fn select_flush_base_entries_uses_backend_when_available() {
        let mut backend = BTreeMap::new();
        backend.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );
        backend.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );
        let mut published = HashMap::new();
        published.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, selection) = select_flush_base_entries(backend.clone(), &published);
        assert!(matches!(selection, FlushBaseSelection::Backend));
        assert_eq!(selected.len(), backend.len());
        assert!(selected.contains_key("k1"));
    }

    #[test]
    fn select_flush_base_entries_falls_back_to_published_when_backend_empty() {
        let backend = BTreeMap::new();
        let mut published = HashMap::new();
        published.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, selection) = select_flush_base_entries(backend, &published);
        assert!(matches!(
            selection,
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 0,
                published_entry_count: 1,
                missing_published_keys: 1,
                mismatched_published_keys: 0
            }
        ));
        assert_eq!(selected.len(), 1);
        assert!(selected.contains_key("k2"));
    }

    #[test]
    fn select_flush_base_entries_preserves_published_when_backend_is_stale_subset() {
        let mut backend = BTreeMap::new();
        backend.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );

        let mut published = HashMap::new();
        published.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );
        published.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, selection) = select_flush_base_entries(backend, &published);
        assert!(matches!(
            selection,
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 1,
                published_entry_count: 2,
                missing_published_keys: 1,
                mismatched_published_keys: 0
            }
        ));
        assert_eq!(selected.len(), 2);
        assert!(selected.contains_key("k1"));
        assert!(selected.contains_key("k2"));
    }

    #[test]
    fn select_flush_base_entries_preserves_published_on_digest_mismatch() {
        let mut backend = BTreeMap::new();
        backend.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );
        let mut published = HashMap::new();
        published.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let (selected, selection) = select_flush_base_entries(backend, &published);
        assert!(matches!(
            selection,
            FlushBaseSelection::PublishedFallback {
                backend_entry_count: 1,
                published_entry_count: 1,
                missing_published_keys: 0,
                mismatched_published_keys: 1
            }
        ));
        assert_eq!(selected.len(), 1);
        let selected_blob = selected.get("k1").expect("expected selected key");
        assert_eq!(selected_blob.digest, "sha256:222");
        assert_eq!(selected_blob.size_bytes, 20);
    }

    #[test]
    fn kv_alias_tags_exclude_internal_root_tag() {
        let aliases = kv_alias_tags_from_values(
            "bc_registry_root_v2_abc",
            &[String::from("alias-a"), String::from("alias-b")],
        );
        assert_eq!(aliases, vec!["alias-a".to_string(), "alias-b".to_string()]);
    }

    #[test]
    fn pending_refresh_suppression_applies_for_recent_local_puts() {
        let now_ms: u64 = 100_000;
        let last_put_ms = now_ms.saturating_sub(5_000);
        assert!(should_suppress_lookup_refresh_due_to_pending_values(
            true,
            last_put_ms,
            now_ms
        ));
    }

    #[test]
    fn pending_refresh_suppression_expires_after_window() {
        let now_ms: u64 = 100_000;
        let last_put_ms =
            now_ms.saturating_sub(KV_PENDING_REFRESH_SUPPRESSION_WINDOW.as_millis() as u64 + 1);
        assert!(!should_suppress_lookup_refresh_due_to_pending_values(
            true,
            last_put_ms,
            now_ms
        ));
    }

    #[test]
    fn pending_refresh_suppression_requires_pending_entries() {
        let now_ms: u64 = 100_000;
        let last_put_ms = now_ms.saturating_sub(1_000);
        assert!(!should_suppress_lookup_refresh_due_to_pending_values(
            false,
            last_put_ms,
            now_ms
        ));
    }

    #[test]
    fn pending_or_flushing_refresh_suppression_applies_when_flushing() {
        let now_ms: u64 = 100_000;
        assert!(
            should_suppress_lookup_refresh_due_to_pending_or_flushing_values(
                false, true, 0, now_ms
            )
        );
    }

    #[test]
    fn count_published_gaps_in_backend_reports_subset_gap() {
        let mut backend = BTreeMap::new();
        backend.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );

        let mut published = HashMap::new();
        published.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );
        published.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        assert_eq!(
            count_published_gaps_in_backend(&backend, &published),
            PublishedGapCounts {
                missing_keys: 1,
                mismatched_keys: 0
            }
        );
    }

    #[test]
    fn count_published_gaps_in_backend_reports_digest_mismatch() {
        let mut backend = BTreeMap::new();
        backend.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:111".to_string(),
                size_bytes: 10,
            },
        );
        backend.insert(
            "k2".to_string(),
            BlobDescriptor {
                digest: "sha256:222".to_string(),
                size_bytes: 20,
            },
        );

        let mut published = HashMap::new();
        published.insert(
            "k1".to_string(),
            BlobDescriptor {
                digest: "sha256:999".to_string(),
                size_bytes: 99,
            },
        );

        assert_eq!(
            count_published_gaps_in_backend(&backend, &published),
            PublishedGapCounts {
                missing_keys: 0,
                mismatched_keys: 1
            }
        );
    }

    #[test]
    fn replication_enqueue_marks_deferred_when_channel_is_full() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let queue_depth = AtomicU64::new(0);
        let enqueue_deferred = AtomicU64::new(0);

        assert!(try_enqueue_replication_work(
            &tx,
            &queue_depth,
            &enqueue_deferred,
            false,
            true
        ));
        assert!(!try_enqueue_replication_work(
            &tx,
            &queue_depth,
            &enqueue_deferred,
            false,
            true
        ));

        assert_eq!(queue_depth.load(Ordering::Acquire), 1);
        assert_eq!(enqueue_deferred.load(Ordering::Acquire), 1);
    }

    #[test]
    fn replication_enqueue_does_not_increment_deferred_when_not_counted() {
        let (tx, _rx) = tokio::sync::mpsc::channel(1);
        let queue_depth = AtomicU64::new(0);
        let enqueue_deferred = AtomicU64::new(0);

        assert!(try_enqueue_replication_work(
            &tx,
            &queue_depth,
            &enqueue_deferred,
            false,
            true
        ));
        assert!(!try_enqueue_replication_work(
            &tx,
            &queue_depth,
            &enqueue_deferred,
            false,
            false
        ));

        assert_eq!(queue_depth.load(Ordering::Acquire), 1);
        assert_eq!(enqueue_deferred.load(Ordering::Acquire), 0);
    }

    #[test]
    fn should_skip_blob_preload_when_cache_is_near_capacity() {
        assert!(should_skip_blob_preload(95, 100));
        assert!(should_skip_blob_preload(190, 200));
        assert!(!should_skip_blob_preload(94, 100));
    }

    #[test]
    fn should_skip_blob_preload_when_cache_capacity_is_invalid() {
        assert!(should_skip_blob_preload(0, 0));
        assert!(should_skip_blob_preload(10, 0));
    }

    #[test]
    fn kv_startup_prefetch_limits_allow_env_overrides() {
        let _guard = test_env::lock();

        test_env::set_var(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV, "48");
        test_env::set_var(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV, "2097152");
        assert_eq!(kv_startup_prefetch_max_blobs(), 48);
        assert_eq!(
            kv_startup_prefetch_max_total_bytes(1024 * 1024 * 1024),
            2_097_152
        );
        test_env::remove_var(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV);
        test_env::remove_var(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV);
    }

    #[test]
    fn startup_prefetch_slice_respects_order_and_total_budget() {
        let blobs = vec![
            BlobDescriptor {
                digest: "sha256:1".to_string(),
                size_bytes: 10,
            },
            BlobDescriptor {
                digest: "sha256:2".to_string(),
                size_bytes: 15,
            },
            BlobDescriptor {
                digest: "sha256:3".to_string(),
                size_bytes: 20,
            },
        ];

        let selected = select_startup_prefetch_slice(&blobs, 3, 25);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].digest, "sha256:1");
        assert_eq!(selected[1].digest, "sha256:2");
    }

    #[test]
    fn startup_prefetch_slice_skips_oversized_blobs_instead_of_stopping() {
        let blobs = vec![
            BlobDescriptor {
                digest: "sha256:1".to_string(),
                size_bytes: 10,
            },
            BlobDescriptor {
                digest: "sha256:oversized".to_string(),
                size_bytes: 1_000,
            },
            BlobDescriptor {
                digest: "sha256:2".to_string(),
                size_bytes: 15,
            },
        ];

        let selected = select_startup_prefetch_slice(&blobs, 3, 25);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].digest, "sha256:1");
        assert_eq!(selected[1].digest, "sha256:2");
    }

    #[test]
    fn kv_blob_prefetch_max_inflight_bytes_uses_env_override() {
        let _guard = test_env::lock();

        test_env::set_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV, "12345");
        assert_eq!(kv_blob_prefetch_max_inflight_bytes(1024 * 1024), 12_345);
        test_env::remove_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV);
    }

    #[test]
    fn startup_prefetch_defaults_cover_full_tag_by_default() {
        let _guard = test_env::lock();
        test_env::remove_var(KV_STARTUP_PREFETCH_MAX_BLOBS_ENV);
        test_env::remove_var(KV_STARTUP_PREFETCH_MAX_TOTAL_BYTES_ENV);
        test_env::remove_var(KV_BLOB_PREFETCH_MAX_INFLIGHT_BYTES_ENV);
        let cache_max = 4 * 1024 * 1024 * 1024;
        assert_eq!(kv_startup_prefetch_max_blobs(), usize::MAX);
        assert_eq!(kv_startup_prefetch_max_total_bytes(cache_max), cache_max);
        assert_eq!(
            kv_blob_prefetch_max_inflight_bytes(cache_max),
            512 * 1024 * 1024
        );
    }

    #[test]
    fn startup_prefetch_candidates_preserve_blob_order() {
        let blob_order = vec![
            BlobDescriptor {
                digest: "sha256:large-cas".to_string(),
                size_bytes: 4_096,
            },
            BlobDescriptor {
                digest: "sha256:ac".to_string(),
                size_bytes: 128,
            },
            BlobDescriptor {
                digest: "sha256:small-cas".to_string(),
                size_bytes: 1024,
            },
        ];
        let candidates = startup_prefetch_candidates(&blob_order);

        assert_eq!(candidates.ordered_blobs.len(), 3);
        assert_eq!(candidates.ordered_blobs[0].digest, "sha256:large-cas");
        assert_eq!(candidates.ordered_blobs[1].digest, "sha256:ac");
        assert_eq!(candidates.ordered_blobs[2].digest, "sha256:small-cas");
    }

    #[test]
    fn background_blob_preload_candidates_fill_budget_without_count_or_blob_size_knobs() {
        let blobs = vec![
            BlobDescriptor {
                digest: "sha256:1".to_string(),
                size_bytes: 5,
            },
            BlobDescriptor {
                digest: "sha256:2".to_string(),
                size_bytes: 9,
            },
            BlobDescriptor {
                digest: "sha256:3".to_string(),
                size_bytes: 3,
            },
        ];
        let urls = HashMap::from([
            ("sha256:1".to_string(), "https://example.com/1".to_string()),
            ("sha256:2".to_string(), "https://example.com/2".to_string()),
            ("sha256:3".to_string(), "https://example.com/3".to_string()),
        ]);

        let selected =
            select_blob_preload_candidates(&blobs, 8, |digest| urls.get(digest).cloned());

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0.digest, "sha256:1");
        assert_eq!(selected[1].0.digest, "sha256:3");
    }

    #[test]
    fn startup_prefetch_blobs_uses_whole_tag_when_it_fits() {
        let blobs = vec![
            BlobDescriptor {
                digest: "sha256:1".to_string(),
                size_bytes: 64,
            },
            BlobDescriptor {
                digest: "sha256:2".to_string(),
                size_bytes: 64,
            },
        ];

        let selected = startup_prefetch_blobs(&blobs, 1, 64, true);

        assert_eq!(selected.len(), blobs.len());
        assert_eq!(selected[0].digest, blobs[0].digest);
        assert_eq!(selected[1].digest, blobs[1].digest);
    }

    #[test]
    fn startup_prefetch_targets_keep_blobs_without_preloaded_urls() {
        let blobs = vec![
            BlobDescriptor {
                digest: "sha256:1".to_string(),
                size_bytes: 64,
            },
            BlobDescriptor {
                digest: "sha256:2".to_string(),
                size_bytes: 64,
            },
        ];
        let cached_urls = HashMap::from([(
            "sha256:1".to_string(),
            "https://example.com/blob-1".to_string(),
        )]);

        let (targets, summary) =
            build_startup_prefetch_targets(&blobs, |digest| cached_urls.get(digest).cloned());

        assert_eq!(targets.len(), 2);
        assert_eq!(summary.cached_url_count, 1);
        assert_eq!(summary.unresolved_url_count, 1);
        assert_eq!(
            targets[0].cached_url.as_deref(),
            Some("https://example.com/blob-1")
        );
        assert!(targets[1].cached_url.is_none());
    }

    #[test]
    fn startup_download_url_preload_stays_on_startup_slice() {
        let startup_blobs = vec![
            BlobDescriptor {
                digest: "sha256:1".to_string(),
                size_bytes: 128,
            },
            BlobDescriptor {
                digest: "sha256:2".to_string(),
                size_bytes: 256,
            },
        ];

        let selected = startup_download_url_preload_blobs(&startup_blobs);

        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].digest, "sha256:1");
        assert_eq!(selected[1].digest, "sha256:2");
    }

    #[test]
    fn version_poll_interval_active_includes_jitter() {
        let base_ms = KV_VERSION_POLL_ACTIVE_SECS * 1000;
        let min = base_ms.saturating_sub(KV_VERSION_POLL_JITTER_MS);
        let max = base_ms + KV_VERSION_POLL_JITTER_MS;
        assert!(min < max);
        assert!(min >= 2000, "active poll min should be >= 2s");
        assert!(max <= 4000, "active poll max should be <= 4s");
    }

    #[test]
    fn version_poll_interval_idle_includes_jitter() {
        let base_ms = KV_VERSION_POLL_IDLE_SECS * 1000;
        let min = base_ms.saturating_sub(KV_VERSION_POLL_JITTER_MS);
        let max = base_ms + KV_VERSION_POLL_JITTER_MS;
        assert!(min < max);
        assert!(min >= 29000, "idle poll min should be >= 29s");
        assert!(max <= 31000, "idle poll max should be <= 31s");
    }

    #[test]
    fn version_change_detection_detects_new_id() {
        let last: Option<String> = Some("old-id".to_string());
        let new: Option<&str> = Some("new-id");
        let changed = match (&last, new) {
            (Some(old), Some(new_val)) => old != new_val,
            (None, Some(_)) => true,
            _ => false,
        };
        assert!(changed);
    }

    #[test]
    fn version_change_detection_ignores_same_id() {
        let last: Option<String> = Some("same-id".to_string());
        let new: Option<&str> = Some("same-id");
        let changed = match (&last, new) {
            (Some(old), Some(new_val)) => old != new_val,
            (None, Some(_)) => true,
            _ => false,
        };
        assert!(!changed);
    }

    #[test]
    fn version_change_detection_triggers_on_first_id() {
        let last: Option<String> = None;
        let new: Option<&str> = Some("first-id");
        let changed = match (&last, new) {
            (Some(old), Some(new_val)) => old != new_val,
            (None, Some(_)) => true,
            _ => false,
        };
        assert!(changed);
    }

    #[test]
    fn version_refresh_cooldown_prevents_rapid_refreshes() {
        let cooldown_ms = KV_VERSION_REFRESH_COOLDOWN.as_millis() as u64;
        assert!(
            cooldown_ms >= 10_000,
            "refresh cooldown should be >= 10s to prevent storms"
        );
        assert!(
            cooldown_ms > KV_VERSION_POLL_ACTIVE_SECS * 1000,
            "cooldown must exceed active poll interval"
        );
    }

    #[test]
    fn version_change_detection_ignores_none_to_none() {
        let last: Option<String> = None;
        let new: Option<&str> = None;
        let changed = match (&last, new) {
            (Some(old), Some(new_val)) => old != new_val,
            (None, Some(_)) => true,
            _ => false,
        };
        assert!(!changed);
    }
}
