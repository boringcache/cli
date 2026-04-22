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
const KV_CONFIRM_RETRY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(90);
const KV_CONFIRM_RETRY_BASE_MS: u64 = 1_000;
const KV_CONFIRM_RETRY_MAX_MS: u64 = 5_000;
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

mod blob_read;
mod confirm;
mod flight;
mod flush;
mod handoff;
mod index;
mod instrumentation;
mod lookup;
mod policy;
mod prefetch;
mod refresh;
mod schedule;
mod types;
mod write;

pub(crate) use blob_read::*;
pub(crate) use confirm::*;
pub(crate) use flight::*;
pub(crate) use flush::*;
pub(crate) use handoff::*;
pub(crate) use index::*;
pub(crate) use instrumentation::*;
pub(crate) use lookup::*;
pub(crate) use policy::*;
pub(crate) use prefetch::*;
pub(crate) use refresh::*;
pub(crate) use schedule::*;
pub(crate) use types::*;
pub(crate) use write::*;

#[cfg(test)]
mod tests;
